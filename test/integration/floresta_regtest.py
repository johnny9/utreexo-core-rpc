#!/usr/bin/env python3
"""Differential regtest: C++ sidecar == reference bridge == Floresta roots.

The reference bridge supplies proof-bearing blocks to Floresta because the C++
sidecar does not expose its P2P bridge endpoint yet. The C++ sidecar and the
reference bridge independently reconstruct the same Core chain. Floresta then
validates the reference proofs and must report the identical roots.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable


SKIP = 77
RPC_USER = "utreexo_harness"
RPC_PASSWORD = "utreexo_harness_password"
FLORESTA_VERSION = "florestad v0.8.1"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def resolve_binary(value: str | None, env_name: str, fallback: str | None = None) -> Path | None:
    candidate = value or os.environ.get(env_name)
    if not candidate and fallback:
        candidate = shutil.which(fallback)
    if not candidate:
        return None
    path = Path(candidate).expanduser().resolve()
    return path if path.is_file() and os.access(path, os.X_OK) else None


class ManagedProcess:
    def __init__(self, name: str, command: list[str], data_dir: Path, env: dict[str, str] | None = None):
        self.name = name
        self.log_path = data_dir / f"{name}.log"
        self.log = self.log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

    def assert_running(self) -> None:
        status = self.process.poll()
        if status is not None:
            raise RuntimeError(f"{self.name} exited with status {status}; see {self.log_path}")

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def http_json(url: str, payload: dict[str, Any] | None = None,
              authorization: tuple[str, str] | None = None, timeout: float = 10) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if authorization:
        token = base64.b64encode(f"{authorization[0]}:{authorization[1]}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {error.code} from {url}: {body}") from error


def rpc(url: str, method: str, params: list[Any] | None = None,
        authorization: tuple[str, str] | None = None, version: str = "1.0") -> Any:
    response = http_json(
        url,
        {"jsonrpc": version, "id": "utreexo-harness", "method": method, "params": params or []},
        authorization,
    )
    if response.get("error") is not None:
        raise RuntimeError(f"RPC {method} failed: {response['error']}")
    return response["result"]


def wait_for(description: str, predicate: Callable[[], Any], processes: list[ManagedProcess],
             timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        for process in processes:
            process.assert_running()
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, RuntimeError) as error:
            last_error = error
        time.sleep(0.25)
    suffix = f": {last_error}" if last_error else ""
    raise TimeoutError(f"timed out waiting for {description}{suffix}")


def normalize_roots(roots: list[str]) -> list[str]:
    return [root.lower() for root in roots]


def run(args: argparse.Namespace) -> int:
    source_dir = Path(__file__).resolve().parents[2]
    bitcoind = resolve_binary(args.bitcoind, "BITCOIND_EXE", "bitcoind")
    sidecar = resolve_binary(args.sidecar, "UTREEXO_BRIDGE_EXE") or (source_dir / "build/utreexo-bridge")
    reference = resolve_binary(args.reference_bridge, "UTREEXO_REFERENCE_BRIDGE_EXE")
    florestad = resolve_binary(args.florestad, "FLORESTAD_EXE")
    missing = [name for name, binary in {
        "bitcoind": bitcoind,
        "C++ utreexo-bridge": sidecar if sidecar.is_file() else None,
        "reference bridge": reference,
        "florestad": florestad,
    }.items() if binary is None]
    if missing:
        print("SKIP: missing executable(s): " + ", ".join(missing), file=sys.stderr)
        return SKIP

    floresta_version = subprocess.run(
        [str(florestad), "--version"], check=True, text=True, capture_output=True).stdout.strip()
    if floresta_version != FLORESTA_VERSION:
        raise RuntimeError(
            f"wire-incompatible Floresta version {floresta_version!r}; "
            f"this legacy bridge harness requires {FLORESTA_VERSION!r}")

    work = Path(args.work_dir).resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix="utreexo-floresta-regtest-"))
    work.mkdir(parents=True, exist_ok=True)
    core_dir = work / "core"
    reference_dir = work / "reference-bridge"
    floresta_dir = work / "floresta"
    for directory in (core_dir, reference_dir, floresta_dir):
        directory.mkdir(parents=True, exist_ok=True)

    core_rpc_port, reference_p2p_port, reference_api_port, floresta_rpc_port = (free_port() for _ in range(4))
    auth = (RPC_USER, RPC_PASSWORD)
    core_url = f"http://127.0.0.1:{core_rpc_port}"
    wallet_url = core_url + "/wallet/bridge-harness"
    processes: list[ManagedProcess] = []
    succeeded = False
    try:
        core = ManagedProcess("bitcoind", [
            str(bitcoind), f"-datadir={core_dir}", "-regtest", "-server=1", "-daemon=0",
            "-listen=0", "-dnsseed=0", "-discover=0", "-txindex=1", "-fallbackfee=0.0002",
            "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", f"-rpcport={core_rpc_port}",
            f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASSWORD}", "-printtoconsole=1",
        ], work)
        processes.append(core)
        wait_for("Bitcoin Core RPC", lambda: rpc(core_url, "getblockcount", authorization=auth) >= 0,
                 processes, args.timeout)

        rpc(core_url, "createwallet", ["bridge-harness"], auth)
        mining_address = rpc(wallet_url, "getnewaddress", ["", "bech32"], auth)
        rpc(wallet_url, "generatetoaddress", [101, mining_address], auth)

        # A SegWit spend ensures txid != wtxid in the source data.
        recipient = rpc(wallet_url, "getnewaddress", ["", "bech32"], auth)
        rpc(wallet_url, "sendtoaddress", [recipient, 1.0], auth)
        rpc(wallet_url, "generatetoaddress", [1, mining_address], auth)

        # Parent and child enter the same block, exercising same-block cancellation.
        parent_address = rpc(wallet_url, "getnewaddress", ["", "bech32"], auth)
        parent_txid = rpc(wallet_url, "sendtoaddress", [parent_address, 0.5], auth)
        parent = rpc(core_url, "getrawtransaction", [parent_txid, True], auth)
        parent_vout = next(output["n"] for output in parent["vout"]
                           if output["scriptPubKey"].get("address") == parent_address)
        child_address = rpc(wallet_url, "getnewaddress", ["", "bech32"], auth)
        child_raw = rpc(core_url, "createrawtransaction",
                        [[{"txid": parent_txid, "vout": parent_vout}], [{child_address: 0.49}]], auth)
        child_signed = rpc(wallet_url, "signrawtransactionwithwallet", [child_raw], auth)
        if not child_signed["complete"]:
            raise RuntimeError("wallet could not sign the same-block child")
        rpc(core_url, "sendrawtransaction", [child_signed["hex"]], auth)
        rpc(wallet_url, "generatetoaddress", [1, mining_address], auth)

        # Include an OP_RETURN plus a normal change output in one transaction.
        op_return = rpc(core_url, "createrawtransaction", [[], [{"data": "deadbeef"}]], auth)
        funded = rpc(wallet_url, "fundrawtransaction", [op_return], auth)
        signed = rpc(wallet_url, "signrawtransactionwithwallet", [funded["hex"]], auth)
        rpc(core_url, "sendrawtransaction", [signed["hex"]], auth)
        rpc(wallet_url, "generatetoaddress", [1, mining_address], auth)

        tip_height = rpc(core_url, "getblockcount", authorization=auth)
        tip_hash = rpc(core_url, "getbestblockhash", authorization=auth)

        reference_env = os.environ.copy()
        reference_env.update({
            "DATA_DIR": str(reference_dir),
            "P2P_HOST": "127.0.0.1",
            "P2P_PORT": str(reference_p2p_port),
            "API_HOST": f"127.0.0.1:{reference_api_port}",
            "BITCOIN_CORE_RPC_URL": core_url,
            "BITCOIN_CORE_RPC_USER": RPC_USER,
            "BITCOIN_CORE_RPC_PASSWORD": RPC_PASSWORD,
        })
        reference_process = ManagedProcess(
            "reference-bridge", [str(reference), "--network", "regtest"], work, reference_env)
        processes.append(reference_process)
        reference_base = f"http://127.0.0.1:{reference_api_port}"
        wait_for("reference bridge tip", lambda: http_json(f"{reference_base}/roots/{tip_hash}").get("data"),
                 processes, args.timeout)
        reference_state = http_json(f"{reference_base}/acc")["data"]

        # Compare both independent reconstructions before adding Floresta as
        # the proof-consuming layer. Core stays online because the reference
        # bridge continuously polls it for new blocks while serving peers.
        state_path = work / "cpp-state.json"
        sidecar_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}", f"--state-json={state_path}",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
        (work / "cpp-sidecar.log").write_text(sidecar_result.stdout, encoding="utf-8")
        if sidecar_result.returncode != 0:
            raise RuntimeError(f"C++ sidecar failed with {sidecar_result.returncode}; see {work / 'cpp-sidecar.log'}")
        cpp_state = json.loads(state_path.read_text(encoding="utf-8"))

        cpp_roots = normalize_roots(cpp_state["roots"])
        reference_roots = normalize_roots(reference_state["roots"])
        if cpp_state["height"] != tip_height or cpp_state["block_hash"] != tip_hash:
            raise AssertionError(f"C++ sidecar tip mismatch: {cpp_state}")
        if cpp_state["num_leaves"] != reference_state["leaves"]:
            raise AssertionError(
                f"leaf-count mismatch: C++={cpp_state['num_leaves']} reference={reference_state['leaves']}")
        if cpp_roots != reference_roots:
            raise AssertionError(f"root mismatch: C++={cpp_roots} reference={reference_roots}")

        floresta_process = ManagedProcess("florestad", [
            str(florestad), "--network=regtest", f"--data-dir={floresta_dir}",
            f"--rpc-address=127.0.0.1:{floresta_rpc_port}",
            f"--connect=127.0.0.1:{reference_p2p_port}", "--allow-v1-fallback",
            # v0.8.1's hardcoded regtest assume-valid point is genesis, so all
            # non-genesis transaction scripts in this chain are still checked.
            "--no-assume-utreexo", "--no-cfilters",
        ], work)
        processes.append(floresta_process)
        floresta_url = f"http://127.0.0.1:{floresta_rpc_port}"

        def floresta_synced() -> bool:
            info = rpc(floresta_url, "getblockchaininfo", version="2.0")
            return (info["height"] == tip_height and info["validated"] == tip_height
                    and info["best_block"] == tip_hash and not info["ibd"])

        wait_for("Floresta validation tip", floresta_synced, processes, args.timeout)
        floresta_roots = rpc(floresta_url, "getroots", version="2.0")
        floresta_roots = normalize_roots(floresta_roots)
        if floresta_roots != reference_roots:
            raise AssertionError(f"root mismatch: Floresta={floresta_roots} reference={reference_roots}")

        print(json.dumps({
            "height": tip_height,
            "block_hash": tip_hash,
            "num_leaves": cpp_state["num_leaves"],
            "roots": cpp_roots,
            "validated": ["cpp-sidecar", "reference-bridge", "floresta"],
        }, indent=2))
        succeeded = True
        return 0
    finally:
        for process in reversed(processes):
            process.stop()
        if succeeded and not args.keep_data and not args.work_dir:
            shutil.rmtree(work)
        else:
            print(f"regtest artifacts: {work}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind")
    parser.add_argument("--sidecar")
    parser.add_argument("--reference-bridge", help="rpc-utreexo-bridge executable")
    parser.add_argument("--florestad")
    parser.add_argument("--work-dir")
    parser.add_argument("--keep-data", action="store_true")
    parser.add_argument("--timeout", type=float, default=180.0)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
