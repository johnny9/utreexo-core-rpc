#!/usr/bin/env python3
"""Differential regtest plus current-Floresta validation through the C++ sidecar.

The C++ sidecar and reference bridge independently reconstruct the same Core
chain. A separate checkpoint-to-tip run validates the primary suffix-archive
bootstrap and reopen path. Floresta initially reaches its AssumeUtreexo state
through the reference peer. Once running, it adds Bitcoin Core as its block peer
and the C++ sidecar as its proof peer; the reference peer is stopped before a
transaction-bearing block proves that split block/proof operation works. The
sidecar intentionally does not participate in header sync in this harness.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Protocol


SKIP = 77
RPC_USER = "utreexo_harness"
RPC_PASSWORD = "utreexo_harness_password"
MIN_FLORESTA_VERSION = (0, 9, 1)


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


class ManagedService(Protocol):
    def assert_running(self) -> None: ...
    def stop(self) -> None: ...


class LegacyReferenceServiceProxy:
    """Translate the retired reference bridge's pre-BIP service bit.

    The frozen differential fixture still advertises its Utreexo capability at
    bit 24. Current Floresta uses BIP service bits 12 and 13, but its block,
    proof, and accumulator-state wire payloads remain compatible. This local
    proxy changes only the reference fixture's version.services field so it can
    bootstrap Floresta into RunningNode; all later proof traffic under test is
    served directly by the C++ sidecar.
    """

    NODE_UTREEXO = 1 << 12
    NODE_UTREEXO_ARCHIVE = 1 << 13
    MAX_MESSAGE_BYTES = 32 * 1024 * 1024

    def __init__(self, listen_port: int, target_port: int):
        self.name = "legacy-reference-service-proxy"
        self._target_port = target_port
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._translated_versions = 0
        self._connections: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", listen_port))
        self._listener.listen()
        self._listener.settimeout(0.25)
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def assert_running(self) -> None:
        if self._error is not None:
            raise RuntimeError(f"{self.name} failed: {self._error}")
        if not self._thread.is_alive() and not self._stop.is_set():
            raise RuntimeError(f"{self.name} stopped unexpectedly")

    def stop(self) -> None:
        self._stop.set()
        self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self._thread.join(timeout=5)

    def translated_versions(self) -> int:
        with self._lock:
            return self._translated_versions

    def _accept(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    client, _ = self._listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        return
                    raise
                threading.Thread(target=self._handle, args=(client,), daemon=True).start()
        except Exception as error:  # surfaced synchronously by wait_for
            if not self._stop.is_set():
                self._error = error

    def _handle(self, client: socket.socket) -> None:
        try:
            upstream = socket.create_connection(("127.0.0.1", self._target_port), timeout=10)
        except OSError:
            client.close()
            return
        client.settimeout(None)
        upstream.settimeout(None)
        with self._lock:
            self._connections.update((client, upstream))
        done = threading.Event()
        raw = threading.Thread(
            target=self._relay_raw, args=(client, upstream, done), daemon=True)
        framed = threading.Thread(
            target=self._relay_reference_messages,
            args=(upstream, client, done), daemon=True,
        )
        raw.start()
        framed.start()
        done.wait()
        for connection in (client, upstream):
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        raw.join(timeout=1)
        framed.join(timeout=1)
        with self._lock:
            self._connections.difference_update((client, upstream))

    @staticmethod
    def _recv_exact(source: socket.socket, size: int) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = source.recv(size - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)

    @staticmethod
    def _relay_raw(source: socket.socket, destination: socket.socket,
                   done: threading.Event) -> None:
        try:
            while not done.is_set():
                chunk = source.recv(64 * 1024)
                if not chunk:
                    return
                destination.sendall(chunk)
        except OSError:
            pass
        finally:
            done.set()

    def _relay_reference_messages(self, source: socket.socket,
                                  destination: socket.socket,
                                  done: threading.Event) -> None:
        try:
            while not done.is_set():
                header = self._recv_exact(source, 24)
                if header is None:
                    return
                payload_size = struct.unpack_from("<I", header, 16)[0]
                if payload_size > self.MAX_MESSAGE_BYTES:
                    raise ValueError(f"reference message is too large: {payload_size}")
                payload = self._recv_exact(source, payload_size)
                if payload is None:
                    return
                command = header[4:16].rstrip(b"\0")
                if command == b"version" and len(payload) >= 12:
                    # version payload: protocol version (i32), services (u64).
                    services = struct.unpack_from("<Q", payload, 4)[0]
                    services |= self.NODE_UTREEXO | self.NODE_UTREEXO_ARCHIVE
                    payload = payload[:4] + struct.pack("<Q", services) + payload[12:]
                    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                    header = header[:16] + struct.pack("<I", len(payload)) + checksum
                    with self._lock:
                        self._translated_versions += 1
                destination.sendall(header + payload)
        except (OSError, ValueError):
            pass
        finally:
            done.set()


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


def wait_for(description: str, predicate: Callable[[], Any], processes: list[ManagedService],
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
    version_match = re.search(r"florestad v(\d+)\.(\d+)\.(\d+)", floresta_version)
    if not version_match or tuple(map(int, version_match.groups())) < MIN_FLORESTA_VERSION:
        raise RuntimeError(
            f"wire-incompatible Floresta version {floresta_version!r}; "
            f"this sidecar harness requires >= v{'.'.join(map(str, MIN_FLORESTA_VERSION))}")

    work = Path(args.work_dir).resolve() if args.work_dir else Path(tempfile.mkdtemp(prefix="utreexo-floresta-regtest-"))
    work.mkdir(parents=True, exist_ok=True)
    core_dir = work / "core"
    reference_dir = work / "reference-bridge"
    floresta_dir = work / "floresta"
    for directory in (core_dir, reference_dir, floresta_dir):
        directory.mkdir(parents=True, exist_ok=True)

    (core_rpc_port, core_p2p_port, reference_p2p_port, reference_api_port,
     reference_proxy_port, sidecar_p2p_port, floresta_rpc_port) = (
         free_port() for _ in range(7))
    auth = (RPC_USER, RPC_PASSWORD)
    core_url = f"http://127.0.0.1:{core_rpc_port}"
    wallet_url = core_url + "/wallet/bridge-harness"
    processes: list[ManagedService] = []
    succeeded = False
    try:
        core = ManagedProcess("bitcoind", [
            str(bitcoind), f"-datadir={core_dir}", "-regtest", "-server=1", "-daemon=0",
            "-listen=1", f"-bind=127.0.0.1:{core_p2p_port}", "-dnsseed=0", "-discover=0",
            "-listenonion=0", "-txindex=1", "-fallbackfee=0.0002",
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
        reference_proxy = LegacyReferenceServiceProxy(
            reference_proxy_port, reference_p2p_port)
        processes.append(reference_proxy)

        # Compare both independent reconstructions before adding Floresta as
        # the proof-consuming layer. Core stays online because the reference
        # bridge continuously polls it for new blocks while serving peers.
        state_path = work / "cpp-state.json"
        online_dir = work / "cpp-online"
        sidecar_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}", f"--state-json={state_path}",
            f"--online-state={online_dir}",
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

        # Add one block after the storage switch. Reopening must rebuild and
        # validate the reverse index, apply this block through the durable WAL,
        # flush the mmap base on clean exit, and remain equal to the independent
        # reference bridge.
        rpc(wallet_url, "generatetoaddress", [1, mining_address], auth)
        tip_height = rpc(core_url, "getblockcount", authorization=auth)
        tip_hash = rpc(core_url, "getbestblockhash", authorization=auth)
        wait_for("reference bridge post-switch tip",
                 lambda: http_json(f"{reference_base}/roots/{tip_hash}").get("data"),
                 processes, args.timeout)
        reference_state = http_json(f"{reference_base}/acc")["data"]

        reopen_state_path = work / "cpp-reopen-state.json"
        reopen_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}",
            f"--state-json={reopen_state_path}", f"--online-state={online_dir}",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=args.timeout)
        (work / "cpp-sidecar-reopen.log").write_text(reopen_result.stdout, encoding="utf-8")
        if reopen_result.returncode != 0:
            raise RuntimeError(
                f"C++ sidecar reopen failed with {reopen_result.returncode}; "
                f"see {work / 'cpp-sidecar-reopen.log'}")
        if "event=online_state_loaded" not in reopen_result.stdout:
            raise AssertionError("C++ sidecar did not report online-state recovery")
        if "event=online_delta_sealed" not in reopen_result.stdout:
            raise AssertionError("C++ sidecar did not report the post-switch delta seal")
        cpp_state = json.loads(reopen_state_path.read_text(encoding="utf-8"))
        cpp_roots = normalize_roots(cpp_state["roots"])
        reference_roots = normalize_roots(reference_state["roots"])
        if cpp_state["height"] != tip_height or cpp_state["block_hash"] != tip_hash:
            raise AssertionError(f"reopened C++ sidecar tip mismatch: {cpp_state}")
        if cpp_state["num_leaves"] != reference_state["leaves"]:
            raise AssertionError(
                f"post-switch leaf-count mismatch: C++={cpp_state['num_leaves']} "
                f"reference={reference_state['leaves']}")
        if cpp_roots != reference_roots:
            raise AssertionError(
                f"post-switch root mismatch: C++={cpp_roots} reference={reference_roots}")

        # Exercise the primary deployment path independently of the full-history
        # archive below: create a compact bootstrap behind the tip, stream it into
        # mmap storage, archive only its suffix, then reopen and scrub both stores.
        # Regtest checkpoints are intentionally local/untrusted; mainnet uses the
        # same format reader plus the separately tested compiled trust anchor.
        suffix_base_height = tip_height - 2
        suffix_block_count = tip_height - suffix_base_height
        suffix_checkpoint = work / "cpp-suffix-bootstrap.chk"
        suffix_checkpoint_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}",
            f"--checkpoint={suffix_checkpoint}", "--allow-untrusted-checkpoint",
            "--fast-sync", f"--stop-height={suffix_base_height}",
            "--log-level=debug",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           timeout=args.timeout)
        suffix_checkpoint_log_path = work / "cpp-suffix-checkpoint.log"
        suffix_checkpoint_log_path.write_text(
            suffix_checkpoint_result.stdout, encoding="utf-8")
        if suffix_checkpoint_result.returncode != 0:
            raise RuntimeError(
                f"suffix bootstrap creation failed with "
                f"{suffix_checkpoint_result.returncode}; see {suffix_checkpoint_log_path}")
        if not suffix_checkpoint.is_file():
            raise AssertionError("suffix bootstrap checkpoint was not created")

        suffix_online_dir = work / "cpp-suffix-online"
        suffix_proof_store_dir = work / "cpp-suffix-proof-store"
        suffix_state_path = work / "cpp-suffix-state.json"
        suffix_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}",
            f"--checkpoint={suffix_checkpoint}", "--allow-untrusted-checkpoint",
            f"--online-state={suffix_online_dir}",
            f"--proof-store={suffix_proof_store_dir}", "--proof-store-scrub",
            f"--stop-height={tip_height}", f"--state-json={suffix_state_path}",
            "--proof-store-group-blocks=2", "--log-level=debug",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           timeout=args.timeout)
        suffix_log_path = work / "cpp-suffix-sidecar.log"
        suffix_log_path.write_text(suffix_result.stdout, encoding="utf-8")
        if suffix_result.returncode != 0:
            raise RuntimeError(
                f"checkpoint suffix archive failed with {suffix_result.returncode}; "
                f"see {suffix_log_path}")
        if not any(
                "event=proof_store_opened" in line and
                f"base_height={suffix_base_height}" in line and
                "full_history=false" in line
                for line in suffix_result.stdout.splitlines()):
            raise AssertionError("checkpoint suffix store reported incorrect coverage")
        if not any(
                "event=proof_store_scrub_completed" in line and
                f"durable_height={tip_height}" in line and
                f"proofs_verified={suffix_block_count}" in line and
                f"states_verified={suffix_block_count + 1}" in line and
                "full_history=false" in line
                for line in suffix_result.stdout.splitlines()):
            raise AssertionError(
                "checkpoint suffix store did not scrub its complete suffix archive")
        suffix_state = json.loads(suffix_state_path.read_text(encoding="utf-8"))
        if (suffix_state["height"] != tip_height or
                suffix_state["block_hash"] != tip_hash or
                suffix_state["num_leaves"] != reference_state["leaves"] or
                normalize_roots(suffix_state["roots"]) != reference_roots):
            raise AssertionError(
                f"checkpoint suffix archive state mismatch: {suffix_state}")

        suffix_reopen_state_path = work / "cpp-suffix-reopen-state.json"
        suffix_reopen_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}",
            f"--online-state={suffix_online_dir}",
            f"--proof-store={suffix_proof_store_dir}", "--proof-store-scrub",
            f"--stop-height={tip_height}",
            f"--state-json={suffix_reopen_state_path}", "--log-level=debug",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           timeout=args.timeout)
        suffix_reopen_log_path = work / "cpp-suffix-sidecar-reopen.log"
        suffix_reopen_log_path.write_text(
            suffix_reopen_result.stdout, encoding="utf-8")
        if suffix_reopen_result.returncode != 0:
            raise RuntimeError(
                f"checkpoint suffix archive reopen failed with "
                f"{suffix_reopen_result.returncode}; see {suffix_reopen_log_path}")
        if "event=online_state_loaded" not in suffix_reopen_result.stdout:
            raise AssertionError("checkpoint suffix reopen did not load mmap state")
        if not any(
                "event=proof_store_scrub_completed" in line and
                f"durable_height={tip_height}" in line and
                f"proofs_verified={suffix_block_count}" in line and
                f"states_verified={suffix_block_count + 1}" in line and
                "full_history=false" in line
                for line in suffix_reopen_result.stdout.splitlines()):
            raise AssertionError(
                "checkpoint suffix reopen did not scrub its complete suffix archive")
        suffix_reopen_state = json.loads(
            suffix_reopen_state_path.read_text(encoding="utf-8"))
        if suffix_reopen_state != suffix_state:
            raise AssertionError(
                f"checkpoint suffix state changed across reopen: "
                f"before={suffix_state} after={suffix_reopen_state}")

        # Build a durable genesis-to-tip proof/state archive and leave it following
        # Core. This is the actual sidecar peer used below, not a wire fixture.
        archive_online_dir = work / "cpp-archive-online"
        proof_store_dir = work / "cpp-proof-store"
        archive_state_path = work / "cpp-archive-state.json"
        archive_process = ManagedProcess("cpp-archive-sidecar", [
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}", f"--online-state={archive_online_dir}",
            f"--proof-store={proof_store_dir}", f"--state-json={archive_state_path}",
            "--proof-store-group-blocks=8",
            "--proof-store-group-delay-ms=25", "--follow", "--poll-interval-ms=50",
            "--log-level=debug",
            f"--p2p-port={sidecar_p2p_port}", "--p2p-bind=127.0.0.1",
            "--p2p-network=regtest",
        ], work)
        processes.append(archive_process)

        def sidecar_listening() -> bool:
            with socket.create_connection(("127.0.0.1", sidecar_p2p_port), timeout=1):
                return True

        wait_for("C++ archival sidecar P2P listener", sidecar_listening,
                 processes, args.timeout)
        sidecar_log = archive_process.log_path.read_text(encoding="utf-8")
        if "services=NODE_UTREEXO|NODE_UTREEXO_ARCHIVE" not in sidecar_log:
            raise AssertionError("genesis archive did not advertise NODE_UTREEXO_ARCHIVE")
        if not any(
                "event=online_switch_complete" in line and "height=0" in line and
                "reason=default_genesis_mmap" in line
                for line in sidecar_log.splitlines()):
            raise AssertionError("genesis archive did not enter the default mmap mode at height 0")

        floresta_process = ManagedProcess("florestad", [
            str(florestad), "--network=regtest", f"--data-dir={floresta_dir}",
            f"--rpc-address=127.0.0.1:{floresta_rpc_port}",
            f"--connect=127.0.0.1:{reference_proxy_port}", "--allow-v1-fallback",
            # Regtest's AssumeUtreexo point is genesis. Disable the redundant
            # background pass so the transition to RunningNode is deterministic.
            "--no-backfill", "--no-cfilters",
        ], work)
        processes.append(floresta_process)
        floresta_url = f"http://127.0.0.1:{floresta_rpc_port}"
        wait_for("legacy reference service-bit translation",
                 lambda: reference_proxy.translated_versions() > 0,
                 processes, args.timeout)

        # Wait until the reference peer has supplied the header chain and
        # Floresta has activated SyncNode. Connecting the proof-only sidecar
        # before this point would require the intentionally deferred getheaders
        # support. The false argument forces v1 for both local peers.
        wait_for(
            "Floresta post-header SyncNode activation",
            lambda: "Starting sync node" in floresta_process.log_path.read_text(
                encoding="utf-8"),
            processes,
            args.timeout,
        )
        rpc(floresta_url, "addnode",
            [f"127.0.0.1:{sidecar_p2p_port}", "add", False], version="2.0")
        rpc(floresta_url, "addnode",
            [f"127.0.0.1:{core_p2p_port}", "add", False], version="2.0")

        def split_peers_connected() -> bool:
            peers = rpc(floresta_url, "getpeerinfo", version="2.0")
            addresses = {peer.get("address", peer.get("addr", "")) for peer in peers}
            return (any(str(sidecar_p2p_port) in address for address in addresses) and
                    any(str(core_p2p_port) in address for address in addresses))

        wait_for("Floresta Core and sidecar peers", split_peers_connected,
                 processes, args.timeout)

        def floresta_synced() -> bool:
            info = rpc(floresta_url, "getblockchaininfo", version="2.0")
            return (info["height"] == tip_height and info["validated"] == tip_height
                    and info["best_block"] == tip_hash and not info["ibd"])

        wait_for("Floresta validation tip", floresta_synced, processes, args.timeout)
        floresta_roots = rpc(floresta_url, "getroots", version="2.0")
        floresta_roots = normalize_roots(floresta_roots)
        if floresta_roots != reference_roots:
            raise AssertionError(f"root mismatch: Floresta={floresta_roots} reference={reference_roots}")

        reference_proxy.stop()
        processes.remove(reference_proxy)
        reference_process.stop()
        processes.remove(reference_process)

        recipient = rpc(wallet_url, "getnewaddress", ["", "bech32"], auth)
        rpc(wallet_url, "sendtoaddress", [recipient, 0.25], auth)
        rpc(wallet_url, "generatetoaddress", [1, mining_address], auth)
        split_tip_height = rpc(core_url, "getblockcount", authorization=auth)
        split_tip_hash = rpc(core_url, "getbestblockhash", authorization=auth)

        def split_tip_validated() -> bool:
            info = rpc(floresta_url, "getblockchaininfo", version="2.0")
            return (info["height"] == split_tip_height and
                    info["validated"] == split_tip_height and
                    info["best_block"] == split_tip_hash and not info["ibd"])

        wait_for("Floresta split block/proof validation", split_tip_validated,
                 processes, args.timeout)
        wait_for(
            "sidecar proof service log",
            lambda: any(
                "event=p2p_proof_served" in line and
                f"height={split_tip_height}" in line
                for line in archive_process.log_path.read_text(
                    encoding="utf-8").splitlines()
            ),
            processes,
            args.timeout,
        )

        # A graceful sidecar stop drains the archive and writes its own final
        # forest state. Compare that independent state with the client which
        # consumed the sidecar proof for the transaction-bearing block.
        archive_process.stop()
        processes.remove(archive_process)
        archive_log = archive_process.log_path.read_text(encoding="utf-8")
        if archive_process.process.returncode != 0:
            raise RuntimeError(
                f"archival sidecar SIGTERM exit was "
                f"{archive_process.process.returncode}; see {archive_process.log_path}")
        if not any("event=shutdown_requested" in line and "signal=SIGTERM" in line
                   for line in archive_log.splitlines()):
            raise AssertionError("archival sidecar did not log its SIGTERM request")
        if not any("event=shutdown_complete" in line and "signal=SIGTERM" in line
                   for line in archive_log.splitlines()):
            raise AssertionError("archival sidecar did not log completed SIGTERM persistence")
        archive_state = json.loads(archive_state_path.read_text(encoding="utf-8"))
        split_info = rpc(floresta_url, "getblockchaininfo", version="2.0")
        split_roots = normalize_roots(split_info["root_hashes"])
        if (archive_state["height"] != split_tip_height or
                archive_state["block_hash"] != split_tip_hash):
            raise AssertionError(f"archival sidecar final tip mismatch: {archive_state}")
        if archive_state["num_leaves"] != split_info["leaf_count"]:
            raise AssertionError(
                f"archival sidecar/Floresta leaf-count mismatch: "
                f"{archive_state['num_leaves']} != {split_info['leaf_count']}")
        if normalize_roots(archive_state["roots"]) != split_roots:
            raise AssertionError(
                f"archival sidecar/Floresta root mismatch: "
                f"{archive_state['roots']} != {split_info['root_hashes']}")

        # Reopen the exact mmap forest and proof archive after the graceful
        # stop. A complete scrub proves every active proof/state record remains
        # readable, while the second state export checks WAL/base recovery did
        # not change the committed accumulator tip.
        archive_reopen_state_path = work / "cpp-archive-reopen-state.json"
        archive_reopen_result = subprocess.run([
            str(sidecar), "--rpc-host=127.0.0.1", f"--rpc-port={core_rpc_port}",
            f"--rpc-auth={RPC_USER}:{RPC_PASSWORD}",
            f"--online-state={archive_online_dir}", f"--proof-store={proof_store_dir}",
            "--proof-store-scrub", f"--stop-height={split_tip_height}",
            f"--state-json={archive_reopen_state_path}", "--log-level=debug",
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
           timeout=args.timeout)
        archive_reopen_log_path = work / "cpp-archive-sidecar-reopen.log"
        archive_reopen_log_path.write_text(archive_reopen_result.stdout, encoding="utf-8")
        if archive_reopen_result.returncode != 0:
            raise RuntimeError(
                f"archival sidecar scrubbed reopen failed with "
                f"{archive_reopen_result.returncode}; see {archive_reopen_log_path}")
        if "event=online_state_loaded" not in archive_reopen_result.stdout:
            raise AssertionError("archival sidecar reopen did not load its mmap state")
        if "event=proof_store_scrub_completed" not in archive_reopen_result.stdout:
            raise AssertionError("archival sidecar reopen did not complete the proof-store scrub")
        archive_reopen_state = json.loads(
            archive_reopen_state_path.read_text(encoding="utf-8"))
        if archive_reopen_state != archive_state:
            raise AssertionError(
                f"archival sidecar state changed across scrubbed reopen: "
                f"before={archive_state} after={archive_reopen_state}")

        print(json.dumps({
            "height": split_tip_height,
            "block_hash": split_tip_hash,
            "num_leaves": archive_state["num_leaves"],
            "roots": normalize_roots(archive_state["roots"]),
            "validated": ["cpp-sidecar", "reference-bridge", "floresta", "sidecar-p2p"],
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
