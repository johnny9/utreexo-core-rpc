#!/usr/bin/env python3
"""Core 31.1 -> sidecar -> compact utreexod v0.6 regtest mining integration.

Use a fresh --work-dir. Nodes and wallets are isolated; no mining RPC on the
sidecar and no full-UTXO/proof index on the validating utreexod are enabled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from floresta_regtest import LegacyReferenceServiceProxy, ManagedProcess, free_port, rpc, wait_for


def compact(n: int) -> bytes:
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_compact(data: bytes, offset: int) -> tuple[int, int]:
    size = data[offset]
    offset += 1
    if size < 253:
        return size, offset
    width = {253: 2, 254: 4, 255: 8}[size]
    return int.from_bytes(data[offset:offset + width], "little"), offset + width


class CorruptOneProof(LegacyReferenceServiceProxy):
    """Reuse the isolated TCP pump, changing one hash and its transport checksum."""
    def __init__(self, listen_port: int, target_port: int):
        self.corrupted = threading.Event()
        super().__init__(listen_port, target_port)
        self.name = "single-bad-transaction-proof"

    def _relay_reference_messages(self, source: socket.socket, destination: socket.socket,
                                  done: threading.Event) -> None:
        try:
            while not done.is_set():
                header = self._recv_exact(source, 24)
                if header is None:
                    return
                length = struct.unpack_from("<I", header, 16)[0]
                if length > self.MAX_MESSAGE_BYTES:
                    raise ValueError("oversized fault-injection frame")
                payload = self._recv_exact(source, length)
                if payload is None:
                    return
                if header[4:16].rstrip(b"\0") == b"utreexotx" and not self.corrupted.is_set():
                    targets, offset = read_compact(payload, 0)
                    for _ in range(targets):
                        _, offset = read_compact(payload, offset)
                    hashes, offset = read_compact(payload, offset)
                    if hashes:
                        payload = payload[:offset] + bytes([payload[offset] ^ 1]) + payload[offset + 1:]
                        header = header[:20] + sha256d(payload)[:4]
                        self.corrupted.set()
                destination.sendall(header + payload)
        except OSError:
            pass
        except Exception as error:
            self._error = error
        finally:
            done.set()


class ProofProbe:
    """Independent v1 peer exercises full/partial/empty transaction getdata."""
    def __init__(self, port: int):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=10)
        agent = b"/sidecar-integration-probe/"
        payload = (struct.pack("<iQq", 70016, (1 << 12) | 8, int(time.time())) + bytes(52) +
                   struct.pack("<Q", 42) + compact(len(agent)) + agent + bytes(4) + b"\x01")
        self.send("version", payload)
        self.receive("verack")
        self.send("verack", b"")

    def close(self):
        self.socket.close()

    def send(self, command: str, payload: bytes):
        self.socket.sendall(b"\xfa\xbf\xb5\xda" + command.encode().ljust(12, b"\0") +
                            struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload)

    def receive(self, command: str) -> bytes:
        while True:
            header = LegacyReferenceServiceProxy._recv_exact(self.socket, 24)
            if header is None:
                raise ConnectionError("proof probe disconnected")
            length = struct.unpack_from("<I", header, 16)[0]
            assert length <= 4_000_000
            payload = LegacyReferenceServiceProxy._recv_exact(self.socket, length)
            assert payload is not None and sha256d(payload)[:4] == header[20:]
            if header[4:16].rstrip(b"\0") == command.encode():
                return payload

    def targets(self, txid: str) -> list[int]:
        wanted = bytes.fromhex(txid)[::-1]
        while True:
            payload = self.receive("inv")
            count, offset = read_compact(payload, 0)
            found, targets = False, []
            for _ in range(count):
                kind = struct.unpack_from("<I", payload, offset)[0]
                value = payload[offset + 4:offset + 36]
                offset += 36
                if kind == 1:
                    if found:
                        return targets
                    found = value == wanted
                elif kind == 6 and found:
                    targets.extend(p for p in struct.unpack("<QQQQ", value) if p != (1 << 64) - 1)
            if found:
                return targets

    def request(self, txid: str, positions: list[int], witness: bool = True) -> tuple[list[int], list[bytes]]:
        inventory = struct.pack("<I", 0x41000001 if witness else 0x01000001) + bytes.fromhex(txid)[::-1]
        for i in range(0, len(positions), 4):
            group = positions[i:i + 4]
            inventory += struct.pack("<IQQQQ", 6, *(group + [(1 << 64) - 1] * (4 - len(group))))
        self.send("getdata", compact(1 + (len(positions) + 3) // 4) + inventory)
        payload = self.receive("utreexotx")
        count, offset = read_compact(payload, 0)
        targets = []
        for _ in range(count):
            target, offset = read_compact(payload, offset)
            targets.append(target)
        count, offset = read_compact(payload, offset)
        return targets, [payload[offset + i * 32:offset + (i + 1) * 32] for i in range(count)]

    def check_missing(self):
        request = b"\x01" + struct.pack("<I", 0x41000001) + bytes(32)
        self.send("getdata", request)
        assert self.receive("notfound") == request


def proof_positions(targets: list[int], leaves: int) -> list[int]:
    roots = {(((1 << 64) - 1) << (64 - row) & ((1 << 64) - 1)) + (leaves >> row) - 1
             for row in range(64) if (leaves >> row) & 1}
    pending, positions = set(targets), set()
    while pending:
        position = min(pending)
        pending.remove(position)
        if position in roots:
            continue
        sibling = position ^ 1
        if sibling in pending:
            pending.remove(sibling)
        else:
            positions.add(sibling)
        pending.add((position >> 1) | (1 << 63))
    return sorted(positions)


def merkle(hashes: list[bytes]) -> bytes:
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes = hashes + [hashes[-1]]
        hashes = [sha256d(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


def mine_template(template: dict) -> str:
    """Act as a local pool: construct coinbase/commitment and solve easy PoW."""
    transactions = template["transactions"]
    witness_root = merkle([bytes(32)] + [bytes.fromhex(tx["hash"])[::-1] for tx in transactions])
    commitment = b"\x6a\x24\xaa\x21\xa9\xed" + sha256d(witness_root + bytes(32))
    height = template["height"]
    height_bytes = height.to_bytes((height.bit_length() + 7) // 8, "little")
    if height_bytes[-1] & 128:
        height_bytes += b"\0"
    script = bytes([len(height_bytes)]) + height_bytes + b"\x00"
    inputs = b"\x01" + bytes(32) + b"\xff" * 4 + compact(len(script)) + script + b"\xff" * 4
    outputs = (b"\x02" + struct.pack("<Q", template["coinbasevalue"]) + b"\x01\x51" +
               bytes(8) + compact(len(commitment)) + commitment)
    stripped = struct.pack("<I", 2) + inputs + outputs + bytes(4)
    coinbase = struct.pack("<I", 2) + b"\x00\x01" + inputs + outputs + b"\x01\x20" + bytes(32) + bytes(4)
    root = merkle([sha256d(stripped)] + [bytes.fromhex(tx["txid"])[::-1] for tx in transactions])
    bits = int(template["bits"], 16)
    target = (bits & 0x7fffff) << (8 * ((bits >> 24) - 3))
    header = (struct.pack("<I", template["version"]) + bytes.fromhex(template["previousblockhash"])[::-1] +
              root + struct.pack("<II", template["curtime"], bits))
    for nonce in range(1 << 32):
        candidate = header + struct.pack("<I", nonce)
        if int.from_bytes(sha256d(candidate), "little") <= target:
            return (candidate + compact(len(transactions) + 1) + coinbase +
                    b"".join(bytes.fromhex(tx["data"]) for tx in transactions)).hex()
    raise AssertionError("regtest nonce space exhausted")


def run(args: argparse.Namespace) -> None:
    work = Path(args.work_dir or tempfile.mkdtemp(prefix="core-utreexod-relay-")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    for name in ("core", "utreexod"):
        (work / name).mkdir(exist_ok=True)
    cp, cr, sp, ur, pp = (free_port() for _ in range(5))
    auth = ("relay_test", "relay_test_password")
    core_url, utree_url = f"http://127.0.0.1:{cr}", f"http://127.0.0.1:{ur}"
    wallet_url = core_url + "/wallet/relay"
    processes = []
    def core(method, params=None): return rpc(core_url, method, params, auth)
    def wallet(method, params=None): return rpc(wallet_url, method, params, auth)
    def utree(method, params=None): return rpc(utree_url, method, params, auth)
    def wait(name, predicate):
        result = wait_for(name, predicate, processes, args.timeout)
        print(name, flush=True)
        return result
    try:
        processes.append(ManagedProcess("core", [str(Path(args.core).resolve()),
            f"-datadir={work / 'core'}", "-nosettings", "-regtest", "-server", "-txindex=1",
            f"-bind=127.0.0.1:{cp}", "-listenonion=0", "-dnsseed=0", "-discover=0",
            f"-rpcport={cr}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcuser={auth[0]}", f"-rpcpassword={auth[1]}", "-fallbackfee=0.0002",
            "-blockversion=536870915"], work))
        wait("Core RPC ready", lambda: core("getnetworkinfo"))
        version = core("getnetworkinfo")["subversion"]
        assert version.startswith("/Satoshi:31.1.0"), version
        core("createwallet", ["relay"])
        mining_address = wallet("getnewaddress", ["", "legacy"])
        # Retain utreexod's native 144-block BIP9 regtest windows. Core signals
        # CSV and SegWit, and 432 blocks activate them without parameter patches.
        for _ in range(4):
            core("generatetoaddress", [108, mining_address])
        a, b = (wallet("getnewaddress", ["", "bech32"]) for _ in range(2))
        funding = wallet("sendmany", ["", {a: 5, b: 5}])
        core("generatetoaddress", [1, mining_address])
        funding_tx = core("getrawtransaction", [funding, True])
        outputs = {v["scriptPubKey"]["address"]: v["n"] for v in funding_tx["vout"]}
        tip = core("getbestblockhash")

        def spend(inputs, amount):
            address = wallet("getnewaddress", ["", "bech32"])
            raw = wallet("createrawtransaction", [inputs, {address: amount}])
            signed = wallet("signrawtransactionwithwallet", [raw])
            assert signed["complete"]
            txid = core("sendrawtransaction", [signed["hex"]])
            return txid

        # A transaction present before the sidecar connects exercises recovery.
        mature = wallet("listunspent", [100])[0]
        legacy = spend([{"txid": mature["txid"], "vout": mature["vout"]}], round(mature["amount"] - 0.001, 8))
        sidecar_command = [str(Path(args.sidecar).resolve()), f"--rpc-port={cr}",
            f"--rpc-auth={auth[0]}:{auth[1]}", f"--online-state={work / 'online'}",
            f"--proof-store={work / 'proofs'}", "--online-wal", "--follow",
            f"--state-json={work / 'sidecar-state.json'}",
            "--poll-interval-ms=100", "--memory-reserve-mib=0", "--p2p-network=regtest",
            "--tx-cache-seconds=1",
            f"--p2p-port={sp}", f"--core-tx-peer=127.0.0.1:{cp}", "--log-level=debug"]
        sidecar = ManagedProcess("sidecar", sidecar_command, work)
        processes.append(sidecar)
        wait("Sidecar listening", lambda: "event=p2p_listening" in sidecar.log_path.read_text())
        fault = CorruptOneProof(pp, sp)
        processes.append(fault)
        (work / "utreexod.conf").write_text("# Isolated integration configuration\n")
        utree_command = [str(Path(args.utreexod).resolve()), "--regtest", "--noassumeutreexo",
            f"--datadir={work / 'utreexod'}", f"--logdir={work / 'utreexod-logs'}",
            f"--configfile={work / 'utreexod.conf'}",
            "--notls", "--nodnsseed", f"--rpcuser={auth[0]}", f"--rpcpass={auth[1]}",
            f"--rpclisten=127.0.0.1:{ur}", f"--connect=127.0.0.1:{cp}",
            f"--connect=127.0.0.1:{pp}",
            "--debuglevel=debug"]
        validator = ManagedProcess("utreexod", utree_command, work)
        processes.append(validator)
        wait("Compact validator caught up", lambda: utree("getbestblockhash") == tip)
        wait("Corrupted proof independently rejected", lambda: fault.corrupted.is_set() and
             "failed the utreexo data verification" in validator.log_path.read_text())
        assert legacy in core("getrawmempool") and legacy not in utree("getrawmempool")
        # Clear the consumer's rejected-tx cache by a normal restart. Its compact
        # accumulator persists; the proxy forwards all subsequent bytes intact.
        validator.stop()
        processes.remove(validator)
        validator = ManagedProcess("utreexod-recovered", utree_command, work)
        processes.append(validator)
        wait("Compact validator reopened", lambda: utree("getbestblockhash") == tip)
        wait("Bootstrap transaction verified", lambda: legacy in utree("getrawmempool"))
        rbf_coin = max(wallet("listunspent", [100]), key=lambda coin: coin["confirmations"])
        rbf_inputs = [{"txid": rbf_coin["txid"], "vout": rbf_coin["vout"], "sequence": 0}]
        original = spend(rbf_inputs, round(rbf_coin["amount"] - 0.001, 8))
        wait("Replaceable transaction proof remembered", lambda: original in utree("getrawmempool"))
        replacement = spend(rbf_inputs, round(rbf_coin["amount"] - 0.003, 8))
        wait("Replacement retains shared input proof", lambda:
             replacement in utree("getrawmempool") and original not in utree("getrawmempool"))
        intake = next(p for p in core("getpeerinfo") if p["subver"] == "/utreexo-bridge:core-tx/")
        core("disconnectnode", ["", intake["id"]])
        wait("Core transaction connection recovered", lambda:
             sidecar.log_path.read_text().count("event=core_tx_connected") >= 2)
        parent = spend([{"txid": funding, "vout": outputs[a]}], 4.999)
        child = spend([{"txid": parent, "vout": 0}, {"txid": funding, "vout": outputs[b]}], 9.998)
        expected = {legacy, replacement, parent, child}
        wait("Legacy, witness, and mixed-input transactions verified", lambda: expected <= set(utree("getrawmempool")))
        wait("Core P2P transaction intake observed", lambda: "event=core_tx_received" in sidecar.log_path.read_text())
        sidecar.stop()
        assert sidecar.process.returncode == 0, sidecar.log_path
        processes.remove(sidecar)
        sidecar = ManagedProcess("sidecar-recovered", sidecar_command, work)
        processes.append(sidecar)
        wait("Sidecar cache rebuilt from Core after restart", lambda:
             sidecar.log_path.read_text().count("event=transaction_proof_prepared") >= len(expected))
        probe = ProofProbe(sp)
        try:
            probe.check_missing()
            targets = probe.targets(legacy)
            leaves = utree("getutreexoroots", [tip])["numleaves"]
            positions = proof_positions(targets, leaves)
            assert len(positions) > 1
            full_targets, full_hashes = probe.request(legacy, positions, witness=False)
            assert full_targets == targets and len(full_hashes) == len(positions)
            partial_positions = list(reversed(positions[::2]))
            partial_targets, partial_hashes = probe.request(legacy, partial_positions)
            assert partial_targets == targets
            expected_hashes = dict(zip(positions, full_hashes))
            assert partial_hashes == [expected_hashes[p] for p in partial_positions]
            assert probe.request(legacy, []) == (targets, [])
            # Keep the peer's old announcement, let its preparation expire, then
            # require the getdata response itself to regenerate at this tip.
            # A background scan may win a particular race, so try boundedly.
            regeneration_marker = f"event=transaction_proof_regenerated txid={legacy} "
            log_start = sidecar.log_path.stat().st_size
            for _ in range(4):
                time.sleep(1.1)
                assert probe.request(legacy, positions) == (targets, full_hashes)
                with sidecar.log_path.open() as log:
                    log.seek(log_start)
                    if regeneration_marker in log.read():
                        break
            else:
                raise AssertionError("no requested transaction proof regeneration observed")
            print("Expired transaction proof regenerated for the original request", flush=True)
            # Targets advertised in inv are not acceptable proof-node requests.
            try:
                probe.request(legacy, [targets[0]])
            except ConnectionError:
                pass
            else:
                raise AssertionError("sidecar accepted an input target as a requested proof node")
            print("Full, reordered partial, and zero-additional-hash requests served", flush=True)
        finally:
            probe.close()
        template = utree("getblocktemplate", [{"rules": ["segwit"]}])
        (work / "template.json").write_text(json.dumps(template, indent=2) + "\n")
        assert expected <= {tx["txid"] for tx in template["transactions"]}
        print("Replacement proof remains available for mining", flush=True)
        incomplete = dict(template)
        incomplete["transactions"] = [tx for tx in template["transactions"] if tx["txid"] != parent]
        rejected = utree("submitblock", [mine_template(incomplete)])
        assert isinstance(rejected, str) and "missing unconfirmed parent" in rejected, rejected

        # An unchanged transaction body reuses its template proof even when the
        # pool changes the coinbase. Full consensus checks must still reject an
        # excessive reward, and that rejection must not mutate the cached proof.
        overpaid = dict(template)
        overpaid["coinbasevalue"] += 1
        overpaid_block = mine_template(overpaid)
        overpaid_hash = sha256d(bytes.fromhex(overpaid_block)[:80])[::-1].hex()
        rejected = utree("submitblock", [overpaid_block])
        assert isinstance(rejected, str) and "coinbase" in rejected.lower(), rejected
        assert f"Reusing cached template proof for block {overpaid_hash}" in validator.log_path.read_text()
        assert f"Assembled submission proof from mempool for block {overpaid_hash}" not in validator.log_path.read_text()
        print("Cached proof still enforces coinbase reward validation", flush=True)

        raw_block = mine_template(template)
        result = utree("submitblock", [raw_block])
        assert result is None, result
        mined_hash = sha256d(bytes.fromhex(raw_block)[:80])[::-1].hex()
        assert f"Reusing cached template proof for block {mined_hash}" in validator.log_path.read_text()
        assert f"Assembled submission proof from mempool for block {mined_hash}" not in validator.log_path.read_text()
        print("Standard submitblock reused the cached template proof", flush=True)
        wait("Standard submitblock relayed to Core", lambda: core("getbestblockhash") == mined_hash)
        assert utree("getbestblockhash") == mined_hash
        wait("Sidecar followed mined block", lambda: f"block_hash={mined_hash}" in sidecar.log_path.read_text())
        assert utree("getrawmempool") == []
        stale = dict(template)
        stale["curtime"] += 1
        stale_block = mine_template(stale)
        stale_hash = sha256d(bytes.fromhex(stale_block)[:80])[::-1].hex()
        rejected = utree("submitblock", [stale_block])
        assert isinstance(rejected, str) and "requires the current tip" in rejected, rejected
        assert f"Reusing cached template proof for block {stale_hash}" not in validator.log_path.read_text()
        # Exercise the opposite block direction after the transaction anchor
        # changes: ordinary Core blocks, independently validated sidecar proofs.
        extra = spend([{"txid": child, "vout": 0}], 9.997)
        wait("Transaction at the new tip verified", lambda: extra in utree("getrawmempool"))
        # A valid pool-selected subset misses the template cache and assembles
        # its proof through the existing local fallback.
        modified = utree("getblocktemplate", [{"rules": ["segwit"]}])
        assert extra in {tx["txid"] for tx in modified["transactions"]}
        modified["coinbasevalue"] -= sum(tx["fee"] for tx in modified["transactions"])
        modified["transactions"] = []
        fallback_block = mine_template(modified)
        fallback_hash = sha256d(bytes.fromhex(fallback_block)[:80])[::-1].hex()
        assert utree("submitblock", [fallback_block]) is None
        assert f"Assembled submission proof from mempool for block {fallback_hash}" in validator.log_path.read_text()
        assert f"Reusing cached template proof for block {fallback_hash}" not in validator.log_path.read_text()
        wait("Modified template used the local proof fallback", lambda: core("getbestblockhash") == fallback_hash)
        next_hash = core("generatetoaddress", [1, mining_address])[0]
        wait("Core-mined block independently validated", lambda: utree("getbestblockhash") == next_hash)
        roots = utree("getutreexoroots", [next_hash])
        sidecar.stop()
        assert sidecar.process.returncode == 0, sidecar.log_path
        processes.remove(sidecar)
        state = json.loads((work / "sidecar-state.json").read_text())
        assert state["num_leaves"] == roots["numleaves"]
        assert state["roots"] == roots["roots"]
        report = {"core": version, "utreexod_base": "fe71f3d9282ef0812f7f6087f0c0df9ce0fda508",
                  "compact": True, "transactions": sorted(expected), "mined_block": mined_hash,
                  "height": core("getblockcount"), "standard_submitblock": True,
                  "bad_proof_rejected": True, "core_p2p_reconnected": True,
                  "core_p2p_intake": True, "sidecar_restart_recovered": True,
                  "full_partial_zero_requests": True, "core_mined_block": next_hash,
                  "incomplete_submitblock_rejected": True,
                  "cached_template_proof_reused": True,
                  "replacement_retains_shared_input_proof": replacement,
                  "cached_proof_consensus_rejection": overpaid_hash,
                  "stale_template_cache_miss": True,
                  "modified_template_fallback": fallback_hash,
                  "matching_roots": roots}
        for name, path in {"utreexod_binary": Path(args.utreexod),
                           "sidecar_binary": Path(args.sidecar),
                           "compatibility_patch": Path(__file__).resolve().parents[2] /
                           "contrib/utreexod-v0.6.0-core-relay.patch"}.items():
            with path.open("rb") as stream:
                report[name + "_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        report["requested_expired_transaction_regenerated"] = True
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {work / 'result.json'}", flush=True)
    finally:
        for process in reversed(processes):
            process.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", default="/usr/local/bin/bitcoind")
    parser.add_argument("--sidecar", default="build/utreexo-bridge")
    parser.add_argument("--utreexod", default="build/utreexod-relay")
    parser.add_argument("--work-dir")
    parser.add_argument("--timeout", type=float, default=90)
    run(parser.parse_args())
