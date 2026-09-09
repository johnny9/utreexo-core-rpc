#!/usr/bin/env python3
"""Exercise independent proof providers with Core, a real sidecar, and utreexod.

The consumer has no proof index. A second utreexod generates standard v0.6
proofs, and every provider uses the same wire format without endpoint-specific options.
Loopback proxies inject transport faults and advertise proof-only services.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import threading
from pathlib import Path

from core_utreexod_relay import compact, mine_template, read_compact, sha256d
from floresta_regtest import LegacyReferenceServiceProxy, ManagedProcess, free_port, rpc, wait_for


class ProofPeerProxy(LegacyReferenceServiceProxy):
    def __init__(self, listen_port, target_port, services=None, mode="normal"):
        self.services = services
        self.mode = mode
        self.requests = []
        self.served = []
        self.block_requests = 0
        self.corrupted = None
        self.disconnected = None
        self.missing_rounds = 0
        self.notfound_transactions = 0
        super().__init__(listen_port, target_port)
        self.name = "proof-peer-proxy"

    def set_mode(self, mode):
        with self._lock:
            self.mode = mode

    def snapshot(self):
        with self._lock:
            return {"requests": list(self.requests), "served": list(self.served),
                    "block_requests": self.block_requests, "corrupted": self.corrupted,
                    "disconnected": self.disconnected, "missing_rounds": self.missing_rounds,
                    "notfound_transactions": self.notfound_transactions}

    def _pump(self, source, destination, done, responses):
        try:
            while not done.is_set():
                header = self._recv_exact(source, 24)
                if header is None:
                    return
                length = struct.unpack_from("<I", header, 16)[0]
                if length > self.MAX_MESSAGE_BYTES:
                    raise ValueError("oversized proof-peer frame")
                payload = self._recv_exact(source, length)
                if payload is None:
                    return
                command = header[4:16].rstrip(b"\0")
                if responses and command == b"inv":
                    with self._lock:
                        if (self.mode == "missing-tx" and self.missing_rounds < 2 and
                                self.notfound_transactions >= 64 * self.missing_rounds):
                            count, offset = read_compact(payload, 0)
                            # Advertised preparations can expire before getdata.
                            # Reannounce the same hashes to also test request release.
                            expired = b"".join(struct.pack("<I", 1) + hashlib.sha256(
                                f"expired-preparation-{i}".encode()).digest() for i in range(64))
                            payload = compact(count + 64) + payload[offset:] + expired
                            self.missing_rounds += 1
                if responses and command == b"notfound":
                    count, offset = read_compact(payload, 0)
                    with self._lock:
                        self.notfound_transactions += sum(struct.unpack_from("<I", payload, offset + i * 36)[0]
                            in (0x01000001, 0x41000001) for i in range(count))
                if responses and command == b"version" and self.services is not None:
                    payload = payload[:4] + struct.pack("<Q", self.services) + payload[12:]
                if not responses and command == b"getdata":
                    count, offset = read_compact(payload, 0)
                    with self._lock:
                        for i in range(count):
                            kind = struct.unpack_from("<I", payload, offset + i * 36)[0]
                            if kind in (2, 0x40000002):
                                self.block_requests += 1
                if not responses and command == b"getuproof":
                    block_hash = payload[:32][::-1].hex()
                    with self._lock:
                        self.requests.append(block_hash)
                        disconnect = self.mode == "disconnect"
                        if disconnect:
                            self.disconnected = block_hash
                            self.mode = "normal"
                    if disconnect:
                        return
                if responses and command == b"uproof":
                    block_hash = payload[:32][::-1].hex()
                    with self._lock:
                        mode = self.mode
                        if mode == "corrupt":
                            self.corrupted = block_hash
                            self.mode = "normal"
                        if mode != "drop":
                            self.served.append(block_hash)
                    if mode == "drop":
                        continue
                    if mode == "corrupt":
                        count, offset = read_compact(payload, 32)
                        if count:
                            payload = payload[:offset] + bytes([payload[offset] ^ 1]) + payload[offset+1:]
                        else:
                            payload = payload[:32] + b"\x01" + bytes(32) + payload[offset:]
                header = header[:16] + struct.pack("<I", len(payload)) + sha256d(payload)[:4]
                destination.sendall(header + payload)
        except OSError:
            pass
        except Exception as error:
            self._error = error
        finally:
            done.set()

    def _relay_raw(self, source: socket.socket, destination: socket.socket, done: threading.Event):
        self._pump(source, destination, done, False)

    def _relay_reference_messages(self, source, destination, done):
        self._pump(source, destination, done, True)


def run(args):
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False)
    for name in ("core", "consumer", "prover"):
        (work / name).mkdir()
    cp, cr, sp, ap, bp, pp, pr, ur = (free_port() for _ in range(8))
    auth = ("proof_test", "proof_test_password")
    core_url = f"http://127.0.0.1:{cr}"
    def core(method, params=None): return rpc(core_url, method, params, auth)
    def wallet(method, params=None): return rpc(core_url + "/wallet/proofs", method, params, auth)
    def spend_mature_input():
        # Avoid spending fresh change whose leaf can itself be a root and need
        # zero proof hashes: the corruption regression needs a nonempty proof.
        coin = max(wallet("listunspent", [101]), key=lambda coin: coin["confirmations"])
        raw = wallet("createrawtransaction", [[{"txid": coin["txid"], "vout": coin["vout"]}],
                                              {wallet("getnewaddress"): 1}])
        funded = wallet("fundrawtransaction", [raw, {"add_inputs": False}])
        signed = wallet("signrawtransactionwithwallet", [funded["hex"]])
        assert signed["complete"]
        return wallet("sendrawtransaction", [signed["hex"]])
    def consumer(method, params=None): return rpc(f"http://127.0.0.1:{ur}", method, params, auth)
    def prover(method, params=None): return rpc(f"http://127.0.0.1:{pr}", method, params, auth)
    processes = []
    def wait(name, predicate):
        result = wait_for(name, predicate, processes, args.timeout)
        print(name, flush=True)
        return result
    def launch(name, command):
        process = ManagedProcess(name, command, work)
        processes.append(process)
        return process
    def stop(process):
        process.stop()
        processes.remove(process)
    try:
        launch("core", [str(Path(args.core).resolve()), f"-datadir={work / 'core'}",
            "-nosettings", "-regtest", "-server", "-listenonion=0", "-dnsseed=0", "-discover=0",
            f"-bind=127.0.0.1:{cp}", f"-rpcport={cr}", "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1", f"-rpcuser={auth[0]}", f"-rpcpassword={auth[1]}",
            "-fallbackfee=0.0002", "-blockversion=536870915"])
        wait("Core ready", lambda: core("getnetworkinfo"))
        assert core("getnetworkinfo")["subversion"].startswith("/Satoshi:31.1.0")
        core("createwallet", ["proofs"])
        payout = wallet("getnewaddress", ["", "legacy"])
        for _ in range(4):
            core("generatetoaddress", [108, payout])
        tip = core("getbestblockhash")
        sidecar = launch("sidecar", [str(Path(args.sidecar).resolve()), f"--rpc-port={cr}",
            f"--rpc-auth={auth[0]}:{auth[1]}", f"--online-state={work / 'online'}",
            f"--proof-store={work / 'proofs'}", "--online-wal", "--follow",
            "--poll-interval-ms=100", "--memory-reserve-mib=0", "--p2p-network=regtest",
            f"--p2p-port={sp}", "--p2p-bind=127.0.0.1",
            f"--core-tx-peer=127.0.0.1:{cp}", "--log-level=debug"])
        wait("Sidecar ready", lambda: "event=p2p_listening" in sidecar.log_path.read_text())
        (work / "utreexod.conf").write_text("# Isolated regtest\n")
        common = [str(Path(args.utreexod).resolve()), "--regtest", "--noassumeutreexo", "--notls",
            "--nodnsseed", f"--rpcuser={auth[0]}", f"--rpcpass={auth[1]}",
            f"--configfile={work / 'utreexod.conf'}", f"--connect=127.0.0.1:{cp}", "--debuglevel=debug"]
        launch("prover", common + ["--utreexoproofindex", "--prune=0",
            f"--datadir={work / 'prover'}", f"--logdir={work / 'prover-logs'}",
            f"--listen=127.0.0.1:{pp}", f"--rpclisten=127.0.0.1:{pr}"])
        wait("Standard v0.6 proof generator caught up", lambda: prover("getbestblockhash") == tip)
        a = ProofPeerProxy(ap, sp, mode="drop")
        processes.append(a)
        consumer_command = common + [f"--datadir={work / 'consumer'}",
            f"--logdir={work / 'consumer-logs'}", f"--rpclisten=127.0.0.1:{ur}",
            f"--connect=127.0.0.1:{ap}",
            f"--connect=127.0.0.1:{bp}"]
        node = launch("consumer", consumer_command)
        wait("First provider has outstanding requests", lambda: a.snapshot()["requests"])
        syncing = consumer("getblockchaininfo")
        assert syncing['headers'] == core('getblockcount') and syncing['blocks'] < syncing['headers']
        tip = core("generatetoaddress", [3, payout])[-1]
        wait("Headers advance while compact proof validation is stalled", lambda:
             consumer("getblockchaininfo")["headers"] == core("getblockcount"))
        assert consumer("getblockcount") < core("getblockcount")
        first_hash = a.snapshot()["requests"][0]
        # Archive-only: this connection has neither NODE_NETWORK nor NODE_UTREEXO.
        b = ProofPeerProxy(bp, pp, services=1 << 13)
        processes.append(b)
        wait("Stalled proof retried with another provider", lambda:
             "proof request timed out" in node.log_path.read_text() and first_hash in b.snapshot()["requests"])
        a.set_mode("normal")
        wait("Consumer bootstrapped with independent providers", lambda: consumer("getbestblockhash") == tip)
        wait("Sidecar reconnected after timeout", lambda:
             any(p["addr"] == f"127.0.0.1:{ap}" for p in consumer("getpeerinfo")))
        tip = core("generatetoaddress", [1, payout])[0]
        wait("Reconnected provider served a new block", lambda: consumer("getbestblockhash") == tip)
        wait("Both proof providers served data", lambda: a.snapshot()["served"] and b.snapshot()["served"])

        before_id = next(p["id"] for p in consumer("getpeerinfo") if p["addr"] == f"127.0.0.1:{ap}")
        a.set_mode("missing-tx")
        missing_probe_tx = spend_mature_input()
        wait("Expired transaction proofs return notfound without banning the provider", lambda:
             a.snapshot()["notfound_transactions"] >= 128 and missing_probe_tx in consumer("getrawmempool"))
        assert any(p["id"] == before_id for p in consumer("getpeerinfo"))
        assert "banning and disconnecting" not in node.log_path.read_text()
        a.set_mode("normal")

        # The next block spends an input whose proof the mempool remembers.
        # A corrupt full proof must still fail before ProcessBlock, without
        # partial-proof verification hiding its bad hashes behind cached data.
        a.set_mode("corrupt")
        for attempt in range(8):
            if attempt:
                cached_tx = spend_mature_input()
                wait("Mempool remembers the next block's input proof", lambda:
                     cached_tx in consumer("getrawmempool"))
            tip = core("generatetoaddress", [1, payout])[0]
            wait("Block validated during bad-proof test", lambda: consumer("getbestblockhash") == tip)
            if a.snapshot()["corrupted"]:
                break
        bad_hash = a.snapshot()["corrupted"]
        assert bad_hash and bad_hash in b.snapshot()["requests"]
        assert "Retrying proofs from another peer" in node.log_path.read_text()
        assert "Failed to process block" not in node.log_path.read_text()
        print("Invalid proof replaced without rejecting Core's block", flush=True)

        a.set_mode("disconnect")
        wait("Sidecar reconnected for disconnect test", lambda:
             any(p["addr"] == f"127.0.0.1:{ap}" for p in consumer("getpeerinfo")))
        for _ in range(8):
            tip = core("generatetoaddress", [1, payout])[0]
            wait("Block validated during disconnect test", lambda: consumer("getbestblockhash") == tip)
            if a.snapshot()["disconnected"]:
                break
        disconnected_hash = a.snapshot()["disconnected"]
        assert disconnected_hash and disconnected_hash in b.snapshot()["requests"]
        print("Disconnected proof provider replaced", flush=True)
        assert a.snapshot()["block_requests"] == b.snapshot()["block_requests"] == 0
        archive_evidence = b.snapshot()
        stop(a)
        stop(sidecar)
        stop(b)
        # Now the only proof provider advertises NODE_UTREEXO alone. It uses the same v0.6 positions and normal peer configuration as the sidecar.
        b = ProofPeerProxy(bp, pp, services=(1 << 12) | 8)
        processes.append(b)
        def live_peer():
            # v0.6 getpeerinfo formats services as a zero-padded decimal string.
            return any(p["addr"] == f"127.0.0.1:{bp}" and int(p["services"]) == ((1 << 12) | 8)
                       for p in consumer("getpeerinfo"))
        wait("NODE_UTREEXO-only provider connected", live_peer)
        # A proof-only provider can retain history without claiming a complete
        # archive. Resume behind the tip with this as the only proof source.
        stop(node)
        history = core("generatetoaddress", [3, payout])
        wait("Proof generator ready for historical fallback", lambda:
             prover("getbestblockhash") == history[-1])
        node = launch("consumer-history-resume", consumer_command)
        wait("Historical proofs received from NODE_UTREEXO-only provider", lambda:
             consumer("getbestblockhash") == history[-1])
        assert all(block_hash in b.snapshot()["served"] for block_hash in history)
        assert consumer("getutreexoroots", [history[-1]]) == prover("getutreexoroots", [history[-1]])
        txid = wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        wait("Transaction proof received from automatic provider", lambda: txid in consumer("getrawmempool"))
        tip = core("generatetoaddress", [1, payout])[0]
        wait("New-block proof received from NODE_UTREEXO-only provider", lambda:
             consumer("getbestblockhash") == tip and tip in b.snapshot()["served"])
        txid = wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        wait("Mining transaction proof ready", lambda: txid in consumer("getrawmempool"))
        template = consumer("getblocktemplate", [{"rules": ["segwit"]}])
        assert txid in {tx["txid"] for tx in template["transactions"]}
        assert consumer("submitblock", [mine_template(template)]) is None
        tip = consumer("getbestblockhash")
        wait("Mined block relayed to Core and proof generator", lambda:
             core("getbestblockhash") == prover("getbestblockhash") == tip)
        roots = consumer("getutreexoroots", [tip])
        assert roots == prover("getutreexoroots", [tip])
        assert b.snapshot()["block_requests"] == 0
        report = {"automatic_proof_peers": True, "archive_only_peer": True,
                  "historical_proof_fallback": history,
                  "headers_reported_while_waiting_for_proofs": True,
                  "headers_advance_during_proof_stall": True,
                  "expired_transaction_notfound": a.snapshot()["notfound_transactions"],
                  "expired_transaction_peer_not_banned": True,
                  "corrupt_full_proof_rejected_with_cached_mempool_inputs": True,
                  "utreexo_only_peer": True, "timeout_failover": first_hash,
                  "invalid_proof_failover": bad_hash, "disconnect_failover": disconnected_hash,
                  "standard_submitblock": True, "matching_roots": roots,
                  "archive_peer": archive_evidence, "live_peer": b.snapshot()}
        for name, filename in {"utreexod": args.utreexod, "sidecar": args.sidecar}.items():
            with Path(filename).open("rb") as stream:
                report[name + "_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {work / 'result.json'}", flush=True)
    finally:
        for process in reversed(processes):
            process.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--utreexod", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--timeout", type=float, default=180)
    run(parser.parse_args())
