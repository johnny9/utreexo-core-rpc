#!/usr/bin/env python3
"""Discover a real sidecar through address gossip, then validate Core's blocks.

Bootstrap fixtures learn their only address from the sidecar's actual addr
announcement. Fresh compact utreexod processes receive it through getaddr,
using legacy addr and negotiated addrv2 in separate runs. A closed SOCKS5
router maps synthetic public endpoints to loopback: the production address
manager still enforces routability, and no public endpoint is ever dialed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import socket
import struct
import threading
import time
from pathlib import Path

from core_utreexod_relay import compact, read_compact, sha256d
from floresta_regtest import LegacyReferenceServiceProxy, ManagedProcess, free_port, rpc, wait_for


MAGIC = b"\xfa\xbf\xb5\xda"
NODE_UTREEXO = 1 << 12
SERVICES = NODE_UTREEXO | (1 << 13) | 8
# Regtest requires a loopback block peer. Discovery endpoints use separate /16
# groups to exercise normal address selection without group collisions. All
# addresses below are wire fixtures routed locally, never public destinations.
CORE = ("127.0.0.1", 18444)
SIDECAR = ("12.0.0.1", 8338)
SEEDS = (("13.0.0.1", 18444), ("14.0.0.1", 18444))


def endpoint(address):
    return f"{address[0]}:{address[1]}"


def receive(sock, size):
    data = LegacyReferenceServiceProxy._recv_exact(sock, size)
    if data is None:
        raise EOFError("peer disconnected")
    return data


def read_message(sock):
    header = receive(sock, 24)
    size = struct.unpack_from("<I", header, 16)[0]
    if header[:4] != MAGIC or size > LegacyReferenceServiceProxy.MAX_MESSAGE_BYTES:
        raise ValueError("invalid regtest frame")
    payload = receive(sock, size)
    if sha256d(payload)[:4] != header[20:]:
        raise ValueError("invalid frame checksum")
    return header, header[4:16].rstrip(b"\0"), payload


def send_message(sock, command, payload=b""):
    sock.sendall(MAGIC + command.ljust(12, b"\0") + struct.pack("<I", len(payload)) +
                 sha256d(payload)[:4] + payload)


class BootstrapPeer(LegacyReferenceServiceProxy):
    """Minimal address-relay peer; it generates neither blocks nor proofs."""

    def __init__(self, port, addrv2):
        self.addrv2 = addrv2
        self.record = None
        self.evidence = {"announcements": 0, "getaddr": 0, "addr": 0, "addrv2": 0}
        super().__init__(port, 0)
        self.name = "bootstrap-addrv2" if addrv2 else "bootstrap-addr"

    def snapshot(self):
        with self._lock:
            return dict(self.evidence, record=copy.deepcopy(self.record))

    def _handle(self, client):
        with self._lock:
            self._connections.add(client)
        client.settimeout(30)
        try:
            _, command, _ = read_message(client)
            if command != b"version":
                raise ValueError("bootstrap expected version")
            agent = b"/address-discovery-fixture/"
            version = (struct.pack("<iQq", 70016 if self.addrv2 else 70015,
                                   NODE_UTREEXO, int(time.time())) + bytes(52) +
                       struct.pack("<Q", time.time_ns()) + compact(len(agent)) + agent +
                       bytes(4) + b"\x00")
            send_message(client, b"version", version)
            if self.addrv2:
                send_message(client, b"sendaddrv2")
            send_message(client, b"verack")
            wants_v2, ready = False, False
            while not self._stop.is_set():
                _, command, payload = read_message(client)
                if command == b"sendaddrv2":
                    wants_v2 = True
                elif command == b"verack":
                    ready = True
                elif command == b"ping":
                    send_message(client, b"pong", payload)
                elif command == b"addr":
                    # The fixture learns exclusively from the sidecar's single
                    # advertised IPv4 record, including its port and services.
                    if not ready or len(payload) != 31 or payload[:1] != b"\x01":
                        raise ValueError("expected one timestamped address")
                    if payload[13:25] != bytes(10) + b"\xff\xff":
                        raise ValueError("expected an IPv4 address")
                    record = {"time": struct.unpack_from("<I", payload, 1)[0],
                              "services": struct.unpack_from("<Q", payload, 5)[0],
                              "address": socket.inet_ntoa(payload[25:29]),
                              "port": struct.unpack_from(">H", payload, 29)[0]}
                    with self._lock:
                        self.record = record
                        self.evidence["announcements"] += 1
                elif command == b"getaddr":
                    with self._lock:
                        record = copy.deepcopy(self.record)
                        self.evidence["getaddr"] += 1
                    if not ready or record is None:
                        raise ValueError("getaddr before handshake or announcement")
                    timestamp = struct.pack("<I", record["time"])
                    ip = socket.inet_aton(record["address"])
                    port = struct.pack(">H", record["port"])
                    kind = b"addrv2" if self.addrv2 and wants_v2 else b"addr"
                    if kind == b"addrv2":
                        payload = b"\x01" + timestamp + compact(record["services"]) + b"\x01\x04" + ip + port
                    else:
                        payload = (b"\x01" + timestamp + struct.pack("<Q", record["services"]) +
                                   bytes(10) + b"\xff\xff" + ip + port)
                    send_message(client, kind, payload)
                    with self._lock:
                        self.evidence[kind.decode()] += 1
                elif command == b"getuproof":
                    # This bootstrap has no chain history. A missing block
                    # proof has no specified notfound encoding; disconnect.
                    return
        except (OSError, EOFError):
            pass
        except Exception as error:
            self._error = error
        finally:
            client.close()
            with self._lock:
                self._connections.discard(client)


class LocalRouter(LegacyReferenceServiceProxy):
    """SOCKS5 endpoint map and passive Bitcoin-message recorder."""

    def __init__(self, port, routes):
        self.routes = routes
        self.evidence = {name: {"dials": 0, "failed_dials": 0, "block_requests": [],
                               "blocks": [], "proof_requests": [], "proofs": [],
                               "nonempty_proofs": [], "tx_proofs": 0}
                         for name, _ in routes.values()}
        super().__init__(port, 0)
        self.name = "isolated-discovery-router"

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self.evidence)

    def _pump(self, source, destination, done, name, responses):
        try:
            while not done.is_set():
                header, command, payload = read_message(source)
                with self._lock:
                    stats = self.evidence[name]
                    if not responses and command == b"getdata":
                        count, offset = read_compact(payload, 0)
                        if len(payload) != offset + count * 36:
                            raise ValueError("invalid getdata inventory length")
                        for index in range(count):
                            start = offset + index * 36
                            if struct.unpack_from("<I", payload, start)[0] in (2, 0x40000002):
                                stats["block_requests"].append(payload[start + 4:start + 36][::-1].hex())
                    elif not responses and command == b"getuproof":
                        stats["proof_requests"].append(payload[:32][::-1].hex())
                    elif responses and command == b"block":
                        stats["blocks"].append(sha256d(payload[:80])[::-1].hex())
                    elif responses and command == b"uproof":
                        block_hash = payload[:32][::-1].hex()
                        stats["proofs"].append(block_hash)
                        count, _ = read_compact(payload, 32)
                        if count:
                            stats["nonempty_proofs"].append(block_hash)
                    elif responses and command == b"utreexotx":
                        stats["tx_proofs"] += 1
                # Observe the real traffic without changing service bits,
                # addresses, requests, transaction bytes, or proof payloads.
                destination.sendall(header + payload)
        except (OSError, EOFError):
            pass
        except Exception as error:
            self._error = error
        finally:
            done.set()

    def _handle(self, client):
        upstream = None
        with self._lock:
            self._connections.add(client)
        client.settimeout(10)
        try:
            version, count = receive(client, 2)
            if version != 5 or 0 not in receive(client, count):
                raise ValueError("expected unauthenticated SOCKS5")
            client.sendall(b"\x05\x00")
            version, command, reserved, kind = receive(client, 4)
            if (version, command, reserved) != (5, 1, 0):
                raise ValueError("only SOCKS5 CONNECT is allowed")
            if kind == 1:
                host = socket.inet_ntoa(receive(client, 4))
            elif kind == 3:
                host = receive(client, receive(client, 1)[0]).decode("ascii")
            else:
                raise ValueError("unexpected SOCKS5 address type")
            address = (host, struct.unpack(">H", receive(client, 2))[0])
            if address not in self.routes:
                raise ValueError(f"refusing unmapped destination {address}")
            name, port = self.routes[address]
            with self._lock:
                self.evidence[name]["dials"] += 1
            try:
                upstream = socket.create_connection(("127.0.0.1", port), timeout=5)
            except OSError:
                with self._lock:
                    self.evidence[name]["failed_dials"] += 1
                client.sendall(b"\x05\x05\x00\x01" + bytes(6))
                return
            with self._lock:
                self._connections.add(upstream)
            client.sendall(b"\x05\x00\x00\x01" + bytes(6))
            client.settimeout(None)
            upstream.settimeout(None)
            done = threading.Event()
            pumps = [threading.Thread(target=self._pump, args=arguments, daemon=True)
                     for arguments in ((client, upstream, done, name, False),
                                       (upstream, client, done, name, True))]
            for pump in pumps:
                pump.start()
            done.wait()
            for connection in (client, upstream):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            for pump in pumps:
                pump.join(timeout=2)
        except (OSError, EOFError):
            pass
        except Exception as error:
            self._error = error
        finally:
            for connection in (client, upstream):
                if connection is not None:
                    connection.close()
                    with self._lock:
                        self._connections.discard(connection)


def run(args):
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False)
    (work / "core").mkdir()
    (work / "utreexod.conf").write_text("# Isolated address discovery integration\n")
    ports = set()
    while len(ports) < 7:
        ports.add(free_port())
    cp, cr, sp, ur, router_port, legacy_port, v2_port = ports
    auth = ("discovery_test", "discovery_test_password")
    core_url = f"http://127.0.0.1:{cr}"
    def core(method, params=None): return rpc(core_url, method, params, auth)
    def wallet(method, params=None): return rpc(core_url + "/wallet/discovery", method, params, auth)
    def consumer(method, params=None): return rpc(f"http://127.0.0.1:{ur}", method, params, auth)
    processes = []
    router = None
    def wait(name, predicate):
        result = wait_for(name, predicate, processes, args.timeout)
        print(name, flush=True)
        return result
    def manage(service):
        processes.append(service)
        return service
    def launch(name, command): return manage(ManagedProcess(name, command, work))
    def stop(service):
        service.stop()
        processes.remove(service)
    def announced(seed):
        record = seed.snapshot()["record"]
        return (record is not None and record["address"] == SIDECAR[0] and
                record["port"] == SIDECAR[1] and record["services"] == SERVICES and
                abs(record["time"] - time.time()) < 30)
    def proof_peer():
        return next((peer for peer in consumer("getpeerinfo")
                     if peer["addr"] == endpoint(SIDECAR) and not peer["inbound"] and
                     int(peer["services"]) == SERVICES), None)
    def command(data_name, bootstrap):
        result = [str(Path(args.utreexod).resolve()), "--regtest", "--noassumeutreexo",
                  "--nodnsseed", "--noonion", "--notls", "--debuglevel=debug",
                  f"--configfile={work / 'utreexod.conf'}", f"--datadir={work / data_name}",
                  f"--logdir={work / (data_name + '-logs')}", f"--rpclisten=127.0.0.1:{ur}",
                  f"--rpcuser={auth[0]}", f"--rpcpass={auth[1]}",
                  f"--proxy=127.0.0.1:{router_port}", f"--addpeer={endpoint(CORE)}"]
        result.extend(f"--addpeer={endpoint(seed)}" for seed in bootstrap)
        assert all(endpoint(SIDECAR) not in option and not option.startswith("--connect")
                   for option in result)
        return result
    try:
        launch("core", [str(Path(args.core).resolve()), f"-datadir={work / 'core'}",
            "-nosettings", "-regtest", "-server", "-listenonion=0", "-dnsseed=0", "-discover=0",
            f"-bind=127.0.0.1:{cp}", f"-rpcport={cr}", "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1", f"-rpcuser={auth[0]}", f"-rpcpassword={auth[1]}",
            "-fallbackfee=0.0002", "-blockversion=536870915"])
        wait("Core ready", lambda: core("getnetworkinfo"))
        assert core("getnetworkinfo")["subversion"].startswith("/Satoshi:31.1.0")
        core("createwallet", ["discovery"])
        payout = wallet("getnewaddress", ["", "legacy"])
        for _ in range(4):
            core("generatetoaddress", [108, payout])
        wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        tip = core("generatetoaddress", [1, payout])[0]
        legacy = manage(BootstrapPeer(legacy_port, False))
        v2 = manage(BootstrapPeer(v2_port, True))
        router = manage(LocalRouter(router_port, {
            CORE: ("core", cp), SIDECAR: ("sidecar", sp),
            SEEDS[0]: ("legacy_seed", legacy_port), SEEDS[1]: ("v2_seed", v2_port)}))
        launch("sidecar", [str(Path(args.sidecar).resolve()), f"--rpc-port={cr}",
            f"--rpc-auth={auth[0]}:{auth[1]}", f"--online-state={work / 'online'}",
            f"--proof-store={work / 'proofs'}", "--online-wal", "--follow",
            "--poll-interval-ms=100", "--memory-reserve-mib=0", "--p2p-network=regtest",
            f"--p2p-port={sp}", f"--core-tx-peer=127.0.0.1:{cp}", "--log-level=debug",
            f"--p2p-advertise={endpoint(SIDECAR)}", "--p2p-gossip-retry-seconds=1",
            f"--p2p-gossip-seed=127.0.0.1:{legacy_port}",
            f"--p2p-gossip-seed=127.0.0.1:{v2_port}"])
        wait("Both bootstrap peers learned the sidecar announcement", lambda: announced(legacy) and announced(v2))
        stop(v2)
        phases = {}
        for name, seed in (("addr", legacy), ("addrv2", None)):
            if name == "addrv2":
                stop(legacy)
                seed = v2 = manage(BootstrapPeer(v2_port, True))
                wait("Restarted bootstrap relearned the sidecar address", lambda: announced(v2))
            data_name = "consumer-" + name
            assert not (work / data_name).exists()
            node = launch(data_name, command(data_name, SEEDS))
            wait(f"Fresh compact node discovered the sidecar through {name}", proof_peer)
            assert seed.snapshot()[name] > 0
            assert seed.snapshot()["addr" if name == "addrv2" else "addrv2"] == 0
            wait(f"Core blocks validated using discovered proofs ({name})", lambda: consumer("getbestblockhash") == tip)
            txid = wallet("sendtoaddress", [wallet("getnewaddress"), 1])
            wait(f"Transaction proof received through discovered peer ({name})", lambda: txid in consumer("getrawmempool"))
            tip = core("generatetoaddress", [1, payout])[0]
            wait(f"New block validated through discovered peer ({name})", lambda: consumer("getbestblockhash") == tip)
            phases[name] = {"bootstrap": seed.snapshot(), "peer": proof_peer(), "tip": tip, "txid": txid}
            stop(node)
            assert node.process.returncode == 0, node.log_path
            saved = json.loads((work / data_name / "regtest/peers.json").read_text())
            record = next(address for address in saved["Addresses"] if address["Addr"] == endpoint(SIDECAR))
            assert record["Services"] == SERVICES
            phases[name]["saved_address"] = record

        # Both bootstrap listeners are now unavailable. The restarted consumer
        # receives only Core's address in its arguments and must use peers.json.
        stop(v2)
        before = router.snapshot()["sidecar"]["dials"]
        node = launch("consumer-restarted", command("consumer-addrv2", ()))
        wait("Discovered proof peer recovered from disk without bootstrap peers", lambda:
             proof_peer() and router.snapshot()["sidecar"]["dials"] > before)
        txid = wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        wait("Proof relay works after consumer restart", lambda: txid in consumer("getrawmempool"))
        tip = core("generatetoaddress", [1, payout])[0]
        wait("Restarted compact node validated a new Core block", lambda: consumer("getbestblockhash") == tip)
        traffic = router.snapshot()
        expected_blocks = {core("getblockhash", [height]) for height in range(1, core("getblockcount") + 1)}
        assert expected_blocks <= set(traffic["core"]["block_requests"]) & set(traffic["core"]["blocks"])
        assert expected_blocks <= set(traffic["sidecar"]["proof_requests"]) & set(traffic["sidecar"]["proofs"])
        assert traffic["sidecar"]["nonempty_proofs"] and traffic["sidecar"]["tx_proofs"] >= 3
        assert not traffic["sidecar"]["block_requests"] and not traffic["sidecar"]["blocks"]
        assert not traffic["core"]["proof_requests"] and not traffic["core"]["proofs"]
        assert traffic["legacy_seed"]["failed_dials"] and traffic["v2_seed"]["failed_dials"]
        for name in ("legacy_seed", "v2_seed"):
            assert not traffic[name]["blocks"] and not traffic[name]["proofs"]
        for service in processes:
            service.assert_running()
        report = {"automatic_address_discovery": phases, "restart_without_bootstrap": True,
                  "final_tip": tip, "height": core("getblockcount"),
                  "verified_blocks": len(expected_blocks), "traffic_file": "traffic.json",
                  "traffic": {name: {key: len(value) if isinstance(value, list) else value
                                     for key, value in stats.items()}
                              for name, stats in traffic.items()},
                  "bootstrap_fixture": "address relay only; no DNS or public-network traffic"}
        for name, filename in {"core": args.core, "utreexod": args.utreexod, "sidecar": args.sidecar}.items():
            with Path(filename).open("rb") as stream:
                report[name + "_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"PASS: {work / 'result.json'}", flush=True)
    finally:
        for process in reversed(processes):
            process.stop()
        if router is not None:
            (work / "traffic.json").write_text(json.dumps(router.snapshot(), indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--utreexod", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--timeout", type=float, default=180)
    run(parser.parse_args())
