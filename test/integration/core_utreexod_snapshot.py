#!/usr/bin/env python3
"""Export a chosen archive height, bootstrap compact utreexod, and resume it."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from core_utreexod_relay import mine_template
from floresta_regtest import ManagedProcess, free_port, rpc, wait_for

EXPORTER = Path(__file__).resolve().parents[2] / "tools" / "export-assumeutreexo.py"
SPEC = importlib.util.spec_from_file_location("export_assumeutreexo", EXPORTER)
export = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = export
SPEC.loader.exec_module(export)


def run(args):
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=False)
    (work / "core").mkdir()
    cp, cr, sp, ur = (free_port() for _ in range(4))
    auth = ("snapshot_test", "snapshot_test_password")
    core_url = f"http://127.0.0.1:{cr}"
    def core(method, params=None): return rpc(core_url, method, params, auth)
    def wallet(method, params=None): return rpc(core_url + "/wallet/snapshot", method, params, auth)
    def node(method, params=None): return rpc(f"http://127.0.0.1:{ur}", method, params, auth)
    processes = []
    def launch(name, command):
        process = ManagedProcess(name, command, work)
        processes.append(process)
        return process
    def stop(process):
        process.stop()
        processes.remove(process)
    def wait(name, predicate):
        result = wait_for(name, predicate, processes, args.timeout)
        print(name, flush=True)
        return result
    try:
        launch("core", [str(Path(args.core).resolve()), f"-datadir={work / 'core'}",
            "-nosettings", "-regtest", "-server", "-listenonion=0", "-dnsseed=0", "-discover=0",
            f"-bind=127.0.0.1:{cp}", f"-rpcport={cr}", "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1", f"-rpcuser={auth[0]}", f"-rpcpassword={auth[1]}",
            "-fallbackfee=0.0002", "-blockversion=536870915"])
        wait("Core ready", lambda: core("getnetworkinfo"))
        core("createwallet", ["snapshot"])
        payout = wallet("getnewaddress", ["", "legacy"])
        core("generatetoaddress", [132, payout])
        # Every mature coin predates the chosen snapshot. Validating this spend
        # requires a real proof against imported roots, not just coinbase adds.
        spend = wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        tip = core("generatetoaddress", [1, payout])[0]
        sidecar = launch("sidecar", [str(Path(args.sidecar).resolve()), f"--rpc-port={cr}",
            f"--rpc-auth={auth[0]}:{auth[1]}", f"--online-state={work / 'online'}",
            f"--proof-store={work / 'proofs'}", "--online-wal", "--follow",
            "--poll-interval-ms=100", "--memory-reserve-mib=0", "--p2p-network=regtest",
            f"--p2p-port={sp}", "--p2p-bind=127.0.0.1", f"--core-tx-peer=127.0.0.1:{cp}"])
        wait("Sidecar archive ready", lambda: "event=p2p_listening" in sidecar.log_path.read_text())
        cookie = work / "export.cookie"
        cookie.write_text(":".join(auth))
        cookie.chmod(0o600)
        snapshot_path = work / "regtest-120.json"
        command = [sys.executable, str(EXPORTER), f"--proof-store={work / 'proofs'}", "--height=120",
                   f"--rpc-url={core_url}", f"--rpc-cookie={cookie}", f"--output={snapshot_path}"]
        completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        result = json.loads(completed.stdout)
        snapshot = json.loads(snapshot_path.read_text())
        assert snapshot["height"] == 120 and snapshot["block_hash"] == core("getblockhash", [120])
        pin = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
        assert result["sha256"] == pin
        print(f"Exported height 120 ({result['bytes']} bytes)", flush=True)
        (work / "utreexod.conf").write_text("# Isolated snapshot integration test\n")
        common = [str(Path(args.utreexod).resolve()), "--regtest", "--regtestkeepdb", "--notls", "--nodnsseed", "--nolisten",
            f"--rpcuser={auth[0]}", f"--rpcpass={auth[1]}", f"--configfile={work / 'utreexod.conf'}",
            f"--datadir={work / 'consumer'}", f"--logdir={work / 'consumer-logs'}",
            f"--rpclisten=127.0.0.1:{ur}", f"--connect=127.0.0.1:{cp}", f"--connect=127.0.0.1:{sp}"]
        snapshot_args = [f"--assumeutreexo-snapshot={snapshot_path}", f"--assumeutreexo-snapshot-sha256={pin}"]
        # A damaged file is rejected before creating a database or contacting peers.
        damaged = work / "damaged.json"
        damaged.write_bytes(snapshot_path.read_bytes() + b" ")
        bad = subprocess.run(common + [f"--assumeutreexo-snapshot={damaged}", snapshot_args[1]],
                             capture_output=True, text=True, timeout=30)
        assert bad.returncode != 0 and "SHA256 does not match" in bad.stdout + bad.stderr, bad.stdout + bad.stderr
        assert not (work / "consumer" / "regtest" / "blocks_ffldb").exists()
        consumer = launch("consumer", common + snapshot_args)
        wait("Compact node validated the snapshot suffix", lambda: node("getbestblockhash") == tip)
        assert "Initialized assumed utreexo point" in consumer.log_path.read_text()
        assert "(120)" in consumer.log_path.read_text()
        assert spend in core("getblock", [tip, 1])["tx"]
        state = export.read_archive_state(work / "proofs", 133)
        roots = node("getutreexoroots", [tip])
        assert roots["numleaves"] == state["num_leaves"] and roots["roots"] == state["roots"]
        assert node("getblockchaininfo")["headers"] == 133
        template = node("getblocktemplate", [{"rules": ["segwit"]}])
        assert template["height"] == 134
        assert node("submitblock", [mine_template(template)]) is None
        wait("Snapshot node mined a valid block", lambda: core("getblockcount") == 134)
        stop(consumer)
        missing = subprocess.run(common, capture_output=True, text=True, timeout=30)
        assert missing.returncode != 0 and "original --assumeutreexo-snapshot" in missing.stdout + missing.stderr
        tip = core("generatetoaddress", [2, payout])[-1]
        resumed = launch("consumer-resumed", common + snapshot_args)
        wait("Snapshot node resumed and caught up", lambda: node("getbestblockhash") == tip)
        assert "Initialized assumed utreexo point" not in resumed.log_path.read_text()
        wait("Sidecar committed the resumed tip", lambda: export.read_archive_state(work / "proofs")["height"] == 136)
        state = export.read_archive_state(work / "proofs", 136)
        roots = node("getutreexoroots", [tip])
        assert roots["numleaves"] == state["num_leaves"] and roots["roots"] == state["roots"]
        stop(resumed)
        # Exercise the default latest-height export when there are no suffix
        # blocks yet, including a restart before the first one arrives.
        latest_path = work / "regtest-136.json"
        latest_command = [part for part in command if not part.startswith(("--height=", "--output="))]
        latest = subprocess.run(latest_command + [f"--output={latest_path}"],
                                check=True, capture_output=True, text=True, timeout=60)
        latest_result = json.loads(latest.stdout)
        latest_snapshot = json.loads(latest_path.read_text())
        assert latest_snapshot["height"] == 136
        latest_args = [f"--assumeutreexo-snapshot={latest_path}",
                       f"--assumeutreexo-snapshot-sha256={latest_result['sha256']}"]
        latest_common = [part for part in common if not part.startswith("--datadir=")]
        latest_common += [f"--datadir={work / 'latest-consumer'}"]
        latest_node = launch("consumer-latest", latest_common + latest_args)
        wait("Latest snapshot reached the header tip", lambda: node("getbestblockhash") == tip)
        assert node("getutreexoroots", [tip]) == roots
        assert node("getblocktemplate", [{"rules": ["segwit"]}])["height"] == 137
        stop(latest_node)
        launch("consumer-latest-resumed", latest_common + latest_args)
        wait("Latest snapshot resumed before any suffix block", lambda: node("getbestblockhash") == tip)
        assert node("getutreexoroots", [tip]) == roots
        wallet("sendtoaddress", [wallet("getnewaddress"), 1])
        tip = core("generatetoaddress", [1, payout])[0]
        wait("Latest snapshot validated its first suffix block", lambda: node("getbestblockhash") == tip)
        wait("Sidecar committed the latest test tip", lambda: export.read_archive_state(work / "proofs")["height"] == 137)
        state = export.read_archive_state(work / "proofs", 137)
        roots = node("getutreexoroots", [tip])
        assert roots["numleaves"] == state["num_leaves"] and roots["roots"] == state["roots"]
        evidence = {"snapshot": result, "snapshot_height": 120, "historical_consumer_final_height": 136,
                    "pre_snapshot_coin_spend": spend, "matching_roots": roots,
                    "tampered_file_rejected": True, "missing_restart_pin_rejected": True,
                    "resumed_without_reinitialization": True, "standard_submitblock": True,
                    "latest_snapshot_height": 136, "final_height": 137,
                    "latest_snapshot_roots_before_suffix": True, "latest_snapshot_restart_before_suffix": True}
        (work / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2), flush=True)
    finally:
        for process in reversed(processes):
            process.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--utreexod", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--timeout", type=int, default=180)
    run(parser.parse_args())
