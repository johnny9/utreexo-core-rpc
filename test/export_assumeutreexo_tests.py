#!/usr/bin/env python3
"""Snapshot export integrity, reorganization, and bounded-read regression tests."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("export_assumeutreexo",
    Path(__file__).resolve().parents[1] / "tools" / "export-assumeutreexo.py")
export = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = export
SPEC.loader.exec_module(export)


def wal_record(event):
    prefix = (b"UPRFWAL1" + struct.pack("<IIII", event.version, event.kind, event.height, 0)
              + event.block_hash + event.previous + struct.pack("<QQ", event.offset, event.size)
              + event.commitment)
    return prefix + export.sha256(prefix) + b"UPRFCMT1"


def record(height, block_hash, previous, offset, base=False, payload=b"proof"):
    if base:
        payload = b""
    header = b"UPRFDAT1" + struct.pack("<II", 2, height) + block_hash + previous + struct.pack("<Q", len(payload))
    body = struct.pack("<QII", 3, 2, 0) + bytes(range(64))
    state_digest = export.sha256(b"UPRFSTA2" + struct.pack("<I", height) + block_hash + body)
    data = header + body + state_digest + payload
    digest = export.sha256(data)
    data += digest + b"UPRFDONE"
    event = export.Event(2, 1 if base else 2, height, block_hash, previous, offset, len(data),
                         export.sha256(b"UPRFCMT2" + digest + state_digest))
    return event, data


class SnapshotExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "archive"
        self.directory.mkdir()
        (self.directory / "FORMAT").write_bytes(b"utreexo-proof-store-v1\n")
        self.base, a = record(100, b"a" * 32, bytes(32), 0, base=True)
        self.next, b = record(101, b"b" * 32, self.base.block_hash, len(a))
        self.last, c = record(102, b"c" * 32, self.next.block_hash, len(a) + len(b))
        self.data = a + b + c
        self.wal = b"".join(map(wal_record, (self.base, self.next, self.last)))
        self.save()

    def save(self):
        (self.directory / "proofs.dat").write_bytes(self.data)
        (self.directory / "index.wal").write_bytes(self.wal)

    def test_latest_and_historical_state(self):
        for height in (100, 101, 102, None):
            state = export.read_archive_state(self.directory, height)
            self.assertEqual(state["height"], height or 102)
            self.assertEqual(state["num_leaves"], 3)
            self.assertEqual(state["roots"], [bytes(range(32)).hex(), bytes(range(32, 64)).hex()])
        for height in (0, 99, 103):
            with self.assertRaises(ValueError):
                export.read_archive_state(self.directory, height)

    def test_reorg_and_truncate_tip(self):
        truncate = export.Event(2, 3, 100, self.base.block_hash, self.last.block_hash, 0, 0, bytes(32))
        self.wal += wal_record(truncate)
        self.save()
        self.assertEqual(export.read_archive_state(self.directory)["height"], 100)
        with self.assertRaises(ValueError):
            export.read_archive_state(self.directory, 101)
        fork, data = record(101, b"d" * 32, self.base.block_hash, len(self.data))
        self.wal += wal_record(fork)
        self.data += data
        self.save()
        self.assertEqual(export.read_archive_state(self.directory)["block_hash"], (b"d" * 32).hex())

    def test_incomplete_tail_is_read_only(self):
        self.wal += b"partial append"
        self.save()
        self.assertEqual(export.read_archive_state(self.directory)["height"], 102)
        self.assertEqual((self.directory / "index.wal").read_bytes(), self.wal)
        self.wal = self.wal[:-14] + bytes(176)
        self.save()
        self.assertEqual(export.read_archive_state(self.directory)["height"], 102)

    def test_corruption_fails_closed(self):
        original_data, original_wal = self.data, self.wal
        cases = [("wal", 24), ("data", self.last.offset), ("data", self.last.offset + 88),
                 ("data", self.last.offset + 104), ("data", len(self.data) - 40),
                 ("data", len(self.data) - 1)]
        for kind, offset in cases:
            with self.subTest(kind=kind, offset=offset):
                self.data, self.wal = original_data, original_wal
                value = bytearray(getattr(self, kind))
                value[offset] ^= 1
                setattr(self, kind, bytes(value))
                self.save()
                with self.assertRaises(ValueError):
                    export.read_archive_state(self.directory)

    def test_large_proof_payload_is_never_read(self):
        event, data = record(101, b"b" * 32, b"a" * 32, 0, payload=bytes(1024 * 1024))
        class BoundedReader(io.BytesIO):
            total = 0
            def read(self, count=-1):
                if not 0 <= count <= 2200:
                    raise AssertionError("unbounded archive read")
                self.total += count
                return super().read(count)
        reader = BoundedReader(data)
        state = export.read_envelope(reader, event)
        self.assertEqual(state["height"], 101)
        self.assertLess(reader.total, 1024)

    def test_core_chain_and_metadata(self):
        state = export.read_archive_state(self.directory)
        calls = []
        reorg = False
        def core(method, params=None):
            calls.append(method)
            if method == "getblockchaininfo": return {"chain": "regtest"}
            if method == "getblockhash":
                if params == [0]: return "00" * 32
                if reorg and calls.count("getblockhash") == 3: return "ff" * 32
                return state["block_hash"]
            if method == "getblock":
                return {"hash": state["block_hash"], "height": 102, "bits": "207fffff",
                        "size": 200, "weight": 800, "nTx": 1, "mediantime": 1700000000}
            if method == "getchaintxstats":
                return {"window_final_block_hash": state["block_hash"], "txcount": 103}
            raise AssertionError(method)
        snapshot = export.build_snapshot(state, core)
        self.assertEqual(snapshot["bits"], 0x207fffff)
        self.assertEqual(snapshot["total_txns"], 103)
        self.assertEqual(snapshot["roots_encoding"], export.ROOTS_ENCODING)
        self.assertEqual(snapshot["network"], "regtest")
        calls.clear()
        reorg = True
        with self.assertRaisesRegex(ValueError, "reorganized"):
            export.build_snapshot(state, core)

    def test_atomic_output_refuses_replacement(self):
        path = Path(self.tmp.name) / "snapshot.json"
        digest = export.write_snapshot(path, {"snapshot": "test"})
        self.assertEqual(digest, export.sha256(path.read_bytes()).hex())
        self.assertEqual(json.loads(path.read_text()), {"snapshot": "test"})
        with self.assertRaises(FileExistsError):
            export.write_snapshot(path, {"replacement": True})
        link = Path(self.tmp.name) / "link.json"
        link.symlink_to(path)
        with self.assertRaises(FileExistsError):
            export.write_snapshot(link, {})
        self.assertEqual(json.loads(path.read_text()), {"snapshot": "test"})
        self.assertEqual(list(Path(self.tmp.name).glob(".assumeutreexo-*")), [])


if __name__ == "__main__":
    unittest.main()
