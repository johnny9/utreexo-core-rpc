#!/usr/bin/env python3
"""Export a compact AssumeUtreexo snapshot from a v2 proof archive and Bitcoin Core.

Reads the checksummed WAL and one independently authenticated state envelope.
Does not open the forest, lock the writer, or read proof payloads. Python 3.10+;
standard library only. The matching utreexod fork/compatibility patch is required.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


ROOTS_ENCODING = "sha512_256_internal_bytes_high_row_to_low_row_present_roots"
NETWORKS = {"main": "mainnet", "test": "testnet3", "signet": "signet", "regtest": "regtest"}
WAL_SIZE = 176
MAX_RECORD_SIZE = 320 * 1024 * 1024
ZERO_HASH = bytes(32)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).digest()


def read_exact(stream, offset, count):
    stream.seek(offset)
    data = stream.read(count)
    require(len(data) == count, "archive changed or is truncated; retry the export")
    return data


@dataclass(frozen=True)
class Event:
    version: int
    kind: int
    height: int
    block_hash: bytes
    previous: bytes
    offset: int
    size: int
    commitment: bytes


def parse_event(raw):
    require(raw[:8] == b"UPRFWAL1" and raw[168:] == b"UPRFCMT1", "invalid proof WAL framing")
    require(sha256(raw[:136]) == raw[136:168], "proof WAL checksum mismatch")
    version, kind, height, reserved = struct.unpack_from("<IIII", raw, 8)
    require(version in (1, 2) and kind in (1, 2, 3) and reserved == 0, "invalid proof WAL fields")
    offset, size = struct.unpack_from("<QQ", raw, 88)
    return Event(version, kind, height, raw[24:56], raw[56:88], offset, size, raw[104:136])


def scan_wal(wal, end, data_size, target=None):
    """Replay a fixed WAL prefix with constant memory, including reorg truncates."""
    tip = base = selected = None
    data_end = 0
    digest = hashlib.sha256()
    for offset in range(0, end, WAL_SIZE):
        raw = read_exact(wal, offset, WAL_SIZE)
        digest.update(raw)
        event = parse_event(raw)
        if tip is None:
            require(event.kind == 1 and event.offset == 0 and event.previous == ZERO_HASH,
                    "proof WAL must start with a base record")
            base = event
            if event.version == 1:
                require(event.size == 0 and event.commitment == ZERO_HASH, "invalid legacy base")
        elif event.kind == 2:
            require(event.height == tip.height + 1 and event.previous == tip.block_hash
                    and event.offset == data_end, "noncontiguous proof WAL connect")
        elif event.kind == 3:
            require(base.height <= event.height < tip.height and event.previous == tip.block_hash
                    and event.offset == event.size == 0 and event.commitment == ZERO_HASH,
                    "invalid proof WAL truncate")
            if event.height == base.height:
                require(event.block_hash == base.block_hash, "truncate changed the archive base")
            if selected is not None:
                if event.height < selected.height:
                    selected = None
                elif event.height == selected.height:
                    require(event.block_hash == selected.block_hash, "truncate hash mismatch")
        else:
            raise ValueError("proof WAL contains a second base record")
        if event.kind != 3:
            if event.version == 2 or event.kind == 2:
                require(128 <= event.size <= MAX_RECORD_SIZE
                        and event.offset + event.size <= data_size, "invalid proof data bounds")
            data_end = event.offset + event.size
            if event.height == target:
                selected = event
        tip = event
    require(tip is not None, "proof archive has no complete committed base")
    return tip, selected, digest.digest()


def read_envelope(data, event):
    require(event.version == 2, "requested height has no v2 accumulator state")
    header = read_exact(data, event.offset, 88)
    require(header[:8] == b"UPRFDAT1" and struct.unpack_from("<II", header, 8) == (2, event.height)
            and header[16:48] == event.block_hash and header[48:80] == event.previous,
            "state header does not match the proof WAL")
    payload_size, = struct.unpack_from("<Q", header, 80)
    require(event.kind != 1 or payload_size == 0, "base state has a proof payload")
    prefix = read_exact(data, event.offset + 88, 16)
    leaves, count, reserved = struct.unpack("<QII", prefix)
    require(count <= 64 and count == leaves.bit_count() and reserved == 0, "invalid accumulator state prefix")
    require(88 + 16 + count * 32 + 32 + payload_size + 40 == event.size, "state record size mismatch")
    roots = read_exact(data, event.offset + 104, count * 32)
    state_digest = read_exact(data, event.offset + 104 + count * 32, 32)
    require(sha256(b"UPRFSTA2" + struct.pack("<I", event.height) + event.block_hash + prefix + roots)
            == state_digest, "accumulator state checksum mismatch")
    footer = read_exact(data, event.offset + event.size - 40, 40)
    require(footer[32:] == b"UPRFDONE" and
            sha256(b"UPRFCMT2" + footer[:32] + state_digest) == event.commitment,
            "state commitment does not match the proof WAL")
    return {"height": event.height, "block_hash": event.block_hash[::-1].hex(), "num_leaves": leaves,
            "roots": [roots[i:i + 32].hex() for i in range(0, len(roots), 32)]}


def read_archive_state(directory, height=None):
    directory = Path(directory)
    require((directory / "FORMAT").read_bytes() == b"utreexo-proof-store-v1\n", "unrecognized proof store")
    with (directory / "index.wal").open("rb") as wal, (directory / "proofs.dat").open("rb") as data:
        identities = [os.fstat(f.fileno()) for f in (wal, data)]
        require(all(stat.S_ISREG(s.st_mode) for s in identities), "archive files must be regular files")
        require((identities[0].st_dev, identities[0].st_ino) != (identities[1].st_dev, identities[1].st_ino),
                "proof WAL and data must be distinct files")
        # Writers append data before publishing fixed-size WAL commits. Ignore
        # an incomplete final append; never repair or mutate the live archive.
        end = identities[0].st_size // WAL_SIZE * WAL_SIZE
        if end and read_exact(wal, end - 8, 8) != b"UPRFCMT1":
            end -= WAL_SIZE
        tip, _, before = scan_wal(wal, end, identities[1].st_size)
        target = tip.height if height is None else height
        require(0 < target <= tip.height, "requested height is not in the committed archive")
        _, selected, after = scan_wal(wal, end, identities[1].st_size, target)
        require(before == after, "proof WAL changed during export; retry")
        require(selected is not None, "requested height is unavailable in the active archive")
        state = read_envelope(data, selected)
        for f, original in zip((wal, data), identities):
            current = Path(f.name).stat()
            require((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
                    and current.st_size >= original.st_size, "archive was replaced or truncated; retry")
        return state


class CoreRPC:
    def __init__(self, url, cookie):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
                and not parsed.password and not parsed.query and not parsed.fragment, "invalid Core RPC URL")
        self.url = url
        self.cookie = Path(cookie)
        # Do not forward cookie credentials through redirects or environment proxies.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, method, params=None):
        auth = base64.b64encode(self.cookie.read_bytes().strip()).decode("ascii")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
        request = urllib.request.Request(self.url, body,
            {"Content-Type": "application/json", "Authorization": "Basic " + auth})
        try:
            with self.opener.open(request, timeout=60) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            raise ValueError(f"Core {method} failed (HTTP {error.code})") from None
        require(len(raw) <= 16 * 1024 * 1024, "oversized Core RPC response")
        reply = json.loads(raw)
        require(reply.get("error") is None, f"Core {method} returned an RPC error")
        return reply["result"]


def build_snapshot(state, core):
    height, block_hash = state["height"], state["block_hash"]
    require(0 < height <= 0x7fffffff and 0 < state["num_leaves"] <= 1 << 63,
            "state is outside utreexod's supported height or accumulator range")
    info = core("getblockchaininfo")
    require(info["chain"] in NETWORKS, "Core network is not supported by utreexod")
    require(core("getblockhash", [height]) == block_hash, "archive state is not on Core's active chain")
    block = core("getblock", [block_hash, 1])
    stats = core("getchaintxstats", [1, block_hash])
    require(block["hash"] == block_hash and block["height"] == height
            and stats["window_final_block_hash"] == block_hash, "Core block metadata mismatch")
    snapshot = {"format": "utreexod-assumeutreexo", "version": 1,
                "network": NETWORKS[info["chain"]], "genesis_hash": core("getblockhash", [0]),
                **state, "bits": int(block["bits"], 16), "block_size": block["size"],
                "block_weight": block["weight"], "num_txns": block["nTx"],
                "total_txns": stats["txcount"], "median_time": block["mediantime"],
                "roots_encoding": ROOTS_ENCODING}
    require(core("getblockhash", [height]) == block_hash, "Core reorganized during export; retry")
    return snapshot


def write_snapshot(path, snapshot):
    """Publish a complete file without replacing an existing path or symlink."""
    path = Path(path)
    raw = (json.dumps(snapshot, indent=2) + "\n").encode()
    require(len(raw) <= 16 * 1024, "snapshot exceeds utreexod's 16 KiB limit")
    fd, temporary = tempfile.mkstemp(prefix=".assumeutreexo-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-store", type=Path, required=True)
    parser.add_argument("--height", type=int, help="archived height to export (default: latest complete commit)")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    parser.add_argument("--rpc-cookie", type=Path, required=True, help="Core RPC cookie (never written to the snapshot)")
    parser.add_argument("--output", type=Path, required=True, help="new snapshot JSON file; existing paths are refused")
    args = parser.parse_args()
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "output already exists")
        require(not args.output.resolve().is_relative_to(args.proof_store.resolve()),
                "output must be outside the proof store")
        state = read_archive_state(args.proof_store, args.height)
        snapshot = build_snapshot(state, CoreRPC(args.rpc_url, args.rpc_cookie))
        digest = write_snapshot(args.output, snapshot)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Snapshot export failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"path": str(args.output), "height": state["height"], "block_hash": state["block_hash"],
                      "sha256": digest, "bytes": args.output.stat().st_size}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
