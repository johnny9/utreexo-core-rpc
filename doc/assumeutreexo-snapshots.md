# Export an AssumeUtreexo snapshot

`utreexo-export-assumeutreexo` exports a small JSON bootstrap state for the
compact utreexod consumer built with this repository's
[compatibility patch](../contrib/utreexod-v0.6.0-core-relay.patch). The same tool
is available in a checkout as `python3 tools/export-assumeutreexo.py`.
It requires Python 3.10 or later and uses only the standard library.

Upstream utreexod v0.6.0 starts from compiled AssumeUtreexo points. It has no
snapshot file loader or runtime height selector; `--addcheckpoint` supplies only
a block height and hash. Our consumer adds `--assumeutreexo-snapshot` and
`--assumeutreexo-snapshot-sha256`. An unpatched upstream binary cannot load these
files. Public Pool needs no additional changes.

## Export from a running sidecar

The sidecar must have a state-bearing v2 proof archive. Core must still have the
selected block available for `getblock` and its chain transaction statistics.
Use the same Core node the sidecar follows. For example:

```sh
python3 tools/export-assumeutreexo.py \
  --proof-store=/path/to/proofs \
  --rpc-url=http://127.0.0.1:8332 \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --height=966110 \
  --output=/path/to/mainnet-966110.json
```

Omit `--height` to select the latest complete archive commit. A specified height
may be the archive base or a later active-chain height with saved v2 state.
An unavailable, rolled-back, legacy state-less, or genesis height is rejected.
The output must be a new path outside the proof store. The tool prints its
height, block hash, file size, and SHA256. RPC credentials are never included.

The exporter opens archive files read-only and scans a fixed prefix of
`index.wal` twice with constant memory. It checks committed WAL checksums,
connect/truncate sequencing, and the selected state envelope's independent
checksum and WAL commitment. It does not read proof payloads or load the forest.
Incomplete final WAL appends are ignored; corruption in a committed record fails
the export. Core's block hash is checked before and after gathering block
metadata, so an observed reorganization aborts the export. A future reorganization
can still invalidate a recent snapshot; choose a sufficiently buried block for
a snapshot you intend to distribute.

This exports the accumulator **stump** (leaf count and ordered roots) and the
block statistics needed by utreexod. It is typically a few kilobytes. It is not
the multi-gigabyte sidecar forest checkpoint and cannot initialize a proof-serving
sidecar. It also does not scrub the archive's proof payloads.

## Start a compact consumer

Obtain the snapshot and its SHA256 from a source you trust. Pinning the file
detects replacement or corruption; it does not independently prove the roots
correct. Bitcoin headers do not commit to Utreexo roots. Loading a custom snapshot
explicitly trusts its chain state through that block, just as the built-in
AssumeUtreexo point does. Subsequent blocks and proofs are validated normally.

```sh
./utreexod-relay \
  --datadir=/mnt/data/utreexod-snapshot/data \
  --logdir=/mnt/data/utreexod-snapshot/logs \
  --assumeutreexo-snapshot=/path/to/mainnet-966110.json \
  --assumeutreexo-snapshot-sha256=<SHA256-PRINTED-BY-EXPORTER> \
  --connect=127.0.0.1:8333 --connect=127.0.0.1:8338
```

Use the block and proof endpoints appropriate to the consumer's host, and add
its normal RPC configuration. Keep both snapshot options and the exact file on
restart. The database records the pin and refuses a different or missing anchor.
For regtest, include `--regtestkeepdb` on every run: the upstream default deletes
the regtest database on startup. This fork adds that option for persistent tests.
Import requires a fresh data directory; it does not replace an existing node's
progress. Header-only bootstrap interrupted before the first suffix block can
resume with the same snapshot. A snapshot at the current tip also works, including
querying its roots and restarting before another block arrives.

The snapshot becomes a block checkpoint, preventing reorganizations below its
trusted boundary. `--noassumeutreexo`, `--noutreexo`, proof-index/full-UTXO modes,
and `--nocheckpoints` cannot be combined with a custom snapshot. Mining still
waits for the validated tip to reach the best header.

## Supported heights

The importer accepts a positive height at or above **every configured block
checkpoint and the committed TTL boundary**. It verifies the snapshot hash at
that height against the downloaded header chain before activating the roots.
The current v0.6.0 network parameters imply these minimum heights:

| Network | Minimum custom height | Built-in AssumeUtreexo height |
| --- | ---: | ---: |
| Mainnet | 943,013 | 943,013 |
| Testnet3 | 4,898,397 | 4,898,397 |
| Signet | 294,687 | 297,353 |
| Regtest | 1 | None |

Additional operator checkpoints can raise the minimum. For mainnet, newer
snapshots shorten the block/proof suffix downloaded by a new compact node.
The node still downloads and verifies headers from genesis. The proof provider
must have proofs for every block after the snapshot through the tip. Custom
signet challenges are outside this export format: use the standard networks.

## JSON format, version 1

The object contains `format: "utreexod-assumeutreexo"`, `version: 1`, `network`,
`genesis_hash`, `height`, `block_hash`, `bits`, `block_size`, `block_weight`,
`num_txns`, `total_txns`, `median_time`, `num_leaves`, `roots_encoding`, and `roots`.
All numeric values are integers; `bits` is the numeric compact difficulty field,
and `median_time` is Unix seconds. `total_txns` includes genesis. Network names
are `mainnet`, `testnet3`, `signet`, and `regtest`.

Block/genesis hashes use Bitcoin display order. Roots are 32-byte lowercase hex
in internal SHA512/256 byte order, ordered from the highest occupied accumulator
row to the lowest. Empty roots are represented by 32 zero bytes; do not omit them.
The exact `roots_encoding` string is
`sha512_256_internal_bytes_high_row_to_low_row_present_roots`.
The number of roots must equal the population count of `num_leaves`.
The importer limits files to 16 KiB and rejects unknown fields, invalid encoding,
network mismatches, invalid statistics, and incompatible heights.

## Validation

`python3 test/export_assumeutreexo_tests.py` covers archive selection, truncation,
corruption, incomplete appends, bounded state reads, Core reorganization checks,
and atomic output publication. The consumer's Go tests cover parsing, checksum
pins, network/height constraints, and database anchor persistence.

`test/integration/core_utreexod_snapshot.py` uses real Core, sidecar, and compact
utreexod processes on loopback. It exports regtest height 120, validates a suffix
containing a spend of a coin created before the snapshot, checks matching roots,
mines through `getblocktemplate`/`submitblock`, and resumes without reinitializing.
It also checks latest-height bootstrap and restart before the first suffix block.

A workstation check on 2026-09-08 exported mainnet height 966,110 as a 1,917-byte
file in 0.14 seconds with 27,796 KiB peak RSS. A fresh compact consumer loaded it,
downloaded headers, validated the eight-block suffix to 966,118, matched the
sidecar's roots, and returned a template for 966,119 in 27.09 seconds. This is a
recent-snapshot workstation measurement, not an Orange Pi sync benchmark.
