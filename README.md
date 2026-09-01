# Utreexo bridge sidecar

This is a C++20, Bitcoin Core-compatible implementation of the low-write bridge
bootstrap design. It reads sequential active-chain blocks from an unpruned Bitcoin
Core node using `getblock(hash, 3)`, derives the exact Utreexo leaf hashes, and keeps
the full proving forest in RAM during bulk bootstrap. At the validated Core tip it
can atomically publish a native mmap generation and continue through a block-atomic
write-ahead log with bounded coalesced RAM deltas.

The accumulator library has no RPC, JSON, filesystem, or P2P dependency. Its value
types and component boundaries are deliberately close to Bitcoin Core conventions so
the implementation can later move behind a Core `BlockSource` adapter without carrying
the sidecar transport with it.

## What is implemented

- Bitcoin-compatible SHA-512/256 parent hashing and `UtreexoV1` leaf serialization.
- A chunked structure-of-arrays forest with 32-bit node IDs and free-slot reuse.
- A keyless open-addressing reverse index. Buckets store only node IDs; full 256-bit
  keys remain in the leaf arena and are checked on lookup.
- Rustreexo-compatible positions, roots, deletion promotion, and batch proofs.
- Exact handling of same-block spends, provably unspendable outputs, genesis, and the
  two historical BIP30-unspendable coinbases.
- A persistent HTTP JSON-RPC transport with two-block bounded prefetch and a
  selective streaming parser for Bitcoin Core verbosity-3 responses.
- Sequential chain-continuity and reorganization detection.
- Bridge-compatible compact leaf classification and UData serialization.
- Optional sparse, atomic, fsync-and-rename checkpoints. Checkpoints include the
  32-byte-per-height block-hash index needed to derive future deletion leaves.
- Native 48-byte-per-slot mmap online storage, a RAM-only rebuildable keyless index,
  per-block redo/undo WAL records, bounded write-back deltas, and double-buffered
  durable superblocks.
- Automatic shallow-reorg rollback from retained WAL before-images. Reorgs older
  than the configured window fail closed to the preserved validated checkpoint.

The executable constructs the tip forest and compact spent-leaf records but
does not generate historical proofs during bootstrap because they are neither retained
nor served. The accumulator retains its on-demand batch-proof API for future tip UTXO,
block, and transaction requests. The executable does not yet publish the Bitcoin P2P
bridge protocol.

## Build and test

The required UniValue sources are vendored under `third_party/univalue`; no Bitcoin
Core source checkout or Bitcoin Core library is required to build the sidecar.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
./build/utreexo-resource-estimate 180000000
```

The standalone accumulator can also be built without the RPC adapter using
`-DUTREEXO_BUILD_RPC=OFF`.

## Run a RAM-first bootstrap

Bitcoin Core must be unpruned and have undo data for every processed block. `txindex`
is not required. With no `--checkpoint`, the sidecar writes no forest state while it
builds and a process failure restarts from genesis.

The JSON-RPC chain source keeps one HTTP connection alive, performs one
`getblockhash` and one verbosity-3 `getblock` call per block, and overlaps a bounded
two-block fetch queue with forest mutation. It checks every block's hash and previous
hash in sequence, then performs one final active-chain hash check before publishing a
checkpoint. The response parser projects only the fields needed for leaf derivation,
rather than constructing a full UniValue tree for the large verbosity-3 payload.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie
```

To make one recoverable checkpoint at shutdown or at the reached tip:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/fast/storage/utreexo-forest.chk \
  --log-level=info
```

Checkpoint format 3 retains the two overwritten BIP30 originals as permanent
Utreexo leaves. The corrected sidecar intentionally refuses format-2 checkpoints,
which may contain the incompatible forest; reconstruct from genesis or from an
independently validated format-3 proving-forest checkpoint.

`--checkpoint-interval=N` is intentionally opt-in because every checkpoint streams the
full forest. Large intervals reduce restart cost while avoiding the per-block rewrite
pattern this project is meant to eliminate.

## Switch to post-sync mmap/WAL operation

Pass `--online-state` on the final bootstrap invocation. The sidecar continues using
the RAM forest while it is behind, revalidates its final chain point against Core, then
writes one native generation and releases the RAM arena. It does not overwrite the
bootstrap checkpoint, which remains the recovery source for a reorg deeper than the
online undo window.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/validated-mainnet.chk \
  --online-state=/nvme/utreexo-online \
  --follow \
  --log-level=debug
```

On later starts, the existing online directory takes precedence over `--checkpoint`.
The sidecar selects the newest valid superblock, replays committed WAL records newer
than the mapped base, rebuilds the free list and RAM-only reverse index, verifies all
branch hashes and roots, reconciles shallow reorgs with Core, and then follows the tip.

Online defaults:

- dirty delta ceiling: 128 MiB on hosts with at most 20 GiB RAM, otherwise 512 MiB;
- WAL segments: 256 MiB;
- before-image/reorg retention: 1,008 blocks;
- WAL synchronization: every block before its state is published;
- base flush: at the delta ceiling, 1 GiB of unapplied redo WAL, after 24 hours in
  follow mode, or at clean non-follow shutdown; and
- full-forest compaction/checkpoint rewrites: never during normal tip following.

The native directory contains `forest.hashes`, `forest.meta`, `chain.hashes`, two
alternating `state.*` superblocks, and `wal-*.log` segments. Do not copy it as a shared
checkpoint while unapplied WAL exists; use the preserved format-3 checkpoint until an
explicit online export command is added.

## Offline arena compaction

`utreexo-checkpoint-compact` rewrites a checkpoint with dense node IDs. It preserves
the checkpoint format, chain point, leaf count, and roots; only internal node IDs and
links change. It is an offline operation: stop the sidecar first, keep the input
checkpoint unchanged, and write to a new path on the same filesystem.

```sh
./build/utreexo-checkpoint-compact \
  /fast/storage/utreexo-forest.chk \
  /fast/storage/utreexo-forest.compact.chk
```

The command validates the input checksum, writes and fsyncs the new checkpoint before
publishing it atomically, and prints source/compact slot counts. It uses a disk-backed
four-byte-per-old-slot ID map rather than loading either forest, so it is suitable for
memory-constrained hosts. Reserve space for the old checkpoint, the new checkpoint,
and the map (roughly 34 GiB at the current 900k-scale checkpoint); do not delete the
original until the compacted checkpoint has been independently loaded and validated.

## Logging and milestone validation

The sidecar emits UTC, single-line key/value records in the form
`timestamp=... level=... event=...`. `--log-level` accepts `error`, `warn`,
`info`, `debug`, or `trace`; the default is `info`.

- `info` records lifecycle events, 1,000-block progress and throughput, aggregate
  sync/RPC timing, checkpoint boundaries, and the final height/hash/leaves/roots
  manifest.
- `warn` records RPC failures and host memory pressure from the supervisor.
- `debug` adds forest arena/index capacity and tombstones, timing by processing
  phase, checkpoint write/checksum/fsync/rename timing, and largest RPC responses.
- `trace` adds one record per processed block and successful RPC call. It is useful
  for short investigations but produces substantial output during a full sync.

For long mainnet runs, `tools/mainnet-sync.sh` defaults to debug logging and samples
process/kernel telemetry once per second. Its resource TSV includes RSS, HWM, PSS,
minor/major faults, CPU ticks, process I/O, system swap activity, Bitcoin Core RSS,
and available memory. A successful milestone also produces a JSON manifest containing
the complete accumulator state, sidecar/format versions, checkpoint size, and SHA-256.
Set `UTREEXO_CHECKPOINT_SHA256=0` to skip the extra full-file read.

An expected state can be checked automatically at a known checkpoint:

```sh
UTREEXO_REFERENCE_STATE=/path/to/expected-943013.json \
  tools/mainnet-sync.sh start 943013
```

The expected JSON must contain `height`, `block_hash`, `num_leaves`, and `roots` in
the same form as `--state-json`. The supervisor compares all four exactly, writes a
`reference_validation` event and embeds the expected state in the milestone manifest.
A mismatch exits with status 2 and does not promote the result to `latest-state.json`.

### Unattended mainnet rebuild and validation

For a format-3 reconstruction from genesis through the pinned 943013 reference,
the supervisor has a staged, resumable controller:

```sh
tools/mainnet-sync.sh rebuild-validate 943013
tools/mainnet-sync.sh rebuild-status
tools/mainnet-sync.sh rebuild-follow
```

The first command performs a Bitcoin Core mainnet/unpruned/undo-data preflight,
pins the reference JSON and executable digests, and starts one detached tmux
session. Internally it checkpoints at 250000, 500000, 800000, and 900000. It then
compacts the 900000 checkpoint, reloads the compact result and compares its full
state with the pre-compaction state, and resumes a reflink/copy rather than the
preserved compact file. The final stage must exactly match the reference height,
block hash, leaf count, and ordered roots.

By default, artifacts are isolated in `artifacts/mainnet-validation-v3`. The
preserved checkpoint is `mainnet-900000-compact-v3.chk`; the 943013 run modifies
only `mainnet-final-active-v3.chk`. A failed transient transport stage is retried
up to three times from the last completed checkpoint. Reference mismatches,
reorganizations, checkpoint errors, memory exhaustion, and other deterministic
failures stop immediately without deleting either 900000 checkpoint. Re-running
`rebuild-validate` resumes a consistent failed run.

To adopt a tested replacement executable without discarding an active stage, schedule
a checkpoint-boundary handoff:

```sh
tools/mainnet-sync.sh rebuild-handoff-binary /path/to/new/utreexo-bridge
```

The active sidecar finishes its milestone unchanged. A digest guard prevents the old
controller from starting the next stage, the completed checkpoint is re-hashed against
its manifest, and the pipeline then resumes under the new executable. The final
validation manifest records both binary hashes, versions, the transition height, and
the exact checkpoint state. If the active stage fails, the old digest is restored so
the existing retry policy remains effective.

## Memory model

Each arena slot uses 45 bytes: a 32-byte hash, three 32-bit links, and a one-byte type.
The reverse index uses approximately 5 bytes per bucket and targets at most 80% load.
It does not duplicate leaf hashes. Allocations are chunked, so growth does not copy the
forest or temporarily require a second arena.

`ForestUsage` reports live and allocated arena slots, arena capacity/free slots,
reverse-index entries/capacity/tombstones, and separate deterministic arena/index byte
estimates. Actual RSS also includes allocator, RPC JSON, block, and executable overhead.
The intended 32 GiB bootstrap profile processes one verbosity-3 block at a time and
checkpoints only sparsely. Online mode maps the 48-byte native arena without populating
or locking it, so the operating system can evict cold forest pages. Its explicit RAM
cost is primarily the keyless reverse index, free-node bookkeeping, and the bounded
delta cache; the mapped virtual size is not equivalent to resident memory.

Before attempting mainnet, follow the staged resource, Core preflight, recovery, and
checkpoint guidance in [MAINNET_SYNC_READINESS.md](MAINNET_SYNC_READINESS.md).

## Test strategy

The deterministic suites include every insertion, deletion, and proof case from
Rustreexo 0.6.0's shared `test_cases.json` corpus; Floresta compact-script recovery
cases; SHA and Bitcoin leaf vectors; the complete BIP30 quartet; genesis handling;
Core's exact unspendable-script boundaries; exact amount parsing; txid/wtxid and
maximum-vout handling; same-block spends; missing-undo rejection; proof-leaf order;
free-slot reuse; mutation prevalidation; duplicate-leaf checkpoint round trips;
sequential sync; and reorg detection. The accumulator tests run without RPC or
Bitcoin Core. See [test/UPSTREAM_TESTS.md](test/UPSTREAM_TESTS.md) for the exact
upstream pins, case mapping, and intentionally inapplicable Rustreexo API suites.

### Floresta differential regtest

The opt-in integration harness creates an exceptional-output regtest chain in
Bitcoin Core, independently reconstructs it with this sidecar and
`rpc-utreexo-bridge`, then makes Floresta proof-validate the reference bridge's
blocks. All three implementations must agree on the tip, leaf count, and roots.

The external binaries are deliberately pinned to:

- `rpc-utreexo-bridge` commit
  `9582853345839d625e80ef46b1a23b6dd0fef6c6`.
- Floresta v0.8.1 commit
  `aaef08453a89a55fdb42e1541de7a18c151cdbe8`.

Floresta v0.9 and later use the newer `getuproof`/`uproof` protocol and cannot
consume the legacy proof-bearing blocks published by that reference bridge. The
harness checks the Floresta version up front.

```sh
cmake -S . -B build-integration \
  -DUTREEXO_ENABLE_REGTEST_INTEGRATION=ON \
  -DUTREEXO_REFERENCE_BRIDGE_EXECUTABLE=/path/to/rpc-utreexo-bridge \
  -DFLORESTAD_EXECUTABLE=/path/to/floresta-v0.8.1/florestad
cmake --build build-integration -j2
ctest --test-dir build-integration -R utreexo_floresta_regtest --output-on-failure
```

The test returns CTest's skip code 77 when an external executable is absent. A
wrong Floresta version is an error because it would test a different wire protocol.
Use `--keep-data` with `test/integration/floresta_regtest.py` to retain daemon logs
and chain data after a successful direct run.

## Continuous validation

GitHub Actions runs the following checks on every push to `master` and every pull
request:

- GCC Debug, GCC Release without the RPC adapter, Clang Release, and Apple Clang
  Release builds, all with warnings treated as errors.
- Address/Leak/UndefinedBehavior Sanitizers and ThreadSanitizer in separate jobs.
- Clang-Tidy's Clang analyzer, use-after-move, and performance checks.
- ASan/UBSan-backed libFuzzer smoke tests for forest deserialization and verbose
  Bitcoin Core RPC JSON parsing.
- Valgrind leak and memory-error checks for both deterministic test executables.
- ShellCheck, Python bytecode compilation, and whitespace validation.
- The pinned Bitcoin Core/reference bridge/Floresta differential regtest described
  above.

The sanitizer interface is also available locally:

```sh
cmake -S . -B build-asan -DUTREEXO_SANITIZERS=address,undefined
cmake --build build-asan -j2
ctest --test-dir build-asan --output-on-failure

cmake -S . -B build-tsan -DUTREEXO_SANITIZERS=thread
cmake --build build-tsan -j2
ctest --test-dir build-tsan --output-on-failure

CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DUTREEXO_BUILD_FUZZERS=ON -DBUILD_TESTING=OFF
cmake --build build-fuzz -j2 --target utreexo_fuzz_forest utreexo_fuzz_rpc_json
./build-fuzz/utreexo_fuzz_forest -runs=10000 -max_len=65536
./build-fuzz/utreexo_fuzz_rpc_json -runs=10000 -max_len=65536
```

Sanitizers supported by the CMake option are `address`, `undefined`, `thread`,
and `leak`. AddressSanitizer and ThreadSanitizer are intentionally rejected when
requested together because the runtimes are incompatible.
