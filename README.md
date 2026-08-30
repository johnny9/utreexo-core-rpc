# Utreexo bridge sidecar

This is a C++20, Bitcoin Core-compatible implementation of the low-write bridge
bootstrap design. It reads sequential active-chain blocks from an unpruned Bitcoin
Core node using `getblock(hash, 3)`, derives the exact Utreexo leaf hashes, and keeps
the full proving forest in RAM.

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
- A minimal HTTP JSON-RPC transport using the vendored Bitcoin Core UniValue parser.
- Sequential chain-continuity and reorganization detection.
- Bridge-compatible compact leaf classification and UData serialization.
- Optional sparse, atomic, fsync-and-rename checkpoints. Checkpoints include the
  32-byte-per-height block-hash index needed to derive future deletion leaves.

The executable currently constructs the tip forest and compact spent-leaf records but
does not generate historical proofs during bootstrap because they are neither retained
nor served. The accumulator retains its on-demand batch-proof API for future tip UTXO,
block, and transaction requests. The executable does not yet publish the Bitcoin P2P
bridge protocol. Reorganizations are detected and fail closed; automatic near-tip
rollback/overlay storage is also a follow-up module.

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

`--checkpoint-interval=N` is intentionally opt-in because every checkpoint streams the
full forest. Large intervals reduce restart cost while avoiding the per-block rewrite
pattern this project is meant to eliminate.

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

## Memory model

Each arena slot uses 45 bytes: a 32-byte hash, three 32-bit links, and a one-byte type.
The reverse index uses approximately 5 bytes per bucket and targets at most 80% load.
It does not duplicate leaf hashes. Allocations are chunked, so growth does not copy the
forest or temporarily require a second arena.

`ForestUsage` reports live and allocated arena slots, arena capacity/free slots,
reverse-index entries/capacity/tombstones, and separate deterministic arena/index byte
estimates. Actual RSS also includes allocator, RPC JSON, block, and executable overhead.
The intended 32 GiB operating profile processes one verbosity-3 block at a time and
checkpoints only sparsely.

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
