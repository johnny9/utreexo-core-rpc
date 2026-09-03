# Mainnet sync readiness checklist

Last reviewed: 2026-09-03

## Current recommendation

The corrected format-3 mainnet reconstruction has completed from the preserved
800000 checkpoint through height 943013. Its block hash, leaf count, and all 18
ordered roots matched the independent Utreexod reference exactly. The validated
compact checkpoint has 3,082,565,786 leaves, is 14,893,913,136 bytes, and has SHA-256
`e869cb2eaf6a42d71010464b1dac7d0cd5cc7ed237ba78d2c653d2c8efa5a492`.

The unattended controller remains the recommended way to reproduce a bounded
format-3 replay. It uses sparse recovery checkpoints, preserves and reload-validates
the compact 900000 checkpoint, and fails closed on an exact-state mismatch.

When loading a validated checkpoint, `--online-state=DIR` streams it directly into one
native mmap generation and uses a synchronized WAL during catch-up and tip following.
A host failure then loses no published block: restart replays committed WAL records
over the last durable base. Preserve the validated format-3 checkpoint for deep-reorg
recovery. `--fast-sync` is opt-in and emits a warning that it requires at least 32 GiB
of system RAM; the unattended historical rebuild controller enables it explicitly.
The authenticated bootstrap is immutable. RAM-mode recovery writes to
`BOOTSTRAP.resume` by default (or an explicit `--recovery-checkpoint`) and prefers that
local descendant on restart only after verifying its trusted-base lineage and active
Core chain point.

To bootstrap Floresta nodes from that checkpoint, add `--proof-store=DIR` while replaying
the checkpoint to the tip. The proof data is appended once, its compact index WAL is
group-synchronized after the data, and the mmap lookup index is rebuildable. Use a new
online-state path for this replay; an existing online directory takes precedence over
the checkpoint and cannot reconstruct proofs for blocks already applied to its forest.
Such a store honestly covers only the checkpoint-to-tip suffix. A full historical
proof/state archive requires a continuous proof-store reconstruction from canonical
genesis; only that mode advertises archive coverage.

## Required Bitcoin Core preflight

- Run against a fully synchronized mainnet node.
- Confirm `getblockchaininfo` reports `initialblockdownload: false`.
- Confirm `getblockchaininfo` reports `pruned: false`.
- Confirm historical undo information is available. Fetch an old non-coinbase block
  with `getblock <hash> 3` and check that every non-coinbase input has a `prevout`.
- `txindex` is not required. It does not replace historical undo information because
  the sidecar needs each spent output's amount, script, creation height, and coinbase
  status.
- Prefer cookie authentication on loopback so credentials do not appear in command
  history or process arguments.

Example preflight:

```sh
bitcoin-cli getblockchaininfo
MAINNET_TEST_HASH=$(bitcoin-cli getblockhash 100000)
bitcoin-cli getblock "$MAINNET_TEST_HASH" 3 \
  | jq '[.tx[1:][]?.vin[]? | has("prevout")] | all'
```

The final command should print `true`.

## Memory and checkpoint storage

For the opt-in RAM fast-sync mode, the deterministic estimator currently reports
approximately:

| Live leaves | Estimated sidecar data |
| ---: | ---: |
| 100 million | 9.05 GiB |
| 180 million | 16.40 GiB |
| 200 million | 18.07 GiB |

Actual resident memory is higher because the estimate excludes allocator overhead,
RPC JSON, the current block, the executable, the operating system, and Bitcoin Core.
The default checkpoint-to-mmap import does not allocate this arena in anonymous RAM,
although it still needs the reverse index and reclaimable filesystem page cache. On a
32 GiB machine using `--fast-sync`:

- keep Bitcoin Core's `dbcache` conservative;
- monitor the combined RSS of Core and the sidecar;
- retain at least 8-10 GiB of practical headroom beyond the sidecar estimate; and
- avoid allowing sustained swap traffic onto the SSD being protected.

A large recovery checkpoint may be roughly 16-17 GiB. Its atomic replacement
temporarily retains the old recovery file while writing the new temporary file, while
the published bootstrap remains untouched, so keep at least 40 GiB free on that
filesystem. Prefer a separate HDD or non-critical storage device when the objective
is minimizing writes to the node's SSD.

The completed 800000-to-943013 acceptance stage measured a peak sidecar RSS of
24,836,720 KiB (23.69 GiB). Bitcoin Core used about 2.73 GiB at that sample, for a
combined footprint of about 26.4 GiB. This validates the 32 GiB-class recommendation
for that workload, provided Core's cache and unrelated host services remain bounded.
Historical-proof pipelining adds a configured 256 MiB queue by default, so operators
should retain the remaining headroom and keep the proactive memory reserve enabled.
One proof larger than the normal queue ceiling may be processed alone, up to the
320 MiB record limit, to avoid rejecting a consensus-valid block; this is a transient
exception rather than an increase to the steady-state queue budget. The completed
acceptance replay established the forest baseline, but a genesis-to-tip proof-archive
replay has not separately reproduced that entire mainnet workload under a 32 GiB cap.

## Low-write staged mainnet run

Leave `--checkpoint-interval=0`. Use stop heights so each successful stage performs
one full checkpoint write instead of repeatedly serializing the forest.

Suggested progression:

1. Height 100,000.
2. Resume the same checkpoint to height 100,100.
3. Compare the height-100,000 leaf count and roots with an independent
   Rustreexo/Floresta-compatible result if available.
4. Continue to approximately 250,000, 500,000, and 750,000.
5. Continue from the last verified checkpoint to the tip captured at startup.

The first height is intentional: 100,000 crosses all four relevant BIP30
duplicate-coinbase events at heights 91,722, 91,812, 91,842, and 91,880. It exercises
the actual historical Core JSON and undo path in addition to the synthetic tests.

Example first stage:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/mainnet.chk \
  --allow-untrusted-checkpoint \
  --state-json=/checkpoint-disk/mainnet-100k.json \
  --stop-height=100000
```

Then verify restoration immediately:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/mainnet.chk \
  --allow-untrusted-checkpoint \
  --fast-sync \
  --state-json=/checkpoint-disk/mainnet-100100.json \
  --stop-height=100100
```

For longer monitored milestones, the workspace includes a tmux supervisor that logs
progress and samples sidecar/Core memory once per second:

```sh
./sidecar/tools/mainnet-sync.sh start 250000
./sidecar/tools/mainnet-sync.sh status
./sidecar/tools/mainnet-sync.sh follow
```

Attach with `./sidecar/tools/mainnet-sync.sh attach` and detach with `Ctrl-b`, then
`d`. `SIGINT` and `SIGTERM` stop at a block boundary, drain the proof pipeline, and
persist the applicable RAM checkpoint or mmap/WAL state before exit.

For the complete known-reference reconstruction, launch the detached controller
once and monitor it without interacting with the sync process:

```sh
./sidecar/tools/mainnet-sync.sh rebuild-validate 943013
./sidecar/tools/mainnet-sync.sh rebuild-status
./sidecar/tools/mainnet-sync.sh rebuild-follow
```

The controller requires at least 80 GiB free by default, uses `info` logging, pins
the sidecar/compactor/reference SHA-256 digests, verifies historical undo prevouts,
and retains both the uncompressed and compact 900000 checkpoints. Its final active
checkpoint is a separate reflink/copy, so reaching 943013 cannot overwrite the
preserved compact recovery point.

Record for every stage:

- final height and active-chain block hash;
- leaf count and ordered roots from the state JSON;
- peak sidecar and Bitcoin Core RSS;
- elapsed time and average blocks per second;
- checkpoint size and checkpoint write duration; and
- free space before and after checkpoint replacement.

## Online-operation boundaries

- Every published online block has a checksummed, synchronized redo/undo WAL record.
- A newly created WAL segment's directory entry is synchronized before its first
  block is published; this adds one directory fsync per segment, not per block.
- Incomplete WAL tails are truncated; corruption inside a committed record fails closed.
- The mapped base is updated only from coalesced node deltas and advances through an
  alternating synchronized superblock. Its chain-height index uses a matching pair of
  alternating snapshots, so reorg suffix replacement never mutates the chain view of
  the currently published superblock.
- Automatic rollback is limited to retained connect transactions (1,008 blocks by
  default). A deeper reorganization, or one crossing the original online-generation
  boundary without a retained connect record, requires the preserved checkpoint.
- Optional Bitcoin-v1 P2P serves recent proofs from RAM and durable proofs from
  `--proof-store`. Checkpoint-based stores do not claim full-history coverage; a
  canonical genesis-to-tip store additionally serves historical accumulator states.
- Graceful signals drain and persist state for operational clarity. Correctness still
  does not depend on a shutdown-time full checkpoint once online: committed WAL replay
  is the crash-recovery path.

## Go/no-go decision

- **Validated:** the dedicated `rebuild-validate` result at the pinned 943013
  Utreexod reference, including compact checkpoint reload and exact state comparison.
- **Go:** tip following from a validated checkpoint with `--online-state`, while the
  bootstrap checkpoint remains available for deep-reorg recovery.
- **Go (beta):** manual/staged Floresta block-proof service with the documented
  admission limits and Core as the consensus/block source.
- **Not yet autonomous:** current Floresta initial peer selection still expects one
  peer to provide block plus archive services. The proof-only sidecar deliberately
  leaves header/block forwarding to upstream peer-role separation.
- **No-go:** a direct genesis-to-tip invocation without the controller's milestone
  recovery points or deleting the validated fallback checkpoint after switching online.
