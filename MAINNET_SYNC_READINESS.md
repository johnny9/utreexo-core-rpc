# Mainnet sync readiness checklist

Last reviewed: 2026-09-01

## Current recommendation

The sidecar has a dedicated unattended controller for the bounded format-3 replay
to a pinned reference height. The controller uses sparse recovery checkpoints,
preserves and reload-validates the compact 900000 checkpoint, and fails closed on
an exact-state mismatch. Use that controller for the 943013 validation run rather
than a single uninterrupted sidecar invocation.

When loading a validated checkpoint, `--online-state=DIR` streams it directly into one
native mmap generation and uses a synchronized WAL during catch-up and tip following.
A host failure then loses no published block: restart replays committed WAL records
over the last durable base. Preserve the validated format-3 checkpoint for deep-reorg
recovery. `--fast-sync` is opt-in and emits a warning that it requires at least 32 GiB
of system RAM; the unattended historical rebuild controller enables it explicitly.

To bootstrap Floresta nodes from that checkpoint, add `--proof-store=DIR` while replaying
the checkpoint to the tip. The proof data is appended once, its compact index WAL is
group-synchronized after the data, and the mmap lookup index is rebuildable. Use a new
online-state path for this replay; an existing online directory takes precedence over
the checkpoint and cannot reconstruct proofs for blocks already applied to its forest.

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

A large checkpoint may be roughly 16-17 GiB. Atomic replacement temporarily retains
the old checkpoint while writing the new temporary file, so keep at least 40 GiB free
on the checkpoint filesystem. Prefer a separate HDD or non-critical storage device
when the objective is minimizing writes to the node's SSD.

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
`d`. Do not press `Ctrl-C` in the sync window because signal-triggered checkpoints
are not implemented yet.

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
- Incomplete WAL tails are truncated; corruption inside a committed record fails closed.
- The mapped base is updated only from coalesced node deltas and advances through an
  alternating synchronized superblock.
- Automatic rollback is limited to retained connect transactions (1,008 blocks by
  default). A deeper reorganization, or one crossing the original online-generation
  boundary without a retained connect record, requires the preserved checkpoint.
- Optional Bitcoin-v1 P2P serves recent proofs from RAM and checkpoint-to-tip proofs
  from `--proof-store`. It deliberately does not claim full-genesis archive coverage.
- Graceful signal handling remains desirable for log clarity, but correctness does not
  depend on a shutdown-time full checkpoint once online: committed WAL replay is the
  recovery path.

## Go/no-go decision

- **Go:** the dedicated `rebuild-validate` pipeline to the pinned 943013 reference,
  after its automatic Core, binary-format, reference, and storage preflight passes.
- **Go:** tip following from a validated checkpoint with `--online-state`, while the
  bootstrap checkpoint remains available for deep-reorg recovery.
- **No-go:** a direct genesis-to-tip invocation without the controller's milestone
  recovery points or deleting the validated fallback checkpoint after switching online.
