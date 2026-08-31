# Mainnet sync readiness checklist

Last reviewed: 2026-08-31

## Current recommendation

The sidecar has a dedicated unattended controller for the bounded format-3 replay
to a pinned reference height. The controller uses sparse recovery checkpoints,
preserves and reload-validates the compact 900000 checkpoint, and fails closed on
an exact-state mismatch. Use that controller for the 943013 validation run rather
than a single uninterrupted sidecar invocation.

The sidecar process itself still does not checkpoint on every signal or ordinary
RPC failure. The controller limits that exposure by checkpointing at 250000,
500000, 800000, and 900000 and retrying transport failures from the last completed
milestone. A host failure can still lose work since the preceding milestone.

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

The deterministic estimator currently reports approximately:

| Live leaves | Estimated sidecar data |
| ---: | ---: |
| 100 million | 9.05 GiB |
| 180 million | 16.40 GiB |
| 200 million | 18.07 GiB |

Actual resident memory is higher because the estimate excludes allocator overhead,
RPC JSON, the current block, the executable, the operating system, and Bitcoin Core.
On a 32 GiB machine:

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

## Hardening before an unattended full-tip run

Implement these before leaving a complete bootstrap unattended:

1. **Checkpoint on clean termination.** Handle SIGINT and SIGTERM at a safe
   between-block boundary and write the last internally consistent state.
2. **Checkpoint after recoverable sync failures.** Forest modification is atomic, so
   an ordinary RPC/parser/proof failure should preserve and checkpoint the state from
   before the failed block.
3. **RPC retries.** Add bounded exponential backoff for connection, read, and timeout
   failures. Make the current 30-second timeout configurable.
4. **Configurable response limit.** Make the current 128 MiB RPC response ceiling
   configurable and report the largest observed verbosity-3 response.
5. **Checkpoint generations.** Retain at least the current and previous known-good
   checkpoints, or use distinct files for milestone heights. Do not overwrite the
   only recoverable checkpoint until the new one is written, validated, and confirmed
   to be on Core's active chain.
6. **Startup storage preflight.** Estimate temporary checkpoint space before starting
   a checkpoint and fail cleanly when the target filesystem is too small.

Automatic reorganization rollback is not implemented. The sidecar detects a change at
or below its current tip and fails closed. Retaining milestone checkpoint generations
is therefore important until the planned recent-reversal ring exists.

## Go/no-go decision

- **Go:** the dedicated `rebuild-validate` pipeline to the pinned 943013 reference,
  after its automatic Core, binary-format, reference, and storage preflight passes.
- **No-go:** an unbounded unattended tip-following process or a direct genesis-to-tip
  sidecar invocation without the controller's milestone recovery points.
