# Utreexo bridge sidecar

This is a C++20, Bitcoin Core-compatible implementation of the low-write bridge
bootstrap design. It reads sequential active-chain blocks from an unpruned Bitcoin
Core node using `getblock(hash, 3)` and derives the exact Utreexo leaf hashes. A new
checkpoint catch-up streams directly into native mmap storage and continues through a
block-atomic write-ahead log with bounded coalesced RAM deltas. High-memory operators
can opt into a RAM-first catch-up with `--fast-sync`. An optional ordered proof pipeline
can retain every Floresta-compatible block proof from an AssumeUtreexo checkpoint to
the tip. A genesis rebuild additionally records the compact post-block accumulator
state at every height and can provide full historical block-proof/state coverage.

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
- A durable proof store with parallel serialization, ordered group commit,
  independently authenticated post-block states, checksummed append-only data, a
  compact index WAL, and a rebuildable mmap height index. Stores can begin at either
  an AssumeUtreexo checkpoint or canonical genesis.
- An optional inbound Bitcoin-v1 proof peer with bounded recent-proof caching plus
  proof-store fallback, Floresta-compatible `getuproof`/`uproof` and historical-state
  messages, handshake, admission/egress limits, explicit public-address gossip, and
  safe handling of unsupported messages.

Without `--proof-store`, bootstrap still omits historical proof generation and P2P
keeps only a bounded, disposable recent cache. With `--proof-store`, each missing proof
is generated and verified against the pre-mutation forest, made durable, and available
to P2P. A checkpoint-based store covers `base + 1` onward and does not claim
full-history service. Only a store constructed continuously from the selected
network's canonical genesis through the durable forest tip can advertise archive
coverage.

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

## Install and run with systemd

The release archive is laid out for the default `/usr/local` prefix and its generated
unit starts `/usr/local/bin/utreexo-bridge`. Verify the adjacent basename-only checksum,
then extract the single top-level archive directory into that prefix:

```sh
sha256sum --check utreexo-bridge-0.4.0-Linux-x86_64.tar.gz.sha256
sudo tar --no-same-owner \
  -xzf utreexo-bridge-0.4.0-Linux-x86_64.tar.gz \
  -C /usr/local --strip-components=1
```

For a conventional `/usr/bin` installation, set the prefix while configuring so the
unit's `ExecStart` is generated correctly; do not change only the install-time prefix:

```sh
cmake -S . -B build-system -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build-system -j2
sudo cmake --install build-system
```

Create an unprivileged service account and its writable state directory, then install
the generated service assets from the selected prefix (replace `/usr/local` with `/usr`
for the second example):

```sh
sudo useradd --system --user-group --home-dir /var/lib/utreexo-bridge \
  --shell /usr/sbin/nologin utreexo
sudo install -d -o utreexo -g utreexo -m 0750 /var/lib/utreexo-bridge
sudo install -d -o root -g utreexo -m 0750 /etc/utreexo-bridge
sudo install -o root -g root -m 0644 \
  /usr/local/share/utreexo-bridge/systemd/utreexo-bridge.service \
  /etc/systemd/system/utreexo-bridge.service
sudo install -o root -g utreexo -m 0640 \
  /usr/local/share/utreexo-bridge/systemd/utreexo-bridge.conf.example \
  /etc/utreexo-bridge/utreexo-bridge.conf
```

Edit the configuration paths, give only the `utreexo` account read access to Core's
cookie, and place the authenticated checkpoint at the configured path before starting;
the service fails closed when that input is absent. All online-state and proof-store
paths must remain under the writable `/var/lib/utreexo-bridge` directory allowed by the
hardened unit. Finally load and enable it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now utreexo-bridge.service
sudo systemctl --no-pager --full status utreexo-bridge.service
```

## Bootstrap from genesis

Bitcoin Core must be unpruned and have undo data for every processed block. `txindex`
is not required. With neither `--checkpoint` nor `--recovery-checkpoint`, the sidecar
writes no forest checkpoint while it builds and a process failure restarts from
genesis.

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
  --recovery-checkpoint=/fast/storage/utreexo-forest.chk \
  --fast-sync \
  --log-level=info
```

A missing bootstrap `--checkpoint` fails closed unless
`--allow-untrusted-checkpoint` is present. This prevents a mistyped distribution path
from silently starting a Genesis rebuild. `--recovery-checkpoint` is explicitly local
read/write state: if it exists it is preferred on restart, its format checksum and
active Core chain point are verified, and otherwise it is created at a completed block
boundary. Protect it with the same filesystem permissions as the online forest.
Loading a RAM recovery checkpoint requires `--fast-sync`; without that explicit flag,
checkpoint catch-up requires `--online-state`. Checkpoint, recovery, and state-JSON files
must be outside both the online-state and proof-store directories. Those two directories
must also be separate and non-nested. Startup resolves normalized paths, symlinks, and
existing hardlinks and rejects violations before opening RPC or modifying storage.

Checkpoint format 3 retains the two overwritten BIP30 originals as permanent
Utreexo leaves. The corrected sidecar intentionally refuses format-2 checkpoints,
which may contain the incompatible forest; reconstruct from genesis or from an
independently validated format-3 proving-forest checkpoint.

The binary contains a trust anchor for the release-candidate mainnet bridge checkpoint
at height 943013. Existing checkpoint files are required to match its consensus state
and exact file identity by default:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/mainnet-943013-compact.chk \
  --online-state=/nvme/utreexo-online \
  --follow
```

The anchor pins the block hash, leaf count, ordered roots, 14,893,913,136-byte file
size, and SHA-256
`e869cb2eaf6a42d71010464b1dac7d0cd5cc7ed237ba78d2c653d2c8efa5a492`.
The sidecar fails closed before deserialization when the file identity differs and
again after deserialization when the accumulator state differs. For private rebuild
milestones or locally generated checkpoints, `--allow-untrusted-checkpoint` skips
both checks and emits a warning that the state is unauthenticated. Use that override
only when the checkpoint's provenance has been established separately. Once the
native online directory exists, it intentionally takes precedence over the bootstrap
file and no checkpoint override is needed. A trusted bootstrap is always immutable:
RAM-mode interval, memory-guard, signal, and final saves go to
`mainnet-943013-compact.chk.resume` by default. An existing resume is preferred over
the bootstrap after its trusted-base lineage and current Core chain point pass
validation. A corrupt, incomplete, or reorged automatically named resume falls back
to exact validation of the preserved bootstrap; an explicitly named recovery file
fails closed so an operator-selected path is never silently ignored. Use
`--recovery-checkpoint=PATH` to choose a different local location; never point it at
the bootstrap file.

The machine-readable release manifest is
[`contrib/checkpoints/mainnet-943013.json`](contrib/checkpoints/mainnet-943013.json).
The 14.9 GB bootstrap is published at
[`https://checkpoints.johnny9.dev/mainnet-943013-compact.chk`](https://checkpoints.johnny9.dev/mainnet-943013-compact.chk).
Treat the download transport as untrusted: the binary enforces the embedded size,
file hash, block hash, leaf count, and ordered roots before accepting it. Operators
can also stream and authenticate the published object without retaining another copy:

```sh
python3 tools/verify-checkpoint-download.py
```

The tagged-release workflow independently performs the same full-stream verification
before publishing a package.

`--checkpoint-interval=N` is intentionally opt-in because every checkpoint streams the
full forest. Large intervals reduce restart cost while avoiding the per-block rewrite
pattern this project is meant to eliminate.

## Switch to post-sync mmap/WAL operation

Pass `--online-state` when loading an existing checkpoint. This is the default
checkpoint catch-up mode: the sidecar verifies the checkpoint checksum, streams its
forest directly into a new native mmap generation without constructing the full RAM
arena, validates every branch and root, and applies subsequent blocks through the WAL.
It does not overwrite the bootstrap checkpoint, which remains the recovery source for
a reorg deeper than the online undo window.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/validated-mainnet.chk \
  --online-state=/nvme/utreexo-online \
  --follow \
  --log-level=debug
```

`--fast-sync` is an explicit performance option. It keeps the checkpoint forest in
RAM while catching up, then publishes `--online-state` at Core's tip. The process emits
a warning before loading that this mode requires at least 32 GiB of system RAM; on
smaller hosts use the default mmap/WAL path. Loading an existing checkpoint without
either `--online-state` or `--fast-sync` fails with an actionable error instead of
silently choosing the high-memory path.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/validated-mainnet.chk \
  --recovery-checkpoint=/checkpoint-disk/validated-mainnet.resume.chk \
  --online-state=/nvme/utreexo-online \
  --fast-sync \
  --follow
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
- WAL directory synchronization: once when each 256 MiB segment is created;
- base flush: at the delta ceiling, 1 GiB of unapplied redo WAL, after 24 hours in
  follow mode, or at clean non-follow shutdown; and
- full-forest compaction/checkpoint rewrites: never during normal tip following.

The native directory contains `forest.hashes`, `forest.meta`, two alternating
`chain.*.hashes` snapshots paired with the two alternating `state.*` superblocks, and
`wal-*.log` segments. The small chain index is rewritten to its inactive generation
before the matching superblock is published, so a reorg cannot expose a mixed chain
view after a crash. Do not copy the directory as a shared checkpoint while unapplied
WAL exists; use the preserved format-3 checkpoint until an explicit online export
command is added.

## Build a proof store

Start from the validated proving-forest checkpoint that will be distributed as the
AssumeUtreexo base. The `--online-state` path in this first invocation must not already
exist; an existing online directory takes precedence over `--checkpoint` and would make
the new proof store start at the online tip instead.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/checkpoint-disk/assumeutreexo-mainnet.chk \
  --proof-store=/nvme/utreexo-proofs \
  --online-state=/nvme/utreexo-online-new \
  --follow \
  --p2p-port=8338 \
  --p2p-bind=127.0.0.1 \
  --log-level=debug
```

The checkpoint height and hash become the immutable proof-store base. Proofs cover
`base + 1` through the durable proof tip. This is the recommended, quick bootstrap
mode for serving clients that start from the same AssumeUtreexo state.

For a full historical archive, start with no existing bootstrap checkpoint,
online-state, or proof-store data. A recovery checkpoint path is useful as the
emergency output for SIGTERM or the RAM guard and is automatically considered local
state on later reloads:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --recovery-checkpoint=/nvme/utreexo-genesis-recovery.chk \
  --proof-store=/nvme/utreexo-proofs-from-genesis \
  --online-state=/nvme/utreexo-online-from-genesis \
  --fast-sync \
  --follow \
  --p2p-port=8338 \
  --log-level=debug
```

This path generates block proofs from height 1 and stores the empty post-genesis state
at height 0 plus every subsequent post-block state. It is the only mode eligible for
historical archive signaling. It performs a full RAM rebuild before the one-time mmap
switch, so use the same 32 GiB-class host precautions as `--fast-sync`; the completed
mainnet acceptance evidence is summarized in `MAINNET_SYNC_READINESS.md`. The default
2 GiB availability reserve stops before the next block and streams an atomic recovery
checkpoint to that path. Exit status 2 deliberately prevents an automatic restart in
the supplied systemd unit, avoiding a low-memory checkpoint/restart loop. Hard power
loss still restarts forest reconstruction from the last completed checkpoint (or
genesis), while already committed proof batches are reused and verified. Add a
deliberately large `--checkpoint-interval` only when that extra restart protection
justifies each full-forest rewrite.

During bulk replay, one sequential forest
thread performs `prove -> verify -> modify`; two workers serialize completed proofs;
one writer publishes them in height order. The default queue is bounded by both 1,008
blocks and 256 MiB. During RAM bootstrap, a batch contains up to 32 proofs; with the
default zero group delay, the writer waits for a full batch unless queue backpressure,
a checkpoint, or shutdown requests an earlier flush. This reduces proof-store syncs by
about 32 times for a long uninterrupted replay. Set a nonzero group delay to enable
timed partial batches. Change these limits with `--proof-store-threads`,
`--proof-store-queue-blocks`, `--proof-store-queue-mib`,
`--proof-store-group-blocks`, and `--proof-store-group-delay-ms`.

The regular queue ceiling does not reject an otherwise valid unusually large block:
one proof may enter an empty queue by itself, up to the 320 MiB record limit. This
preserves forward progress while keeping normal pipelining bounded, but an adversarial
consensus-valid block can temporarily use more than the nominal 256 MiB queue budget.
The record limit includes headroom for the maximum input count, 10,000-byte spent
scripts supplied by Core's undo data, and the batch-proof hashes. Keep the 2 GiB memory
reserve enabled during the full-RAM archival build.

The directory has four files:

- `FORMAT` is the durable ownership marker. It is synchronized before any mutable
  store file is first created, and must remain a regular file with a single link and
  the exact supported marker value.
- `proofs.dat` is append-only proof/state data. Each record includes its height,
  block/previous hashes, post-block leaf count and ordered roots, an independently
  authenticated state prefix, a full-record SHA-256 checksum, and a commit marker.
- `index.wal` is the small authoritative active-chain index. A batch is appended and
  synchronized only after all referenced proof data has been synchronized.
- `height.index` is an 80-byte-per-proof mmap lookup table. It is rebuilt from the WAL
  on every open and is not synchronized per block; losing or corrupting it does not
  lose proofs.

A markerless nonempty directory is adopted only as a legacy proof store after a
read-only scan validates every committed WAL record and referenced data record and
confirms there is no uncommitted tail. Partial stores, unrelated entries, and
same-name files that do not form a complete archive are rejected unchanged. Once
adopted, `FORMAT` is synchronized before recovery or index rebuilding can mutate any
file.

The pipeline drains before a sparse checkpoint is published and before the forest
switches to online mmap/WAL storage. During mmap catch-up, proof commits remain batched
but the non-durable distance is never allowed to exceed the forest's retained undo
window. Live tip following makes each proof durable before publishing that height to
the P2P cache. After a crash, startup rolls an mmap forest back to the durable proof
tip when necessary and replays the bounded suffix. If the archive is ahead of an older
online forest, Core's active-chain hashes are checked first: an active archive is kept
for proof reuse, while only a stale branch suffix is truncated. Existing durable
proofs are hash-checked, their compact leaves are compared with Core-derived leaves,
and their proofs are verified against the pre-mutation forest before reuse on restart.
A logically invalid record is truncated and regenerated. Shallow reorgs append one
proof-index truncation record and overwrite only mmap index entries; old payload bytes
are not rewritten or immediately reclaimed.

`--proof-store-scrub` rereads, bounds, parses, and checksum-verifies every active record
before serving. It is an on-disk integrity check, not an independent Bitcoin-consensus
validation of an archive supplied by an untrusted party. The normal construction and
replay path obtains blocks from Core, verifies generated/reused proofs against the
forest, and checks archived post-block states against the reconstructed state.

For distribution, copy the proof directory only while the sidecar is stopped or from
one filesystem-level snapshot; copying `proofs.dat` and `index.wal` at unrelated live
instants is not a coherent archive. Ship the matching format-3 checkpoint and record
the base/tip hashes plus file digests in the release manifest. The mmap index need not
be distributed because it is reconstructed from `index.wal`.

## Serve proofs to Floresta

P2P service is deliberately available only in durable follow mode. It never advertises
`NODE_NETWORK` or serves headers/blocks: Floresta downloads ordinary chain data from
another Bitcoin peer and uses this sidecar for `getuproof`. Checkpoint-to-tip stores
advertise only the new-proof compatibility service. A canonical genesis-to-tip store
also advertises historical archive service and answers Floresta's type-1 `getcfilters`
state requests.

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --online-state=/nvme/utreexo-online \
  --proof-store=/nvme/utreexo-proofs \
  --follow \
  --p2p-port=8338 \
  --p2p-bind=127.0.0.1 \
  --p2p-network=mainnet
```

The default RAM cache retains at most 288 proofs and 256 MiB. Both limits apply, and
can be changed with `--p2p-proof-cache-blocks` and `--p2p-proof-cache-mib`. The cache is
disposable: restart begins empty, while reorganization rollback immediately removes
entries above the recovered active-chain height. A single proof larger than this RAM
budget is intentionally not cached and increments `proof_cache_oversized_skips`; it
does not stop the sidecar. With `--proof-store`, that cache miss is served from the
durable checkpoint-to-tip index. Without it, proofs are captured only for blocks
arriving after this process starts, and an oversized uncached proof is unavailable. A
request that races the sidecar's Core poll waits up to 15 seconds for publication,
avoiding Floresta's longer retry.

The listener also limits total peers, peers per IPv4 address, concurrent archive work,
proof-response bandwidth, and each peer's inbound traffic to a whole-message 4 MiB/s
window by default. One absolute deadline covers each inbound message and each complete
outbound response or gossip handshake, so byte dribbling cannot extend a connection's
resource hold indefinitely. A cache miss waits for tip publication without holding a
proof-work slot or egress reservation, and shutdown cancels those waits. After a proof
is found, its response size is measured against the payload limit and that exact wire
size is reserved before the response vector is created. Reservations are charged
conservatively on later serialization or send failure, avoiding concurrent refunds
that could exceed the configured burst. The framed header and payload are sent without
building a second full response copy. The corresponding `--p2p-*` options are listed
by `utreexo-bridge --help`; lower them before exposing a resource-constrained host.

For a directly reachable public listener, forward/open the chosen TCP port, bind all
interfaces, provide the numeric globally routable IPv4 endpoint that clients should
dial, and name one or more Utreexo-aware peers to relay that address:

```sh
./build/utreexo-bridge \
  --rpc-cookie=/path/to/bitcoin/.cookie \
  --online-state=/nvme/utreexo-online \
  --proof-store=/nvme/utreexo-proofs \
  --follow \
  --p2p-port=8338 \
  --p2p-bind=0.0.0.0 \
  --p2p-advertise=YOUR_PUBLIC_IPV4:8338 \
  --p2p-gossip-seed=UTREEXO_AWARE_IPV4:PORT \
  --p2p-network=mainnet
```

`--p2p-gossip-seed` is repeatable. At startup and every five minutes by default, the
sidecar performs a bounded v1 handshake, verifies the peer advertises a Utreexo
service bit, and sends its advertised endpoint with the same Utreexo service bits
offered by its listener. It also returns that endpoint to
inbound `getaddr` requests using `addr` or `addrv2`. This is best-effort Bitcoin
address relay, not automatic external-IP detection or a DNS seed: verify the public
NAT/firewall path independently and use more than one trusted seed for redundancy.
Ordinary Bitcoin Core peers discard Utreexo-only address records, so they are not
valid gossip seeds and the successful-send log does not claim downstream relay.
The clearnet gossip implementation accepts numeric IPv4 endpoints only; use the Tor
deployment below for onion reachability.

The first implementation supports the Bitcoin v1 transport. Current Floresta must be
configured with `--allow-v1-fallback`. Floresta v0.9.1 requires its initial sync peer to
provide headers and blocks as well as Utreexo archive service, which this proof-only
sidecar intentionally does not claim. Until Floresta separates those peer roles during
initial selection, first activate it through a normal/reference peer and then add Core
and the sidecar with Floresta's `addnode` RPC. The integration test exercises exactly
that staged arrangement. Header forwarding is intentionally deferred to Floresta-side
peer-role work.

```sh
florestad \
  --connect=REFERENCE_PEER:8333 \
  --allow-v1-fallback
```

After `getblockchaininfo` reports that Floresta is active, call `addnode` for the Core
block peer and the sidecar proof peer, then remove the temporary reference peer. See
`test/integration/floresta_regtest.py` for the current JSON-RPC sequence.

The draft service bit used for Floresta interoperability also describes unconfirmed
transaction-proof relay, which is not implemented here; this beta serves block proofs
only. The type-1 `getcfilters` state exchange is a current-Floresta compatibility
protocol rather than BIP157 compact-filter service. Floresta v0.9.1's transport also
rejects messages over 5,000,000 bytes. Ordinary mainnet proofs fit below that client
limit, but a deliberately adversarial valid block could require a larger proof; the
archive and sidecar retain a 320 MiB safety bound for such blocks, while support in
that Floresta release remains an upstream limitation.

To share both peers without exposing either listener on a clearnet interface, publish
separate Tor onion services for Core and the sidecar. Keep the sidecar on
`--p2p-bind=127.0.0.1`; Tor forwards the public onion port to that loopback listener.
The complete mainnet configuration, client example, and verification checklist are in
[`doc/tor.md`](doc/tor.md).

Keep the listener on loopback while testing; binding `0.0.0.0` is an explicit operator
choice. BIP 324 transport, transaction relay, standard block service, and proofs at or
before an AssumeUtreexo base remain out of scope.

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
- `debug` adds forest arena/index capacity and tombstones; 1,000-block timing windows
  split into prefetch wait, RPC, parse, archive policy, prove, verify, modify, proof
  enqueue, and durability wait; proof queue/backpressure/batch/write/fsync statistics;
  mmap-forest WAL serialization/rotation/write/fsync timing and segment-directory
  sync count; checkpoint timing; and
  process RSS/HWM, CPU, faults, context switches, and I/O.
- `trace` adds the same phase timings for every processed block plus every successful
  RPC call. It is useful for short investigations but produces substantial output
  during a full sync.

The `process_resources` fields are cumulative so adjacent debug samples can be
subtracted to obtain interval CPU, fault, and I/O rates. Linux additionally reports
current anonymous/file RSS and `/proc/self/io`; availability flags distinguish zeros
from unsupported counters on other platforms.

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
The opt-in fast-sync profile requires at least 32 GiB of system RAM, processes one
verbosity-3 block at a time, and checkpoints only sparsely. Default checkpoint catch-up
maps the 48-byte native arena without populating or locking it, so the operating system
can evict cold forest pages. Its explicit RAM cost is primarily the keyless reverse
index, free-node bookkeeping, and the bounded delta cache; the mapped virtual size is
not equivalent to resident memory.

Before attempting mainnet, follow the staged resource, Core preflight, recovery, and
checkpoint guidance in [MAINNET_SYNC_READINESS.md](MAINNET_SYNC_READINESS.md).

## Test strategy

The deterministic suites include every insertion, deletion, and proof case from
Rustreexo 0.6.0's shared `test_cases.json` corpus; Floresta compact-script recovery
cases; SHA and Bitcoin leaf vectors; the complete BIP30 quartet; genesis handling;
Core's exact unspendable-script boundaries; exact amount parsing; txid/wtxid and
maximum-vout handling; same-block spends; missing-undo rejection; proof-leaf order;
free-slot reuse; mutation prevalidation; duplicate-leaf checkpoint round trips;
sequential sync; reorg detection; randomized RAM-versus-mmap differential
sequences; WAL crash/corruption recovery; alternating-superblock recovery;
multi-block undo/redo; WAL rotation/retention boundaries; ordered proof-pipeline
publication; proof-WAL torn-tail and corruption recovery; mmap-index rebuild;
proof-store v1-to-v2 migration, authenticated bounded state reads, proof-store
reorgs; per-IP/concurrency/egress admission; and real-socket P2P archive fallback.
The accumulator
tests run without RPC or Bitcoin Core. See
[test/UPSTREAM_TESTS.md](test/UPSTREAM_TESTS.md) for the exact upstream pins,
case mapping, utreexod durability-test review, and intentionally inapplicable
Rustreexo API suites.

### Floresta differential regtest

The opt-in integration harness creates an exceptional-output regtest chain in
Bitcoin Core, independently reconstructs it with this sidecar and
`rpc-utreexo-bridge`, switches and reopens the C++ mmap/WAL state, and compares all
three accumulators. It also creates a compact checkpoint below the tip, streams it
into a fresh mmap forest, builds only the checkpoint-to-tip proof suffix, and verifies
that both stores survive a scrubbed reopen. It then constructs a C++ Genesis
proof/state archive,
activates current Floresta through the reference peer, stages Core as the block peer
and the C++ sidecar as the proof peer, stops the reference peer, and mines a
transaction-bearing block. Floresta must validate that block using the sidecar's
actual `uproof`, and graceful sidecar shutdown must persist the same final state.

The external binaries are deliberately pinned to:

- `rpc-utreexo-bridge` commit
  `9582853345839d625e80ef46b1a23b6dd0fef6c6`.
- Floresta v0.9.1 commit
  `bc2db8d07e72651f9981ce589c5688f4d575dc7a`.

The harness requires Floresta v0.9.1 or newer and checks the version up front.

```sh
cmake -S . -B build-integration \
  -DUTREEXO_ENABLE_REGTEST_INTEGRATION=ON \
  -DUTREEXO_REFERENCE_BRIDGE_EXECUTABLE=/path/to/rpc-utreexo-bridge \
  -DFLORESTAD_EXECUTABLE=/path/to/floresta-v0.9.1/florestad
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
  Bitcoin Core RPC JSON parsing plus P2P envelopes and proof requests.
- Valgrind leak and memory-error checks for both deterministic test executables.
- ShellCheck, Python bytecode compilation, and whitespace validation.
- The pinned Bitcoin Core/reference bridge/Floresta differential regtest described
  above.
- A current-Floresta Rust fixture that decodes the exact sidecar proof and historical
  state messages into Floresta's own wire and accumulator types.

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
cmake --build build-fuzz -j2 --target \
  utreexo_fuzz_forest utreexo_fuzz_rpc_json utreexo_fuzz_p2p
./build-fuzz/utreexo_fuzz_forest -runs=10000 -max_len=65536
./build-fuzz/utreexo_fuzz_rpc_json -runs=10000 -max_len=65536
./build-fuzz/utreexo_fuzz_p2p -runs=10000 -max_len=131072
```

Sanitizers supported by the CMake option are `address`, `undefined`, `thread`,
and `leak`. AddressSanitizer and ThreadSanitizer are intentionally rejected when
requested together because the runtimes are incompatible.
