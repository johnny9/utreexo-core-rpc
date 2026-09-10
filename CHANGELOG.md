# Changelog

All notable changes to the Utreexo bridge sidecar are documented here. The
project follows Semantic Versioning while the command line, checkpoint, and
proof-store formats remain explicitly versioned.

## Unreleased

## 0.6.0 - 2026-09-10

### Added

- Export compact AssumeUtreexo snapshots from a running sidecar's state-bearing
  proof archive with `utreexo-export-assumeutreexo`. The bundled utreexod consumer
  accepts a snapshot file with an explicit SHA256 pin and preserves that trusted
  anchor across restarts. Newer snapshots shorten block/proof catch-up; consumers
  still download and verify headers from genesis.
- Regenerate expired or evicted transaction proofs when a peer requests a
  previously announced preparation. Bounded, coalesced jobs recheck Core metadata
  and require the regenerated proof identity to match the original announcement,
  including partial and zero-additional-hash requests.
- Add a saved-forest validation benchmark and regression/integration coverage for
  snapshots, historical restart catch-up, cache regeneration, peer ban policy,
  transaction replacement, and shared input-proof ownership.

### Changed

- Bound full saved-forest validation memory with sequential node windows and
  temporary disk storage for cross-window hashes. A recorded 330-million-node
  mainnet test under a 3 GiB memory limit completed in 121.9 seconds at 1.36 GiB
  peak RSS; v0.5.0 timed out after 300 seconds. Normal cached startup remains
  available. Full validation needs scratch space on the online-state filesystem.
- Improve compact consumer checkpoint recovery and historical proof catch-up.
  Bounded fallback can use a checkpoint-only proof provider for its retained
  suffix. Proof deadlines track transfer progress and exclude local validation
  time; mining waits for the validated tip to reach the greatest-work header.
- Pace transaction announcements to keep legitimate requests below the existing
  inbound limit. If an announced proof cannot be regenerated, reconnect instead
  of sending a burst of `notfound` responses that can trigger a consumer ban.
  Normal consumer ban scoring remains enabled, and disconnect reasons are logged
  at INFO level.

### Fixed

- Reload rotated Bitcoin Core authentication cookies after HTTP 401 and retry
  once when the cookie changed. Preserve ordinary Core RPC error envelopes so a
  transaction leaving the mempool does not withdraw unrelated prepared proofs.
- Retain shared compact input proofs through fee replacement, orphan promotion,
  and sibling removal; release them after their final owner disappears. Preserve
  selected leaf data during concurrent mining-template assembly and replacement.
- Recover compact peers after invalid proofs and verify complete block proofs
  even when their inputs are already remembered by the mempool.
- Isolate Ubuntu CI dependency installation from unrelated vendor package feeds.

### Compatibility and scope

- Targets Bitcoin Core 31.1 and utreexod v0.6.0 commit
  `fe71f3d9282ef0812f7f6087f0c0df9ce0fda508` with the included patch, matching
  [utreexod 5609e4f](https://github.com/johnny9/utreexod/commit/5609e4f72cc8848ffcbb5ca7733efeee1db7c8f3).
  Upgrade both the sidecar and patched consumer to receive all fixes. An unpatched
  upstream utreexod binary cannot load the new snapshot files.
- Checkpoint, forest, proof-store, and validation-cache formats are unchanged;
  existing sidecar state requires no migration or reimport. Snapshot export needs
  Python 3.10 or later and a state-bearing v2 proof archive. A compact snapshot
  initializes a fresh consumer, not a proof-serving sidecar, and explicitly trusts
  the selected accumulator state through its anchor block.
- Production sidecar bootstrap still begins at mainnet height 943,013. A compact
  consumer may use a newer supported snapshot, but its proof provider must retain
  every subsequent block proof. Mainnet catch-up and pool jobs have been observed
  on ARM64, and recent-snapshot bootstrap has been measured on a workstation.
  Sustained mainnet load, public discovery infrastructure, and a combined reorg
  integration remain unvalidated. Production genesis synchronization, TTL serving,
  and compact-wallet `sendrawtransaction` proof acquisition remain outside scope.

## 0.5.0 - 2026-09-06

- Relay Core-validated transactions with proofs to compact utreexod. The sidecar
  maintains a bounded proof-preparation cache while Core handles transaction
  submission and mempool policy. Implement the exact utreexod v0.6 transaction
  codec, including witness transactions and full, partial, and zero-additional-hash
  proof requests.
- Bundle a generic utreexod v0.6 compatibility patch for separate block and proof
  peers, multiple proof providers, and retry after timeout, disconnect, or invalid
  proof. Core can supply blocks and headers while the sidecar supplies proofs.
  Network block targets use standard fixed 63-row positions; stored proof archives
  retain their native encoding.
- Support compact mempool mining through utreexod's `getblocktemplate` and ordinary
  `submitblock`. Reuse the cached template proof when the parent and ordered witness
  transaction IDs match, allowing coinbase and header changes. Cache misses use
  verified mempool data; full consensus validation still runs.
- Add regtest coverage for proof rejection and recovery, independent providers,
  mining, and automatic discovery through `addr` and `addrv2`. Discovery tests cover
  unavailable bootstraps and saved-address recovery using isolated local fixtures.

### Compatibility and scope

- Targets Bitcoin Core 31.1 and utreexod v0.6.0 commit
  `fe71f3d9282ef0812f7f6087f0c0df9ce0fda508` with the included patch, matching
  [utreexod b8a4004](https://github.com/johnny9/utreexod/commit/b8a4004bd3bb6624dd5e3f88940f520b6667db86).
  Upgrade both binaries from beta.1 and remove the retired `utreexoproofpeer` option.
- Production bootstrap begins at the mainnet checkpoint at height 943,013.
  A checkpoint-only sidecar advertises `NODE_UTREEXO`, which the bundled consumer
  uses for new-block proofs. Historical catch-up currently requires an additional
  proof peer advertising coverage for the requested heights; a checkpoint-only
  sidecar cannot be its sole proof source during catch-up.
- Regtest validates the local Core/sidecar/compact-node setup. Mainnet catch-up,
  sustained mainnet load, public discovery infrastructure, and a combined reorg
  integration remain unvalidated. Production genesis synchronization, TTL serving,
  and compact-wallet `sendrawtransaction` proof acquisition remain outside scope.

## 0.5.0-beta.2 - 2026-09-06

- The utreexod v0.6 compatibility patch selects multiple proof providers by
  `NODE_UTREEXO` / `NODE_UTREEXO_ARCHIVE` services and historical availability,
  independently of block peers. Timeouts, invalid proofs, and disconnects retry
  another provider while retaining downloaded blocks.
- Remove the provider-specific option and adapter from utreexod. The sidecar now
  sends fixed 63-row block targets using pre-block state, preserving the native
  proof archive format. Upgrade both binaries together; beta.1 sidecar binaries
  still use the previous network target encoding.
- Bound block-proof decoder allocations, preserve witness transaction requests,
  and add real Core/sidecar/standard-utreexod tests for proof-only providers and
  failover. Consumer documentation now describes generic proof peers.
- Includes the consumer patch matching
  [utreexod 1f1fa85](https://github.com/johnny9/utreexod/commit/1f1fa8541031026842a3ae410d96a1d17035a989).
  Connect the compact validator to Core and proof providers with ordinary
  `connect`/`addpeer` entries; remove `utreexoproofpeer` from its configuration.

## 0.5.0-beta.1 - 2026-09-05

### Added

- Core-backed transaction proof relay for compact utreexod, enabled with
  `--core-tx-peer`. Bitcoin Core 31.1 supplies validated transaction announcements
  and RPC metadata; the sidecar prepares and serves proofs from its accumulator.
- The exact utreexod v0.6.0 transaction wire codec, including legacy and witness
  transactions, confirmed-input target announcements, compact leaf data, and
  full, partial, and zero-additional-hash requests.
- A transaction proof cache bounded by retained bytes, entry count, and lifetime,
  with Core inventory recovery after missed announcements or restarts.
- A compatibility patch for utreexod v0.6.0 commit
  `fe71f3d9282ef0812f7f6087f0c0df9ce0fda508`. It separates Core block/header peers
  from the sidecar proof peer and supports compact `getblocktemplate` and ordinary
  `submitblock` using verified mempool proofs. The patch and run guide are included
  in the release package.
- Pinned Go codec fixtures, malformed-input and resource-bound tests, transaction
  codec fuzzing, and a Core/sidecar/compact-utreexod integration job in CI.

### Changed

- Transaction proofs are invalidated before accumulator mutations and withdrawn
  when Core metadata cannot establish their anchor. Proof peers reconnect after
  anchor changes to disambiguate v0.6 transaction announcements.
- Transaction requests share the listener's existing admission, bandwidth, and
  deadline limits. Raw transaction bytes and identities remain immutable.

### Validation and beta scope

- Regtest integration covers independent rejection of corrupt proofs, legacy and
  witness transactions, mixed confirmed/unconfirmed inputs, reconnect and restart
  recovery, mining templates, standard block submission, and matching final roots.
  C++/Go suites, sanitizers, static analysis, and seeded fuzzing pass locally.
- Mainnet synchronization requires the shared AssumeUtreexo checkpoint at height
  943,013. Live mainnet checkpoint catch-up, sustained transaction load, and full
  Core/sidecar/compact-utreexod reorganization recovery still need validation.
- Wallets submit ordinary transactions to Core. The sidecar does not implement a
  mempool, transaction policy, replacement logic, or mining RPCs. TTL proof serving,
  production genesis synchronization, and compact-wallet proof acquisition are
  outside this relay implementation.
- Checkpoint, forest, and proof-store format versions are unchanged.

## 0.4.0-beta.3 - 2026-09-04

### Changed

- Online restart restores allocator bookkeeping and the RAM-only leaf index from a
  checksummed, base-bound validation cache, then applies only newer delta/WAL records.
  This replaces repeated whole-arena scans on normal startup.
- Missing, stale, truncated, or corrupt validation caches fall back to the complete
  branch/root scan and are regenerated atomically. Existing beta.2 state therefore
  pays the legacy scan once after upgrade; the cache remains disposable derived state.
- Software-release preflight now probes the published checkpoint's first and last
  byte ranges after matching its manifest to the compiled trust anchor. Full 14.9 GB
  transport authentication remains explicit and the binary still verifies it before use.

### Added

- Startup diagnostics report cache bytes, replayed records, validation time, cache-hit
  status, and whether the fallback full scan ran.
- Regression coverage exercises cache reuse, WAL and sealed-delta replay, corruption,
  deletion/recreation, mmap-base identity changes, and hard-link rejection.

## 0.4.0-beta.2 - 2026-09-04

### Changed

- Normal online persistence now seals coalesced node updates into immutable,
  NodeId-sorted delta runs instead of dirtying scattered mmap base pages.
- Minor compaction uses measured obsolete-record or run-count pressure and writes a
  sorted base-relative snapshot. Normal operation never rewrites the mmap base.
- The compact RAM dirty-node overlay now seals only at its configured memory ceiling
  or clean shutdown by default. Timed seals are opt-in.
- The per-block forest recovery/undo WAL is now opt-in with `--online-wal`.
  WAL-free crashes replay Bitcoin Core from the last active-chain delta; a deeper
  reorg requires the retained bootstrap checkpoint.

### Added

- Exact proof-equivalence, delta corruption/gap, incomplete-publication, hard-link,
  immutable-base, WAL reorg, and garbage/run-cap compaction tests.
- Cache-resident blocked Bloom filters avoid disk-backed searches for almost all
  absent node IDs; sparse 64-record fence indexes bound positive searches to one
  small run window.
- `utreexo-online-storage-benchmark` for delta write volume, reopen latency, proof
  lookup performance, base immutability, and RAM-reference proof comparison.

### Security

- Delta runs commit their base identity, generation/LSN link, chain suffix, roots,
  allocator state, sorted node records, checksum, and final marker before publication.
- Seal and compaction diagnostics report logical/file bytes, run garbage, write/sync
  timing, compaction input/output records, and process-attributed write bytes.

## 0.4.0-beta.1 - 2026-09-03

### Added

- A durable, batched proof archive that can start either at the compiled
  AssumeUtreexo checkpoint or at mainnet genesis.
- Historical accumulator-state records for full-genesis Floresta archive
  service, plus offline proof-store integrity verification.
- Graceful signal shutdown, proactive host/cgroup memory protection, and
  exclusive ownership of writable online state.
- Per-address and global resource limits for the public proof listener.
- Explicit public IPv4 advertisement, `getaddr` responses, and bounded periodic
  address gossip through operator-selected Bitcoin peers.
- Install, systemd, checkpoint-manifest, and automated release-package
  support.

### Changed

- Mmap catch-up retains proof batching while bounding the non-durable proof
  window by the forest undo window; live following remains block-durable.
- Direct checkpoint import is published only after its trusted state has been
  validated.
- Oversized individual proofs bypass the disposable RAM cache and may occupy an
  otherwise empty proof queue without weakening the configured record bound.

### Security

- Concurrent writers are rejected before WAL recovery or mutation.
- Proof-store ownership is made durable before mutable files are created; markerless
  legacy stores are adopted only after a complete, non-mutating WAL/data validation.
- Inbound proof work, per-peer traffic, and response bandwidth are bounded
  independently of the connection count, with absolute message/response deadlines.
- Proof cache misses hold no work or worst-case egress admission, while exact response
  sizing avoids an additional full-size framing copy.

## 0.3.0 - 2026-09-03

- Added native mmap/WAL online operation and opt-in RAM-first synchronization.
- Added authenticated mainnet checkpoint loading and durable proof storage.
- Added Floresta-compatible Bitcoin-v1 `getuproof` service and validation CI.
