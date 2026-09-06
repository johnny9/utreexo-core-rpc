# Changelog

All notable changes to the Utreexo bridge sidecar are documented here. The
project follows Semantic Versioning while the command line, checkpoint, and
proof-store formats remain explicitly versioned.

## Unreleased

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
