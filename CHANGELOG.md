# Changelog

All notable changes to the Utreexo bridge sidecar are documented here. The
project follows Semantic Versioning while the command line, checkpoint, and
proof-store formats remain explicitly versioned.

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
