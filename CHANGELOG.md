# Changelog

All notable changes to the Utreexo bridge sidecar are documented here. The
project follows Semantic Versioning while the command line, checkpoint, and
proof-store formats remain explicitly versioned.

## 0.4.0 - 2026-09-03

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
