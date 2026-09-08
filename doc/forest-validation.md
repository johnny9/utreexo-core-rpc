# Bounded saved-forest validation

An online forest without a usable `validated-state.cache` is validated with two
sequential passes through windows of 262,144 node slots. Each pass merges the
immutable base, ordered delta runs and newer recovered WAL overrides. The checks
verify branch hashes, child/parent links, node types and roots while rebuilding
the leaf index and allocator bookkeeping.

Cross-window child hashes are grouped by their parent's window in an anonymous
scratch file on the online-state filesystem. The node/hash window needs about
21 MiB, write buffers use at most 32 MiB, and cursors use about 7 MiB at the maximum
delta-run count. The normal leaf index, allocator bookkeeping, delta lookup
indexes and recovered WAL overlay still scale with the forest. Delta checksums
also use buffered reads instead of making the entire mapping resident.

Scratch data uses 40 bytes per crossing child, plus filesystem block overhead.
Sparse bucket offsets can make the logical file length larger than its allocated
space. Closing the file or exiting reclaims its blocks. A scratch I/O failure
rejects the open without publishing a validated cache. No disk-format or cache
format migration is required.

## Mainnet measurement

The 2026-09-08 measurement used an isolated copy of a saved mainnet forest at
height 943442, with 330,354,736 live nodes and a 1.25 GiB leaf index. Every process
had a 3 GiB cgroup memory limit, including filesystem cache, with swap disabled.
Before each full scan, the derived cache was removed from the copy and only that
copy's pages were evicted using `POSIX_FADV_DONTNEED`.

| Validator | Result | Elapsed | Peak process RSS | Filesystem reads |
|---|---|---:|---:|---:|
| Original, commit `7f0f082` | Timed out before completing | 300 s limit | Sampled at 2.37 GiB | Over 104 GB before timeout |
| Bounded validator | Full validation succeeded | 121.908 s | 1.358 GiB | 42.11 GB |
| Bounded validator, cached reopen | Cache hit, matching state | 11.025 s | 1.467 GiB | 1.39 GB |

The full scan wrote 11.81 GB including scratch data and the new startup cache.
All 20 ordered roots, the block hash and the leaf count matched the original
saved state. These results concern this saved forest; storage speed, node layout,
delta/WAL state and memory available to other processes affect timing.

Run the benchmark on an isolated copy of a stopped online directory:

```sh
./build/utreexo-forest-validation-benchmark /disk/online-state-copy
```

The command may refresh the copy's startup cache. Remove that cache from the copy
before measuring a full scan; run again to measure cached startup. Do not copy a
live directory as a checkpoint.

Validation includes the full CTest suite and AddressSanitizer/UndefinedBehaviorSanitizer
tests. Regression coverage scatters node IDs across windows, preserves free
slots, combines overlapping delta runs with newer WAL changes, rejects hash/link/type
corruption and exercises scratch-write failure followed by a successful reopen.
