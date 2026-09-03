# Upstream test provenance

The bridge compatibility tests are pinned to concrete upstream behavior so a
future dependency update cannot silently redefine the accumulator or wire
format being tested.

## Rustreexo

The vectors in `rustreexo_vector_tests.cpp` come from Rustreexo 0.6.0 commit
`8bb8b26f4b67c4f998f265b09bc92afa026266c0`, specifically
`test_values/test_cases.json`.

| Upstream group | C++ coverage |
| --- | --- |
| Four insertion cases, including the 199-leaf random case | `rustreexo_all_insertion_vectors` |
| Fourteen deletion cases | `rustreexo_all_deletion_vectors` |
| Thirteen proof cases, including an invalid proof | `rustreexo_all_proof_verification_vectors` |

Every case in that shared root/deletion/proof corpus is present. Rustreexo's
`cached_proof_tests.json` and `update_data_tests.json` exercise cached-proof and
client-side stump-update APIs that this full proving forest does not expose.
Those suites become applicable if either API is added.

The random insertion case contains repeated leaf hashes. Its inclusion found a
real incompatibility in the original reverse index, which is why duplicate
leaves and their checkpoint round trip have dedicated regression coverage.

## Floresta

Leaf reconstruction behavior was ported from Floresta commit
`81eaf6a39773a10307c8555d06460b227739682e` in
`crates/floresta-chain/src/pruned_utreexo/udata.rs`:

| Floresta behavior | C++ coverage |
| --- | --- |
| `test_spk_recovery` | `floresta_compact_script_recovery_vectors` |
| `test_invalid_spk_recovery` | `floresta_compact_script_recovery_rejects_bad_inputs` |
| compact script classification | `floresta_compact_script_classification` |
| reject a proof leaf created at genesis | `verbose_block_rejects_genesis_proof_leaf_before_hash_lookup` |
| exclude unspendable and same-block-spent additions | `verbose_block_matches_core_unspendable_boundaries_and_sparse_vouts` and `verbose_block_cancels_same_block_spends` |

Additional Bitcoin-specific regressions cover the complete BIP30 quartet,
genesis coinbases on every network, exact `MAX_MONEY` parsing, txid versus
wtxid, maximum `vout`, mixed prior-block and same-block inputs, empty scripts,
the 10,000/10,001-byte script boundary, and OP_RETURN only when it is the first
opcode.

The v1 proof-peer format is pinned to the same Floresta commit's
`crates/floresta-wire/src/p2p_wire/block_proof.rs` and utreexod commit
`25deba281b612f8b87f734b0ac169d8a46ede988` in `wire/msggetutreexoproof.go` and
`wire/msgutreexoproof.go`. `p2p_tests.cpp` checks Bitcoin envelope checksums,
network separation, strict request decoding, full and selective proof responses,
bounded/reorg-aware caching, fragmented socket delivery, the `NODE_UTREEXO` service
bit, version/verack, sendaddrv2/getaddr, ping/pong, and a complete Floresta-shaped
`getuproof` exchange. `sync_tests.cpp` separately proves that the served proof is
captured and verified before its block mutates the forest. The P2P envelope and request
decoders also have a sanitizer-backed libFuzzer target.

## Differential regtest and current wire consumer

`integration/floresta_regtest.py` uses:

- `rpc-utreexo-bridge` commit
  `9582853345839d625e80ef46b1a23b6dd0fef6c6` as the independent forest and
  proof producer.
- Floresta v0.9.1 commit
  `bc2db8d07e72651f9981ce589c5688f4d575dc7a` as the proof-validating consumer.

The current pin is intentional: Floresta v0.9 switched to separate
`getuproof`/`uproof` messages and historical-state exchange. A Rust fixture is
compiled inside that checkout and decodes sidecar vectors with Floresta's own
wire and accumulator types.

The harness mines a 104-block regtest chain containing a SegWit spend, a
same-block parent/child spend, and an OP_RETURN transaction. It requires:

1. The C++ sidecar and reference bridge to report the same tip, leaf count, and
   roots after independent reconstruction from Bitcoin Core.
2. A local checkpoint below the tip to bootstrap a fresh mmap forest and bounded
   suffix proof archive, which must retain identical state across a scrubbed reopen.
3. A second sidecar to construct a canonical-genesis proof/state archive.
4. Floresta to activate through the reference peer, then use Bitcoin Core for
   ordinary blocks and the C++ proof-only sidecar for a newly mined
   transaction-bearing block, reaching the exact Core tip and roots.

The harness also converts the C++ forest to its mmap/WAL representation, mines
one more block, reopens the online state, applies that block through the WAL,
flushes the native base, and repeats the independent root/leaf comparison. The
sidecar is stopped with SIGTERM and must drain its proof WAL and preserve the
same final state. Current Floresta still couples initial archive peer selection
to header/block service, so initial activation is deliberately staged; header
forwarding remains an upstream peer-role concern rather than a sidecar feature.

## Utreexod durability-test review

The mmap/WAL tests were reviewed against utreexod commit
`25deba281b612f8b87f734b0ac169d8a46ede988` and its accumulator dependency,
utreexo v0.18.0 commit `9869ffeefc970ab0aa46a7408589112a8970ddea`.
The relevant upstream patterns are the accumulator's `wal_test.go`,
`forest_test.go`, and `pollard_test.go`, plus utreexod's proof-index and reorg
tests in `blockchain/indexers/indexers_test.go`.

The corresponding C++ online-storage coverage includes:

- a deterministic 120-block RAM-versus-mmap differential sequence with proof
  equality, automatic/explicit flushes, and recovery every ten blocks;
- multi-block disconnect, recovery after each disconnect, and alternate-branch
  replay;
- recovery from the older superblock plus WAL when the newest superblock is
  corrupt;
- rejection of a checksum-corrupt committed record and rollback of an
  incomplete first record;
- real WAL segment rotation, pruning, and fail-closed rollback outside the
  retained undo window; and
- the Core/reference-bridge/Floresta integration transition described above.
