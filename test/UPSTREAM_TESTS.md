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

## Differential regtest

`integration/floresta_regtest.py` uses:

- `rpc-utreexo-bridge` commit
  `9582853345839d625e80ef46b1a23b6dd0fef6c6` as the independent forest and
  proof producer.
- Floresta v0.8.1 commit
  `aaef08453a89a55fdb42e1541de7a18c151cdbe8` as the proof-validating consumer.

That Floresta pin is intentional. It is the last tagged release using the
legacy proof-bearing block inventory `0x41000002` implemented by the reference
bridge. Floresta v0.9 switched to separate `getuproof`/`uproof` messages and is
not wire-compatible with that bridge.

The harness mines a 104-block regtest chain containing a SegWit spend, a
same-block parent/child spend, and an OP_RETURN transaction. It requires:

1. The C++ sidecar and reference bridge to report the same tip, leaf count, and
   roots after independent reconstruction from Bitcoin Core.
2. Floresta to validate every proof-bearing block, leave IBD, reach the exact
   Core tip, and report the same roots.

