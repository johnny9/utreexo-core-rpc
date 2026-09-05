# Core-Backed Transaction Proof Relay for Compact Utreexod

## Objective and scope

Implement the sidecar functionality needed to supply block and transaction
proofs to a compact utreexod validator that maintains a mempool and exposes
`getblocktemplate` and standard `submitblock` for a local mining pool.

Bitcoin Core remains responsible for transaction submission, its mempool
policy, chain selection, and ordinary Bitcoin block/header messaging. Utreexod
independently validates the proofs and transactions it receives.

The sidecar maintains its proof-generating accumulator and a bounded cache of
prepared transaction proofs. It does not implement a mempool, transaction
policy, replacement logic, package selection, or mining RPCs.

Supported deployment:

```text
Wallets --sendrawtransaction--> Bitcoin Core
                                  |
                 +----------------+-------------------+
                 |                |                   |
          Validated tx relay   RPC metadata     Blocks / headers
                 |                |                   |
                 +------> Sidecar |                   |
                             |                        |
                    Transaction / block proofs        |
                             |                        |
                             +-----> Utreexod <-------+
                                         |
                               Proof-aware mempool
                                         |
                                  getblocktemplate
                                         |
                                    Local pool
                                         |
                                     submitblock
                                         |
                               Utreexod validates and
                               relays block to Core
```

### Reviewed baselines

- Sidecar: `/home/codex/workspaces/utreexo/sidecar`, `v0.4.0-beta.3`.
- Bitcoin Core integration target: 31.1.
- Utreexod compatibility target: v0.6.0,
  commit `fe71f3d9282ef0812f7f6087f0c0df9ce0fda508`.
- Shared mainnet AssumeUtreexo checkpoint: height 943,013,
  hash `00000000000000000001c595730bd4a5fb0e2b35af70882962ce7ae602f48aff`.

Production synchronization support begins at this checkpoint. Genesis
synchronization and TTL proof serving remain outside this implementation.
Regtest builds a small chain locally using its existing parameters without TTL
commitments. Compact-mode `sendrawtransaction` proof acquisition is also outside
scope. Wallets submit ordinary transactions to Core.

## Implementation changes

### 2.1 Exact utreexod v0.6 transaction-proof codec

Implement the actual v0.6 wire format, rather than assuming the latest draft BIP
matches it. Support:

- Transaction inventory followed by `MSG_UTREEXO_PROOF_HASH` vectors carrying
  confirmed-input target positions.
- Four little-endian `uint64` positions per inventory hash, with `UINT64_MAX`
  padding.
- Utreexo transaction `getdata` requests, including the applicable witness variant.
- `utreexotx` responses containing the batch proof first, then the transaction,
  then compact leaf data.
- Input-vout encoding where the original index is shifted left and the low bit
  identifies an unconfirmed input.
- Compact leaf data only for confirmed inputs, without adding a leaf-data count.
- Full, partial, and zero-additional-hash proof requests.

Keep announcement target positions distinct from the proof-node positions
requested by the consumer. Preserve confirmed-input target order and return
requested proof hashes in the required request order.

Validate counts, lengths, canonical encodings, padding, requested positions,
and payload limits before performing expensive work.

Parse raw legacy and witness transactions safely. Preserve the original
transaction bytes and identity; rewrite vout flags in a separate serialization
buffer. Never mutate the cached transaction.

## Execution and validation

1. Pin the v0.6 inventory, position, batch-proof, transaction, and compact-leaf
   formats against the reviewed Go source.
2. Implement immutable legacy/witness transaction parsing and separate
   announcement targets from requested proof-node positions.
3. Generate deterministic Go compatibility fixtures and verify byte identity,
   hash order, compact metadata, and full-proof roots in C++.
4. Bound untrusted counts, payloads, canonical encodings, padding, and requests;
   add malformed-input tests and an instrumented fuzz target.
5. Receive Core transactions through a bounded outbound P2P connection, with
   reconnects and bounded RPC inventory recovery.
6. Check Core membership, witness identity, confirmed UTXO metadata, unconfirmed
   parents, and the accumulator tip before publishing verified proofs.
7. Bound the preparation cache by retained bytes, count, and age; invalidate
   before accumulator changes and on RPC/metadata uncertainty.
8. Connect inventory/getdata/utreexotx to the existing listener and its resource
   limits. Preserve announcement identity across expiry and anchor changes.
9. Supply a reproducible v0.6 consumer patch for split block/proof peers and
   compact mining, retaining independent transaction and proof validation.
10. Run isolated Core/sidecar/compact-utreexod integration, negative cases,
    recovery checks, C++/Go suites, static analysis, sanitizers, and fuzzing.

## Implementation status

All ten steps are implemented. The codec lives in
`include/utreexo/transaction_wire.h` and `src/transaction_wire.cpp`. Core intake
and P2P dispatch live in `src/p2p.cpp`; bounded caching and metadata/proof
preparation live in `src/transaction_cache.cpp` and `src/transaction_relay.cpp`.
`SequentialSync` invalidates transaction readers before accumulator mutations.
`--core-tx-peer` enables the relay, with mainnet checkpoint and regtest scope
checks. See the [run guide](core-backed-transaction-proof-relay.md) and
[codec reference](transaction-proof-codec.md).

The reproducible consumer patch is
`contrib/utreexod-v0.6.0-core-relay.patch`, based exactly on
`fe71f3d9282ef0812f7f6087f0c0df9ce0fda508`. An isolated checkout is available in
`/home/codex/workspaces/utreexo/third_party/utreexod-relay`. The patch fixes the
compact template UTXO lookup, attaches verified mempool proofs to ordinary block
submissions, separates block/header and proof peers, and recovers independently
arriving block/proof pairs. The block archive retains its existing native-row
format; the explicit consumer adapter translates block targets to the v0.6 API.
Transaction proofs use the v0.6 wire format directly.

Validation on 2026-09-05:

- 20 deterministic pinned-Go fixtures match the codec, with Go-root verification.
- GCC Debug: six CTest suites; GCC Release without RPC: four suites.
- Clang 21 with ASan, UBSan, and LeakSanitizer: five configured suites.
- Clang-Tidy passes for the changed production code and tests.
- 20,000 seeded libFuzzer executions pass with the codec instrumented.
- Patched Go `netsync`, `mining`, `mempool`, and `wire` suites pass; the patch
  applies cleanly to the pinned upstream tree.
- Full regtest integration passes with both the normal and sanitized sidecar:
  bootstrap legacy transactions, witness transactions, mixed confirmed and
  unconfirmed inputs, corrupted-proof rejection, Core intake reconnect,
  sidecar/validator restart recovery, full/partial/zero-hash requests, invalid
  positions, unavailable proofs, template contents, rejected incomplete block
  submission, standard `submitblock`, and ordinary block relay in both directions.
- The final sanitized run reached height 435 with 441 leaves and identical roots.
  Its logs, template, source-target commit, executable/patch SHA256s, and
  `result.json` are in `build/relay-integration/sanitized-final/`.

CI contains the same Core 31.1/pinned-Go integration and codec fixture/fuzz checks.
The local checks use a workspace temporary directory because the system `/tmp`
quota is small. LeakSanitizer runs outside the tracing sandbox. Validation is
regtest-based; no live mainnet synchronization is claimed. TTL proof serving,
production genesis synchronization, compact-wallet proof acquisition, sidecar
mempool policy, and sidecar mining RPCs remain outside scope.
