# Utreexod v0.6 transaction-proof codec

`include/utreexo/transaction_wire.h` provides the transport-independent codec in
`utreexo::txwire`. It is built into `utreexo_accumulator`, including builds with
RPC disabled. This implements §2.1 of the
[Core-backed relay plan](core-backed-transaction-proof-relay-plan.md).

The executable connects this codec to a Core transaction feed, RPC input metadata,
a bounded preparation cache, and P2P inventory/getdata dispatch when
`--core-tx-peer` is set. See the [relay guide](core-backed-transaction-proof-relay.md).
The sidecar has no mining RPCs or mempool policy.

## Pinned reference

The reference is utreexod v0.6.0, commit
`fe71f3d9282ef0812f7f6087f0c0df9ce0fda508`, with its `utreexo v0.18.0`
dependency. The relevant sources are:

- [Inventory types](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/wire/invvect.go)
  and [packed positions](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/chaincfg/chainhash/hash.go).
- [Transaction message](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/wire/msgutreexotx.go),
  [batch proof](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/wire/batchproof.go),
  and [compact leaves](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/wire/leaf.go).
- `OnGetData`, `pushUtreexoTxMsg`, and inventory relay in
  [server.go](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/server.go),
  and request construction in
  [netsync/manager.go](https://github.com/utreexo/utreexod/blob/fe71f3d9282ef0812f7f6087f0c0df9ce0fda508/netsync/manager.go).

## Wire behavior

| Payload | Encoding |
| --- | --- |
| Transaction `inv` | CompactSize inventory count; `MSG_TX` (`1`) with txid; immediately following `MSG_UTREEXO_PROOF_HASH` (`6`) vectors pack confirmed-input targets |
| Transaction `getdata` | Same inventory layout, starting with `MSG_UTREEXO_TX` (`0x01000001`) or `MSG_WITNESS_UTREEXO_TX` (`0x41000001`); attached vectors contain requested **proof-node** positions |
| Packed positions | Four little-endian uint64s in each 32-byte hash; unused final slots contain `UINT64_MAX` |
| `utreexotx` | CompactSize target count, CompactSize targets, CompactSize hash count, 32-byte hashes, flagged transaction, confirmed compact leaves |
| Flagged input vout | `(original_vout << 1) \| unconfirmed_bit` |
| Confirmed compact leaf | uint32 LE header code, uint64 LE amount, byte script type; only type 0 adds a CompactSize script length and script bytes |

There is no remember-index field, transaction-length prefix, or leaf-data count
in `utreexotx`. Unconfirmed inputs have no compact-leaf bytes. Target order
matches confirmed input order. Response hashes follow the requested position
order, including when that order differs from the full proof order.

An empty position list requests **zero additional hashes**. A full request
explicitly names every needed proof node; a partial request names a subset.
Both request inventory types receive witness serialization, matching the pinned
server's behavior and preserving the data needed to reconstruct compact leaves.

The v0.18 accumulator's wire/API position space has 63 rows. `PackedForest`
uses `TreeRows(num_leaves)` internally. Preparation translates both targets and
proof-node positions, including leaves promoted above row zero after deletions.
Callers must supply a native full `PackedForest` proof to `Create`; do not pass
an already translated wire proof.

## API and ownership

```cpp
using namespace utreexo::txwire;

auto transaction = Transaction::Parse(core_raw_transaction);
if (!transaction) return; // handle malformed or oversized Core relay data

// Capture these together at one accumulator tip:
// - full_proof from PackedForest::Prove(confirmed_leaf_hashes)
// - one optional CompactLeafData per transaction input (nullopt = unconfirmed)
// - forest.NumLeaves()
auto prepared = PreparedTransactionProof::Create(
    transaction.Take(), std::move(full_proof), std::move(input_leaves), num_leaves);
if (!prepared) return;

const std::array announcements{prepared.Value().Announcement()};
auto inv_payload = SerializeTransactionAnnouncements(announcements);

auto requests = ParseTransactionProofRequests(getdata_payload);
if (!requests) return;
for (const auto& request : requests.Value()) {
    // Look up this request's txid in the caller's bounded cache first.
    auto payload = prepared.Value().Serialize(request, peer_payload_limit);
    // Frame successful payloads as command "utreexotx" with EncodeP2PMessage.
}
```

`Transaction` owns the original bytes, txid, wtxid, outpoints, and checked vout
offsets. Its public accessors expose constant views. Encoding copies the raw
bytes into the response and rewrites vouts there. Repeated requests, partial
requests, and both witness inventory variants leave the preparation unchanged.
`ParseUtreexoTransaction` restores ordinary vouts in a separate buffer and
returns the original transaction identities with the decoded proof and leaves.

The inventory parsers accept batched groups and skip unrelated inventory.
Proof vectors must immediately follow a recognized transaction entry in the
same payload. The request parser recognizes the two Utreexo types; the
announcement parser recognizes `MSG_TX`. Unknown/ordinary getdata entries can
be handled separately by the future peer dispatcher.

## Bounds and validation

Counts, canonical CompactSize encodings, remaining byte lengths, witness flags,
padding, and trailing bytes are checked. Empty/redundant padding vectors,
duplicate positions, misplaced proof vectors, and data after padding are
rejected. Parsers bound allocations by the supplied bytes and protocol limits.
Raw parsing checks the complete structure before allocating transaction storage
or computing txid/wtxid.

Preparation rejects invalid or overlapping native targets, mismatched full-proof
hash counts, inconsistent input/leaf counts, malformed compact leaves, and vouts
above `0x7fffffff`, which cannot survive the v0.6 flag encoding. Requested
positions must be unique members of that transaction's prepared proof-node set.
No arbitrary accumulator lookup is performed for a request.

The inventory limit is 50,000 vectors, including packed-position vectors. Raw
transactions and complete `utreexotx` payloads are limited to 4,000,000 bytes;
compact leaf scripts are limited to 10,000 bytes. A caller can lower payload
limits but cannot raise these protocol ceilings. Exact response size is checked
before allocating its buffer. A large preparation may serve a partial request
even if its full response would exceed the payload limit.

These are structural checks. Core supplies accepted transactions and metadata;
utreexod independently verifies transaction validity and proofs. The codec does
not validate scripts, fees, replacements, packages, or chain freshness. A relay
must invalidate/rebuild prepared proofs when its accumulator tip changes.

## Compatibility fixtures and tests

`test/data/utreexod_tx_vectors.h` contains 20 deterministic fixtures generated by
the pinned Go wire encoder and accumulator. They cover legacy/witness encoding,
all five compact-script types, confirmed/unconfirmed mixtures, promoted targets,
root-only proofs, padding across vector boundaries, full/partial/empty requests,
and both request types. Partial requests use reversed order. The generator also
decodes each response with Go and checks the restored txid and wtxid. C++ tests
compare exact payloads, verify the native full proofs against Go roots, check
repeated serialization, and reject truncated and malformed inputs.

To reproduce the fixtures, with Go 1.25 or newer and the pinned checkout:

```sh
cd /path/to/utreexod
test "$(git rev-parse HEAD)" = fe71f3d9282ef0812f7f6087f0c0df9ce0fda508
go run -mod=readonly /path/to/sidecar/test/integration/utreexod_tx_vectors.go \
  -check /path/to/sidecar/test/data/utreexod_tx_vectors.h
```

Omit `-check` to emit the header to stdout. Ordinary C++ tests need neither Go
nor network access. `utreexo_fuzz_transaction_wire` instruments the codec itself
and exercises raw parsing, inventory grouping, response decoding, and immutable
proof selection. Seed it with the same fixtures:

```sh
python3 test/integration/utreexod_tx_fuzz_seeds.py build/tx-corpus
./build/utreexo_fuzz_transaction_wire build/tx-corpus -runs=10000 -max_len=131072
```
