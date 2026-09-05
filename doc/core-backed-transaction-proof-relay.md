# Core-backed transaction proof relay

The sidecar can supply block and transaction proofs to compact utreexod v0.6.0
while Bitcoin Core 31.1 supplies ordinary transactions, blocks, and headers.
Wallets submit transactions to Core. A pool uses utreexod's `getblocktemplate`
and ordinary `submitblock`; utreexod validates and relays the mined block to Core.

## Run the relay

Add these options to a sidecar following Core, with its proof archive enabled:

```sh
utreexo-bridge \
  --rpc-port=8332 --rpc-cookie=/path/to/bitcoin/.cookie \
  --checkpoint=/path/to/mainnet-943013.checkpoint \
  --online-state=/path/to/online --online-wal --follow \
  --proof-store=/path/to/proofs --p2p-network=mainnet --p2p-port=8338 \
  --core-tx-peer=127.0.0.1:8333
```

Use the existing checkpoint/online-state setup appropriate to your installation.
Mainnet relay requires the trusted height-943,013 checkpoint or its online resume;
an untrusted checkpoint override is rejected. Regtest uses `--p2p-network=regtest`
and can start with an empty online state and archive. Both RPC and the transaction
P2P endpoint must refer to the same Core node. The P2P endpoint is numeric IPv4.

Cache limits are `--tx-cache-entries=10000`, `--tx-cache-mib=64`, and
`--tx-cache-seconds=60` by default. Core intake retains at most 256 transactions,
32 MiB, and 64 outstanding requests. A Core RPC inventory scan repairs missed
announcements and removes absent transactions every five seconds, using batches
of at most 64 preparations. Each metadata response is limited to 32 MiB with a
five-second timeout. A full batch yields to chain synchronization before continuing.

The sidecar checks Core membership and witness identity, resolves confirmed
inputs with `gettxout(txid, vout, false)`, anchors every returned UTXO to the
accumulator tip, and confirms unconfirmed parents through Core. Proof generation
and verification run on the sync thread. Cached transactions remain immutable.
There is no local transaction graph, replacement policy, package selection, or
mining RPC server. Removal from this cache does not evict an already validated
transaction from utreexod's independent mempool.

Entries expire by time, count, and retained bytes. Chain mutations and metadata
uncertainty withdraw them. Expired, evicted, unannounced, and otherwise unavailable
transaction requests return `notfound`. Because v0.6 requests carry no tip or
announcement identifier, a peer that received transaction inventory reconnects
after an anchor change before the same txid can be announced at another tip.
The compatibility patch recovers outstanding block-proof requests on reconnect.
The listener's existing concurrency, inbound, egress, peer, and deadline limits
also apply to transaction service. Repeated inventory passes allow a consumer to
recover announcements ignored during initial block download.

## Build the compact consumer

Apply [the compatibility patch](../contrib/utreexod-v0.6.0-core-relay.patch) to
exactly `fe71f3d9282ef0812f7f6087f0c0df9ce0fda508`:

```sh
git clone https://github.com/utreexo/utreexod utreexod-relay
cd utreexod-relay
git checkout --detach fe71f3d9282ef0812f7f6087f0c0df9ce0fda508
git apply /path/to/sidecar/contrib/utreexod-v0.6.0-core-relay.patch
go test -mod=readonly ./netsync ./mining ./mempool ./wire
go build -mod=readonly -o utreexod-relay .
```

Connect that compact node to Core and the sidecar:

```sh
./utreexod-relay \
  --connect=127.0.0.1:8333 --connect=127.0.0.1:8338 \
  --utreexoproofpeer=127.0.0.1:8338
```

Configure utreexod's usual local RPC authentication for the pool. Keep compact
validation enabled; proof indexes select full-UTXO mode and are not part of this
deployment. The patch routes block/header synchronization to ordinary peers,
orders independently arriving block/proof pairs, and constructs mining UTXO views
and submission proofs from verified mempool leaves. A submitted block whose
needed transactions/proofs are unavailable fails closed. It also fixes the
upstream sync-manager double reply on rejected RPC blocks.

The existing sidecar **block archive** uses native `TreeRows(num_leaves)` target
positions. The explicit sidecar peer adapter translates those block targets into
v0.6's fixed 63-row API space. Transaction inventory, requests, and responses use
the exact v0.6 format directly; see the [codec guide](transaction-proof-codec.md).
TTL serving, production genesis synchronization, and compact-wallet
`sendrawtransaction` proof acquisition remain outside this implementation.

## Reproduce the integration test

```sh
python3 test/integration/core_utreexod_relay.py \
  --core=/path/to/bitcoin-31.1/bin/bitcoind \
  --sidecar=build/utreexo-bridge \
  --utreexod=/path/to/utreexod-relay \
  --work-dir=/path/to/fresh-test-directory --timeout=180
```

The harness uses isolated wallets, data directories, and loopback ports. It mines
432 signaling blocks to activate SegWit under utreexod's unchanged regtest
parameters; no TTL commitment or proof index is enabled. It checks bootstrap
recovery, legacy/witness/mixed inputs, independent rejection of a corrupted proof,
Core P2P reconnect/intake, sidecar restart, full/reordered-partial/zero-hash requests,
missing and invalid-position requests, template contents, rejection of an
incomplete submission, standard `submitblock`, and block relay in both directions.
Final accumulator roots and leaf counts must match. Logs, the template, and
`result.json` remain in the test directory. CI runs the same pinned integration;
live mainnet synchronization is not claimed by the regtest results.
