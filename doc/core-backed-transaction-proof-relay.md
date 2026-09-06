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
  --connect=127.0.0.1:8333 --connect=127.0.0.1:8338
```

Configure utreexod's usual local RPC authentication for the pool. Keep compact
validation enabled; proof indexes select full-UTXO mode and are not part of this
deployment. The patch routes block/header synchronization to ordinary peers,
orders independently arriving block/proof pairs, and constructs mining UTXO views
and submission proofs from verified mempool leaves. A submitted block whose
needed transactions/proofs are unavailable fails closed. It also fixes the
upstream sync-manager double reply on rejected RPC blocks.

The current patch also reuses the assembled template proof on `submitblock` when
the parent and ordered non-coinbase witness transaction IDs match. Header and
coinbase changes are allowed. The proof is copied before normal validation; an
invalid reward or other consensus violation still fails. A changed transaction
body or unavailable template uses the local mempool proof fallback. This cache
optimization follows the beta.2 bundled patch and is available on master and the
updated consumer fork.

The sidecar keeps native `TreeRows(num_leaves)` targets in its **block archive**
and converts them to fixed 63-row positions when sending network proofs. Cached
proofs retain their pre-block leaf count; archive reads use the authenticated
previous block's accumulator state. Conversion preserves target order and never
changes archived or cached targets. No provider-specific flag or adapter is
needed in utreexod.

Standard v0.6 proof providers need only a normal peer connection. The patched
consumer selects multiple providers by their advertised services:

| Services | Proof availability |
| --- | --- |
| `NODE_UTREEXO` | New blocks |
| `NODE_UTREEXO \| NODE_NETWORK` | All historical blocks |
| `NODE_UTREEXO \| NODE_NETWORK_LIMITED` | Latest 288 blocks |
| `NODE_UTREEXO_ARCHIVE` | All historical blocks, without requiring block service |

Blocks and headers come from peers offering `NODE_NETWORK` or
`NODE_NETWORK_LIMITED`. Proof-only peers need neither block-service bits nor
`NODE_WITNESS`. Requests are balanced across eligible connected providers in a
bounded window of 32 block/proof pairs. Disconnects, invalid proofs, and
15-second proof timeouts retry another provider while retaining downloaded
blocks. Historical catch-up waits for a provider covering the requested heights;
`NODE_UTREEXO` alone does not promise historical proofs. The upstream committed-TTL
synchronization path is unchanged.

These consumer changes ship with v0.5.0-beta.2. Use its bundled patch or the
[patched utreexod branch](https://github.com/johnny9/utreexod/tree/core-sidecar-relay-v0.6.0).
Build both the updated sidecar and consumer. The beta.1 sidecar binary sends the
older block-target encoding and is not compatible with this adapter-free consumer.
Existing state-bearing proof archives remain usable without rewriting them;
nonempty proofs require the archived pre-block accumulator state.

Transaction inventory, requests, and responses use
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

Run the multiple-provider integration with the same binaries and a fresh directory:

```sh
python3 test/integration/core_utreexod_proof_peers.py \
  --core=/path/to/bitcoin-31.1/bin/bitcoind \
  --sidecar=build/utreexo-bridge \
  --utreexod=/path/to/utreexod-relay \
  --work-dir=/path/to/fresh-proof-peer-test-directory --timeout=180
```

It runs the sidecar alongside a standard v0.6 utreexod proof generator. Loopback
proxies advertise archive-only and `NODE_UTREEXO`-only services and inject a
timeout, invalid proof, and disconnect. The test requires recovery through the
other provider, no block requests to proof-only peers, transaction proof relay,
standard pool submission, and matching accumulator roots. Only the separate
proof generator enables a proof index; the consumer remains compact. Full mainnet
catch-up, sustained mainnet load, and a combined reorg integration remain unvalidated.

Run the address-discovery integration with the same binaries and another fresh directory:

```sh
python3 test/integration/core_utreexod_discovery.py \
  --core=/path/to/bitcoin-31.1/bin/bitcoind \
  --sidecar=build/utreexo-bridge \
  --utreexod=/path/to/utreexod-relay \
  --work-dir=/path/to/fresh-discovery-test-directory --timeout=180
```

The sidecar announces its endpoint to two local bootstrap fixtures with
`--p2p-advertise` and `--p2p-gossip-seed`. The fixtures learn their only address
from that announcement and return it in response to `getaddr`. Two fresh compact
consumers exercise legacy `addr` and negotiated `addrv2`, each with the other
bootstrap unavailable. The consumers use `--addpeer` for Core and the bootstrap
peers, leaving automatic discovery enabled; no sidecar address is configured.
The test also restarts a consumer with both bootstraps unavailable and requires
it to reconnect using the address saved in `peers.json`.

A local SOCKS5 router maps synthetic public endpoints to loopback so utreexod's
production address manager can enforce routability. It refuses every unmapped
destination and records P2P messages without changing them. Assertions require
block requests and responses from Core, block and transaction proofs from the
discovered sidecar, nonempty inclusion proofs, and compact validation of the chain.
This tests P2P address discovery and persistence; public DNS seed inclusion,
third-party bootstrap relay policies, and public NAT/firewall reachability still
need deployment checks. CI runs all three integrations.
