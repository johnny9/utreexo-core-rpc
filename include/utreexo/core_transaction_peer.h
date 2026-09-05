// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_CORE_TRANSACTION_PEER_H
#define UTREEXO_CORE_TRANSACTION_PEER_H

#include <utreexo/p2p.h>
#include <utreexo/transaction_wire.h>

namespace utreexo {

struct CoreTransactionPeerConfig {
    BitcoinNetwork network{BitcoinNetwork::MAINNET};
    P2PIPv4Endpoint endpoint{"127.0.0.1", 8333};
    uint32_t max_queued{256};
    uint64_t max_queue_bytes{32ULL * 1024 * 1024};
    uint32_t max_inflight{64};
    uint32_t connect_timeout_seconds{5};
    uint32_t reconnect_seconds{2};
};

struct CoreTransactionPeerStats {
    uint64_t connections{0};
    uint64_t received{0};
    uint64_t dropped{0};
    uint64_t queued{0};
    uint64_t queue_bytes{0};
    bool connected{false};
};

/** Outbound, transaction-only Bitcoin v1 connection to the operator's Core.
 * No transaction policy, block/header requests, or accumulator access. */
class CoreTransactionPeer
{
public:
    static Result<std::unique_ptr<CoreTransactionPeer>> Start(CoreTransactionPeerConfig config);
    ~CoreTransactionPeer();
    CoreTransactionPeer(const CoreTransactionPeer&) = delete;
    CoreTransactionPeer& operator=(const CoreTransactionPeer&) = delete;
    std::vector<txwire::Transaction> Take(uint32_t limit);
    /** Wake promptly on transaction or block inventory, bounded by timeout. */
    void Wait(std::chrono::milliseconds timeout);
    CoreTransactionPeerStats Stats();

private:
    class Impl;
    explicit CoreTransactionPeer(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

} // namespace utreexo
#endif // UTREEXO_CORE_TRANSACTION_PEER_H
