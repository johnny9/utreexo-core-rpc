// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_TRANSACTION_RELAY_H
#define UTREEXO_TRANSACTION_RELAY_H

#include <utreexo/core_rpc.h>
#include <utreexo/sync.h>
#include <utreexo/transaction_cache.h>

namespace utreexo {

struct TransactionRelayConfig {
    uint32_t batch_size{64};
    std::chrono::seconds recovery_interval{5};
};

/** Run only on the accumulator's sync thread. RPC supplies Core's membership
 * and confirmed UTXO metadata; no local transaction policy or dependency pool. */
class TransactionRelay
{
public:
    TransactionRelay(CoreRpcClient client, PackedForest& forest, SequentialSync& sync,
                     std::shared_ptr<TransactionProofCache> cache,
                     TransactionRelayConfig config = {});
    Result<void> Poll(std::vector<txwire::Transaction> incoming = {});

private:
    Result<void> CheckTip(const ChainPoint& point);
    Result<bool> Prepare(txwire::Transaction tx, const ChainPoint& point);
    Result<std::vector<Hash256>> RecoveryCandidates();
    CoreRpcClient m_client;
    PackedForest& m_forest;
    SequentialSync& m_sync;
    std::shared_ptr<TransactionProofCache> m_cache;
    TransactionRelayConfig m_config;
    uint64_t m_scan_cursor{0};
    uint64_t m_epoch{UINT64_MAX};
    std::chrono::steady_clock::time_point m_next_recovery{};
};

} // namespace utreexo
#endif // UTREEXO_TRANSACTION_RELAY_H
