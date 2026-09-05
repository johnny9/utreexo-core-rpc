// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_TRANSACTION_CACHE_H
#define UTREEXO_TRANSACTION_CACHE_H

#include <utreexo/transaction_wire.h>

#include <chrono>
#include <memory>
#include <optional>

namespace utreexo {

struct TransactionCacheConfig {
    uint32_t max_entries{10'000};
    uint64_t max_bytes{64ULL * 1024 * 1024};
    std::chrono::seconds lifetime{60};
};

struct TransactionCacheStats {
    uint64_t entries{0};
    uint64_t bytes{0};
    uint64_t published{0};
    uint64_t evicted{0};
    uint64_t expired{0};
    uint64_t oversized{0};
    uint64_t invalidations{0};
    uint64_t epoch{0};
    bool ready{false};
};

struct PreparedTransactionEntry {
    ChainPoint point;
    uint64_t sequence;
    txwire::PreparedTransactionProof proof;
    std::chrono::steady_clock::time_point expires;
    uint64_t bytes;
};

struct TransactionAnnouncementEntry {
    uint64_t sequence;
    txwire::TransactionAnnouncement announcement;
};

/** Disposable preparation cache, not a mempool. The sync thread is the sole
 * publisher. Peers read immutable entries, and must retain the announcement's
 * sequence so a request cannot silently switch to a proof at another tip. */
class TransactionProofCache
{
public:
    explicit TransactionProofCache(TransactionCacheConfig config);
    ~TransactionProofCache();
    TransactionProofCache(const TransactionProofCache&) = delete;
    TransactionProofCache& operator=(const TransactionProofCache&) = delete;

    void Invalidate();
    void Activate(const ChainPoint& point);
    Result<bool> Publish(const ChainPoint& point, txwire::PreparedTransactionProof proof);
    void Erase(const Hash256& txid);
    std::shared_ptr<const PreparedTransactionEntry> Find(
        const Hash256& txid, std::optional<uint64_t> sequence = std::nullopt);
    /** Bound the copy by inventory vectors as well as entry count. A single
     * larger announcement is returned alone if it fits the protocol limit. */
    std::vector<TransactionAnnouncementEntry> AnnouncementsAfter(
        uint64_t& cursor, uint32_t max_entries = 64, uint32_t max_vectors = 2048,
        std::optional<uint64_t> expected_epoch = std::nullopt);
    std::vector<Hash256> Txids();
    TransactionCacheStats Stats();
    uint32_t MaxEntries() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace utreexo
#endif // UTREEXO_TRANSACTION_CACHE_H
