// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_TRANSACTION_CACHE_H
#define UTREEXO_TRANSACTION_CACHE_H

#include <utreexo/transaction_wire.h>

#include <chrono>
#include <atomic>
#include <memory>
#include <optional>

namespace utreexo {

struct TransactionCacheConfig {
    uint32_t max_entries{10'000};
    uint64_t max_bytes{64ULL * 1024 * 1024};
    std::chrono::seconds lifetime{60};
    uint32_t max_regenerations{128};
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
    uint64_t regeneration_queued{0};
    uint64_t regeneration_coalesced{0};
    uint64_t regenerated{0};
    uint64_t regeneration_misses{0};
    uint64_t regeneration_pending{0};
};

/** Fixed-size commitment to the complete preparation and its cache epoch. */
struct TransactionProofIdentity {
    uint64_t epoch;
    Hash256 digest;
    auto operator<=>(const TransactionProofIdentity&) const = default;
};

struct TransactionRegenerationRequest {
    Hash256 txid;
    TransactionProofIdentity identity;
    auto operator<=>(const TransactionRegenerationRequest&) const = default;
};

struct PreparedTransactionEntry {
    ChainPoint point;
    uint64_t sequence;
    txwire::PreparedTransactionProof proof;
    std::chrono::steady_clock::time_point expires;
    uint64_t bytes;
    TransactionProofIdentity identity;
};

struct TransactionAnnouncementEntry {
    uint64_t sequence;
    txwire::TransactionAnnouncement announcement;
    TransactionProofIdentity identity;
};

/** Disposable preparation cache, not a mempool. The sync thread is the sole
 * publisher. Peers retain the announcement's epoch-bound preparation identity
 * so regeneration cannot silently substitute a different proof or chain tip. */
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
    std::shared_ptr<const PreparedTransactionEntry> FindMatching(const TransactionRegenerationRequest& request);
    /** Queue/coalesce a miss and wait within one caller-supplied deadline.
     * Only previously announced identities may be supplied by network callers.
     * At most 128 queued/in-progress jobs; no forest or RPC access here. */
    std::shared_ptr<const PreparedTransactionEntry> WaitFor(
        const TransactionRegenerationRequest& request,
        std::chrono::steady_clock::time_point deadline,
        const std::atomic<bool>* cancelled = nullptr);
    /** The accumulator sync thread alone takes and completes regeneration. */
    std::optional<TransactionRegenerationRequest> TakeRegeneration();
    bool CompleteRegeneration(const TransactionRegenerationRequest& request);
    void NotifyWaiters();
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
