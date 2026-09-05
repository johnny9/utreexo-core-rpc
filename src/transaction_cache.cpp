// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/transaction_cache.h>

#include <map>
#include <mutex>
#include <stdexcept>

namespace utreexo {

class TransactionProofCache::Impl
{
public:
    explicit Impl(TransactionCacheConfig settings) : config{settings}
    {
        if (config.max_entries == 0 || config.max_bytes == 0 || config.lifetime.count() <= 0 ||
            config.lifetime > std::chrono::hours(24)) {
            throw std::invalid_argument{"invalid transaction proof cache bounds"};
        }
    }

    using EntryMap = std::map<uint64_t, std::shared_ptr<const PreparedTransactionEntry>>;

    void Erase(EntryMap::iterator entry)
    {
        stats.bytes -= entry->second->bytes;
        by_txid.erase(entry->second->proof.Tx().Txid());
        entries.erase(entry);
    }

    void Expire()
    {
        const auto now{std::chrono::steady_clock::now()};
        while (!entries.empty() && entries.begin()->second->expires <= now) {
            Erase(entries.begin());
            ++stats.expired;
        }
    }

    void Clear()
    {
        entries.clear();
        by_txid.clear();
        stats.bytes = 0;
        stats.ready = false;
        ++stats.epoch;
        ++stats.invalidations;
        point.reset();
    }

    TransactionCacheConfig config;
    std::mutex mutex;
    std::optional<ChainPoint> point;
    uint64_t sequence{0};
    TransactionCacheStats stats;
    EntryMap entries;
    std::map<Hash256, uint64_t> by_txid;
};

TransactionProofCache::TransactionProofCache(TransactionCacheConfig config)
    : m_impl{std::make_unique<Impl>(config)} {}
TransactionProofCache::~TransactionProofCache() = default;

void TransactionProofCache::Invalidate()
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->Clear();
}

void TransactionProofCache::Activate(const ChainPoint& point)
{
    std::lock_guard lock{m_impl->mutex};
    if (m_impl->point && *m_impl->point != point) m_impl->Clear();
    m_impl->point = point;
    m_impl->stats.ready = true;
}

Result<bool> TransactionProofCache::Publish(const ChainPoint& point, txwire::PreparedTransactionProof proof)
{
    std::lock_guard lock{m_impl->mutex};
    if (!m_impl->stats.ready || !m_impl->point || *m_impl->point != point) {
        return Result<bool>::Err("transaction cache anchor changed during preparation");
    }
    m_impl->Expire();
    // Include fixed map/shared_ptr overhead conservatively, in addition to all
    // retained vector capacities. In-flight readers are bounded by P2P admission.
    const uint64_t bytes{proof.MemoryUsage() + sizeof(PreparedTransactionEntry) + 256};
    if (bytes > m_impl->config.max_bytes) {
        ++m_impl->stats.oversized;
        return Result<bool>::Ok(false);
    }
    const auto existing{m_impl->by_txid.find(proof.Tx().Txid())};
    if (existing != m_impl->by_txid.end()) m_impl->Erase(m_impl->entries.find(existing->second));
    while (!m_impl->entries.empty() &&
           (m_impl->entries.size() >= m_impl->config.max_entries ||
            bytes > m_impl->config.max_bytes - m_impl->stats.bytes)) {
        m_impl->Erase(m_impl->entries.begin());
        ++m_impl->stats.evicted;
    }
    auto entry{std::make_shared<PreparedTransactionEntry>(PreparedTransactionEntry{
        point, ++m_impl->sequence, std::move(proof),
        std::chrono::steady_clock::now() + m_impl->config.lifetime, bytes})};
    m_impl->entries.emplace(entry->sequence, entry);
    try {
        m_impl->by_txid.emplace(entry->proof.Tx().Txid(), entry->sequence);
    } catch (...) {
        m_impl->entries.erase(entry->sequence);
        throw;
    }
    m_impl->stats.bytes += bytes;
    ++m_impl->stats.published;
    return Result<bool>::Ok(true);
}

void TransactionProofCache::Erase(const Hash256& txid)
{
    std::lock_guard lock{m_impl->mutex};
    const auto entry{m_impl->by_txid.find(txid)};
    if (entry != m_impl->by_txid.end()) m_impl->Erase(m_impl->entries.find(entry->second));
}

std::shared_ptr<const PreparedTransactionEntry> TransactionProofCache::Find(
    const Hash256& txid, std::optional<uint64_t> sequence)
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->Expire();
    if (!m_impl->stats.ready) return {};
    const auto entry{m_impl->by_txid.find(txid)};
    if (entry == m_impl->by_txid.end() || (sequence && entry->second != *sequence)) return {};
    return m_impl->entries.at(entry->second);
}

std::vector<TransactionAnnouncementEntry> TransactionProofCache::AnnouncementsAfter(
    uint64_t& cursor, uint32_t max_entries, uint32_t max_vectors,
    std::optional<uint64_t> expected_epoch)
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->Expire();
    std::vector<TransactionAnnouncementEntry> output;
    if (!m_impl->stats.ready || max_entries == 0 || max_vectors == 0 ||
        (expected_epoch && *expected_epoch != m_impl->stats.epoch)) return output;
    uint64_t vectors{0};
    for (auto entry{m_impl->entries.upper_bound(cursor)}; entry != m_impl->entries.end(); ++entry) {
        const uint64_t count{1 + (entry->second->proof.WireProof().targets.size() + 3) / 4};
        if (count > txwire::MAX_INVENTORY) { cursor = entry->first; continue; }
        if (!output.empty() && (output.size() >= max_entries || vectors + count > max_vectors)) break;
        output.push_back({entry->first, entry->second->proof.Announcement()});
        cursor = entry->first;
        vectors += count;
    }
    return output;
}

std::vector<Hash256> TransactionProofCache::Txids()
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->Expire();
    std::vector<Hash256> txids;
    txids.reserve(m_impl->entries.size());
    for (const auto& [sequence, entry] : m_impl->entries) {
        static_cast<void>(sequence);
        txids.push_back(entry->proof.Tx().Txid());
    }
    return txids;
}

TransactionCacheStats TransactionProofCache::Stats()
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->Expire();
    auto stats{m_impl->stats};
    stats.entries = m_impl->entries.size();
    return stats;
}

uint32_t TransactionProofCache::MaxEntries() const { return m_impl->config.max_entries; }

} // namespace utreexo
