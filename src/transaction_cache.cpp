// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/transaction_cache.h>

#include <map>
#include <mutex>
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <stdexcept>

namespace utreexo {

class TransactionProofCache::Impl
{
public:
    explicit Impl(TransactionCacheConfig settings) : config{settings}
    {
        if (config.max_entries == 0 || config.max_bytes == 0 || config.lifetime.count() <= 0 ||
            config.lifetime > std::chrono::hours(24) || config.max_regenerations == 0 || config.max_regenerations > 128) {
            throw std::invalid_argument{"invalid transaction proof cache bounds"};
        }
    }

    using EntryMap = std::map<uint64_t, std::shared_ptr<const PreparedTransactionEntry>>;
    struct Regeneration {
        TransactionRegenerationRequest request;
        uint32_t waiters{0};
        bool running{false};
        bool done{false};
        std::shared_ptr<const PreparedTransactionEntry> result;
    };

    std::shared_ptr<const PreparedTransactionEntry> Match(const TransactionRegenerationRequest& request)
    {
        Expire();
        if (!stats.ready || stats.epoch != request.identity.epoch) return {};
        const auto found{by_txid.find(request.txid)};
        if (found == by_txid.end()) return {};
        const auto entry{entries.at(found->second)};
        return entry->identity == request.identity ? entry : nullptr;
    }

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
        for (auto& [request, job] : regeneration) { job->done = true; job->result.reset(); }
        regeneration.clear();
        pending.clear();
        changed.notify_all();
    }

    TransactionCacheConfig config;
    std::mutex mutex;
    std::optional<ChainPoint> point;
    uint64_t sequence{0};
    TransactionCacheStats stats;
    EntryMap entries;
    std::map<Hash256, uint64_t> by_txid;
    std::condition_variable changed;
    std::map<TransactionRegenerationRequest, std::shared_ptr<Regeneration>> regeneration;
    std::deque<TransactionRegenerationRequest> pending;
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
    // The digest includes transaction witnesses, all proof hashes/targets and
    // leaf metadata. Rebuilding at the same epoch must reproduce this exact
    // preparation before an old partial or zero-hash request can be answered.
    const auto encoded{proof.Serialize({proof.Tx().Txid(), txwire::MSG_UTREEXO_TX, {}})};
    if (!encoded) return Result<bool>::Err(encoded.Error());
    // Hash the zero-additional-hash payload and the ordered full hash vector
    // separately: a large full proof can exceed the wire limit even when a
    // requested partial proof fits. Hash256 contains exactly its 32 raw bytes.
    static_assert(sizeof(Hash256) == Hash256::SIZE);
    const auto digest{ParentHash(Sha256(encoded.Value()),
        Sha256(std::as_bytes(std::span{proof.WireProof().hashes})))};
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
        std::chrono::steady_clock::now() + m_impl->config.lifetime, bytes,
        TransactionProofIdentity{m_impl->stats.epoch, digest}})};
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

std::shared_ptr<const PreparedTransactionEntry> TransactionProofCache::FindMatching(
    const TransactionRegenerationRequest& request)
{
    std::lock_guard lock{m_impl->mutex};
    return m_impl->Match(request);
}

std::shared_ptr<const PreparedTransactionEntry> TransactionProofCache::WaitFor(
    const TransactionRegenerationRequest& request,
    std::chrono::steady_clock::time_point deadline, const std::atomic<bool>* cancelled)
{
    std::unique_lock lock{m_impl->mutex};
    if (auto entry{m_impl->Match(request)}) return entry;
    if (!m_impl->stats.ready || request.identity.epoch != m_impl->stats.epoch ||
        std::chrono::steady_clock::now() >= deadline || (cancelled && cancelled->load())) return {};
    auto found{m_impl->regeneration.find(request)};
    std::shared_ptr<Impl::Regeneration> job;
    if (found != m_impl->regeneration.end()) {
        job = found->second;
        ++m_impl->stats.regeneration_coalesced;
    } else {
        if (m_impl->regeneration.size() >= m_impl->config.max_regenerations) return {};
        job = std::make_shared<Impl::Regeneration>(Impl::Regeneration{request, 0, false, false, {}});
        m_impl->regeneration.emplace(request, job);
        try {
            m_impl->pending.push_back(request);
        } catch (...) {
            m_impl->regeneration.erase(request);
            throw;
        }
        ++m_impl->stats.regeneration_queued;
    }
    ++job->waiters;
    m_impl->changed.wait_until(lock, deadline, [&] {
        return job->done || (cancelled && cancelled->load()) || request.identity.epoch != m_impl->stats.epoch;
    });
    const auto result{job->done && m_impl->stats.ready && request.identity.epoch == m_impl->stats.epoch &&
        !(cancelled && cancelled->load()) ? job->result : nullptr};
    if (--job->waiters == 0 && (!job->running || job->done)) {
        // An invalidation may already have removed this job.
        const auto current{m_impl->regeneration.find(request)};
        if (current != m_impl->regeneration.end() && current->second == job) {
            m_impl->regeneration.erase(current);
            std::erase(m_impl->pending, request);
        }
    }
    return result;
}

std::optional<TransactionRegenerationRequest> TransactionProofCache::TakeRegeneration()
{
    std::lock_guard lock{m_impl->mutex};
    if (m_impl->pending.empty()) return {};
    const auto request{m_impl->pending.front()};
    m_impl->pending.pop_front();
    m_impl->regeneration.at(request)->running = true;
    return request;
}

bool TransactionProofCache::CompleteRegeneration(const TransactionRegenerationRequest& request)
{
    std::lock_guard lock{m_impl->mutex};
    const auto found{m_impl->regeneration.find(request)};
    if (found == m_impl->regeneration.end()) return false;
    const auto job{found->second};
    if (!job->running || job->done) return false;
    job->result = m_impl->Match(request);
    job->done = true;
    if (job->result) ++m_impl->stats.regenerated;
    else ++m_impl->stats.regeneration_misses;
    if (job->waiters == 0) m_impl->regeneration.erase(found);
    m_impl->changed.notify_all();
    return static_cast<bool>(job->result);
}

void TransactionProofCache::NotifyWaiters()
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->changed.notify_all();
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
        output.push_back({entry->first, entry->second->proof.Announcement(), entry->second->identity});
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
    stats.regeneration_pending = m_impl->regeneration.size();
    return stats;
}

uint32_t TransactionProofCache::MaxEntries() const { return m_impl->config.max_entries; }

} // namespace utreexo
