// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_PROOF_STORE_H
#define UTREEXO_PROOF_STORE_H

#include <utreexo/block_delta.h>
#include <utreexo/p2p.h>
#include <utreexo/result.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>

namespace utreexo {

struct ProofStoreConfig {
    std::filesystem::path directory;
    /** Used only when creating a new store. Existing stores carry their own base. */
    std::optional<ChainPoint> create_base;
    uint32_t serializer_threads{2};
    uint32_t group_commit_blocks{32};
    /** Zero waits for a full group or an explicit durability/backpressure flush. */
    uint32_t group_commit_delay_ms{0};
    uint32_t max_queued_blocks{1'008};
    uint64_t max_queued_bytes{256ULL * 1024ULL * 1024ULL};
    uint64_t max_record_bytes{64ULL * 1024ULL * 1024ULL};
};

struct ProofStoreStats {
    uint32_t base_height{0};
    uint32_t durable_height{0};
    uint32_t enqueued_height{0};
    uint64_t active_proofs{0};
    uint64_t data_bytes{0};
    uint64_t wal_bytes{0};
    uint64_t index_bytes{0};
    uint64_t queued_blocks{0};
    uint64_t queued_bytes{0};
    uint64_t input_blocks{0};
    uint64_t ready_blocks{0};
    uint64_t peak_queued_blocks{0};
    uint64_t peak_queued_bytes{0};
    uint64_t peak_input_blocks{0};
    uint64_t peak_ready_blocks{0};
    uint64_t enqueue_blocked{0};
    uint64_t backpressure_flushes{0};
    uint64_t durability_waits{0};
    uint64_t serialized_proofs{0};
    uint64_t serialized_bytes{0};
    uint64_t largest_record_bytes{0};
    uint64_t enqueue_wait_us{0};
    uint64_t serialization_us{0};
    uint64_t committed_proofs{0};
    uint64_t committed_batches{0};
    uint64_t full_batches{0};
    uint64_t partial_batches{0};
    uint64_t largest_batch_proofs{0};
    uint64_t commit_us{0};
    uint64_t data_write_us{0};
    uint64_t data_syncs{0};
    uint64_t data_sync_us{0};
    uint64_t wal_write_us{0};
    uint64_t wal_syncs{0};
    uint64_t wal_sync_us{0};
    uint64_t index_publish_us{0};
    uint64_t hits{0};
    uint64_t misses{0};
};

/**
 * Durable checkpoint-to-tip proof archive.
 *
 * Proof payloads are appended once to proofs.dat. A small, checksummed index WAL is
 * authoritative and is synchronized only after the referenced payloads. The mmap
 * height index is rebuilt from that WAL on every open and is never a durability
 * dependency. Serialization is parallel; data and WAL publication remain ordered.
 */
class ProofStore
{
public:
    static constexpr uint32_t FORMAT_VERSION{1};

    static Result<std::shared_ptr<ProofStore>> Open(ProofStoreConfig config);
    ~ProofStore();
    ProofStore(const ProofStore&) = delete;
    ProofStore& operator=(const ProofStore&) = delete;

    /** Queue one proof. Heights and previous hashes must extend EnqueuedPoint(). */
    Result<void> Enqueue(const BlockDelta& delta, Proof proof);
    /** Force a group commit through height and wait for its data and index WAL. */
    Result<void> WaitDurable(uint32_t height);
    /** Commit every queued proof. */
    Result<void> Drain();
    /** Durably move the active proof tip backwards. Old payload bytes remain for later compaction. */
    Result<void> Truncate(const ChainPoint& point);

    /** A successful result containing nullptr is a normal archive miss. */
    Result<std::shared_ptr<const CachedBlockProof>> Read(const Hash256& block_hash) const;
    Result<std::optional<Hash256>> HashAt(uint32_t height) const;

    ChainPoint BasePoint() const;
    ChainPoint DurablePoint() const;
    ChainPoint EnqueuedPoint() const;
    ProofStoreStats Stats() const;

private:
    class Impl;
    explicit ProofStore(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

} // namespace utreexo

#endif // UTREEXO_PROOF_STORE_H
