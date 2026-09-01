// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_SYNC_H
#define UTREEXO_SYNC_H

#include <utreexo/core_rpc.h>
#include <utreexo/forest.h>
#include <utreexo/result.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace utreexo {

struct BlockProcessingMetrics {
    /** Time ProcessNext waited for the prefetched block (or fetched synchronously). */
    uint64_t fetch_wait_us{0};
    uint64_t chain_check_us{0};
    uint64_t block_hash_us{0};
    uint64_t block_fetch_us{0};
    uint64_t parse_us{0};
    uint64_t proof_policy_us{0};
    uint64_t prove_us{0};
    uint64_t verify_us{0};
    uint64_t modify_us{0};
    /** Filled by the bridge executable after ProcessNext returns. */
    uint64_t proof_enqueue_us{0};
    uint64_t proof_durable_wait_us{0};
    /** SequentialSync work through the durable forest mutation. */
    uint64_t total_us{0};
    /** Full caller iteration; initially equal to total_us. */
    uint64_t end_to_end_us{0};
};

struct ProcessedBlock {
    BlockDelta delta;
    BlockProcessingMetrics metrics;
    /** Present only when tip-proof capture was enabled before processing. */
    std::optional<Proof> proof;
};

/** Sequential adapter. It owns no Core internals and can later consume an IPC BlockSource. */
class SequentialSync
{
public:
    SequentialSync(BlockSource& source, PackedForest& forest,
                   std::vector<Hash256> chain_hashes = {});
    ~SequentialSync();

    Result<ProcessedBlock> ProcessNext();
    Result<uint32_t> TipHeight();
    Result<void> StartPrefetch(uint32_t target_height);
    void StopPrefetch();
    Result<void> ValidateCurrentPoint();
    /** Roll back an online forest until its point is on Core's active chain. */
    Result<uint32_t> ReconcileCurrentPoint();
    /** Roll back an online forest to one exact retained chain point. */
    Result<uint32_t> RollbackTo(const ChainPoint& point);
    /** Generate and verify deletion proofs against each block's pre-mutation forest. */
    void SetProofGeneration(bool enabled) { m_generate_proofs = enabled; }
    /** Decide proof capture after parsing a block but before mutating the forest. */
    void SetProofGenerationPolicy(std::function<Result<bool>(const BlockDelta&)> policy)
    {
        m_proof_policy = std::move(policy);
    }

    const std::vector<Hash256>& ChainHashes() const { return m_chain_hashes; }
    std::optional<ChainPoint> CurrentPoint() const;

private:
    struct PrefetchState;
    Result<FetchedBlock> NextFetchedBlock(uint32_t height);

    BlockSource& m_source;
    PackedForest& m_forest;
    std::vector<Hash256> m_chain_hashes;
    std::unique_ptr<PrefetchState> m_prefetch;
    bool m_generate_proofs{false};
    std::function<Result<bool>(const BlockDelta&)> m_proof_policy;
};

} // namespace utreexo

#endif // UTREEXO_SYNC_H
