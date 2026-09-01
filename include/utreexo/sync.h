// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_SYNC_H
#define UTREEXO_SYNC_H

#include <utreexo/core_rpc.h>
#include <utreexo/forest.h>
#include <utreexo/result.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace utreexo {

struct BlockProcessingMetrics {
    uint64_t chain_check_us{0};
    uint64_t block_hash_us{0};
    uint64_t block_fetch_us{0};
    uint64_t parse_us{0};
    uint64_t modify_us{0};
    uint64_t total_us{0};
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
    /** Generate and verify deletion proofs against each block's pre-mutation forest. */
    void SetProofGeneration(bool enabled) { m_generate_proofs = enabled; }

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
};

} // namespace utreexo

#endif // UTREEXO_SYNC_H
