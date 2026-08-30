// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_CHECKPOINT_H
#define UTREEXO_CHECKPOINT_H

#include <utreexo/block_delta.h>
#include <utreexo/forest.h>
#include <utreexo/result.h>

#include <filesystem>
#include <span>
#include <vector>

namespace utreexo {

struct CheckpointMetrics {
    uint64_t payload_bytes{0};
    uint64_t final_bytes{0};
    uint64_t write_us{0};
    uint64_t checksum_us{0};
    uint64_t checksum_append_us{0};
    uint64_t file_sync_us{0};
    uint64_t rename_us{0};
    uint64_t directory_sync_us{0};
    uint64_t deserialize_us{0};
    uint64_t total_us{0};
};

struct LoadedCheckpoint {
    ChainPoint point;
    std::vector<Hash256> chain_hashes;
    PackedForest forest;
};

/** Write one fsync-and-rename checkpoint. Intended for sparse bootstrap milestones. */
Result<void> SaveCheckpoint(const std::filesystem::path& path,
                            const ChainPoint& point, const PackedForest& forest,
                            std::span<const Hash256> chain_hashes = {},
                            CheckpointMetrics* metrics = nullptr);
Result<LoadedCheckpoint> LoadCheckpoint(const std::filesystem::path& path,
                                        CheckpointMetrics* metrics = nullptr);

} // namespace utreexo

#endif // UTREEXO_CHECKPOINT_H
