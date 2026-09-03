// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_TRUSTED_CHECKPOINT_H
#define UTREEXO_TRUSTED_CHECKPOINT_H

#include <utreexo/checkpoint.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>

namespace utreexo {

struct TrustedCheckpoint {
    std::string_view name;
    ChainPoint point;
    uint64_t num_leaves;
    std::span<const Hash256> roots;
    uint64_t file_size;
    Hash256 file_sha256;
};

struct CheckpointFileIdentity {
    uint64_t size;
    Hash256 sha256;
};

/** Return a compiled trust anchor by its stable command-line name. */
const TrustedCheckpoint* FindTrustedCheckpoint(std::string_view name);

/** Return a compiled trust anchor at this height, if one exists. */
const TrustedCheckpoint* FindTrustedCheckpoint(uint32_t height);

/** Compare the consensus-relevant state of a loaded checkpoint with an anchor. */
Result<void> ValidateTrustedCheckpointState(const TrustedCheckpoint& trusted,
                                            const LoadedCheckpoint& loaded);
Result<void> ValidateTrustedCheckpointState(
    const TrustedCheckpoint& trusted, const ChainPoint& point, uint64_t num_leaves,
    std::span<const std::optional<Hash256>> roots);

/** Hash a checkpoint as stored on disk. */
Result<CheckpointFileIdentity> ReadCheckpointFileIdentity(
    const std::filesystem::path& path);

/** Require the exact published byte representation of a trusted checkpoint. */
Result<void> ValidateTrustedCheckpointFile(const TrustedCheckpoint& trusted,
                                           const CheckpointFileIdentity& actual);

} // namespace utreexo

#endif // UTREEXO_TRUSTED_CHECKPOINT_H
