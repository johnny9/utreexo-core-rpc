// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_FOREST_H
#define UTREEXO_FOREST_H

#include <utreexo/block_delta.h>
#include <utreexo/hash.h>
#include <utreexo/result.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace utreexo {

using NodeId = uint32_t;
inline constexpr NodeId NO_NODE{UINT32_MAX};

struct Proof {
    std::vector<uint64_t> targets;
    std::vector<Hash256> hashes;
};

/** Verify a Rustreexo-compatible proof against high-row-to-low-row roots. */
Result<bool> VerifyProof(const Proof& proof, std::span<const Hash256> target_hashes,
                         std::span<const Hash256> roots, uint64_t num_leaves);

struct ForestUsage {
    uint64_t live_nodes{0};
    uint64_t allocated_slots{0};
    uint64_t arena_capacity_slots{0};
    uint64_t free_slots{0};
    uint64_t index_entries{0};
    uint64_t index_capacity{0};
    uint64_t index_tombstones{0};
    uint64_t arena_estimated_bytes{0};
    uint64_t index_estimated_bytes{0};
    uint64_t estimated_bytes{0};
};

struct OnlineForestConfig {
    /** Maximum coalesced node-delta memory before a base flush is required. */
    uint64_t max_dirty_bytes{512ULL * 1024 * 1024};
    /** Rotate the append-only WAL after this many bytes. */
    uint64_t wal_segment_bytes{256ULL * 1024 * 1024};
    /** Retain before-images for at least this many connected blocks. */
    uint32_t undo_depth{1'008};
    /** Synchronize every WAL transaction before publishing it. */
    bool sync_wal{true};
};

struct OnlineForestUsage {
    uint64_t base_bytes{0};
    uint64_t dirty_nodes{0};
    uint64_t dirty_bytes{0};
    uint64_t wal_bytes{0};
    uint64_t redo_wal_bytes{0};
    uint64_t base_lsn{0};
    uint64_t current_lsn{0};
    uint64_t last_transaction_nodes{0};
    uint64_t last_transaction_wal_bytes{0};
    uint64_t last_transaction_serialize_us{0};
    uint64_t last_transaction_segment_us{0};
    uint64_t last_transaction_write_us{0};
    uint64_t last_transaction_sync_us{0};
    uint64_t last_transaction_publish_us{0};
    uint64_t last_transaction_total_us{0};
};

class PackedForest
{
public:
    static constexpr uint32_t FORMAT_VERSION{1};

    PackedForest();
    ~PackedForest();
    PackedForest(PackedForest&&) noexcept;
    PackedForest& operator=(PackedForest&&) noexcept;
    PackedForest(const PackedForest&) = delete;
    PackedForest& operator=(const PackedForest&) = delete;

    Result<void> Modify(std::span<const Hash256> additions,
                        std::span<const Hash256> deletions);
    /** Apply and durably publish one block when online storage is enabled. */
    Result<void> ModifyBlock(std::span<const Hash256> additions,
                             std::span<const Hash256> deletions,
                             const ChainPoint& point);
    Result<void> Add(const Hash256& leaf);
    Result<void> Delete(const Hash256& leaf);
    Result<Proof> Prove(std::span<const Hash256> targets) const;

    uint64_t NumLeaves() const;
    bool Contains(const Hash256& leaf) const;
    std::vector<std::optional<Hash256>> Roots() const;
    ForestUsage Usage() const;

    /**
     * Atomically create a native mmap generation and switch this forest from
     * bootstrap RAM storage to WAL-backed online storage.
     */
    Result<void> EnableOnline(const std::filesystem::path& directory,
                              const ChainPoint& point,
                              std::span<const Hash256> chain_hashes,
                              OnlineForestConfig config = {});
    /** Open and recover an existing native online generation. */
    static Result<PackedForest> OpenOnline(const std::filesystem::path& directory,
                                           std::vector<Hash256>& chain_hashes,
                                           ChainPoint& point,
                                           OnlineForestConfig config = {});
    /** Flush coalesced records into the mmap base and advance its superblock. */
    Result<void> FlushOnline();
    /** Durably disconnect the current online tip using its retained WAL before-images. */
    Result<ChainPoint> RollbackOnlineBlock();
    bool IsOnline() const;
    std::optional<ChainPoint> OnlinePoint() const;
    OnlineForestUsage OnlineUsage() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

    friend Result<void> WriteForest(std::ostream&, const PackedForest&);
    friend Result<PackedForest> ReadForest(std::istream&);
    friend Result<PackedForest> ReadForestOnline(std::istream&,
                                                 const std::filesystem::path&,
                                                 const ChainPoint&,
                                                 std::span<const Hash256>,
                                                 OnlineForestConfig);
};

/** Stable, endian-defined accumulator serialization used inside checkpoints. */
Result<void> WriteForest(std::ostream& output, const PackedForest& forest);
Result<PackedForest> ReadForest(std::istream& input);
/**
 * Stream the stable forest serialization directly into a native mmap/WAL
 * generation. This avoids materializing the checkpoint arena in RAM.
 */
Result<PackedForest> ReadForestOnline(std::istream& input,
                                      const std::filesystem::path& directory,
                                      const ChainPoint& point,
                                      std::span<const Hash256> chain_hashes,
                                      OnlineForestConfig config = {});

} // namespace utreexo

#endif // UTREEXO_FOREST_H
