// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_FOREST_H
#define UTREEXO_FOREST_H

#include <utreexo/hash.h>
#include <utreexo/result.h>

#include <array>
#include <cstddef>
#include <cstdint>
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
    Result<void> Add(const Hash256& leaf);
    Result<void> Delete(const Hash256& leaf);
    Result<Proof> Prove(std::span<const Hash256> targets) const;

    uint64_t NumLeaves() const;
    bool Contains(const Hash256& leaf) const;
    std::vector<std::optional<Hash256>> Roots() const;
    ForestUsage Usage() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

    friend Result<void> WriteForest(std::ostream&, const PackedForest&);
    friend Result<PackedForest> ReadForest(std::istream&);
};

/** Stable, endian-defined accumulator serialization used inside checkpoints. */
Result<void> WriteForest(std::ostream& output, const PackedForest& forest);
Result<PackedForest> ReadForest(std::istream& input);

} // namespace utreexo

#endif // UTREEXO_FOREST_H
