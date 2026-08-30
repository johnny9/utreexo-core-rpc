// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_BLOCK_DELTA_H
#define UTREEXO_BLOCK_DELTA_H

#include <utreexo/hash.h>
#include <utreexo/leaf.h>

#include <cstdint>
#include <vector>

namespace utreexo {

struct ChainPoint {
    uint32_t height{0};
    Hash256 block_hash;
    auto operator<=>(const ChainPoint&) const = default;
};

/** Accumulator-only block transition. No historical outpoint database is retained. */
struct BlockDelta {
    ChainPoint point;
    Hash256 previous_block_hash;
    std::vector<Hash256> additions;
    std::vector<Hash256> deletions;
    std::vector<CompactLeafData> proof_leaves;
};

} // namespace utreexo

#endif // UTREEXO_BLOCK_DELTA_H
