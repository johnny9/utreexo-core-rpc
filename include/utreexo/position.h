// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_POSITION_H
#define UTREEXO_POSITION_H

#include <cstdint>
#include <vector>

namespace utreexo::position {

uint8_t TreeRows(uint64_t leaves);
uint8_t DetectRow(uint64_t pos, uint8_t forest_rows);
uint64_t LeftChild(uint64_t pos, uint8_t forest_rows);
uint64_t RightChild(uint64_t pos, uint8_t forest_rows);
uint64_t Parent(uint64_t pos, uint8_t forest_rows);
uint64_t RootPosition(uint64_t leaves, uint8_t row, uint8_t forest_rows);
bool IsRootPosition(uint64_t pos, uint64_t leaves, uint8_t forest_rows);

struct Offset {
    uint8_t tree_index;
    uint8_t branch_length;
    uint64_t path_bits;
};

Offset DetectOffset(uint64_t pos, uint64_t leaves);
std::vector<uint64_t> ProofPositions(const std::vector<uint64_t>& targets,
                                     uint64_t leaves, uint8_t forest_rows);

} // namespace utreexo::position

#endif // UTREEXO_POSITION_H
