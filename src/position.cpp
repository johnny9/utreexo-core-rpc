// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/position.h>

#include <bit>
#include <set>
#include <unordered_set>

namespace utreexo::position {

uint8_t TreeRows(uint64_t leaves)
{
    if (leaves == 0) return 0;
    return static_cast<uint8_t>(
        64U - static_cast<unsigned int>(std::countl_zero(leaves - 1)));
}

uint8_t DetectRow(uint64_t pos, uint8_t forest_rows)
{
    uint64_t marker{uint64_t{1} << forest_rows};
    uint8_t row{0};
    while ((pos & marker) != 0) {
        marker >>= 1;
        ++row;
    }
    return row;
}

uint64_t LeftChild(uint64_t pos, uint8_t forest_rows)
{
    const uint64_t mask{(uint64_t{2} << forest_rows) - 1};
    return (pos << 1) & mask;
}

uint64_t RightChild(uint64_t pos, uint8_t forest_rows) { return LeftChild(pos, forest_rows) + 1; }
uint64_t Parent(uint64_t pos, uint8_t forest_rows) { return (pos >> 1) | (uint64_t{1} << forest_rows); }

uint64_t RootPosition(uint64_t leaves, uint8_t row, uint8_t forest_rows)
{
    const uint64_t mask{(uint64_t{2} << forest_rows) - 1};
    const uint64_t before{leaves & (mask << (row + 1))};
    const uint64_t shifted{(before >> row) | (mask << (forest_rows + 1 - row))};
    return shifted & mask;
}

bool IsRootPosition(uint64_t pos, uint64_t leaves, uint8_t forest_rows)
{
    const uint8_t row{DetectRow(pos, forest_rows)};
    return ((leaves & (uint64_t{1} << row)) != 0) && RootPosition(leaves, row, forest_rows) == pos;
}

Offset DetectOffset(uint64_t pos, uint64_t leaves)
{
    uint8_t tree_rows{TreeRows(leaves)};
    const uint8_t node_row{DetectRow(pos, tree_rows)};
    uint8_t bigger_trees{0};
    uint64_t marker{pos};

    // Invalid positions must not drive the unsigned row counter below zero.
    // Valid forest positions naturally stop before tree_rows reaches node_row.
    if (node_row > tree_rows) return Offset{0, 0, ~marker};
    while (tree_rows > node_row &&
           ((marker << node_row) & ((uint64_t{2} << tree_rows) - 1)) >=
           ((uint64_t{1} << tree_rows) & leaves)) {
        const uint64_t tree_size{(uint64_t{1} << tree_rows) & leaves};
        if (tree_size != 0) {
            marker -= tree_size;
            ++bigger_trees;
        }
        --tree_rows;
    }
    return Offset{bigger_trees, static_cast<uint8_t>(tree_rows - node_row), ~marker};
}

std::vector<uint64_t> ProofPositions(const std::vector<uint64_t>& targets,
                                     uint64_t leaves, uint8_t forest_rows)
{
    std::set<uint64_t> proof_positions;
    std::unordered_set<uint64_t> known;
    std::vector<uint64_t> computed{targets};
    known.insert(targets.begin(), targets.end());

    for (std::size_t i{0}; i < computed.size(); ++i) {
        const uint64_t pos{computed[i]};
        if (IsRootPosition(pos, leaves, forest_rows)) continue;
        const uint64_t sibling{pos ^ 1};
        if (!known.contains(sibling)) proof_positions.insert(sibling);
        else proof_positions.erase(pos);

        const uint64_t parent{Parent(pos, forest_rows)};
        if (known.insert(parent).second) computed.push_back(parent);
    }
    return {proof_positions.begin(), proof_positions.end()};
}

} // namespace utreexo::position
