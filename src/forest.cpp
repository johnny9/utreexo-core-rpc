// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/forest.h>

#include <utreexo/position.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <istream>
#include <limits>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_set>

namespace utreexo {
namespace {

enum class NodeType : uint8_t { FREE = 0, LEAF = 1, BRANCH = 2 };

class NodeArena
{
public:
    static constexpr uint32_t CHUNK_SHIFT{20};
    static constexpr uint32_t CHUNK_SIZE{uint32_t{1} << CHUNK_SHIFT};
    static constexpr uint32_t CHUNK_MASK{CHUNK_SIZE - 1};

    struct Chunk {
        std::unique_ptr<Hash256[]> hashes{std::make_unique<Hash256[]>(CHUNK_SIZE)};
        std::unique_ptr<NodeId[]> parents{std::make_unique<NodeId[]>(CHUNK_SIZE)};
        std::unique_ptr<NodeId[]> left{std::make_unique<NodeId[]>(CHUNK_SIZE)};
        std::unique_ptr<NodeId[]> right{std::make_unique<NodeId[]>(CHUNK_SIZE)};
        std::unique_ptr<NodeType[]> types{std::make_unique<NodeType[]>(CHUNK_SIZE)};

        Chunk()
        {
            std::fill_n(parents.get(), CHUNK_SIZE, NO_NODE);
            std::fill_n(left.get(), CHUNK_SIZE, NO_NODE);
            std::fill_n(right.get(), CHUNK_SIZE, NO_NODE);
            std::fill_n(types.get(), CHUNK_SIZE, NodeType::FREE);
        }
    };

    NodeId Allocate(NodeType type, const Hash256& hash, NodeId left = NO_NODE, NodeId right = NO_NODE)
    {
        NodeId id;
        if (!m_free.empty()) {
            id = m_free.back();
            m_free.pop_back();
        } else {
            if (m_next == NO_NODE) throw std::length_error{"packed forest exhausted 32-bit node IDs"};
            id = m_next++;
            Ensure(id);
        }
        Hash(id) = hash;
        ParentRef(id) = NO_NODE;
        LeftRef(id) = left;
        RightRef(id) = right;
        TypeRef(id) = type;
        ++m_live;
        return id;
    }

    void Free(NodeId id)
    {
        TypeRef(id) = NodeType::FREE;
        ParentRef(id) = LeftRef(id) = RightRef(id) = NO_NODE;
        m_free.push_back(id);
        --m_live;
    }

    bool Live(NodeId id) const { return id < m_next && Type(id) != NodeType::FREE; }
    bool IsLeaf(NodeId id) const { return Live(id) && Type(id) == NodeType::LEAF; }
    const Hash256& Hash(NodeId id) const { return Get(id).hashes[id & CHUNK_MASK]; }
    Hash256& Hash(NodeId id) { return Get(id).hashes[id & CHUNK_MASK]; }
    NodeId Parent(NodeId id) const { return Get(id).parents[id & CHUNK_MASK]; }
    NodeId Left(NodeId id) const { return Get(id).left[id & CHUNK_MASK]; }
    NodeId Right(NodeId id) const { return Get(id).right[id & CHUNK_MASK]; }
    NodeType Type(NodeId id) const { return Get(id).types[id & CHUNK_MASK]; }
    NodeId& ParentRef(NodeId id) { return Get(id).parents[id & CHUNK_MASK]; }
    NodeId& LeftRef(NodeId id) { return Get(id).left[id & CHUNK_MASK]; }
    NodeId& RightRef(NodeId id) { return Get(id).right[id & CHUNK_MASK]; }
    NodeType& TypeRef(NodeId id) { return Get(id).types[id & CHUNK_MASK]; }
    uint64_t Next() const { return m_next; }
    uint64_t LiveCount() const { return m_live; }
    uint64_t Capacity() const { return static_cast<uint64_t>(m_chunks.size()) * CHUNK_SIZE; }
    uint64_t FreeCount() const { return m_free.size(); }

    uint64_t EstimatedBytes() const
    {
        constexpr uint64_t bytes_per_slot{sizeof(Hash256) + sizeof(NodeId) * 3 + sizeof(NodeType)};
        return static_cast<uint64_t>(m_chunks.size()) * CHUNK_SIZE * bytes_per_slot +
               static_cast<uint64_t>(m_free.capacity()) * sizeof(NodeId);
    }

    void Import(NodeId id, NodeType type, const Hash256& hash, NodeId parent, NodeId left, NodeId right)
    {
        Ensure(id);
        m_next = std::max(m_next, static_cast<NodeId>(id + 1));
        Hash(id) = hash;
        ParentRef(id) = parent;
        LeftRef(id) = left;
        RightRef(id) = right;
        TypeRef(id) = type;
        if (type == NodeType::FREE) m_free.push_back(id); else ++m_live;
    }

private:
    void Ensure(NodeId id)
    {
        const std::size_t required{static_cast<std::size_t>(id >> CHUNK_SHIFT) + 1};
        while (m_chunks.size() < required) m_chunks.push_back(std::make_unique<Chunk>());
    }
    Chunk& Get(NodeId id) { return *m_chunks.at(id >> CHUNK_SHIFT); }
    const Chunk& Get(NodeId id) const { return *m_chunks.at(id >> CHUNK_SHIFT); }

    std::vector<std::unique_ptr<Chunk>> m_chunks;
    std::vector<NodeId> m_free;
    NodeId m_next{0};
    uint64_t m_live{0};
};

class KeylessLeafIndex
{
public:
    explicit KeylessLeafIndex(const NodeArena& arena) : m_arena{arena} { Rehash(16); }

    std::optional<NodeId> Find(const Hash256& hash) const
    {
        const std::size_t mask{m_slots.size() - 1};
        std::size_t slot{Bucket(hash) & mask};
        for (std::size_t probes{0}; probes < m_slots.size(); ++probes) {
            if (m_control[slot] == EMPTY) return std::nullopt;
            if (m_control[slot] == FULL) {
                const NodeId id{m_slots[slot]};
                if (m_arena.IsLeaf(id) && m_arena.Hash(id) == hash) return id;
            }
            slot = (slot + 1) & mask;
        }
        return std::nullopt;
    }

    void Insert(const Hash256& hash, NodeId id)
    {
        if ((m_size + m_tombstones + 1) * 10 >= m_slots.size() * 8) Rehash(m_slots.size() * 2);
        const std::size_t mask{m_slots.size() - 1};
        std::size_t slot{Bucket(hash) & mask};
        std::size_t tombstone{m_slots.size()};
        for (;;) {
            if (m_control[slot] == EMPTY) {
                const std::size_t destination{tombstone == m_slots.size() ? slot : tombstone};
                if (tombstone != m_slots.size()) --m_tombstones;
                m_slots[destination] = id;
                m_control[destination] = FULL;
                ++m_size;
                return;
            }
            if (m_control[slot] == DELETED && tombstone == m_slots.size()) tombstone = slot;
            slot = (slot + 1) & mask;
        }
    }

    bool Erase(const Hash256& hash, NodeId id)
    {
        const std::size_t mask{m_slots.size() - 1};
        std::size_t slot{Bucket(hash) & mask};
        while (m_control[slot] != EMPTY) {
            if (m_control[slot] == FULL && m_slots[slot] == id) {
                m_control[slot] = DELETED;
                --m_size;
                ++m_tombstones;
                return true;
            }
            slot = (slot + 1) & mask;
        }
        return false;
    }

    uint64_t Size() const { return m_size; }
    uint64_t Capacity() const { return m_slots.size(); }
    uint64_t Tombstones() const { return m_tombstones; }
    uint64_t EstimatedBytes() const
    {
        return static_cast<uint64_t>(m_slots.capacity()) * sizeof(NodeId) + m_control.capacity();
    }

private:
    static constexpr uint8_t EMPTY{0};
    static constexpr uint8_t FULL{1};
    static constexpr uint8_t DELETED{2};

    static std::size_t Bucket(const Hash256& hash)
    {
        uint64_t value{0};
        std::memcpy(&value, hash.Bytes().data(), sizeof(value));
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdULL;
        value ^= value >> 33;
        value *= 0xc4ceb9fe1a85ec53ULL;
        value ^= value >> 33;
        return static_cast<std::size_t>(value);
    }

    void Rehash(std::size_t capacity)
    {
        capacity = std::max<std::size_t>(16, std::bit_ceil(capacity));
        std::vector<NodeId> old_slots{std::move(m_slots)};
        std::vector<uint8_t> old_control{std::move(m_control)};
        m_slots.assign(capacity, NO_NODE);
        m_control.assign(capacity, EMPTY);
        m_size = 0;
        m_tombstones = 0;
        for (std::size_t i{0}; i < old_slots.size(); ++i) {
            if (old_control[i] == FULL && m_arena.IsLeaf(old_slots[i])) {
                Insert(m_arena.Hash(old_slots[i]), old_slots[i]);
            }
        }
    }

    const NodeArena& m_arena;
    std::vector<NodeId> m_slots;
    std::vector<uint8_t> m_control;
    uint64_t m_size{0};
    uint64_t m_tombstones{0};
};

} // namespace

class PackedForest::Impl
{
public:
    Impl() : index{arena} { roots.fill(NO_NODE); }

    Result<void> Add(const Hash256& hash)
    {
        NodeId node{arena.Allocate(NodeType::LEAF, hash)};
        index.Insert(hash, node);

        uint64_t leaves{num_leaves};
        uint8_t row{0};
        while ((leaves & 1) != 0) {
            const NodeId left{roots[row]};
            roots[row] = NO_NODE;
            if (left != NO_NODE) {
                const NodeId branch{arena.Allocate(NodeType::BRANCH, ParentHash(arena.Hash(left), arena.Hash(node)), left, node)};
                arena.ParentRef(left) = branch;
                arena.ParentRef(node) = branch;
                node = branch;
            }
            leaves >>= 1;
            ++row;
        }
        roots[row] = node;
        ++num_leaves;
        return Result<void>::Ok();
    }

    Result<void> DeleteId(NodeId leaf)
    {
        if (!arena.IsLeaf(leaf)) return Result<void>::Err("node is not a live leaf");
        const Hash256 hash{arena.Hash(leaf)};
        const NodeId parent{arena.Parent(leaf)};
        if (parent == NO_NODE) {
            auto root{std::ranges::find(roots, leaf)};
            if (root == roots.end()) return Result<void>::Err("leaf root is not registered");
            *root = NO_NODE;
            index.Erase(hash, leaf);
            arena.Free(leaf);
            return Result<void>::Ok();
        }

        const NodeId sibling{arena.Left(parent) == leaf ? arena.Right(parent) : arena.Left(parent)};
        const NodeId grandparent{arena.Parent(parent)};
        if (grandparent == NO_NODE) {
            auto root{std::ranges::find(roots, parent)};
            if (root == roots.end()) return Result<void>::Err("branch root is not registered");
            *root = sibling;
            arena.ParentRef(sibling) = NO_NODE;
        } else {
            if (arena.Left(grandparent) == parent) arena.LeftRef(grandparent) = sibling;
            else if (arena.Right(grandparent) == parent) arena.RightRef(grandparent) = sibling;
            else return Result<void>::Err("parent is detached from grandparent");
            arena.ParentRef(sibling) = grandparent;
            Recompute(grandparent);
        }
        index.Erase(hash, leaf);
        arena.Free(leaf);
        arena.Free(parent);
        return Result<void>::Ok();
    }

    Result<uint64_t> PositionOf(NodeId leaf) const
    {
        uint64_t directions{0};
        uint8_t distance{0};
        NodeId node{leaf};
        while (arena.Parent(node) != NO_NODE) {
            const NodeId parent{arena.Parent(node)};
            directions <<= 1;
            if (arena.Right(parent) == node) directions |= 1;
            else if (arena.Left(parent) != node) return Result<uint64_t>::Err("node parent link is inconsistent");
            ++distance;
            node = parent;
        }

        std::optional<uint8_t> root_row;
        const uint8_t forest_rows{position::TreeRows(num_leaves)};
        for (uint8_t row{0}; row <= forest_rows; ++row) {
            if (((num_leaves >> row) & 1U) != 0 && roots[row] == node) {
                root_row = row;
                break;
            }
        }
        if (!root_row) return Result<uint64_t>::Err("could not locate the leaf's root");

        uint64_t pos{position::RootPosition(num_leaves, *root_row, forest_rows)};
        for (uint8_t i{0}; i < distance; ++i) {
            pos = (directions & 1U) == 0 ? position::LeftChild(pos, forest_rows)
                                         : position::RightChild(pos, forest_rows);
            directions >>= 1;
        }
        return Result<uint64_t>::Ok(pos);
    }

    Result<NodeId> NodeAt(uint64_t pos) const
    {
        if (num_leaves == 0) return Result<NodeId>::Err("forest is empty");
        const auto offset{position::DetectOffset(pos, num_leaves)};
        const uint8_t forest_rows{position::TreeRows(num_leaves)};
        uint8_t tree_index{0};
        NodeId node{NO_NODE};
        for (int row{forest_rows}; row >= 0; --row) {
            if (((num_leaves >> row) & 1U) == 0) continue;
            if (tree_index++ == offset.tree_index) {
                node = roots[static_cast<std::size_t>(row)];
                break;
            }
        }
        if (node == NO_NODE) return Result<NodeId>::Err("position belongs to a deleted subtree");

        for (int row{static_cast<int>(offset.branch_length) - 1}; row >= 0; --row) {
            if (!arena.Live(node) || arena.IsLeaf(node)) return Result<NodeId>::Err("position descends past a leaf");
            const uint64_t niece{(offset.path_bits >> row) & 1U};
            node = niece == 0 ? arena.Right(node) : arena.Left(node);
            if (node == NO_NODE) return Result<NodeId>::Err("position has no live node");
        }
        return Result<NodeId>::Ok(node);
    }

    void Recompute(NodeId node)
    {
        while (node != NO_NODE) {
            arena.Hash(node) = ParentHash(arena.Hash(arena.Left(node)), arena.Hash(arena.Right(node)));
            node = arena.Parent(node);
        }
    }

    NodeArena arena;
    KeylessLeafIndex index;
    std::array<NodeId, 64> roots{};
    uint64_t num_leaves{0};
};

PackedForest::PackedForest() : m_impl{std::make_unique<Impl>()} {}
PackedForest::~PackedForest() = default;
PackedForest::PackedForest(PackedForest&&) noexcept = default;
PackedForest& PackedForest::operator=(PackedForest&&) noexcept = default;

Result<void> PackedForest::Add(const Hash256& leaf) { return m_impl->Add(leaf); }

Result<void> PackedForest::Delete(const Hash256& leaf)
{
    const auto id{m_impl->index.Find(leaf)};
    if (!id) return Result<void>::Err("leaf does not exist in forest");
    return m_impl->DeleteId(*id);
}

Result<void> PackedForest::Modify(std::span<const Hash256> additions,
                                  std::span<const Hash256> deletions)
{
    std::unordered_set<Hash256, Hash256Hasher> deleting;
    std::vector<std::pair<uint64_t, NodeId>> delete_nodes;
    delete_nodes.reserve(deletions.size());
    for (const auto& hash : deletions) {
        if (!deleting.insert(hash).second) return Result<void>::Err("duplicate deletion");
        const auto id{m_impl->index.Find(hash)};
        if (!id) return Result<void>::Err("deletion is not in forest");
        const auto pos{m_impl->PositionOf(*id)};
        if (!pos) return Result<void>::Err(pos.Error());
        delete_nodes.emplace_back(pos.Value(), *id);
    }

    std::ranges::sort(delete_nodes, {}, &std::pair<uint64_t, NodeId>::first);
    for (const auto& [position, id] : delete_nodes) {
        static_cast<void>(position);
        const auto deleted{m_impl->DeleteId(id)};
        if (!deleted) return deleted;
    }
    for (const auto& hash : additions) {
        const auto added{m_impl->Add(hash)};
        if (!added) return added;
    }
    return Result<void>::Ok();
}

Result<Proof> PackedForest::Prove(std::span<const Hash256> targets) const
{
    Proof proof;
    proof.targets.reserve(targets.size());
    for (const auto& target : targets) {
        const auto id{m_impl->index.Find(target)};
        if (!id) return Result<Proof>::Err("proof target is not in forest");
        const auto pos{m_impl->PositionOf(*id)};
        if (!pos) return Result<Proof>::Err(pos.Error());
        proof.targets.push_back(pos.Value());
    }
    const auto needed{position::ProofPositions(proof.targets, m_impl->num_leaves,
                                                position::TreeRows(m_impl->num_leaves))};
    proof.hashes.reserve(needed.size());
    for (const auto pos : needed) {
        const auto node{m_impl->NodeAt(pos)};
        if (!node) return Result<Proof>::Err(node.Error());
        proof.hashes.push_back(m_impl->arena.Hash(node.Value()));
    }
    return Result<Proof>::Ok(std::move(proof));
}

Result<bool> VerifyProof(const Proof& proof, std::span<const Hash256> target_hashes,
                         std::span<const Hash256> roots, uint64_t num_leaves)
{
    if (proof.targets.size() != target_hashes.size()) {
        return Result<bool>::Err("proof target and target-hash counts differ");
    }
    if (proof.targets.empty()) return Result<bool>::Ok(true);
    if (num_leaves == 0) return Result<bool>::Err("non-empty proof for an empty forest");
    if (roots.size() != static_cast<std::size_t>(std::popcount(num_leaves))) {
        return Result<bool>::Err("root count does not match the forest leaf count");
    }

    const uint8_t forest_rows{position::TreeRows(num_leaves)};
    const auto proof_positions{position::ProofPositions(proof.targets, num_leaves, forest_rows)};
    if (proof_positions.size() != proof.hashes.size()) {
        return Result<bool>::Err("proof hash count does not match its required positions");
    }

    std::vector<std::pair<uint64_t, Hash256>> provided;
    provided.reserve(proof.targets.size() + proof.hashes.size());
    for (std::size_t i{0}; i < proof.targets.size(); ++i) {
        provided.emplace_back(proof.targets[i], target_hashes[i]);
    }
    for (std::size_t i{0}; i < proof_positions.size(); ++i) {
        provided.emplace_back(proof_positions[i], proof.hashes[i]);
    }
    std::ranges::sort(provided, {}, &std::pair<uint64_t, Hash256>::first);
    for (std::size_t i{1}; i < provided.size(); ++i) {
        if (provided[i - 1].first == provided[i].first) {
            return Result<bool>::Err("proof contains duplicate node positions");
        }
    }

    std::map<uint64_t, Hash256> expected_roots;
    std::size_t root_index{0};
    for (int row{forest_rows}; row >= 0; --row) {
        if (((num_leaves >> row) & 1U) == 0) continue;
        expected_roots.emplace(position::RootPosition(num_leaves, static_cast<uint8_t>(row), forest_rows),
                               roots[root_index++]);
    }

    std::vector<std::pair<uint64_t, Hash256>> computed;
    computed.reserve(provided.size() * 2);
    std::size_t computed_index{0};
    std::size_t provided_index{0};
    const auto next_node = [&]() -> std::optional<std::pair<uint64_t, Hash256>> {
        const bool have_computed{computed_index < computed.size()};
        const bool have_provided{provided_index < provided.size()};
        if (!have_computed && !have_provided) return std::nullopt;
        if (have_computed && (!have_provided || computed[computed_index].first < provided[provided_index].first)) {
            return computed[computed_index++];
        }
        return provided[provided_index++];
    };

    while (const auto node = next_node()) {
        const auto [position_value, hash]{*node};
        if (position::IsRootPosition(position_value, num_leaves, forest_rows)) {
            const auto expected{expected_roots.find(position_value)};
            if (expected == expected_roots.end() || expected->second != hash) return Result<bool>::Ok(false);
            continue;
        }
        if ((position_value & 1U) != 0) return Result<bool>::Err("proof is missing a left sibling");
        const auto sibling{next_node()};
        if (!sibling || sibling->first != (position_value | 1U)) {
            return Result<bool>::Err("proof is missing a right sibling");
        }
        computed.emplace_back(position::Parent(position_value, forest_rows),
                              ParentHash(hash, sibling->second));
    }
    return Result<bool>::Ok(true);
}

uint64_t PackedForest::NumLeaves() const { return m_impl->num_leaves; }
bool PackedForest::Contains(const Hash256& leaf) const { return m_impl->index.Find(leaf).has_value(); }

std::vector<std::optional<Hash256>> PackedForest::Roots() const
{
    std::vector<std::optional<Hash256>> roots;
    const uint8_t rows{position::TreeRows(m_impl->num_leaves)};
    for (int row{rows}; row >= 0; --row) {
        if (((m_impl->num_leaves >> row) & 1U) == 0) continue;
        const NodeId id{m_impl->roots[static_cast<std::size_t>(row)]};
        if (id == NO_NODE) roots.emplace_back(std::nullopt);
        else roots.emplace_back(m_impl->arena.Hash(id));
    }
    return roots;
}

ForestUsage PackedForest::Usage() const
{
    const uint64_t arena_bytes{m_impl->arena.EstimatedBytes()};
    const uint64_t index_bytes{m_impl->index.EstimatedBytes()};
    return ForestUsage{
        .live_nodes = m_impl->arena.LiveCount(),
        .allocated_slots = m_impl->arena.Next(),
        .arena_capacity_slots = m_impl->arena.Capacity(),
        .free_slots = m_impl->arena.FreeCount(),
        .index_entries = m_impl->index.Size(),
        .index_capacity = m_impl->index.Capacity(),
        .index_tombstones = m_impl->index.Tombstones(),
        .arena_estimated_bytes = arena_bytes,
        .index_estimated_bytes = index_bytes,
        .estimated_bytes = arena_bytes + index_bytes,
    };
}

namespace {

template <typename T>
bool WriteLE(std::ostream& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    std::array<char, sizeof(T)> bytes{};
    uint64_t accumulator{value};
    for (std::size_t i{0}; i < bytes.size(); ++i) {
        bytes[i] = static_cast<char>(accumulator & 0xffU);
        accumulator >>= 8;
    }
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return output.good();
}

template <typename T>
bool ReadLE(std::istream& input, T& value)
{
    static_assert(std::is_unsigned_v<T>);
    std::array<unsigned char, sizeof(T)> bytes{};
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input) return false;
    uint64_t accumulator{0};
    for (std::size_t i{0}; i < bytes.size(); ++i) {
        accumulator |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    value = static_cast<T>(accumulator);
    return true;
}

} // namespace

Result<void> WriteForest(std::ostream& output, const PackedForest& forest)
{
    constexpr std::array<char, 8> MAGIC{'U', 'T', 'R', 'F', 'O', 'R', 'S', 'T'};
    output.write(MAGIC.data(), static_cast<std::streamsize>(MAGIC.size()));
    if (!WriteLE(output, PackedForest::FORMAT_VERSION) ||
        !WriteLE(output, forest.m_impl->num_leaves) ||
        !WriteLE(output, forest.m_impl->arena.Next())) {
        return Result<void>::Err("failed to write forest header");
    }
    for (const NodeId root : forest.m_impl->roots) {
        if (!WriteLE(output, root)) return Result<void>::Err("failed to write forest roots");
    }
    for (uint64_t raw_id{0}; raw_id < forest.m_impl->arena.Next(); ++raw_id) {
        const NodeId id{static_cast<NodeId>(raw_id)};
        const NodeType type{forest.m_impl->arena.Type(id)};
        if (!WriteLE(output, static_cast<uint8_t>(type))) return Result<void>::Err("failed to write node type");
        output.write(reinterpret_cast<const char*>(forest.m_impl->arena.Hash(id).Bytes().data()), Hash256::SIZE);
        if (!WriteLE(output, forest.m_impl->arena.Parent(id)) ||
            !WriteLE(output, forest.m_impl->arena.Left(id)) ||
            !WriteLE(output, forest.m_impl->arena.Right(id))) {
            return Result<void>::Err("failed to write node links");
        }
    }
    if (!output) return Result<void>::Err("failed to finish forest serialization");
    return Result<void>::Ok();
}

Result<PackedForest> ReadForest(std::istream& input)
{
    constexpr std::array<char, 8> MAGIC{'U', 'T', 'R', 'F', 'O', 'R', 'S', 'T'};
    std::array<char, MAGIC.size()> magic{};
    input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (!input || magic != MAGIC) return Result<PackedForest>::Err("invalid forest magic");

    uint32_t version{0};
    uint64_t leaves{0};
    uint64_t slots{0};
    if (!ReadLE(input, version) || !ReadLE(input, leaves) || !ReadLE(input, slots)) {
        return Result<PackedForest>::Err("truncated forest header");
    }
    if (version != PackedForest::FORMAT_VERSION) return Result<PackedForest>::Err("unsupported forest version");
    if (slots >= NO_NODE) return Result<PackedForest>::Err("forest node count exceeds the NodeId range");

    PackedForest forest;
    forest.m_impl->num_leaves = leaves;
    for (NodeId& root : forest.m_impl->roots) {
        if (!ReadLE(input, root)) return Result<PackedForest>::Err("truncated forest roots");
        if (root != NO_NODE && root >= slots) return Result<PackedForest>::Err("forest root is out of range");
    }

    for (uint64_t raw_id{0}; raw_id < slots; ++raw_id) {
        uint8_t raw_type{0};
        Hash256::Storage hash_bytes{};
        NodeId parent{NO_NODE};
        NodeId left{NO_NODE};
        NodeId right{NO_NODE};
        if (!ReadLE(input, raw_type)) return Result<PackedForest>::Err("truncated node type");
        input.read(reinterpret_cast<char*>(hash_bytes.data()), Hash256::SIZE);
        if (!input || !ReadLE(input, parent) || !ReadLE(input, left) || !ReadLE(input, right)) {
            return Result<PackedForest>::Err("truncated node record");
        }
        if (raw_type > static_cast<uint8_t>(NodeType::BRANCH)) {
            return Result<PackedForest>::Err("invalid node type");
        }
        const auto link_valid{[slots](NodeId link) { return link == NO_NODE || link < slots; }};
        if (!link_valid(parent) || !link_valid(left) || !link_valid(right)) {
            return Result<PackedForest>::Err("node link is out of range");
        }
        forest.m_impl->arena.Import(static_cast<NodeId>(raw_id), static_cast<NodeType>(raw_type),
                                    Hash256{hash_bytes}, parent, left, right);
    }

    uint64_t leaf_count{0};
    for (uint64_t raw_id{0}; raw_id < slots; ++raw_id) {
        const NodeId id{static_cast<NodeId>(raw_id)};
        const NodeType type{forest.m_impl->arena.Type(id)};
        if (type == NodeType::LEAF) {
            ++leaf_count;
            if (forest.m_impl->arena.Left(id) != NO_NODE || forest.m_impl->arena.Right(id) != NO_NODE) {
                return Result<PackedForest>::Err("leaf has children");
            }
            forest.m_impl->index.Insert(forest.m_impl->arena.Hash(id), id);
        } else if (type == NodeType::BRANCH) {
            const NodeId left{forest.m_impl->arena.Left(id)};
            const NodeId right{forest.m_impl->arena.Right(id)};
            if (left == NO_NODE || right == NO_NODE ||
                !forest.m_impl->arena.Live(left) || !forest.m_impl->arena.Live(right)) {
                return Result<PackedForest>::Err("branch has a missing child");
            }
            if (forest.m_impl->arena.Parent(left) != id || forest.m_impl->arena.Parent(right) != id) {
                return Result<PackedForest>::Err("branch child has an inconsistent parent");
            }
            if (ParentHash(forest.m_impl->arena.Hash(left), forest.m_impl->arena.Hash(right)) !=
                forest.m_impl->arena.Hash(id)) {
                return Result<PackedForest>::Err("branch hash does not match its children");
            }
        }
    }
    if (leaf_count != forest.m_impl->index.Size()) {
        return Result<PackedForest>::Err("leaf index reconstruction failed");
    }
    return Result<PackedForest>::Ok(std::move(forest));
}

} // namespace utreexo
