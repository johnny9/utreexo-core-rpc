// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/forest.h>

#include <utreexo/position.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <istream>
#include <limits>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>

namespace utreexo {
namespace {

enum class NodeType : uint8_t { FREE = 0, LEAF = 1, BRANCH = 2 };

struct NodeRecord {
    Hash256 hash;
    NodeId parent{NO_NODE};
    NodeId left{NO_NODE};
    NodeId right{NO_NODE};
    NodeType type{NodeType::FREE};
    auto operator<=>(const NodeRecord&) const = default;
};

struct DiskMeta {
    NodeId parent{NO_NODE};
    NodeId left{NO_NODE};
    NodeId right{NO_NODE};
    uint8_t type{0};
    std::array<uint8_t, 3> reserved{};
};

static_assert(sizeof(Hash256) == 32);
static_assert(std::is_trivially_copyable_v<Hash256>);
static_assert(sizeof(DiskMeta) == 16);
static_assert(std::endian::native == std::endian::little,
              "native online forest storage currently requires little endian");

std::string ErrnoMessage(std::string_view operation)
{
    return std::string{operation} + ": " + std::strerror(errno);
}

Result<void> SyncDescriptor(int descriptor, std::string_view description)
{
    if (::fdatasync(descriptor) != 0) {
        return Result<void>::Err(ErrnoMessage(std::string{"fdatasync "} + std::string{description}));
    }
    return Result<void>::Ok();
}

uint64_t ElapsedMicros(std::chrono::steady_clock::time_point start)
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count());
}

Result<void> PwriteAll(int descriptor, std::span<const std::byte> bytes, uint64_t file_offset);

class MappedArenaFiles
{
public:
    MappedArenaFiles() = default;
    ~MappedArenaFiles() { Close(); }
    MappedArenaFiles(const MappedArenaFiles&) = delete;
    MappedArenaFiles& operator=(const MappedArenaFiles&) = delete;

    Result<void> Open(const std::filesystem::path& hashes_path,
                      const std::filesystem::path& meta_path,
                      uint64_t capacity_slots)
    {
        Close();
        if (capacity_slots == 0 || capacity_slots >= NO_NODE) {
            return Result<void>::Err("invalid mapped arena capacity");
        }
        m_hash_fd = ::open(hashes_path.c_str(), O_RDWR | O_CLOEXEC);
        if (m_hash_fd < 0) return Result<void>::Err(ErrnoMessage("open forest hashes"));
        m_meta_fd = ::open(meta_path.c_str(), O_RDWR | O_CLOEXEC);
        if (m_meta_fd < 0) {
            const auto error{ErrnoMessage("open forest metadata")};
            Close();
            return Result<void>::Err(error);
        }
        const uint64_t hash_bytes{capacity_slots * sizeof(Hash256)};
        const uint64_t meta_bytes{capacity_slots * sizeof(DiskMeta)};
        struct stat hash_stat{};
        struct stat meta_stat{};
        if (::fstat(m_hash_fd, &hash_stat) != 0 || ::fstat(m_meta_fd, &meta_stat) != 0 ||
            static_cast<uint64_t>(hash_stat.st_size) != hash_bytes ||
            static_cast<uint64_t>(meta_stat.st_size) != meta_bytes) {
            Close();
            return Result<void>::Err("mapped arena files have unexpected sizes");
        }
        m_capacity = capacity_slots;
        m_hashes = static_cast<Hash256*>(::mmap(nullptr, static_cast<std::size_t>(hash_bytes),
                                                PROT_READ | PROT_WRITE, MAP_SHARED, m_hash_fd, 0));
        if (m_hashes == MAP_FAILED) {
            m_hashes = nullptr;
            const auto error{ErrnoMessage("mmap forest hashes")};
            Close();
            return Result<void>::Err(error);
        }
        m_meta = static_cast<DiskMeta*>(::mmap(nullptr, static_cast<std::size_t>(meta_bytes),
                                               PROT_READ | PROT_WRITE, MAP_SHARED, m_meta_fd, 0));
        if (m_meta == MAP_FAILED) {
            m_meta = nullptr;
            const auto error{ErrnoMessage("mmap forest metadata")};
            Close();
            return Result<void>::Err(error);
        }
        return Result<void>::Ok();
    }

    Result<void> Resize(const std::filesystem::path& hashes_path,
                        const std::filesystem::path& meta_path,
                        uint64_t capacity_slots)
    {
        Close();
        const int hash_fd{::open(hashes_path.c_str(), O_RDWR | O_CLOEXEC)};
        if (hash_fd < 0) return Result<void>::Err(ErrnoMessage("open forest hashes for resize"));
        const int meta_fd{::open(meta_path.c_str(), O_RDWR | O_CLOEXEC)};
        if (meta_fd < 0) {
            const auto error{ErrnoMessage("open forest metadata for resize")};
            ::close(hash_fd);
            return Result<void>::Err(error);
        }
        const uint64_t hash_bytes{capacity_slots * sizeof(Hash256)};
        const uint64_t meta_bytes{capacity_slots * sizeof(DiskMeta)};
        if (::ftruncate(hash_fd, static_cast<off_t>(hash_bytes)) != 0 ||
            ::ftruncate(meta_fd, static_cast<off_t>(meta_bytes)) != 0) {
            const auto error{ErrnoMessage("resize mapped arena")};
            ::close(hash_fd);
            ::close(meta_fd);
            return Result<void>::Err(error);
        }
        ::close(hash_fd);
        ::close(meta_fd);
        return Open(hashes_path, meta_path, capacity_slots);
    }

    const Hash256& Hash(NodeId id) const { return m_hashes[id]; }
    const DiskMeta& Meta(NodeId id) const { return m_meta[id]; }
    Hash256& Hash(NodeId id) { return m_hashes[id]; }
    DiskMeta& Meta(NodeId id) { return m_meta[id]; }
    uint64_t Capacity() const { return m_capacity; }
    uint64_t Bytes() const { return m_capacity * (sizeof(Hash256) + sizeof(DiskMeta)); }

    Result<void> SyncPages(std::span<const NodeId> ids)
    {
        if (ids.empty()) return Result<void>::Ok();
        const long raw_page_size{::sysconf(_SC_PAGESIZE)};
        if (raw_page_size <= 0) return Result<void>::Err("could not determine system page size");
        const uint64_t page_size{static_cast<uint64_t>(raw_page_size)};
        const auto sync_mapping = [&](void* mapping, uint64_t element_size) -> Result<void> {
            std::vector<uint64_t> pages;
            pages.reserve(ids.size());
            for (const NodeId id : ids) pages.push_back(static_cast<uint64_t>(id) * element_size / page_size);
            std::ranges::sort(pages);
            pages.erase(std::unique(pages.begin(), pages.end()), pages.end());
            std::size_t begin{0};
            while (begin < pages.size()) {
                std::size_t end{begin + 1};
                while (end < pages.size() && pages[end] == pages[end - 1] + 1) ++end;
                const uint64_t offset{pages[begin] * page_size};
                const uint64_t length{(pages[end - 1] - pages[begin] + 1) * page_size};
                if (::msync(static_cast<std::byte*>(mapping) + offset,
                            static_cast<std::size_t>(length), MS_SYNC) != 0) {
                    return Result<void>::Err(ErrnoMessage("msync mapped arena"));
                }
                begin = end;
            }
            return Result<void>::Ok();
        };
        auto hashes{sync_mapping(m_hashes, sizeof(Hash256))};
        if (!hashes) return hashes;
        auto meta{sync_mapping(m_meta, sizeof(DiskMeta))};
        if (!meta) return meta;
        auto hash_sync{SyncDescriptor(m_hash_fd, "forest hashes")};
        if (!hash_sync) return hash_sync;
        return SyncDescriptor(m_meta_fd, "forest metadata");
    }

private:
    void Close()
    {
        if (m_hashes != nullptr) {
            ::munmap(m_hashes, static_cast<std::size_t>(m_capacity * sizeof(Hash256)));
            m_hashes = nullptr;
        }
        if (m_meta != nullptr) {
            ::munmap(m_meta, static_cast<std::size_t>(m_capacity * sizeof(DiskMeta)));
            m_meta = nullptr;
        }
        if (m_hash_fd >= 0) ::close(m_hash_fd);
        if (m_meta_fd >= 0) ::close(m_meta_fd);
        m_hash_fd = m_meta_fd = -1;
        m_capacity = 0;
    }

    int m_hash_fd{-1};
    int m_meta_fd{-1};
    Hash256* m_hashes{nullptr};
    DiskMeta* m_meta{nullptr};
    uint64_t m_capacity{0};
};

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

    struct NodeChange {
        NodeId id{NO_NODE};
        NodeRecord before;
        NodeRecord after;
        bool was_dirty{false};
    };

    NodeId Allocate(NodeType type, const Hash256& hash, NodeId left = NO_NODE, NodeId right = NO_NODE)
    {
        NodeId id;
        if (Mapped()) {
            while (!m_free.empty() && !m_free_set.contains(m_free.back())) m_free.pop_back();
        }
        if ((!Mapped() && !m_free.empty()) || (Mapped() && !m_free_set.empty())) {
            if (m_free.empty()) throw std::logic_error{"online free-node stack is inconsistent"};
            id = m_free.back();
            m_free.pop_back();
            if (Mapped()) {
                m_free_set.erase(id);
                if (m_transaction) m_free_operations.emplace_back(false, id);
            }
        } else {
            if (m_next == NO_NODE) throw std::length_error{"packed forest exhausted 32-bit node IDs"};
            id = m_next++;
            Ensure(id);
        }
        Write(id, NodeRecord{hash, NO_NODE, left, right, type});
        ++m_live;
        return id;
    }

    void Free(NodeId id)
    {
        NodeRecord record{Read(id)};
        record.type = NodeType::FREE;
        record.parent = record.left = record.right = NO_NODE;
        Write(id, record);
        m_free.push_back(id);
        if (Mapped()) {
            m_free_set.insert(id);
            if (m_transaction) m_free_operations.emplace_back(true, id);
        }
        --m_live;
    }

    bool Live(NodeId id) const { return id < m_next && Type(id) != NodeType::FREE; }
    bool IsLeaf(NodeId id) const { return Live(id) && Type(id) == NodeType::LEAF; }
    const Hash256& Hash(NodeId id) const
    {
        if (Mapped()) {
            const auto dirty{m_dirty.find(id)};
            return dirty == m_dirty.end() ? m_files.Hash(id) : dirty->second.hash;
        }
        return Get(id).hashes[id & CHUNK_MASK];
    }
    NodeId Parent(NodeId id) const { return Read(id).parent; }
    NodeId Left(NodeId id) const { return Read(id).left; }
    NodeId Right(NodeId id) const { return Read(id).right; }
    NodeType Type(NodeId id) const { return Read(id).type; }
    void SetHash(NodeId id, const Hash256& value)
    {
        if (Mapped()) Mutable(id).hash = value;
        else Get(id).hashes[id & CHUNK_MASK] = value;
    }
    void SetParent(NodeId id, NodeId value)
    {
        if (Mapped()) Mutable(id).parent = value;
        else Get(id).parents[id & CHUNK_MASK] = value;
    }
    void SetLeft(NodeId id, NodeId value)
    {
        if (Mapped()) Mutable(id).left = value;
        else Get(id).left[id & CHUNK_MASK] = value;
    }
    void SetRight(NodeId id, NodeId value)
    {
        if (Mapped()) Mutable(id).right = value;
        else Get(id).right[id & CHUNK_MASK] = value;
    }
    uint64_t Next() const { return m_next; }
    uint64_t LiveCount() const { return m_live; }
    uint64_t Capacity() const
    {
        return Mapped() ? m_files.Capacity() : static_cast<uint64_t>(m_chunks.size()) * CHUNK_SIZE;
    }
    uint64_t FreeCount() const { return Mapped() ? m_free_set.size() : m_free.size(); }

    uint64_t EstimatedBytes() const
    {
        constexpr uint64_t bytes_per_slot{sizeof(Hash256) + sizeof(NodeId) * 3 + sizeof(NodeType)};
        if (Mapped()) {
            return static_cast<uint64_t>(m_dirty.size()) * sizeof(NodeRecord) +
                   static_cast<uint64_t>(m_free.capacity()) * sizeof(NodeId) +
                   static_cast<uint64_t>(m_free_set.size()) * (sizeof(NodeId) * 3);
        }
        return static_cast<uint64_t>(m_chunks.size()) * CHUNK_SIZE * bytes_per_slot +
               static_cast<uint64_t>(m_free.capacity()) * sizeof(NodeId);
    }

    /**
     * Ensure allocating `count` nodes cannot allocate while a block transition
     * is mutating the forest.  This lets callers retain the previous block as
     * a recoverable checkpoint boundary after std::bad_alloc.
     */
    void PrepareAllocations(uint64_t count)
    {
        const uint64_t free_count{FreeCount()};
        if (count <= free_count) return;
        const uint64_t new_slots{count - free_count};
        const uint64_t last{m_next + new_slots - 1};
        if (last >= NO_NODE) throw std::length_error{"packed forest exhausted 32-bit node IDs"};
        Ensure(static_cast<NodeId>(last));
    }

    void PrepareFrees(uint64_t count)
    {
        m_free.reserve(m_free.size() + count);
    }

    void Import(NodeId id, NodeType type, const Hash256& hash, NodeId parent, NodeId left, NodeId right)
    {
        Ensure(id);
        m_next = std::max(m_next, static_cast<NodeId>(id + 1));
        Write(id, NodeRecord{hash, parent, left, right, type});
        if (type == NodeType::FREE) m_free.push_back(id); else ++m_live;
    }

    bool Mapped() const { return m_mapped; }
    uint64_t BaseBytes() const { return Mapped() ? m_files.Bytes() : 0; }
    uint64_t DirtyNodes() const { return m_dirty.size(); }
    uint64_t DirtyBytes() const { return static_cast<uint64_t>(m_dirty.size()) * 80; }

    Result<void> WriteNative(const std::filesystem::path& hashes_path,
                             const std::filesystem::path& meta_path,
                             uint64_t capacity_slots) const
    {
        const int hash_fd{::open(hashes_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600)};
        if (hash_fd < 0) return Result<void>::Err(ErrnoMessage("create forest hashes"));
        const int meta_fd{::open(meta_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600)};
        if (meta_fd < 0) {
            const auto error{ErrnoMessage("create forest metadata")};
            ::close(hash_fd);
            return Result<void>::Err(error);
        }
        const uint64_t hash_bytes{capacity_slots * sizeof(Hash256)};
        const uint64_t meta_bytes{capacity_slots * sizeof(DiskMeta)};
        if (::ftruncate(hash_fd, static_cast<off_t>(hash_bytes)) != 0 ||
            ::ftruncate(meta_fd, static_cast<off_t>(meta_bytes)) != 0) {
            const auto error{ErrnoMessage("size native forest files")};
            ::close(hash_fd);
            ::close(meta_fd);
            return Result<void>::Err(error);
        }
        std::vector<DiskMeta> meta_buffer(CHUNK_SIZE);
        for (uint64_t first{0}; first < m_next; first += CHUNK_SIZE) {
            const uint64_t count{std::min<uint64_t>(CHUNK_SIZE, m_next - first)};
            const auto& chunk{*m_chunks.at(static_cast<std::size_t>(first >> CHUNK_SHIFT))};
            auto hash_written{PwriteAll(hash_fd,
                std::as_bytes(std::span<const Hash256>{chunk.hashes.get(), static_cast<std::size_t>(count)}),
                first * sizeof(Hash256))};
            if (!hash_written) {
                const auto error{hash_written.Error()};
                ::close(hash_fd);
                ::close(meta_fd);
                return Result<void>::Err(error);
            }
            for (std::size_t i{0}; i < static_cast<std::size_t>(count); ++i) {
                meta_buffer[i] = DiskMeta{chunk.parents[i], chunk.left[i], chunk.right[i],
                                          static_cast<uint8_t>(chunk.types[i]), {}};
            }
            auto meta_written{PwriteAll(meta_fd,
                std::as_bytes(std::span<const DiskMeta>{meta_buffer.data(), static_cast<std::size_t>(count)}),
                first * sizeof(DiskMeta))};
            if (!meta_written) {
                const auto error{meta_written.Error()};
                ::close(hash_fd);
                ::close(meta_fd);
                return Result<void>::Err(error);
            }
        }
        auto hash_sync{SyncDescriptor(hash_fd, "native forest hashes")};
        auto meta_sync{SyncDescriptor(meta_fd, "native forest metadata")};
        ::close(hash_fd);
        ::close(meta_fd);
        if (!hash_sync) return hash_sync;
        return meta_sync;
    }

    Result<void> SwitchToMapped(const std::filesystem::path& hashes_path,
                                const std::filesystem::path& meta_path,
                                uint64_t capacity_slots)
    {
        auto opened{m_files.Open(hashes_path, meta_path, capacity_slots)};
        if (!opened) return opened;
        m_free_set.clear();
        m_free_set.reserve(m_free.size() * 2);
        for (const NodeId id : m_free) m_free_set.insert(id);
        m_chunks.clear();
        m_chunks.shrink_to_fit();
        m_mapped = true;
        return Result<void>::Ok();
    }

    Result<void> OpenMapped(const std::filesystem::path& hashes_path,
                            const std::filesystem::path& meta_path,
                            uint64_t capacity_slots, NodeId next)
    {
        auto opened{m_files.Open(hashes_path, meta_path, capacity_slots)};
        if (!opened) return opened;
        m_mapped = true;
        m_next = next;
        return RebuildBookkeeping();
    }

    Result<void> RebuildBookkeeping()
    {
        m_live = 0;
        m_free.clear();
        m_free_set.clear();
        for (uint64_t raw_id{0}; raw_id < m_next; ++raw_id) {
            const NodeId id{static_cast<NodeId>(raw_id)};
            if (Type(id) == NodeType::FREE) {
                m_free.push_back(id);
                if (Mapped()) m_free_set.insert(id);
            } else {
                ++m_live;
            }
        }
        return Result<void>::Ok();
    }

    void BeginTransaction()
    {
        if (!Mapped()) return;
        if (m_transaction) throw std::logic_error{"nested forest transaction"};
        m_transaction.emplace();
        m_transaction_next = m_next;
        m_transaction_live = m_live;
        m_free_operations.clear();
    }

    std::vector<NodeChange> TransactionChanges() const
    {
        std::vector<NodeChange> changes;
        if (!m_transaction) return changes;
        changes.reserve(m_transaction->size());
        for (const auto& [id, original] : *m_transaction) {
            changes.push_back(NodeChange{id, original.record, Read(id), original.was_dirty});
        }
        std::ranges::sort(changes, {}, &NodeChange::id);
        return changes;
    }

    void CommitTransaction()
    {
        m_transaction.reset();
        m_free_operations.clear();
    }

    void RollbackTransaction()
    {
        if (!m_transaction) return;
        for (const auto& [id, original] : *m_transaction) {
            if (original.was_dirty) m_dirty[id] = original.record;
            else m_dirty.erase(id);
        }
        for (auto it{m_free_operations.rbegin()}; it != m_free_operations.rend(); ++it) {
            const auto [was_free, id]{*it};
            if (was_free) {
                m_free_set.erase(id);
            } else {
                m_free_set.insert(id);
                m_free.push_back(id);
            }
        }
        m_next = m_transaction_next;
        m_live = m_transaction_live;
        CommitTransaction();
    }

    Result<void> WriteDirtyToBase(const std::filesystem::path& hashes_path,
                                  const std::filesystem::path& meta_path)
    {
        if (!Mapped()) return Result<void>::Err("forest is not mapped");
        if (m_next > m_files.Capacity()) {
            uint64_t capacity{std::max<uint64_t>(CHUNK_SIZE, m_files.Capacity())};
            while (capacity < m_next) capacity += CHUNK_SIZE;
            auto resized{m_files.Resize(hashes_path, meta_path, capacity)};
            if (!resized) return resized;
        }
        std::vector<NodeId> ids;
        ids.reserve(m_dirty.size());
        for (const auto& [id, record] : m_dirty) {
            m_files.Hash(id) = record.hash;
            m_files.Meta(id) = DiskMeta{record.parent, record.left, record.right,
                                        static_cast<uint8_t>(record.type), {}};
            ids.push_back(id);
        }
        std::ranges::sort(ids);
        return m_files.SyncPages(ids);
    }

    void ClearDirty() { m_dirty.clear(); }

    void ApplyRuntime(NodeId id, const NodeRecord& record)
    {
        if (!Mapped()) throw std::logic_error{"runtime record application requires a mapped arena"};
        const NodeRecord current{Read(id)};
        const bool current_live{current.type != NodeType::FREE};
        const bool next_live{record.type != NodeType::FREE};
        if (current_live != next_live) {
            if (next_live) {
                m_free_set.erase(id);
                if (m_transaction) m_free_operations.emplace_back(false, id);
                ++m_live;
            } else {
                m_free_set.insert(id);
                m_free.push_back(id);
                if (m_transaction) m_free_operations.emplace_back(true, id);
                --m_live;
            }
        }
        Write(id, record);
    }

    void SetRuntimeNext(NodeId next, std::span<const NodeChange> changes)
    {
        m_next = next;
        for (const auto& change : changes) {
            if (change.id >= next) m_free_set.erase(change.id);
        }
    }

    void ApplyRecovered(NodeId id, const NodeRecord& record)
    {
        if (id >= m_next) m_next = id + 1;
        m_dirty[id] = record;
    }

    void SetRecoveredNext(NodeId next) { m_next = next; }

    NodeRecord Read(NodeId id) const
    {
        if (Mapped()) {
            const auto dirty{m_dirty.find(id)};
            if (dirty != m_dirty.end()) return dirty->second;
            const auto& meta{m_files.Meta(id)};
            return NodeRecord{m_files.Hash(id), meta.parent, meta.left, meta.right,
                              static_cast<NodeType>(meta.type)};
        }
        const auto& chunk{Get(id)};
        const std::size_t offset{id & CHUNK_MASK};
        return NodeRecord{chunk.hashes[offset], chunk.parents[offset], chunk.left[offset],
                          chunk.right[offset], chunk.types[offset]};
    }

    void Write(NodeId id, const NodeRecord& record)
    {
        if (Mapped()) {
            Mutable(id) = record;
            return;
        }
        auto& chunk{Get(id)};
        const std::size_t offset{id & CHUNK_MASK};
        chunk.hashes[offset] = record.hash;
        chunk.parents[offset] = record.parent;
        chunk.left[offset] = record.left;
        chunk.right[offset] = record.right;
        chunk.types[offset] = record.type;
    }

private:
    struct OriginalRecord {
        NodeRecord record;
        bool was_dirty{false};
    };

    void Ensure(NodeId id)
    {
        if (Mapped()) return;
        const std::size_t required{static_cast<std::size_t>(id >> CHUNK_SHIFT) + 1};
        while (m_chunks.size() < required) m_chunks.push_back(std::make_unique<Chunk>());
    }

    NodeRecord& Mutable(NodeId id)
    {
        if (Mapped()) {
            auto dirty{m_dirty.find(id)};
            const bool was_dirty{dirty != m_dirty.end()};
            if (!was_dirty) dirty = m_dirty.emplace(id, Read(id)).first;
            if (m_transaction && !m_transaction->contains(id)) {
                m_transaction->emplace(id, OriginalRecord{dirty->second, was_dirty});
            }
            return dirty->second;
        }
        throw std::logic_error{"Mutable called for RAM arena"};
    }

    Chunk& Get(NodeId id) { return *m_chunks.at(id >> CHUNK_SHIFT); }
    const Chunk& Get(NodeId id) const { return *m_chunks.at(id >> CHUNK_SHIFT); }

    std::vector<std::unique_ptr<Chunk>> m_chunks;
    std::vector<NodeId> m_free;
    std::unordered_set<NodeId> m_free_set;
    MappedArenaFiles m_files;
    std::unordered_map<NodeId, NodeRecord> m_dirty;
    std::optional<std::unordered_map<NodeId, OriginalRecord>> m_transaction;
    std::vector<std::pair<bool, NodeId>> m_free_operations;
    NodeId m_transaction_next{0};
    uint64_t m_transaction_live{0};
    NodeId m_next{0};
    uint64_t m_live{0};
    bool m_mapped{false};
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
        if ((m_size + m_tombstones + 1) * 10 >= m_slots.size() * 8) {
            const std::size_t capacity{(m_size + 1) * 10 < m_slots.size() * 8 ?
                m_slots.size() : m_slots.size() * 2};
            Rehash(capacity);
        }
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
                --m_size;
                // Back-shift the following probe cluster. This avoids
                // accumulating tombstones and the multi-gigabyte growth that
                // a tombstone-triggered capacity doubling caused in IBD.
                std::size_t hole{slot};
                std::size_t cursor{(slot + 1) & mask};
                while (m_control[cursor] != EMPTY) {
                    if (m_control[cursor] == FULL) {
                        const std::size_t home{Bucket(m_arena.Hash(m_slots[cursor])) & mask};
                        const std::size_t cursor_distance{(cursor - home) & mask};
                        const std::size_t hole_distance{(hole - home) & mask};
                        if (hole_distance < cursor_distance) {
                            m_slots[hole] = m_slots[cursor];
                            m_control[hole] = FULL;
                            hole = cursor;
                        }
                    }
                    cursor = (cursor + 1) & mask;
                }
                m_slots[hole] = NO_NODE;
                m_control[hole] = EMPTY;
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

    void Clear(std::size_t capacity = 16)
    {
        capacity = std::max<std::size_t>(16, std::bit_ceil(capacity));
        m_slots.assign(capacity, NO_NODE);
        m_control.assign(capacity, EMPTY);
        m_size = 0;
        m_tombstones = 0;
    }

    /** Reserve enough room that inserts following a block's deletions cannot
     * rehash while the forest is being modified. */
    void PrepareInsertions(uint64_t deletions, uint64_t additions)
    {
        // Deletions turn full slots into tombstones, so they do not reduce the
        // occupied-slot count which controls when Insert() rehashes.
        static_cast<void>(deletions);
        const uint64_t needed{m_size + m_tombstones + additions + 1};
        const uint64_t capacity_needed{(needed * 10 + 7) / 8};
        if (capacity_needed > m_slots.size()) {
            const uint64_t live_needed{m_size + additions + 1};
            const uint64_t live_capacity{(live_needed * 10 + 7) / 8};
            Rehash(static_cast<std::size_t>(std::max<uint64_t>(m_slots.size(), live_capacity)));
        }
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
        // Construct replacement storage before changing this index.  A failed
        // allocation therefore leaves the existing forest and index usable for
        // an emergency checkpoint.
        std::vector<NodeId> slots(capacity, NO_NODE);
        std::vector<uint8_t> control(capacity, EMPTY);
        uint64_t size{0};
        const std::size_t mask{capacity - 1};
        for (std::size_t i{0}; i < m_slots.size(); ++i) {
            if (m_control[i] == FULL && m_arena.IsLeaf(m_slots[i])) {
                std::size_t slot{Bucket(m_arena.Hash(m_slots[i])) & mask};
                while (control[slot] == FULL) slot = (slot + 1) & mask;
                slots[slot] = m_slots[i];
                control[slot] = FULL;
                ++size;
            }
        }
        m_slots.swap(slots);
        m_control.swap(control);
        m_size = size;
        m_tombstones = 0;
    }

    const NodeArena& m_arena;
    std::vector<NodeId> m_slots;
    std::vector<uint8_t> m_control;
    uint64_t m_size{0};
    uint64_t m_tombstones{0};
};

constexpr std::array<std::byte, 8> ONLINE_MAGIC{
    std::byte{'U'}, std::byte{'T'}, std::byte{'R'}, std::byte{'O'},
    std::byte{'N'}, std::byte{'L'}, std::byte{'N'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> WAL_MAGIC{
    std::byte{'U'}, std::byte{'T'}, std::byte{'R'}, std::byte{'W'},
    std::byte{'A'}, std::byte{'L'}, std::byte{'0'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> WAL_COMMIT{
    std::byte{'C'}, std::byte{'O'}, std::byte{'M'}, std::byte{'M'},
    std::byte{'I'}, std::byte{'T'}, std::byte{'0'}, std::byte{'1'}};
constexpr uint32_t ONLINE_FORMAT_VERSION{1};

template <typename T>
void AppendUnsigned(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    uint64_t accumulator{value};
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(accumulator & 0xffU));
        accumulator >>= 8;
    }
}

void AppendHash(std::vector<std::byte>& output, const Hash256& hash)
{
    output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
}

void AppendRecord(std::vector<std::byte>& output, const NodeRecord& record)
{
    AppendHash(output, record.hash);
    AppendUnsigned(output, record.parent);
    AppendUnsigned(output, record.left);
    AppendUnsigned(output, record.right);
    AppendUnsigned(output, static_cast<uint8_t>(record.type));
    output.insert(output.end(), 3, std::byte{0});
}

class ByteReader
{
public:
    explicit ByteReader(std::span<const std::byte> bytes) : m_bytes{bytes} {}

    template <typename T>
    bool ReadUnsigned(T& value)
    {
        static_assert(std::is_unsigned_v<T>);
        if (m_offset + sizeof(T) > m_bytes.size()) return false;
        uint64_t accumulator{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            accumulator |= static_cast<uint64_t>(std::to_integer<uint8_t>(m_bytes[m_offset + i])) << (i * 8);
        }
        value = static_cast<T>(accumulator);
        m_offset += sizeof(T);
        return true;
    }

    bool ReadHash(Hash256& hash)
    {
        if (m_offset + Hash256::SIZE > m_bytes.size()) return false;
        Hash256::Storage storage{};
        std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(m_offset), Hash256::SIZE,
                    storage.begin());
        hash = Hash256{storage};
        m_offset += Hash256::SIZE;
        return true;
    }

    bool ReadRecord(NodeRecord& record)
    {
        uint8_t type{0};
        if (!ReadHash(record.hash) || !ReadUnsigned(record.parent) ||
            !ReadUnsigned(record.left) || !ReadUnsigned(record.right) ||
            !ReadUnsigned(type) || type > static_cast<uint8_t>(NodeType::BRANCH) ||
            m_offset + 3 > m_bytes.size()) {
            return false;
        }
        record.type = static_cast<NodeType>(type);
        m_offset += 3;
        return true;
    }

    bool ReadBytes(std::span<std::byte> output)
    {
        if (m_offset + output.size() > m_bytes.size()) return false;
        std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(m_offset), output.size(), output.begin());
        m_offset += output.size();
        return true;
    }

    bool Done() const { return m_offset == m_bytes.size(); }

private:
    std::span<const std::byte> m_bytes;
    std::size_t m_offset{0};
};

uint64_t Checksum(std::span<const std::byte> bytes)
{
    constexpr uint64_t OFFSET{14695981039346656037ULL};
    constexpr uint64_t PRIME{1099511628211ULL};
    uint64_t value{OFFSET};
    for (const std::byte byte : bytes) {
        value ^= std::to_integer<uint8_t>(byte);
        value *= PRIME;
    }
    return value;
}

Result<void> WriteAll(int descriptor, std::span<const std::byte> bytes)
{
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t written{::write(descriptor, bytes.data() + offset, bytes.size() - offset)};
        if (written < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("write online state"));
        }
        if (written == 0) return Result<void>::Err("short write to online state");
        offset += static_cast<std::size_t>(written);
    }
    return Result<void>::Ok();
}

Result<void> PwriteAll(int descriptor, std::span<const std::byte> bytes, uint64_t file_offset)
{
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t written{::pwrite(descriptor, bytes.data() + offset, bytes.size() - offset,
            static_cast<off_t>(file_offset + offset))};
        if (written < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("write online-state range"));
        }
        if (written == 0) return Result<void>::Err("short positional write to online state");
        offset += static_cast<std::size_t>(written);
    }
    return Result<void>::Ok();
}

Result<void> SyncDirectory(const std::filesystem::path& directory)
{
    const int descriptor{::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open online-state directory"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoMessage("fsync online-state directory"));
    return Result<void>::Ok();
}

struct OnlineSuperblock {
    uint64_t generation{0};
    uint64_t base_lsn{0};
    ChainPoint point;
    uint64_t num_leaves{0};
    NodeId next{0};
    uint64_t live_nodes{0};
    uint64_t capacity_slots{0};
    uint64_t chain_hash_count{0};
    std::array<NodeId, 64> roots{};
};

std::vector<std::byte> SerializeSuperblock(const OnlineSuperblock& state)
{
    std::vector<std::byte> bytes;
    bytes.reserve(384);
    bytes.insert(bytes.end(), ONLINE_MAGIC.begin(), ONLINE_MAGIC.end());
    AppendUnsigned(bytes, ONLINE_FORMAT_VERSION);
    AppendUnsigned(bytes, state.generation);
    AppendUnsigned(bytes, state.base_lsn);
    AppendUnsigned(bytes, state.point.height);
    AppendHash(bytes, state.point.block_hash);
    AppendUnsigned(bytes, state.num_leaves);
    AppendUnsigned(bytes, state.next);
    AppendUnsigned(bytes, state.live_nodes);
    AppendUnsigned(bytes, state.capacity_slots);
    AppendUnsigned(bytes, state.chain_hash_count);
    for (const NodeId root : state.roots) AppendUnsigned(bytes, root);
    AppendUnsigned(bytes, Checksum(bytes));
    return bytes;
}

Result<OnlineSuperblock> ParseSuperblock(std::span<const std::byte> bytes)
{
    if (bytes.size() < ONLINE_MAGIC.size() + sizeof(uint64_t)) {
        return Result<OnlineSuperblock>::Err("online superblock is truncated");
    }
    uint64_t expected_checksum{0};
    ByteReader checksum_reader{bytes.last(sizeof(uint64_t))};
    if (!checksum_reader.ReadUnsigned(expected_checksum) ||
        Checksum(bytes.first(bytes.size() - sizeof(uint64_t))) != expected_checksum) {
        return Result<OnlineSuperblock>::Err("online superblock checksum mismatch");
    }
    ByteReader reader{bytes.first(bytes.size() - sizeof(uint64_t))};
    std::array<std::byte, ONLINE_MAGIC.size()> magic{};
    uint32_t version{0};
    OnlineSuperblock state;
    if (!reader.ReadBytes(magic) || magic != ONLINE_MAGIC || !reader.ReadUnsigned(version) ||
        version != ONLINE_FORMAT_VERSION || !reader.ReadUnsigned(state.generation) ||
        !reader.ReadUnsigned(state.base_lsn) || !reader.ReadUnsigned(state.point.height) ||
        !reader.ReadHash(state.point.block_hash) || !reader.ReadUnsigned(state.num_leaves) ||
        !reader.ReadUnsigned(state.next) || !reader.ReadUnsigned(state.live_nodes) ||
        !reader.ReadUnsigned(state.capacity_slots) || !reader.ReadUnsigned(state.chain_hash_count)) {
        return Result<OnlineSuperblock>::Err("invalid online superblock");
    }
    for (NodeId& root : state.roots) {
        if (!reader.ReadUnsigned(root)) return Result<OnlineSuperblock>::Err("truncated online roots");
    }
    if (!reader.Done() || state.next >= NO_NODE || state.capacity_slots < state.next ||
        state.capacity_slots >= NO_NODE || state.chain_hash_count != static_cast<uint64_t>(state.point.height) + 1) {
        return Result<OnlineSuperblock>::Err("online superblock fields are inconsistent");
    }
    return Result<OnlineSuperblock>::Ok(state);
}

Result<void> WriteSuperblock(const std::filesystem::path& directory,
                             const OnlineSuperblock& state)
{
    const auto bytes{SerializeSuperblock(state)};
    const std::filesystem::path final_path{directory / (state.generation % 2 == 0 ? "state.0" : "state.1")};
    const std::filesystem::path temporary{final_path.string() + ".tmp"};
    const int descriptor{::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600)};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("create online superblock"));
    auto written{WriteAll(descriptor, bytes)};
    if (written) written = SyncDescriptor(descriptor, "online superblock");
    const int close_result{::close(descriptor)};
    if (!written) return written;
    if (close_result != 0) return Result<void>::Err(ErrnoMessage("close online superblock"));
    std::error_code rename_error;
    std::filesystem::rename(temporary, final_path, rename_error);
    if (rename_error) return Result<void>::Err("publish online superblock: " + rename_error.message());
    return SyncDirectory(directory);
}

Result<std::vector<std::byte>> ReadFile(const std::filesystem::path& path)
{
    std::error_code size_error;
    const uint64_t size{std::filesystem::file_size(path, size_error)};
    if (size_error || size > std::numeric_limits<std::size_t>::max()) {
        return Result<std::vector<std::byte>>::Err("could not size " + path.string());
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    std::ifstream input{path, std::ios::binary};
    if (!input) return Result<std::vector<std::byte>>::Err("could not open " + path.string());
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input && !bytes.empty()) return Result<std::vector<std::byte>>::Err("could not read " + path.string());
    return Result<std::vector<std::byte>>::Ok(std::move(bytes));
}

Result<OnlineSuperblock> ReadBestSuperblock(const std::filesystem::path& directory)
{
    std::optional<OnlineSuperblock> best;
    std::string errors;
    for (const std::string_view name : {"state.0", "state.1"}) {
        const auto path{directory / name};
        if (!std::filesystem::exists(path)) continue;
        auto bytes{ReadFile(path)};
        if (!bytes) {
            errors += bytes.Error() + "; ";
            continue;
        }
        auto parsed{ParseSuperblock(bytes.Value())};
        if (!parsed) {
            errors += parsed.Error() + "; ";
            continue;
        }
        if (!best || parsed.Value().generation > best->generation) best = parsed.Take();
    }
    if (!best) return Result<OnlineSuperblock>::Err("no valid online superblock: " + errors);
    return Result<OnlineSuperblock>::Ok(*best);
}

enum class WalKind : uint32_t { CONNECT = 1, DISCONNECT = 2 };

struct WalTransaction {
    WalKind kind{WalKind::CONNECT};
    uint64_t lsn{0};
    ChainPoint previous;
    ChainPoint point;
    uint64_t before_num_leaves{0};
    uint64_t after_num_leaves{0};
    NodeId before_next{0};
    NodeId after_next{0};
    std::array<NodeId, 64> before_roots{};
    std::array<NodeId, 64> after_roots{};
    std::vector<NodeArena::NodeChange> changes;
};

std::vector<std::byte> SerializeWal(const WalTransaction& transaction)
{
    std::vector<std::byte> payload;
    payload.reserve(640 + transaction.changes.size() * 100);
    AppendUnsigned(payload, ONLINE_FORMAT_VERSION);
    AppendUnsigned(payload, static_cast<uint32_t>(transaction.kind));
    AppendUnsigned(payload, transaction.lsn);
    AppendUnsigned(payload, transaction.previous.height);
    AppendHash(payload, transaction.previous.block_hash);
    AppendUnsigned(payload, transaction.point.height);
    AppendHash(payload, transaction.point.block_hash);
    AppendUnsigned(payload, transaction.before_num_leaves);
    AppendUnsigned(payload, transaction.after_num_leaves);
    AppendUnsigned(payload, transaction.before_next);
    AppendUnsigned(payload, transaction.after_next);
    for (const NodeId root : transaction.before_roots) AppendUnsigned(payload, root);
    for (const NodeId root : transaction.after_roots) AppendUnsigned(payload, root);
    AppendUnsigned(payload, static_cast<uint64_t>(transaction.changes.size()));
    for (const auto& change : transaction.changes) {
        AppendUnsigned(payload, change.id);
        AppendRecord(payload, change.before);
        AppendRecord(payload, change.after);
    }

    std::vector<std::byte> record;
    record.reserve(WAL_MAGIC.size() + sizeof(uint64_t) + payload.size() + sizeof(uint64_t) + WAL_COMMIT.size());
    record.insert(record.end(), WAL_MAGIC.begin(), WAL_MAGIC.end());
    AppendUnsigned(record, static_cast<uint64_t>(payload.size()));
    record.insert(record.end(), payload.begin(), payload.end());
    AppendUnsigned(record, Checksum(record));
    record.insert(record.end(), WAL_COMMIT.begin(), WAL_COMMIT.end());
    return record;
}

Result<WalTransaction> ParseWal(std::span<const std::byte> record)
{
    if (record.size() < WAL_MAGIC.size() + sizeof(uint64_t) * 2 + WAL_COMMIT.size()) {
        return Result<WalTransaction>::Err("WAL record is truncated");
    }
    std::array<std::byte, WAL_COMMIT.size()> commit{};
    std::copy(record.end() - static_cast<std::ptrdiff_t>(commit.size()), record.end(), commit.begin());
    if (commit != WAL_COMMIT) return Result<WalTransaction>::Err("WAL commit marker is missing");
    uint64_t expected_checksum{0};
    const std::size_t checksum_offset{record.size() - WAL_COMMIT.size() - sizeof(uint64_t)};
    ByteReader checksum_reader{record.subspan(checksum_offset, sizeof(uint64_t))};
    if (!checksum_reader.ReadUnsigned(expected_checksum) ||
        Checksum(record.first(checksum_offset)) != expected_checksum) {
        return Result<WalTransaction>::Err("committed WAL checksum mismatch");
    }
    ByteReader header{record.first(WAL_MAGIC.size() + sizeof(uint64_t))};
    std::array<std::byte, WAL_MAGIC.size()> magic{};
    uint64_t payload_size{0};
    if (!header.ReadBytes(magic) || magic != WAL_MAGIC || !header.ReadUnsigned(payload_size) ||
        payload_size != checksum_offset - WAL_MAGIC.size() - sizeof(uint64_t)) {
        return Result<WalTransaction>::Err("invalid WAL record header");
    }
    ByteReader reader{record.subspan(WAL_MAGIC.size() + sizeof(uint64_t),
                                      static_cast<std::size_t>(payload_size))};
    uint32_t version{0};
    uint32_t kind{0};
    WalTransaction transaction;
    uint64_t change_count{0};
    if (!reader.ReadUnsigned(version) || version != ONLINE_FORMAT_VERSION ||
        !reader.ReadUnsigned(kind) || kind < static_cast<uint32_t>(WalKind::CONNECT) ||
        kind > static_cast<uint32_t>(WalKind::DISCONNECT) ||
        !reader.ReadUnsigned(transaction.lsn) || !reader.ReadUnsigned(transaction.previous.height) ||
        !reader.ReadHash(transaction.previous.block_hash) || !reader.ReadUnsigned(transaction.point.height) ||
        !reader.ReadHash(transaction.point.block_hash) ||
        !reader.ReadUnsigned(transaction.before_num_leaves) ||
        !reader.ReadUnsigned(transaction.after_num_leaves) ||
        !reader.ReadUnsigned(transaction.before_next) || !reader.ReadUnsigned(transaction.after_next)) {
        return Result<WalTransaction>::Err("invalid WAL transaction metadata");
    }
    transaction.kind = static_cast<WalKind>(kind);
    for (NodeId& root : transaction.before_roots) {
        if (!reader.ReadUnsigned(root)) return Result<WalTransaction>::Err("truncated WAL before-roots");
    }
    for (NodeId& root : transaction.after_roots) {
        if (!reader.ReadUnsigned(root)) return Result<WalTransaction>::Err("truncated WAL after-roots");
    }
    if (!reader.ReadUnsigned(change_count) || change_count > NO_NODE) {
        return Result<WalTransaction>::Err("invalid WAL node-change count");
    }
    transaction.changes.reserve(static_cast<std::size_t>(change_count));
    for (uint64_t i{0}; i < change_count; ++i) {
        NodeArena::NodeChange change;
        if (!reader.ReadUnsigned(change.id) || !reader.ReadRecord(change.before) ||
            !reader.ReadRecord(change.after)) {
            return Result<WalTransaction>::Err("truncated WAL node change");
        }
        transaction.changes.push_back(change);
    }
    const bool height_valid{
        (transaction.kind == WalKind::CONNECT &&
         transaction.point.height == transaction.previous.height + 1) ||
        (transaction.kind == WalKind::DISCONNECT &&
         transaction.previous.height == transaction.point.height + 1)};
    if (!reader.Done() || !height_valid || transaction.after_next >= NO_NODE) {
        return Result<WalTransaction>::Err("WAL transaction is inconsistent");
    }
    return Result<WalTransaction>::Ok(std::move(transaction));
}

class OnlineStore
{
public:
    OnlineStore(std::filesystem::path directory, OnlineForestConfig config,
                OnlineSuperblock base, std::vector<Hash256> chain_hashes)
        : m_directory{std::move(directory)}, m_config{config}, m_base{base},
          m_point{base.point}, m_chain_hashes{std::move(chain_hashes)},
          m_current_lsn{base.base_lsn}
    {
    }

    ~OnlineStore()
    {
        if (m_wal_fd >= 0) ::close(m_wal_fd);
    }

    const std::filesystem::path& Directory() const { return m_directory; }
    const OnlineForestConfig& Config() const { return m_config; }
    const ChainPoint& Point() const { return m_point; }
    const std::vector<Hash256>& ChainHashes() const { return m_chain_hashes; }
    uint64_t BaseLsn() const { return m_base.base_lsn; }
    uint64_t CurrentLsn() const { return m_current_lsn; }
    uint64_t WalBytes() const { return m_wal_bytes; }
    uint64_t RedoWalBytes() const { return m_redo_wal_bytes; }
    uint64_t LastTransactionNodes() const { return m_last_transaction_nodes; }
    uint64_t LastTransactionWalBytes() const { return m_last_transaction_wal_bytes; }
    uint64_t LastTransactionSerializeUs() const { return m_last_transaction_serialize_us; }
    uint64_t LastTransactionSegmentUs() const { return m_last_transaction_segment_us; }
    uint64_t LastTransactionWriteUs() const { return m_last_transaction_write_us; }
    uint64_t LastTransactionSyncUs() const { return m_last_transaction_sync_us; }
    uint64_t LastTransactionPublishUs() const { return m_last_transaction_publish_us; }
    uint64_t LastTransactionTotalUs() const { return m_last_transaction_total_us; }

    Result<void> Append(WalTransaction& transaction)
    {
        const auto total_start{std::chrono::steady_clock::now()};
        const bool chain_valid{transaction.previous == m_point &&
            ((transaction.kind == WalKind::CONNECT &&
              transaction.point.height == m_chain_hashes.size() &&
              transaction.previous.height + 1 == transaction.point.height) ||
             (transaction.kind == WalKind::DISCONNECT &&
              m_chain_hashes.size() == static_cast<std::size_t>(transaction.previous.height) + 1 &&
              transaction.previous.height == transaction.point.height + 1 &&
              m_chain_hashes.size() >= 2 &&
              m_chain_hashes[transaction.point.height] == transaction.point.block_hash))};
        if (!chain_valid) {
            return Result<void>::Err("WAL transaction does not extend the online chain");
        }
        transaction.lsn = m_current_lsn + 1;
        const auto serialize_start{std::chrono::steady_clock::now()};
        const auto bytes{SerializeWal(transaction)};
        const uint64_t serialize_us{ElapsedMicros(serialize_start)};
        const auto segment_start{std::chrono::steady_clock::now()};
        auto opened{OpenAppendSegment(bytes.size())};
        if (!opened) return opened;
        const uint64_t segment_us{ElapsedMicros(segment_start)};
        const auto write_start{std::chrono::steady_clock::now()};
        auto written{WriteAll(m_wal_fd, bytes)};
        if (!written) return written;
        const uint64_t write_us{ElapsedMicros(write_start)};
        uint64_t sync_us{0};
        if (m_config.sync_wal) {
            const auto sync_start{std::chrono::steady_clock::now()};
            auto synced{SyncDescriptor(m_wal_fd, "forest WAL")};
            if (!synced) return synced;
            sync_us = ElapsedMicros(sync_start);
        }
        const auto publish_start{std::chrono::steady_clock::now()};
        m_wal_segment_size += bytes.size();
        m_wal_bytes += bytes.size();
        m_redo_wal_bytes += bytes.size();
        m_last_transaction_nodes = transaction.changes.size();
        m_last_transaction_wal_bytes = bytes.size();
        m_current_lsn = transaction.lsn;
        m_point = transaction.point;
        if (transaction.kind == WalKind::CONNECT) m_chain_hashes.push_back(transaction.point.block_hash);
        else m_chain_hashes.pop_back();
        m_last_transaction_serialize_us = serialize_us;
        m_last_transaction_segment_us = segment_us;
        m_last_transaction_write_us = write_us;
        m_last_transaction_sync_us = sync_us;
        m_last_transaction_publish_us = ElapsedMicros(publish_start);
        m_last_transaction_total_us = ElapsedMicros(total_start);
        return Result<void>::Ok();
    }

    Result<WalTransaction> ReadConnectTransaction(const ChainPoint& point) const
    {
        std::vector<std::filesystem::path> segments;
        std::error_code iterator_error;
        for (std::filesystem::directory_iterator iterator{m_directory, iterator_error}, end;
             !iterator_error && iterator != end; iterator.increment(iterator_error)) {
            const auto name{iterator->path().filename().string()};
            if (name.starts_with("wal-") && name.ends_with(".log")) segments.push_back(iterator->path());
        }
        if (iterator_error) {
            return Result<WalTransaction>::Err("scan WAL for undo: " + iterator_error.message());
        }
        std::ranges::sort(segments);
        std::optional<WalTransaction> match;
        for (const auto& path : segments) {
            auto bytes{ReadFile(path)};
            if (!bytes) return Result<WalTransaction>::Err(bytes.Error());
            std::size_t offset{0};
            while (offset < bytes.Value().size()) {
                if (bytes.Value().size() - offset < WAL_MAGIC.size() + sizeof(uint64_t)) break;
                ByteReader header{std::span<const std::byte>{bytes.Value()}.subspan(
                    offset, WAL_MAGIC.size() + sizeof(uint64_t))};
                std::array<std::byte, WAL_MAGIC.size()> magic{};
                uint64_t payload{0};
                if (!header.ReadBytes(magic) || magic != WAL_MAGIC || !header.ReadUnsigned(payload)) break;
                const uint64_t total{WAL_MAGIC.size() + sizeof(uint64_t) + payload +
                                     sizeof(uint64_t) + WAL_COMMIT.size()};
                if (total > bytes.Value().size() - offset) break;
                auto transaction{ParseWal(std::span<const std::byte>{bytes.Value()}.subspan(
                    offset, static_cast<std::size_t>(total)))};
                if (!transaction) return Result<WalTransaction>::Err(transaction.Error());
                if (transaction.Value().kind == WalKind::CONNECT &&
                    transaction.Value().point == point) {
                    match = transaction.Take();
                }
                offset += static_cast<std::size_t>(total);
            }
        }
        if (!match) return Result<WalTransaction>::Err("tip before-images are outside the retained WAL window");
        return Result<WalTransaction>::Ok(std::move(*match));
    }

    Result<void> Recover(NodeArena& arena, std::array<NodeId, 64>& roots,
                         uint64_t& num_leaves)
    {
        std::vector<std::filesystem::path> segments;
        std::error_code iterator_error;
        for (std::filesystem::directory_iterator iterator{m_directory, iterator_error}, end;
             !iterator_error && iterator != end; iterator.increment(iterator_error)) {
            const auto name{iterator->path().filename().string()};
            if (name.starts_with("wal-") && name.ends_with(".log")) segments.push_back(iterator->path());
        }
        if (iterator_error) return Result<void>::Err("scan WAL directory: " + iterator_error.message());
        std::ranges::sort(segments);
        uint64_t last_seen_lsn{m_base.base_lsn};
        for (const auto& path : segments) {
            auto recovered{RecoverSegment(path, arena, roots, num_leaves, last_seen_lsn)};
            if (!recovered) return recovered;
        }
        m_current_lsn = std::max(m_base.base_lsn, last_seen_lsn);
        return Result<void>::Ok();
    }

    Result<void> FlushBase(NodeArena& arena, const std::array<NodeId, 64>& roots,
                           uint64_t num_leaves)
    {
        auto forest_written{arena.WriteDirtyToBase(m_directory / "forest.hashes",
                                                    m_directory / "forest.meta")};
        if (!forest_written) return forest_written;
        auto chain_written{WriteChainHashes()};
        if (!chain_written) return chain_written;
        OnlineSuperblock next{
            .generation = m_base.generation + 1,
            .base_lsn = m_current_lsn,
            .point = m_point,
            .num_leaves = num_leaves,
            .next = static_cast<NodeId>(arena.Next()),
            .live_nodes = arena.LiveCount(),
            .capacity_slots = arena.Capacity(),
            .chain_hash_count = m_chain_hashes.size(),
            .roots = roots,
        };
        auto state_written{WriteSuperblock(m_directory, next)};
        if (!state_written) return state_written;
        arena.ClearDirty();
        m_base = next;
        m_redo_wal_bytes = 0;
        return PruneWal();
    }

private:
    Result<void> OpenAppendSegment(std::size_t record_size)
    {
        if (m_wal_fd >= 0 &&
            (m_wal_segment_size == 0 || m_wal_segment_size + record_size <= m_config.wal_segment_bytes)) {
            return Result<void>::Ok();
        }
        if (m_wal_fd >= 0) {
            ::close(m_wal_fd);
            m_wal_fd = -1;
        }
        const uint64_t start_lsn{m_current_lsn + 1};
        std::ostringstream name;
        name << "wal-" << std::setw(20) << std::setfill('0') << start_lsn << ".log";
        const auto path{m_directory / name.str()};
        m_wal_fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (m_wal_fd < 0) return Result<void>::Err(ErrnoMessage("open WAL segment"));
        struct stat status{};
        if (::fstat(m_wal_fd, &status) != 0) return Result<void>::Err(ErrnoMessage("stat WAL segment"));
        m_wal_segment_size = static_cast<uint64_t>(status.st_size);
        return Result<void>::Ok();
    }

    Result<void> RecoverSegment(const std::filesystem::path& path, NodeArena& arena,
                                std::array<NodeId, 64>& roots, uint64_t& num_leaves,
                                uint64_t& last_seen_lsn)
    {
        auto bytes_result{ReadFile(path)};
        if (!bytes_result) return Result<void>::Err(bytes_result.Error());
        const auto& bytes{bytes_result.Value()};
        std::size_t offset{0};
        std::size_t valid_size{0};
        while (offset < bytes.size()) {
            if (bytes.size() - offset < WAL_MAGIC.size() + sizeof(uint64_t)) break;
            ByteReader header{std::span<const std::byte>{bytes}.subspan(offset,
                WAL_MAGIC.size() + sizeof(uint64_t))};
            std::array<std::byte, WAL_MAGIC.size()> magic{};
            uint64_t payload_size{0};
            if (!header.ReadBytes(magic) || magic != WAL_MAGIC || !header.ReadUnsigned(payload_size)) {
                return Result<void>::Err("invalid WAL magic in " + path.string());
            }
            const uint64_t total_size{WAL_MAGIC.size() + sizeof(uint64_t) + payload_size +
                                      sizeof(uint64_t) + WAL_COMMIT.size()};
            if (total_size > bytes.size() - offset) break;
            auto transaction{ParseWal(std::span<const std::byte>{bytes}.subspan(
                offset, static_cast<std::size_t>(total_size)))};
            if (!transaction) return Result<void>::Err(path.string() + ": " + transaction.Error());
            if (transaction.Value().lsn > m_base.base_lsn) {
                if (transaction.Value().lsn != last_seen_lsn + 1) {
                    return Result<void>::Err("non-contiguous WAL LSN after durable base");
                }
                const bool chain_valid{transaction.Value().previous == m_point &&
                    ((transaction.Value().kind == WalKind::CONNECT &&
                      transaction.Value().point.height == m_chain_hashes.size()) ||
                     (transaction.Value().kind == WalKind::DISCONNECT &&
                      m_chain_hashes.size() >= 2 &&
                      transaction.Value().previous.height + 1 == m_chain_hashes.size() &&
                      transaction.Value().point.height + 1 == transaction.Value().previous.height &&
                      m_chain_hashes[transaction.Value().point.height] ==
                          transaction.Value().point.block_hash))};
                if (!chain_valid ||
                    transaction.Value().before_num_leaves != num_leaves) {
                    return Result<void>::Err("WAL does not extend the recovered online state");
                }
                for (const auto& change : transaction.Value().changes) {
                    arena.ApplyRecovered(change.id, change.after);
                }
                arena.SetRecoveredNext(transaction.Value().after_next);
                roots = transaction.Value().after_roots;
                num_leaves = transaction.Value().after_num_leaves;
                m_point = transaction.Value().point;
                if (transaction.Value().kind == WalKind::CONNECT) m_chain_hashes.push_back(m_point.block_hash);
                else m_chain_hashes.pop_back();
                last_seen_lsn = transaction.Value().lsn;
                m_redo_wal_bytes += total_size;
            }
            offset += static_cast<std::size_t>(total_size);
            valid_size = offset;
        }
        m_wal_bytes += valid_size;
        if (valid_size != bytes.size()) {
            const int descriptor{::open(path.c_str(), O_WRONLY | O_CLOEXEC)};
            if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open incomplete WAL tail"));
            const int truncate_result{::ftruncate(descriptor, static_cast<off_t>(valid_size))};
            const int saved_errno{errno};
            ::close(descriptor);
            errno = saved_errno;
            if (truncate_result != 0) return Result<void>::Err(ErrnoMessage("truncate incomplete WAL tail"));
        }
        return Result<void>::Ok();
    }

    Result<void> WriteChainHashes()
    {
        const auto path{m_directory / "chain.hashes"};
        const int descriptor{::open(path.c_str(), O_RDWR | O_CLOEXEC)};
        if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open online chain hashes"));
        struct stat status{};
        if (::fstat(descriptor, &status) != 0 || status.st_size < 0 ||
            status.st_size % static_cast<off_t>(Hash256::SIZE) != 0) {
            ::close(descriptor);
            return Result<void>::Err("online chain-hash file is invalid");
        }
        uint64_t stored{static_cast<uint64_t>(status.st_size) / Hash256::SIZE};
        if (stored > m_chain_hashes.size()) stored = m_chain_hashes.size();
        for (uint64_t i{stored}; i < m_chain_hashes.size(); ++i) {
            const auto& bytes{m_chain_hashes[static_cast<std::size_t>(i)].Bytes()};
            auto written{PwriteAll(descriptor, bytes, i * Hash256::SIZE)};
            if (!written) {
                const auto error{written.Error()};
                ::close(descriptor);
                return Result<void>::Err(error);
            }
        }
        if (::ftruncate(descriptor, static_cast<off_t>(m_chain_hashes.size() * Hash256::SIZE)) != 0) {
            const auto error{ErrnoMessage("truncate online chain hashes")};
            ::close(descriptor);
            return Result<void>::Err(error);
        }
        auto synced{SyncDescriptor(descriptor, "online chain hashes")};
        ::close(descriptor);
        return synced;
    }

    Result<void> PruneWal()
    {
        // Retain complete segments covering the reorg window. Segment-granular
        // pruning avoids rewriting live WAL data merely to save a partial file.
        const uint32_t floor{m_point.height > m_config.undo_depth ?
            m_point.height - m_config.undo_depth : 0};
        std::error_code iterator_error;
        for (std::filesystem::directory_iterator iterator{m_directory, iterator_error}, end;
             !iterator_error && iterator != end; iterator.increment(iterator_error)) {
            const auto path{iterator->path()};
            const auto name{path.filename().string()};
            if (!name.starts_with("wal-") || !name.ends_with(".log")) continue;
            if (m_wal_fd >= 0) {
                struct stat current{};
                struct stat candidate{};
                if (::fstat(m_wal_fd, &current) == 0 && ::stat(path.c_str(), &candidate) == 0 &&
                    current.st_ino == candidate.st_ino && current.st_dev == candidate.st_dev) {
                    continue;
                }
            }
            auto bytes{ReadFile(path)};
            if (!bytes || bytes.Value().empty()) continue;
            std::size_t offset{0};
            uint32_t max_height{0};
            uint64_t max_lsn{0};
            bool valid{true};
            while (offset < bytes.Value().size()) {
                if (bytes.Value().size() - offset < WAL_MAGIC.size() + sizeof(uint64_t)) { valid = false; break; }
                ByteReader header{std::span<const std::byte>{bytes.Value()}.subspan(
                    offset, WAL_MAGIC.size() + sizeof(uint64_t))};
                std::array<std::byte, WAL_MAGIC.size()> magic{};
                uint64_t payload{0};
                if (!header.ReadBytes(magic) || magic != WAL_MAGIC || !header.ReadUnsigned(payload)) {
                    valid = false;
                    break;
                }
                const uint64_t total{WAL_MAGIC.size() + sizeof(uint64_t) + payload +
                                     sizeof(uint64_t) + WAL_COMMIT.size()};
                if (total > bytes.Value().size() - offset) { valid = false; break; }
                auto transaction{ParseWal(std::span<const std::byte>{bytes.Value()}.subspan(
                    offset, static_cast<std::size_t>(total)))};
                if (!transaction) { valid = false; break; }
                max_height = std::max(max_height, transaction.Value().point.height);
                max_lsn = std::max(max_lsn, transaction.Value().lsn);
                offset += static_cast<std::size_t>(total);
            }
            if (valid && max_height < floor && max_lsn <= m_base.base_lsn) {
                std::error_code remove_error;
                const uint64_t size{std::filesystem::file_size(path, remove_error)};
                if (!remove_error && std::filesystem::remove(path, remove_error) && !remove_error) {
                    m_wal_bytes = size > m_wal_bytes ? 0 : m_wal_bytes - size;
                }
            }
        }
        if (iterator_error) return Result<void>::Err("prune WAL directory: " + iterator_error.message());
        return SyncDirectory(m_directory);
    }

    std::filesystem::path m_directory;
    OnlineForestConfig m_config;
    OnlineSuperblock m_base;
    ChainPoint m_point;
    std::vector<Hash256> m_chain_hashes;
    uint64_t m_current_lsn{0};
    uint64_t m_wal_bytes{0};
    uint64_t m_redo_wal_bytes{0};
    int m_wal_fd{-1};
    uint64_t m_wal_segment_size{0};
    uint64_t m_last_transaction_nodes{0};
    uint64_t m_last_transaction_wal_bytes{0};
    uint64_t m_last_transaction_serialize_us{0};
    uint64_t m_last_transaction_segment_us{0};
    uint64_t m_last_transaction_write_us{0};
    uint64_t m_last_transaction_sync_us{0};
    uint64_t m_last_transaction_publish_us{0};
    uint64_t m_last_transaction_total_us{0};
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
                arena.SetParent(left, branch);
                arena.SetParent(node, branch);
                node = branch;
            }
            leaves >>= 1;
            ++row;
        }
        roots[row] = node;
        ++num_leaves;
        return Result<void>::Ok();
    }

    void PrepareModify(uint64_t additions, uint64_t deletions)
    {
        uint64_t branches{0};
        for (uint64_t i{0}; i < additions; ++i) {
            branches += std::countr_one(num_leaves + i);
        }
        // Each deletion frees at most a leaf and one branch.
        arena.PrepareFrees(deletions * 2);
        index.PrepareInsertions(deletions, additions);
        arena.PrepareAllocations(additions + branches);
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
            arena.SetParent(sibling, NO_NODE);
        } else {
            if (arena.Left(grandparent) == parent) arena.SetLeft(grandparent, sibling);
            else if (arena.Right(grandparent) == parent) arena.SetRight(grandparent, sibling);
            else return Result<void>::Err("parent is detached from grandparent");
            arena.SetParent(sibling, grandparent);
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
            arena.SetHash(node, ParentHash(arena.Hash(arena.Left(node)), arena.Hash(arena.Right(node))));
            node = arena.Parent(node);
        }
    }

    Result<void> Modify(std::span<const Hash256> additions,
                        std::span<const Hash256> deletions)
    {
        std::unordered_set<Hash256, Hash256Hasher> deleting;
        std::vector<std::pair<uint64_t, NodeId>> delete_nodes;
        delete_nodes.reserve(deletions.size());
        for (const auto& hash : deletions) {
            if (!deleting.insert(hash).second) return Result<void>::Err("duplicate deletion");
            const auto id{index.Find(hash)};
            if (!id) return Result<void>::Err("deletion is not in forest");
            const auto pos{PositionOf(*id)};
            if (!pos) return Result<void>::Err(pos.Error());
            delete_nodes.emplace_back(pos.Value(), *id);
        }

        std::ranges::sort(delete_nodes, {}, &std::pair<uint64_t, NodeId>::first);
        PrepareModify(additions.size(), deletions.size());
        for (const auto& [position_value, id] : delete_nodes) {
            static_cast<void>(position_value);
            const auto deleted{DeleteId(id)};
            if (!deleted) return deleted;
        }
        for (const auto& hash : additions) {
            const auto added{Add(hash)};
            if (!added) return added;
        }
        return Result<void>::Ok();
    }

    Result<void> RebuildIndexAndValidate()
    {
        uint64_t leaf_count{0};
        for (uint64_t raw_id{0}; raw_id < arena.Next(); ++raw_id) {
            if (arena.Type(static_cast<NodeId>(raw_id)) == NodeType::LEAF) ++leaf_count;
        }
        const uint64_t required{std::max<uint64_t>(16, (leaf_count * 10 + 7) / 8)};
        if (required > std::numeric_limits<std::size_t>::max()) {
            return Result<void>::Err("online leaf index exceeds addressable memory");
        }
        index.Clear(static_cast<std::size_t>(required));
        for (uint64_t raw_id{0}; raw_id < arena.Next(); ++raw_id) {
            const NodeId id{static_cast<NodeId>(raw_id)};
            const NodeType type{arena.Type(id)};
            if (type == NodeType::LEAF) {
                if (arena.Left(id) != NO_NODE || arena.Right(id) != NO_NODE) {
                    return Result<void>::Err("online leaf has children");
                }
                index.Insert(arena.Hash(id), id);
            } else if (type == NodeType::BRANCH) {
                const NodeId left{arena.Left(id)};
                const NodeId right{arena.Right(id)};
                if (left == NO_NODE || right == NO_NODE || !arena.Live(left) || !arena.Live(right)) {
                    return Result<void>::Err("online branch has a missing child");
                }
                if (arena.Parent(left) != id || arena.Parent(right) != id) {
                    return Result<void>::Err("online branch child has an inconsistent parent");
                }
                if (ParentHash(arena.Hash(left), arena.Hash(right)) != arena.Hash(id)) {
                    return Result<void>::Err("online branch hash does not match its children");
                }
            }
        }
        for (const NodeId root : roots) {
            if (root != NO_NODE && (root >= arena.Next() || !arena.Live(root) || arena.Parent(root) != NO_NODE)) {
                return Result<void>::Err("online forest has an invalid root");
            }
        }
        if (leaf_count != index.Size()) return Result<void>::Err("online leaf index reconstruction failed");
        return Result<void>::Ok();
    }

    Result<void> ApplyPhysicalChanges(std::span<const NodeArena::NodeChange> changes,
                                      bool use_after, NodeId next)
    {
        for (const auto& change : changes) {
            const NodeRecord current{arena.Read(change.id)};
            const NodeRecord& replacement{use_after ? change.after : change.before};
            const NodeRecord& expected{use_after ? change.before : change.after};
            if (current != expected) {
                return Result<void>::Err("WAL before-image does not match the current mapped node");
            }
            if (current.type == NodeType::LEAF && !index.Erase(current.hash, change.id)) {
                return Result<void>::Err("could not remove the current leaf during WAL state application");
            }
            arena.ApplyRuntime(change.id, replacement);
            if (replacement.type == NodeType::LEAF) index.Insert(replacement.hash, change.id);
        }
        arena.SetRuntimeNext(next, changes);
        return Result<void>::Ok();
    }

    NodeArena arena;
    KeylessLeafIndex index;
    std::array<NodeId, 64> roots{};
    uint64_t num_leaves{0};
    std::unique_ptr<OnlineStore> online;
};

PackedForest::PackedForest() : m_impl{std::make_unique<Impl>()} {}
PackedForest::~PackedForest() = default;
PackedForest::PackedForest(PackedForest&&) noexcept = default;
PackedForest& PackedForest::operator=(PackedForest&&) noexcept = default;

Result<void> PackedForest::Add(const Hash256& leaf)
{
    if (IsOnline()) return Result<void>::Err("use ModifyBlock for an online forest");
    return m_impl->Add(leaf);
}

Result<void> PackedForest::Delete(const Hash256& leaf)
{
    if (IsOnline()) return Result<void>::Err("use ModifyBlock for an online forest");
    const auto id{m_impl->index.Find(leaf)};
    if (!id) return Result<void>::Err("leaf does not exist in forest");
    return m_impl->DeleteId(*id);
}

Result<void> PackedForest::Modify(std::span<const Hash256> additions,
                                  std::span<const Hash256> deletions)
{
    if (IsOnline()) return Result<void>::Err("use ModifyBlock for an online forest");
    return m_impl->Modify(additions, deletions);
}

Result<void> PackedForest::ModifyBlock(std::span<const Hash256> additions,
                                       std::span<const Hash256> deletions,
                                       const ChainPoint& point)
{
    if (!m_impl->online) return m_impl->Modify(additions, deletions);
    const ChainPoint previous{m_impl->online->Point()};
    if (point.height != previous.height + 1) {
        return Result<void>::Err("online block height does not extend the durable tip");
    }
    constexpr uint64_t MAX_REDO_WAL_BYTES{1024ULL * 1024 * 1024};
    if (m_impl->arena.DirtyBytes() >= m_impl->online->Config().max_dirty_bytes ||
        m_impl->online->RedoWalBytes() >= MAX_REDO_WAL_BYTES) {
        auto flushed{FlushOnline()};
        if (!flushed) return Result<void>::Err("online base flush required before block: " + flushed.Error());
    }

    WalTransaction transaction{
        .previous = previous,
        .point = point,
        .before_num_leaves = m_impl->num_leaves,
        .before_next = static_cast<NodeId>(m_impl->arena.Next()),
        .before_roots = m_impl->roots,
        .changes = {},
    };
    m_impl->arena.BeginTransaction();
    Result<void> modified{Result<void>::Err("uninitialized online modification")};
    try {
        modified = m_impl->Modify(additions, deletions);
    } catch (...) {
        m_impl->arena.RollbackTransaction();
        m_impl->roots = transaction.before_roots;
        m_impl->num_leaves = transaction.before_num_leaves;
        static_cast<void>(m_impl->RebuildIndexAndValidate());
        throw;
    }
    if (!modified) {
        m_impl->arena.RollbackTransaction();
        m_impl->roots = transaction.before_roots;
        m_impl->num_leaves = transaction.before_num_leaves;
        auto rebuilt{m_impl->RebuildIndexAndValidate()};
        if (!rebuilt) return Result<void>::Err(modified.Error() + "; rollback failed: " + rebuilt.Error());
        return modified;
    }
    Result<void> appended{Result<void>::Err("uninitialized WAL append")};
    try {
        transaction.after_num_leaves = m_impl->num_leaves;
        transaction.after_next = static_cast<NodeId>(m_impl->arena.Next());
        transaction.after_roots = m_impl->roots;
        transaction.changes = m_impl->arena.TransactionChanges();
        appended = m_impl->online->Append(transaction);
    } catch (...) {
        m_impl->arena.RollbackTransaction();
        m_impl->roots = transaction.before_roots;
        m_impl->num_leaves = transaction.before_num_leaves;
        static_cast<void>(m_impl->RebuildIndexAndValidate());
        throw;
    }
    if (!appended) {
        m_impl->arena.RollbackTransaction();
        m_impl->roots = transaction.before_roots;
        m_impl->num_leaves = transaction.before_num_leaves;
        auto rebuilt{m_impl->RebuildIndexAndValidate()};
        if (!rebuilt) return Result<void>::Err(appended.Error() + "; rollback failed: " + rebuilt.Error());
        return appended;
    }
    m_impl->arena.CommitTransaction();
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

Result<void> PackedForest::EnableOnline(const std::filesystem::path& directory,
                                        const ChainPoint& point,
                                        std::span<const Hash256> chain_hashes,
                                        OnlineForestConfig config)
{
    if (IsOnline()) return Result<void>::Err("forest is already using online storage");
    if (config.max_dirty_bytes == 0 || config.wal_segment_bytes < 1024 * 1024 ||
        config.undo_depth == 0) {
        return Result<void>::Err("invalid online forest configuration");
    }
    if (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
        chain_hashes.empty() || chain_hashes.back() != point.block_hash) {
        return Result<void>::Err("online chain-hash index does not match its chain point");
    }
    if (std::filesystem::exists(directory)) {
        return Result<void>::Err("online-state directory already exists");
    }
    const std::filesystem::path temporary{directory.string() + ".tmp"};
    if (std::filesystem::exists(temporary)) {
        return Result<void>::Err("online-state temporary directory already exists: " + temporary.string());
    }
    std::error_code create_error;
    std::filesystem::create_directories(temporary, create_error);
    if (create_error) return Result<void>::Err("create online-state directory: " + create_error.message());

    uint64_t capacity{NodeArena::CHUNK_SIZE};
    while (capacity < m_impl->arena.Next()) capacity += NodeArena::CHUNK_SIZE;
    auto native_written{m_impl->arena.WriteNative(temporary / "forest.hashes",
                                                   temporary / "forest.meta", capacity)};
    if (!native_written) return native_written;

    const auto chain_path{temporary / "chain.hashes"};
    const int chain_fd{::open(chain_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)};
    if (chain_fd < 0) return Result<void>::Err(ErrnoMessage("create online chain hashes"));
    auto chain_written{WriteAll(chain_fd, std::as_bytes(chain_hashes))};
    if (chain_written) chain_written = SyncDescriptor(chain_fd, "online chain hashes");
    const int chain_close{::close(chain_fd)};
    if (!chain_written) return chain_written;
    if (chain_close != 0) return Result<void>::Err(ErrnoMessage("close online chain hashes"));

    OnlineSuperblock state{
        .generation = 0,
        .base_lsn = 0,
        .point = point,
        .num_leaves = m_impl->num_leaves,
        .next = static_cast<NodeId>(m_impl->arena.Next()),
        .live_nodes = m_impl->arena.LiveCount(),
        .capacity_slots = capacity,
        .chain_hash_count = chain_hashes.size(),
        .roots = m_impl->roots,
    };
    auto state_written{WriteSuperblock(temporary, state)};
    if (!state_written) return state_written;

    std::error_code rename_error;
    std::filesystem::rename(temporary, directory, rename_error);
    if (rename_error) return Result<void>::Err("publish online-state directory: " + rename_error.message());
    const auto parent{directory.has_parent_path() ? directory.parent_path() : std::filesystem::path{"."}};
    auto parent_synced{SyncDirectory(parent)};
    if (!parent_synced) return parent_synced;

    auto mapped{m_impl->arena.SwitchToMapped(directory / "forest.hashes",
                                              directory / "forest.meta", capacity)};
    if (!mapped) {
        return Result<void>::Err("online state was published but could not be mapped: " + mapped.Error());
    }
    std::vector<Hash256> chain_copy{chain_hashes.begin(), chain_hashes.end()};
    m_impl->online = std::make_unique<OnlineStore>(directory, config, state, std::move(chain_copy));
    return Result<void>::Ok();
}

Result<PackedForest> PackedForest::OpenOnline(const std::filesystem::path& directory,
                                              std::vector<Hash256>& chain_hashes,
                                              ChainPoint& point,
                                              OnlineForestConfig config)
{
    if (config.max_dirty_bytes == 0 || config.wal_segment_bytes < 1024 * 1024 ||
        config.undo_depth == 0) {
        return Result<PackedForest>::Err("invalid online forest configuration");
    }
    auto state{ReadBestSuperblock(directory)};
    if (!state) return Result<PackedForest>::Err(state.Error());
    const auto chain_path{directory / "chain.hashes"};
    std::error_code chain_size_error;
    const uint64_t chain_size{std::filesystem::file_size(chain_path, chain_size_error)};
    const uint64_t required_chain_bytes{state.Value().chain_hash_count * Hash256::SIZE};
    if (chain_size_error || chain_size < required_chain_bytes || chain_size % Hash256::SIZE != 0) {
        return Result<PackedForest>::Err("online chain-hash file is truncated or malformed");
    }
    std::ifstream chain_input{chain_path, std::ios::binary};
    if (!chain_input) return Result<PackedForest>::Err("could not open online chain hashes");
    std::vector<Hash256> recovered_chain;
    recovered_chain.reserve(static_cast<std::size_t>(state.Value().chain_hash_count));
    for (uint64_t i{0}; i < state.Value().chain_hash_count; ++i) {
        Hash256::Storage bytes{};
        chain_input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!chain_input) return Result<PackedForest>::Err("online chain-hash file is truncated");
        recovered_chain.emplace_back(bytes);
    }
    if (recovered_chain.empty() || recovered_chain.back() != state.Value().point.block_hash) {
        return Result<PackedForest>::Err("online chain hashes do not match the base superblock");
    }

    PackedForest forest;
    forest.m_impl->roots = state.Value().roots;
    forest.m_impl->num_leaves = state.Value().num_leaves;
    auto mapped{forest.m_impl->arena.OpenMapped(directory / "forest.hashes",
                                                directory / "forest.meta",
                                                state.Value().capacity_slots,
                                                state.Value().next)};
    if (!mapped) return Result<PackedForest>::Err(mapped.Error());
    if (forest.m_impl->arena.LiveCount() != state.Value().live_nodes) {
        return Result<PackedForest>::Err("online arena live-node count does not match its superblock");
    }
    auto online{std::make_unique<OnlineStore>(directory, config, state.Value(),
                                               std::move(recovered_chain))};
    auto recovered{online->Recover(forest.m_impl->arena, forest.m_impl->roots,
                                   forest.m_impl->num_leaves)};
    if (!recovered) return Result<PackedForest>::Err(recovered.Error());
    auto bookkeeping{forest.m_impl->arena.RebuildBookkeeping()};
    if (!bookkeeping) return Result<PackedForest>::Err(bookkeeping.Error());
    auto rebuilt{forest.m_impl->RebuildIndexAndValidate()};
    if (!rebuilt) return Result<PackedForest>::Err(rebuilt.Error());
    chain_hashes = online->ChainHashes();
    point = online->Point();
    if (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
        chain_hashes.back() != point.block_hash) {
        return Result<PackedForest>::Err("recovered WAL chain does not match its online point");
    }
    forest.m_impl->online = std::move(online);
    return Result<PackedForest>::Ok(std::move(forest));
}

Result<void> PackedForest::FlushOnline()
{
    if (!m_impl->online) return Result<void>::Err("forest is not using online storage");
    if (m_impl->arena.DirtyNodes() == 0 &&
        m_impl->online->BaseLsn() == m_impl->online->CurrentLsn()) {
        return Result<void>::Ok();
    }
    return m_impl->online->FlushBase(m_impl->arena, m_impl->roots, m_impl->num_leaves);
}

Result<ChainPoint> PackedForest::RollbackOnlineBlock()
{
    if (!m_impl->online) return Result<ChainPoint>::Err("forest is not using online storage");
    const ChainPoint current{m_impl->online->Point()};
    if (current.height == 0) return Result<ChainPoint>::Err("cannot roll back the genesis point");
    auto original{m_impl->online->ReadConnectTransaction(current)};
    if (!original) return Result<ChainPoint>::Err(original.Error());
    if (original.Value().point != current) {
        return Result<ChainPoint>::Err("retained WAL transaction does not match the online tip");
    }
    WalTransaction rollback{
        .kind = WalKind::DISCONNECT,
        .previous = current,
        .point = original.Value().previous,
        .before_num_leaves = original.Value().after_num_leaves,
        .after_num_leaves = original.Value().before_num_leaves,
        .before_next = original.Value().after_next,
        .after_next = original.Value().before_next,
        .before_roots = original.Value().after_roots,
        .after_roots = original.Value().before_roots,
        .changes = {},
    };
    rollback.changes.reserve(original.Value().changes.size());
    for (const auto& change : original.Value().changes) {
        rollback.changes.push_back(NodeArena::NodeChange{
            .id = change.id,
            .before = change.after,
            .after = change.before,
            .was_dirty = false,
        });
    }

    m_impl->arena.BeginTransaction();
    auto applied{m_impl->ApplyPhysicalChanges(rollback.changes, true, rollback.after_next)};
    if (applied) {
        m_impl->roots = rollback.after_roots;
        m_impl->num_leaves = rollback.after_num_leaves;
        applied = m_impl->online->Append(rollback);
    }
    if (!applied) {
        m_impl->arena.RollbackTransaction();
        m_impl->roots = rollback.before_roots;
        m_impl->num_leaves = rollback.before_num_leaves;
        auto rebuilt{m_impl->RebuildIndexAndValidate()};
        if (!rebuilt) {
            return Result<ChainPoint>::Err(applied.Error() + "; rollback recovery failed: " + rebuilt.Error());
        }
        return Result<ChainPoint>::Err(applied.Error());
    }
    m_impl->arena.CommitTransaction();
    return Result<ChainPoint>::Ok(rollback.point);
}

bool PackedForest::IsOnline() const { return static_cast<bool>(m_impl->online); }

std::optional<ChainPoint> PackedForest::OnlinePoint() const
{
    if (!m_impl->online) return std::nullopt;
    return m_impl->online->Point();
}

OnlineForestUsage PackedForest::OnlineUsage() const
{
    if (!m_impl->online) return {};
    return OnlineForestUsage{
        .base_bytes = m_impl->arena.BaseBytes(),
        .dirty_nodes = m_impl->arena.DirtyNodes(),
        .dirty_bytes = m_impl->arena.DirtyBytes(),
        .wal_bytes = m_impl->online->WalBytes(),
        .redo_wal_bytes = m_impl->online->RedoWalBytes(),
        .base_lsn = m_impl->online->BaseLsn(),
        .current_lsn = m_impl->online->CurrentLsn(),
        .last_transaction_nodes = m_impl->online->LastTransactionNodes(),
        .last_transaction_wal_bytes = m_impl->online->LastTransactionWalBytes(),
        .last_transaction_serialize_us = m_impl->online->LastTransactionSerializeUs(),
        .last_transaction_segment_us = m_impl->online->LastTransactionSegmentUs(),
        .last_transaction_write_us = m_impl->online->LastTransactionWriteUs(),
        .last_transaction_sync_us = m_impl->online->LastTransactionSyncUs(),
        .last_transaction_publish_us = m_impl->online->LastTransactionPublishUs(),
        .last_transaction_total_us = m_impl->online->LastTransactionTotalUs(),
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
