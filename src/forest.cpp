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
#include <iterator>
#include <limits>
#include <map>
#include <new>
#include <ostream>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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

constexpr std::array<std::byte, 8> DELTA_MAGIC{
    std::byte{'U'}, std::byte{'T'}, std::byte{'R'}, std::byte{'D'},
    std::byte{'E'}, std::byte{'L'}, std::byte{'T'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> DELTA_COMMIT{
    std::byte{'D'}, std::byte{'E'}, std::byte{'L'}, std::byte{'T'},
    std::byte{'A'}, std::byte{'O'}, std::byte{'K'}, std::byte{'1'}};
constexpr uint32_t DELTA_FORMAT_VERSION{1};
constexpr uint32_t DELTA_FLAG_SNAPSHOT{1U};
constexpr std::size_t DELTA_HEADER_SIZE{432};
constexpr std::size_t DELTA_TRAILER_SIZE{sizeof(uint64_t) + DELTA_COMMIT.size()};
constexpr std::size_t DELTA_FENCE_RECORDS{64};

struct DeltaDiskRecord {
    NodeId id{NO_NODE};
    Hash256 hash;
    NodeId parent{NO_NODE};
    NodeId left{NO_NODE};
    NodeId right{NO_NODE};
    uint8_t type{0};
    std::array<uint8_t, 3> reserved{};
};

static_assert(sizeof(DeltaDiskRecord) == 52);
static_assert(std::is_trivially_copyable_v<DeltaDiskRecord>);

uint64_t MixDeltaNodeId(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

uint64_t DeltaBloomMask(NodeId id)
{
    const uint64_t hash{MixDeltaNodeId(
        static_cast<uint64_t>(id) ^ 0xd6e8feb86659fd93ULL)};
    uint64_t mask{0};
    for (uint32_t probe{0}; probe < 6; ++probe) {
        mask |= uint64_t{1} << ((hash >> (probe * 10)) & 63U);
    }
    return mask;
}

struct DeltaState {
    bool snapshot{false};
    uint64_t generation{0};
    uint64_t previous_generation{0};
    uint64_t base_generation{0};
    uint64_t physical_base_lsn{0};
    Hash256 base_fingerprint;
    uint64_t previous_lsn{0};
    uint64_t end_lsn{0};
    uint64_t base_chain_count{0};
    ChainPoint point;
    uint64_t num_leaves{0};
    NodeId next{0};
    uint64_t live_nodes{0};
    uint64_t chain_hash_count{0};
    uint64_t record_count{0};
    std::array<NodeId, 64> roots{};
};

std::string ErrnoMessage(std::string_view operation)
{
    return std::string{operation} + ": " + std::strerror(errno);
}

Result<void> SyncDescriptor(int descriptor, std::string_view description)
{
#if defined(__APPLE__)
    const int result{::fsync(descriptor)};
#else
    const int result{::fdatasync(descriptor)};
#endif
    if (result != 0) {
        return Result<void>::Err(ErrnoMessage(std::string{"sync "} + std::string{description}));
    }
    return Result<void>::Ok();
}

uint64_t ElapsedMicros(std::chrono::steady_clock::time_point start)
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count());
}

Result<void> PwriteAll(int descriptor, std::span<const std::byte> bytes, uint64_t file_offset);
Result<void> PreadAll(int descriptor, std::span<std::byte> bytes, uint64_t file_offset);
Result<void> WriteAll(int descriptor, std::span<const std::byte> bytes);
uint64_t Checksum(std::span<const std::byte> bytes);

class ScopedDescriptor
{
public:
    explicit ScopedDescriptor(int descriptor = -1) : m_descriptor{descriptor} {}
    ~ScopedDescriptor() { if (m_descriptor >= 0) ::close(m_descriptor); }
    ScopedDescriptor(const ScopedDescriptor&) = delete;
    ScopedDescriptor& operator=(const ScopedDescriptor&) = delete;
    ScopedDescriptor(ScopedDescriptor&& other) noexcept
        : m_descriptor{std::exchange(other.m_descriptor, -1)}
    {
    }
    ScopedDescriptor& operator=(ScopedDescriptor&& other) noexcept
    {
        if (this == &other) return *this;
        if (m_descriptor >= 0) ::close(m_descriptor);
        m_descriptor = std::exchange(other.m_descriptor, -1);
        return *this;
    }
    int Get() const { return m_descriptor; }
    int Release() { return std::exchange(m_descriptor, -1); }

private:
    int m_descriptor{-1};
};

int NoFollowFlag()
{
#ifdef O_NOFOLLOW
    return O_NOFOLLOW;
#else
    return 0;
#endif
}

Result<void> InspectOwnedRegularFile(int descriptor,
                                     const std::filesystem::path& path,
                                     std::string_view description)
{
    struct stat descriptor_status{};
    struct stat path_status{};
    if (::fstat(descriptor, &descriptor_status) != 0 ||
        ::lstat(path.c_str(), &path_status) != 0) {
        return Result<void>::Err(ErrnoMessage(
            std::string{"inspect "} + std::string{description}));
    }
    if (!S_ISREG(descriptor_status.st_mode) || !S_ISREG(path_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        return Result<void>::Err(std::string{description} +
            " must be an unaliased regular file in the online-state directory");
    }
    if (descriptor_status.st_nlink != 1) {
        return Result<void>::Err(std::string{description} +
            " must not be hard-linked outside its online-state path");
    }
    return Result<void>::Ok();
}

Result<ScopedDescriptor> OpenOwnedRegularFile(const std::filesystem::path& path,
                                              int flags,
                                              std::string_view description)
{
    const int descriptor{::open(path.c_str(), flags | O_CLOEXEC | NoFollowFlag(), 0600)};
    if (descriptor < 0) {
        return Result<ScopedDescriptor>::Err(ErrnoMessage(
            std::string{"open "} + std::string{description}));
    }
    ScopedDescriptor scoped{descriptor};
    auto inspected{InspectOwnedRegularFile(descriptor, path, description)};
    if (!inspected) return Result<ScopedDescriptor>::Err(inspected.Error());
    return Result<ScopedDescriptor>::Ok(std::move(scoped));
}

Result<ScopedDescriptor> CreateFreshTemporaryFile(
    const std::filesystem::path& path, std::string_view description)
{
    int descriptor{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
        NoFollowFlag(), 0600)};
    if (descriptor < 0 && errno == EEXIST) {
        struct stat path_status{};
        if (::lstat(path.c_str(), &path_status) != 0) {
            return Result<ScopedDescriptor>::Err(ErrnoMessage(
                std::string{"inspect stale "} + std::string{description}));
        }
        if (S_ISLNK(path_status.st_mode)) {
            return Result<ScopedDescriptor>::Err(
                std::string{description} + " must not be a symbolic link");
        }
        if (!S_ISREG(path_status.st_mode)) {
            return Result<ScopedDescriptor>::Err(
                std::string{description} + " must be a regular file");
        }
        auto stale{OpenOwnedRegularFile(path, O_RDONLY | O_NONBLOCK, description)};
        if (!stale) return Result<ScopedDescriptor>::Err(stale.Error());
        if (::unlink(path.c_str()) != 0) {
            return Result<ScopedDescriptor>::Err(ErrnoMessage(
                std::string{"remove stale "} + std::string{description}));
        }
        descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
            NoFollowFlag(), 0600);
    }
    if (descriptor < 0) {
        return Result<ScopedDescriptor>::Err(ErrnoMessage(
            std::string{"create "} + std::string{description}));
    }
    ScopedDescriptor scoped{descriptor};
    auto inspected{InspectOwnedRegularFile(descriptor, path, description)};
    if (!inspected) return Result<ScopedDescriptor>::Err(inspected.Error());
    return Result<ScopedDescriptor>::Ok(std::move(scoped));
}

Result<void> ValidateReplaceableOwnedFile(const std::filesystem::path& path,
                                          std::string_view description)
{
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) return Result<void>::Ok();
        return Result<void>::Err(ErrnoMessage(
            std::string{"inspect "} + std::string{description}));
    }
    if (S_ISLNK(status.st_mode)) {
        return Result<void>::Err(std::string{description} +
            " must not be a symbolic link");
    }
    auto opened{OpenOwnedRegularFile(path, O_RDONLY | O_NONBLOCK, description)};
    if (!opened) return Result<void>::Err(opened.Error());
    return Result<void>::Ok();
}

constexpr std::string_view ONLINE_LOCK_CONTENT{"utreexo-online-state-lock-v1\n"};
constexpr std::string_view ONLINE_OWNER_CONTENT{"utreexo-online-state-v1\n"};
constexpr std::string_view ONLINE_LOCK_FILE{"LOCK"};
constexpr std::string_view ONLINE_OWNER_FILE{"FORMAT"};

class OnlineStateLock
{
public:
    OnlineStateLock() = default;
    explicit OnlineStateLock(int descriptor) : m_descriptor{descriptor} {}
    ~OnlineStateLock()
    {
        if (m_descriptor >= 0) ::close(m_descriptor);
    }
    OnlineStateLock(const OnlineStateLock&) = delete;
    OnlineStateLock& operator=(const OnlineStateLock&) = delete;
    OnlineStateLock(OnlineStateLock&& other) noexcept
        : m_descriptor{std::exchange(other.m_descriptor, -1)}
    {
    }
    OnlineStateLock& operator=(OnlineStateLock&& other) noexcept
    {
        if (this == &other) return *this;
        if (m_descriptor >= 0) ::close(m_descriptor);
        m_descriptor = std::exchange(other.m_descriptor, -1);
        return *this;
    }

    static Result<OnlineStateLock> Acquire(const std::filesystem::path& directory,
                                           bool allow_create)
    {
        const auto path{directory / ONLINE_LOCK_FILE};
        const int create_flags{allow_create ? O_CREAT : 0};
        const int descriptor{::open(path.c_str(), O_RDWR | O_CLOEXEC | NoFollowFlag() |
                                                     create_flags, 0600)};
        if (descriptor < 0) {
            return Result<OnlineStateLock>::Err(ErrnoMessage(
                allow_create ? "open online-state lock" : "open existing online-state lock"));
        }
        auto inspected{InspectOwnedRegularFile(descriptor, path, "online-state lock")};
        if (!inspected) {
            ::close(descriptor);
            return Result<OnlineStateLock>::Err(inspected.Error());
        }
        if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
            const int saved_errno{errno};
            ::close(descriptor);
            errno = saved_errno;
            if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
                return Result<OnlineStateLock>::Err(
                    "online-state directory is locked by another process: " +
                    directory.string());
            }
            return Result<OnlineStateLock>::Err(ErrnoMessage("lock online state"));
        }

        struct stat status{};
        if (::fstat(descriptor, &status) != 0) {
            const auto error{ErrnoMessage("stat online-state lock")};
            ::close(descriptor);
            return Result<OnlineStateLock>::Err(error);
        }
        if (status.st_size == 0 && allow_create) {
            auto written{WriteAll(descriptor, std::as_bytes(std::span<const char>{
                ONLINE_LOCK_CONTENT.data(), ONLINE_LOCK_CONTENT.size()}))};
            if (written) written = SyncDescriptor(descriptor, "online-state lock");
            if (!written) {
                const auto& error{written.Error()};
                ::close(descriptor);
                return Result<OnlineStateLock>::Err(error);
            }
        } else {
            if (status.st_size != static_cast<off_t>(ONLINE_LOCK_CONTENT.size())) {
                ::close(descriptor);
                return Result<OnlineStateLock>::Err(
                    "online-state lock has an unrecognized format: " + path.string());
            }
            std::array<char, ONLINE_LOCK_CONTENT.size()> content{};
            const ssize_t count{::pread(descriptor, content.data(), content.size(), 0)};
            if (count != static_cast<ssize_t>(content.size()) ||
                std::string_view{content.data(), content.size()} != ONLINE_LOCK_CONTENT) {
                ::close(descriptor);
                return Result<OnlineStateLock>::Err(
                    "online-state lock has an unrecognized format: " + path.string());
            }
        }
        return Result<OnlineStateLock>::Ok(OnlineStateLock{descriptor});
    }

private:
    int m_descriptor{-1};
};

struct MappedSyncStats {
    uint64_t hash_pages{0};
    uint64_t meta_pages{0};
    uint64_t ranges{0};
    uint64_t span_bytes{0};
    uint64_t msync_us{0};
    uint64_t descriptor_sync_us{0};
};

class MappedArenaFiles
{
public:
    MappedArenaFiles() = default;
    ~MappedArenaFiles() { Close(); }
    MappedArenaFiles(const MappedArenaFiles&) = delete;
    MappedArenaFiles& operator=(const MappedArenaFiles&) = delete;

    Result<void> Open(const std::filesystem::path& hashes_path,
                      const std::filesystem::path& meta_path,
                      uint64_t capacity_slots, bool writable = false)
    {
        Close();
        if (capacity_slots == 0 || capacity_slots >= NO_NODE) {
            return Result<void>::Err("invalid mapped arena capacity");
        }
        auto hash_opened{OpenOwnedRegularFile(
            hashes_path, writable ? O_RDWR : O_RDONLY, "forest hashes")};
        if (!hash_opened) return Result<void>::Err(hash_opened.Error());
        m_hash_fd = hash_opened.Value().Release();
        auto meta_opened{OpenOwnedRegularFile(
            meta_path, writable ? O_RDWR : O_RDONLY, "forest metadata")};
        if (!meta_opened) {
            Close();
            return Result<void>::Err(meta_opened.Error());
        }
        m_meta_fd = meta_opened.Value().Release();
        const uint64_t hash_bytes{capacity_slots * sizeof(Hash256)};
        const uint64_t meta_bytes{capacity_slots * sizeof(DiskMeta)};
        struct stat hash_stat{};
        struct stat meta_stat{};
        if (::fstat(m_hash_fd, &hash_stat) != 0 || ::fstat(m_meta_fd, &meta_stat) != 0 ||
            hash_stat.st_size < 0 || meta_stat.st_size < 0 ||
            static_cast<uint64_t>(hash_stat.st_size) < hash_bytes ||
            static_cast<uint64_t>(meta_stat.st_size) < meta_bytes ||
            static_cast<uint64_t>(hash_stat.st_size) % sizeof(Hash256) != 0 ||
            static_cast<uint64_t>(meta_stat.st_size) % sizeof(DiskMeta) != 0) {
            Close();
            return Result<void>::Err("mapped arena files have unexpected sizes");
        }
        m_capacity = capacity_slots;
        const int protection{PROT_READ | (writable ? PROT_WRITE : 0)};
        m_hashes = static_cast<Hash256*>(::mmap(nullptr, static_cast<std::size_t>(hash_bytes),
                                                protection, MAP_SHARED, m_hash_fd, 0));
        if (m_hashes == MAP_FAILED) {
            m_hashes = nullptr;
            const auto error{ErrnoMessage("mmap forest hashes")};
            Close();
            return Result<void>::Err(error);
        }
        m_meta = static_cast<DiskMeta*>(::mmap(nullptr, static_cast<std::size_t>(meta_bytes),
                                               protection, MAP_SHARED, m_meta_fd, 0));
        if (m_meta == MAP_FAILED) {
            m_meta = nullptr;
            const auto error{ErrnoMessage("mmap forest metadata")};
            Close();
            return Result<void>::Err(error);
        }
        m_writable = writable;
        return Result<void>::Ok();
    }

    const Hash256& Hash(NodeId id) const { return m_hashes[id]; }
    const DiskMeta& Meta(NodeId id) const { return m_meta[id]; }
    Hash256& Hash(NodeId id) { return m_hashes[id]; }
    DiskMeta& Meta(NodeId id) { return m_meta[id]; }
    uint64_t Capacity() const { return m_capacity; }
    bool Writable() const { return m_writable; }
    uint64_t Bytes() const { return m_capacity * (sizeof(Hash256) + sizeof(DiskMeta)); }

    Result<void> SyncPages(std::span<const NodeId> ids)
    {
        m_last_sync = {};
        if (ids.empty()) return Result<void>::Ok();
        if (!std::ranges::is_sorted(ids)) {
            return Result<void>::Err("mapped arena sync node IDs are unsorted");
        }
        const long raw_page_size{::sysconf(_SC_PAGESIZE)};
        if (raw_page_size <= 0) return Result<void>::Err("could not determine system page size");
        const uint64_t page_size{static_cast<uint64_t>(raw_page_size)};
        const auto sync_mapping = [&](void* mapping, uint64_t element_size,
                                      uint64_t& page_count) -> Result<void> {
            std::vector<uint64_t> pages;
            const uint64_t mapping_pages{
                (m_capacity * element_size + page_size - 1) / page_size};
            pages.reserve(static_cast<std::size_t>(std::min<uint64_t>(
                ids.size(), mapping_pages)));
            uint64_t previous_page{std::numeric_limits<uint64_t>::max()};
            for (const NodeId id : ids) {
                const uint64_t page{
                    static_cast<uint64_t>(id) * element_size / page_size};
                if (page != previous_page) pages.push_back(page);
                previous_page = page;
            }
            page_count = pages.size();
            std::size_t begin{0};
            // A large forest can have hundreds of thousands of one-page runs.
            // Synchronizing each run separately turns a legacy base restoration into the same
            // number of blocking syscalls.  Including a small clean gap does not
            // dirty or write those pages, and collapses the syscall count without
            // weakening the MS_SYNC durability boundary.
            constexpr uint64_t MAX_CLEAN_GAP_PAGES{16};
            while (begin < pages.size()) {
                std::size_t end{begin + 1};
                while (end < pages.size() &&
                       pages[end] - pages[end - 1] <= MAX_CLEAN_GAP_PAGES + 1) {
                    ++end;
                }
                const uint64_t offset{pages[begin] * page_size};
                const uint64_t length{(pages[end - 1] - pages[begin] + 1) * page_size};
                const auto sync_start{std::chrono::steady_clock::now()};
                if (::msync(static_cast<std::byte*>(mapping) + offset,
                            static_cast<std::size_t>(length), MS_SYNC) != 0) {
                    return Result<void>::Err(ErrnoMessage("msync mapped arena"));
                }
                m_last_sync.msync_us += ElapsedMicros(sync_start);
                ++m_last_sync.ranges;
                m_last_sync.span_bytes += length;
                begin = end;
            }
            return Result<void>::Ok();
        };
        auto hashes{sync_mapping(m_hashes, sizeof(Hash256), m_last_sync.hash_pages)};
        if (!hashes) return hashes;
        auto meta{sync_mapping(m_meta, sizeof(DiskMeta), m_last_sync.meta_pages)};
        if (!meta) return meta;
        const auto descriptor_start{std::chrono::steady_clock::now()};
        auto hash_sync{SyncDescriptor(m_hash_fd, "forest hashes")};
        if (!hash_sync) return hash_sync;
        auto meta_sync{SyncDescriptor(m_meta_fd, "forest metadata")};
        m_last_sync.descriptor_sync_us = ElapsedMicros(descriptor_start);
        return meta_sync;
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
        m_writable = false;
    }

    int m_hash_fd{-1};
    int m_meta_fd{-1};
    Hash256* m_hashes{nullptr};
    DiskMeta* m_meta{nullptr};
    uint64_t m_capacity{0};
    bool m_writable{false};
    MappedSyncStats m_last_sync;
};

/** One immutable, checksummed run of NodeId-sorted overrides. */
class MappedDeltaRun
{
public:
    MappedDeltaRun() = default;
    ~MappedDeltaRun() { Close(); }
    MappedDeltaRun(const MappedDeltaRun&) = delete;
    MappedDeltaRun& operator=(const MappedDeltaRun&) = delete;

    static Result<std::unique_ptr<MappedDeltaRun>> Open(
        const std::filesystem::path& path)
    {
        auto opened{OpenOwnedRegularFile(path, O_RDONLY, "forest delta run")};
        if (!opened) {
            return Result<std::unique_ptr<MappedDeltaRun>>::Err(opened.Error());
        }
        struct stat status{};
        if (::fstat(opened.Value().Get(), &status) != 0 || status.st_size < 0 ||
            static_cast<uint64_t>(status.st_size) >
                std::numeric_limits<std::size_t>::max()) {
            return Result<std::unique_ptr<MappedDeltaRun>>::Err(
                "could not size forest delta run: " + path.string());
        }
        const auto size{static_cast<std::size_t>(status.st_size)};
        if (size < DELTA_HEADER_SIZE + DELTA_TRAILER_SIZE) {
            return Result<std::unique_ptr<MappedDeltaRun>>::Err(
                "forest delta run is truncated: " + path.string());
        }
        void* mapping{::mmap(nullptr, size, PROT_READ, MAP_SHARED,
                             opened.Value().Get(), 0)};
        if (mapping == MAP_FAILED) {
            return Result<std::unique_ptr<MappedDeltaRun>>::Err(
                ErrnoMessage("mmap forest delta run"));
        }
        auto run{std::unique_ptr<MappedDeltaRun>{new MappedDeltaRun}};
        run->m_descriptor = opened.Value().Release();
        run->m_mapping = static_cast<const std::byte*>(mapping);
        run->m_size = size;
        run->m_path = path;
        auto parsed{run->Parse()};
        if (!parsed) {
            return Result<std::unique_ptr<MappedDeltaRun>>::Err(
                path.string() + ": " + parsed.Error());
        }
#ifdef MADV_RANDOM
        static_cast<void>(::madvise(mapping, size, MADV_RANDOM));
#endif
        return Result<std::unique_ptr<MappedDeltaRun>>::Ok(std::move(run));
    }

    const DeltaState& State() const { return m_state; }
    uint64_t FileBytes() const { return m_size; }
    uint64_t FilterBytes() const
    {
        return m_filter.capacity() * sizeof(uint64_t);
    }
    uint64_t IndexBytes() const
    {
        return m_fences.capacity() * sizeof(NodeId);
    }
    const std::filesystem::path& Path() const { return m_path; }
    std::size_t RecordCount() const
    {
        return static_cast<std::size_t>(m_state.record_count);
    }
    const DeltaDiskRecord& Record(std::size_t index) const
    {
        return m_records[index];
    }
    const DeltaDiskRecord* Find(NodeId id) const
    {
        if (!MayContain(id)) return nullptr;
        const auto upper{std::upper_bound(m_fences.begin(), m_fences.end(), id)};
        if (upper == m_fences.begin()) return nullptr;
        const std::size_t fence{static_cast<std::size_t>(
            std::distance(m_fences.begin(), upper) - 1)};
        std::size_t first{fence * DELTA_FENCE_RECORDS};
        std::size_t last{std::min(first + DELTA_FENCE_RECORDS, RecordCount())};
        while (first < last) {
            const std::size_t middle{first + (last - first) / 2};
            if (m_records[middle].id < id) first = middle + 1;
            else last = middle;
        }
        if (first == RecordCount() || m_records[first].id != id) return nullptr;
        return &m_records[first];
    }
    Hash256 ChainSuffixHash(std::size_t index) const
    {
        Hash256::Storage storage{};
        const auto* begin{m_chain_suffix + index * Hash256::SIZE};
        std::copy_n(begin, Hash256::SIZE, storage.begin());
        return Hash256{storage};
    }

private:
    bool MayContain(NodeId id) const
    {
        if (m_filter.empty()) return false;
        const uint64_t hash{MixDeltaNodeId(static_cast<uint64_t>(id))};
        const auto index{static_cast<std::size_t>(
            hash % static_cast<uint64_t>(m_filter.size()))};
        const uint64_t mask{DeltaBloomMask(id)};
        return (m_filter[index] & mask) == mask;
    }

    Result<void> InitializeLookupIndex()
    {
        if (m_state.record_count == 0) return Result<void>::Ok();
        // Eight bits per record in a blocked Bloom filter keep one negative
        // lookup to one small, cache-resident word instead of faulting through
        // a disk-backed binary search. Six probes give a roughly 2% false
        // positive rate at the average occupancy.
        const uint64_t words{(m_state.record_count + 7) / 8};
        if (words > std::numeric_limits<std::size_t>::max() /
                        sizeof(uint64_t)) {
            return Result<void>::Err("forest delta filter size overflows this platform");
        }
        const uint64_t fences{
            (m_state.record_count + DELTA_FENCE_RECORDS - 1) /
            DELTA_FENCE_RECORDS};
        if (fences > std::numeric_limits<std::size_t>::max() /
                         sizeof(NodeId)) {
            return Result<void>::Err("forest delta fence index overflows this platform");
        }
        try {
            m_filter.assign(static_cast<std::size_t>(words), 0);
            m_fences.reserve(static_cast<std::size_t>(fences));
        } catch (const std::bad_alloc&) {
            return Result<void>::Err("could not allocate forest delta lookup index");
        }
        return Result<void>::Ok();
    }

    template <typename T>
    bool ReadUnsigned(std::size_t& offset, T& value) const
    {
        static_assert(std::is_unsigned_v<T>);
        if (offset + sizeof(T) > DELTA_HEADER_SIZE) return false;
        uint64_t accumulator{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            accumulator |= static_cast<uint64_t>(
                std::to_integer<uint8_t>(m_mapping[offset + i])) << (i * 8);
        }
        value = static_cast<T>(accumulator);
        offset += sizeof(T);
        return true;
    }

    bool ReadHash(std::size_t& offset, Hash256& hash) const
    {
        if (offset + Hash256::SIZE > DELTA_HEADER_SIZE) return false;
        Hash256::Storage storage{};
        std::copy_n(m_mapping + offset, Hash256::SIZE, storage.begin());
        hash = Hash256{storage};
        offset += Hash256::SIZE;
        return true;
    }

    Result<void> Parse()
    {
        const std::span<const std::byte> bytes{m_mapping, m_size};
        if (!std::equal(DELTA_COMMIT.begin(), DELTA_COMMIT.end(),
                        bytes.end() - static_cast<std::ptrdiff_t>(DELTA_COMMIT.size()))) {
            return Result<void>::Err("forest delta commit marker is missing");
        }
        const std::size_t checksum_offset{m_size - DELTA_TRAILER_SIZE};
        uint64_t expected_checksum{0};
        std::size_t checksum_cursor{checksum_offset};
        for (std::size_t i{0}; i < sizeof(expected_checksum); ++i) {
            expected_checksum |= static_cast<uint64_t>(
                std::to_integer<uint8_t>(m_mapping[checksum_cursor++])) << (i * 8);
        }
        if (Checksum(bytes.first(checksum_offset)) != expected_checksum) {
            return Result<void>::Err("forest delta checksum mismatch");
        }

        std::size_t offset{0};
        std::array<std::byte, DELTA_MAGIC.size()> magic{};
        std::copy_n(m_mapping, magic.size(), magic.begin());
        offset += magic.size();
        uint32_t version{0};
        uint32_t flags{0};
        if (magic != DELTA_MAGIC || !ReadUnsigned(offset, version) ||
            !ReadUnsigned(offset, flags) || version != DELTA_FORMAT_VERSION ||
            (flags & ~DELTA_FLAG_SNAPSHOT) != 0 ||
            !ReadUnsigned(offset, m_state.generation) ||
            !ReadUnsigned(offset, m_state.previous_generation) ||
            !ReadUnsigned(offset, m_state.base_generation) ||
            !ReadUnsigned(offset, m_state.physical_base_lsn) ||
            !ReadHash(offset, m_state.base_fingerprint) ||
            !ReadUnsigned(offset, m_state.previous_lsn) ||
            !ReadUnsigned(offset, m_state.end_lsn) ||
            !ReadUnsigned(offset, m_state.base_chain_count) ||
            !ReadUnsigned(offset, m_state.point.height) ||
            !ReadHash(offset, m_state.point.block_hash) ||
            !ReadUnsigned(offset, m_state.num_leaves) ||
            !ReadUnsigned(offset, m_state.next) ||
            !ReadUnsigned(offset, m_state.live_nodes) ||
            !ReadUnsigned(offset, m_state.chain_hash_count) ||
            !ReadUnsigned(offset, m_state.record_count)) {
            return Result<void>::Err("forest delta header is invalid");
        }
        m_state.snapshot = (flags & DELTA_FLAG_SNAPSHOT) != 0;
        for (NodeId& root : m_state.roots) {
            if (!ReadUnsigned(offset, root)) {
                return Result<void>::Err("forest delta roots are truncated");
            }
        }
        if (offset != DELTA_HEADER_SIZE || m_state.generation == 0 ||
            m_state.previous_generation >= m_state.generation ||
            m_state.previous_lsn > m_state.end_lsn || m_state.next >= NO_NODE ||
            m_state.live_nodes > m_state.next ||
            m_state.base_chain_count == 0 ||
            m_state.chain_hash_count < m_state.base_chain_count ||
            m_state.chain_hash_count !=
                static_cast<uint64_t>(m_state.point.height) + 1) {
            return Result<void>::Err("forest delta fields are inconsistent");
        }
        const uint64_t suffix_count{
            m_state.chain_hash_count - m_state.base_chain_count};
        if (m_state.record_count >
                (std::numeric_limits<std::size_t>::max() - DELTA_HEADER_SIZE -
                 DELTA_TRAILER_SIZE) / sizeof(DeltaDiskRecord) ||
            suffix_count >
                (std::numeric_limits<std::size_t>::max() - DELTA_HEADER_SIZE -
                 DELTA_TRAILER_SIZE -
                 static_cast<std::size_t>(m_state.record_count) *
                     sizeof(DeltaDiskRecord)) /
                    Hash256::SIZE) {
            return Result<void>::Err("forest delta size overflows this platform");
        }
        const std::size_t records_bytes{
            static_cast<std::size_t>(m_state.record_count) *
            sizeof(DeltaDiskRecord)};
        const std::size_t expected_size{DELTA_HEADER_SIZE + records_bytes +
            static_cast<std::size_t>(suffix_count) * Hash256::SIZE +
            DELTA_TRAILER_SIZE};
        if (expected_size != m_size) {
            return Result<void>::Err("forest delta size is inconsistent");
        }
        m_records = reinterpret_cast<const DeltaDiskRecord*>(
            m_mapping + DELTA_HEADER_SIZE);
        m_chain_suffix = m_mapping + DELTA_HEADER_SIZE + records_bytes;
        auto initialized_index{InitializeLookupIndex()};
        if (!initialized_index) return initialized_index;
        NodeId previous{NO_NODE};
        for (std::size_t i{0}; i < RecordCount(); ++i) {
            const auto& record{m_records[i]};
            const auto valid_link{[this](NodeId link) {
                return link == NO_NODE || link < m_state.next;
            }};
            if (record.id >= m_state.next ||
                (previous != NO_NODE && record.id <= previous) ||
                record.type > static_cast<uint8_t>(NodeType::BRANCH) ||
                record.reserved != std::array<uint8_t, 3>{} ||
                !valid_link(record.parent) || !valid_link(record.left) ||
                !valid_link(record.right)) {
                return Result<void>::Err(
                    "forest delta records are invalid or unsorted");
            }
            if (i % DELTA_FENCE_RECORDS == 0) m_fences.push_back(record.id);
            const uint64_t hash{MixDeltaNodeId(static_cast<uint64_t>(record.id))};
            const auto filter_index{static_cast<std::size_t>(
                hash % static_cast<uint64_t>(m_filter.size()))};
            m_filter[filter_index] |= DeltaBloomMask(record.id);
            previous = record.id;
        }
        for (const NodeId root : m_state.roots) {
            if (root != NO_NODE && root >= m_state.next) {
                return Result<void>::Err("forest delta root is out of range");
            }
        }
        if (suffix_count != 0 &&
            ChainSuffixHash(static_cast<std::size_t>(suffix_count - 1)) !=
                m_state.point.block_hash) {
            return Result<void>::Err("forest delta chain suffix has the wrong tip");
        }
        return Result<void>::Ok();
    }

    void Close()
    {
        if (m_mapping != nullptr) {
            ::munmap(const_cast<std::byte*>(m_mapping), m_size);
            m_mapping = nullptr;
        }
        if (m_descriptor >= 0) ::close(m_descriptor);
        m_descriptor = -1;
        m_size = 0;
        m_records = nullptr;
        m_chain_suffix = nullptr;
    }

    int m_descriptor{-1};
    const std::byte* m_mapping{nullptr};
    std::size_t m_size{0};
    std::filesystem::path m_path;
    DeltaState m_state;
    const DeltaDiskRecord* m_records{nullptr};
    const std::byte* m_chain_suffix{nullptr};
    std::vector<uint64_t> m_filter;
    std::vector<NodeId> m_fences;
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
            if (dirty != m_dirty.end()) return dirty->second.hash;
            if (const auto* delta{FindDeltaRecord(id)}) return delta->hash;
            if (id < m_base_next) return m_files.Hash(id);
            static const Hash256 EMPTY_HASH{};
            return EMPTY_HASH;
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
        return Mapped() ? std::max<uint64_t>(m_files.Capacity(), m_next) :
            static_cast<uint64_t>(m_chunks.size()) * CHUNK_SIZE;
    }
    uint64_t FreeCount() const { return Mapped() ? m_free_set.size() : m_free.size(); }

    uint64_t EstimatedBytes() const
    {
        constexpr uint64_t bytes_per_slot{sizeof(Hash256) + sizeof(NodeId) * 3 + sizeof(NodeType)};
        if (Mapped()) {
            return static_cast<uint64_t>(m_dirty.size()) * sizeof(NodeRecord) +
                   static_cast<uint64_t>(m_free.capacity()) * sizeof(NodeId) +
                   static_cast<uint64_t>(m_free_set.size()) * (sizeof(NodeId) * 3) +
                   DeltaFilterBytes() + DeltaIndexBytes();
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
    uint64_t DeltaBytes() const
    {
        uint64_t bytes{0};
        for (const auto& run : m_delta_runs) bytes += run->FileBytes();
        return bytes;
    }
    uint64_t DeltaFilterBytes() const
    {
        uint64_t bytes{0};
        for (const auto& run : m_delta_runs) bytes += run->FilterBytes();
        return bytes;
    }
    uint64_t DeltaIndexBytes() const
    {
        uint64_t bytes{0};
        for (const auto& run : m_delta_runs) bytes += run->IndexBytes();
        return bytes;
    }
    uint64_t DeltaRecords() const
    {
        uint64_t records{0};
        for (const auto& run : m_delta_runs) records += run->State().record_count;
        return records;
    }
    uint64_t DeltaRunCount() const { return m_delta_runs.size(); }
    uint64_t DirtyNodes() const { return m_dirty.size(); }
    uint64_t DirtyBytes() const { return static_cast<uint64_t>(m_dirty.size()) * 80; }
    std::vector<NodeId> SortedDirtyIds() const
    {
        std::vector<NodeId> ids;
        ids.reserve(m_dirty.size());
        for (const auto& [id, record] : m_dirty) {
            static_cast<void>(record);
            ids.push_back(id);
        }
        std::ranges::sort(ids);
        return ids;
    }

    std::vector<NodeId> SortedVisibleDirtyIds() const
    {
        auto ids{SortedDirtyIds()};
        const auto end{std::lower_bound(ids.begin(), ids.end(), m_next)};
        ids.erase(end, ids.end());
        return ids;
    }

    const NodeRecord& DirtyRecord(NodeId id) const { return m_dirty.at(id); }

    const std::vector<std::unique_ptr<MappedDeltaRun>>& DeltaRuns() const
    {
        return m_delta_runs;
    }

    void AppendDeltaRun(std::unique_ptr<MappedDeltaRun> run)
    {
        m_delta_runs.push_back(std::move(run));
    }

    void ReplaceDeltaRuns(std::unique_ptr<MappedDeltaRun> run)
    {
        m_delta_runs.clear();
        m_delta_runs.push_back(std::move(run));
    }

    template <typename Callback>
    void ForEachLatestDeltaRecordFrom(std::size_t first_run,
                                      Callback&& callback) const
    {
        struct Cursor {
            NodeId id{NO_NODE};
            std::size_t run_index{0};
            std::size_t record_index{0};
        };
        const auto later = [](const Cursor& left, const Cursor& right) {
            if (left.id != right.id) return left.id > right.id;
            return left.run_index > right.run_index;
        };
        std::priority_queue<Cursor, std::vector<Cursor>, decltype(later)> pending{later};
        for (std::size_t run_index{first_run}; run_index < m_delta_runs.size();
             ++run_index) {
            const auto& run{*m_delta_runs[run_index]};
            if (run.RecordCount() != 0) {
                pending.push(Cursor{run.Record(0).id, run_index, 0});
            }
        }

        // Runs and their records are oldest-to-newest and NodeId-sorted. Keep
        // one cursor per run, consume every occurrence of the smallest NodeId,
        // and emit only the occurrence from the newest run. This bounds merge
        // memory by the run count and avoids O(unique_records * run_count)
        // overlap accounting at the safety cap.
        while (!pending.empty()) {
            const NodeId next_id{pending.top().id};
            const DeltaDiskRecord* newest{nullptr};
            std::size_t newest_run{0};
            while (!pending.empty() && pending.top().id == next_id) {
                Cursor cursor{pending.top()};
                pending.pop();
                const auto& run{*m_delta_runs[cursor.run_index]};
                const auto& record{run.Record(cursor.record_index)};
                if (newest == nullptr || cursor.run_index > newest_run) {
                    newest = &record;
                    newest_run = cursor.run_index;
                }
                ++cursor.record_index;
                if (cursor.record_index < run.RecordCount()) {
                    cursor.id = run.Record(cursor.record_index).id;
                    pending.push(cursor);
                }
            }
            if (next_id < m_next && !callback(next_id, FromDisk(*newest))) return;
        }
    }

    template <typename Callback>
    void ForEachLatestDeltaRecord(Callback&& callback) const
    {
        ForEachLatestDeltaRecordFrom(0, std::forward<Callback>(callback));
    }

    uint64_t UniqueDeltaRecords() const
    {
        uint64_t records{0};
        ForEachLatestDeltaRecord(
            [&records](NodeId, const NodeRecord&) {
                ++records;
                return true;
            });
        return records;
    }

    bool EqualsPhysicalBase(NodeId id, const NodeRecord& record) const
    {
        const NodeRecord base{ReadPhysicalBase(id)};
        if (record.type == NodeType::FREE && base.type == NodeType::FREE) return true;
        return record == base;
    }

    Result<NodeRecord> BaseRecord(NodeId id) const
    {
        if (!Mapped() || id >= m_base_next) {
            return Result<NodeRecord>::Err(
                "base forest node is outside the mapped arena");
        }
        const auto& meta{m_files.Meta(id)};
        return Result<NodeRecord>::Ok(NodeRecord{
            m_files.Hash(id), meta.parent, meta.left, meta.right,
            static_cast<NodeType>(meta.type)});
    }

    Result<void> WriteNative(const std::filesystem::path& hashes_path,
                             const std::filesystem::path& meta_path,
                             uint64_t capacity_slots) const
    {
        const int hash_fd{::open(hashes_path.c_str(), O_RDWR | O_CREAT | O_EXCL |
            O_CLOEXEC | NoFollowFlag(), 0600)};
        if (hash_fd < 0) return Result<void>::Err(ErrnoMessage("create forest hashes"));
        auto hash_inspected{InspectOwnedRegularFile(hash_fd, hashes_path, "forest hashes")};
        if (!hash_inspected) {
            ::close(hash_fd);
            return hash_inspected;
        }
        const int meta_fd{::open(meta_path.c_str(), O_RDWR | O_CREAT | O_EXCL |
            O_CLOEXEC | NoFollowFlag(), 0600)};
        if (meta_fd < 0) {
            const auto error{ErrnoMessage("create forest metadata")};
            ::close(hash_fd);
            return Result<void>::Err(error);
        }
        auto meta_inspected{InspectOwnedRegularFile(meta_fd, meta_path, "forest metadata")};
        if (!meta_inspected) {
            ::close(hash_fd);
            ::close(meta_fd);
            return meta_inspected;
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
                const auto& error{hash_written.Error()};
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
                const auto& error{meta_written.Error()};
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
        m_base_next = m_next;
        return Result<void>::Ok();
    }

    Result<void> OpenMapped(const std::filesystem::path& hashes_path,
                            const std::filesystem::path& meta_path,
                            uint64_t capacity_slots, NodeId next,
                            bool rebuild_bookkeeping = true,
                            bool writable = false)
    {
        auto opened{m_files.Open(hashes_path, meta_path, capacity_slots, writable)};
        if (!opened) return opened;
        m_mapped = true;
        m_base_next = next;
        m_next = next;
        return rebuild_bookkeeping ? RebuildBookkeeping() : Result<void>::Ok();
    }

    Result<void> ReopenBaseReadOnly(const std::filesystem::path& hashes_path,
                                    const std::filesystem::path& meta_path)
    {
        if (!Mapped()) return Result<void>::Err("forest is not mapped");
        return m_files.Open(hashes_path, meta_path, m_files.Capacity(), false);
    }

    Result<void> RebuildBookkeeping()
    {
        auto rebuilt{RebuildBookkeepingAndCountLeaves()};
        if (!rebuilt) return Result<void>::Err(rebuilt.Error());
        return Result<void>::Ok();
    }

    Result<uint64_t> RebuildBookkeepingAndCountLeaves()
    {
        m_live = 0;
        m_free.clear();
        m_free_set.clear();
        uint64_t leaves{0};
        for (uint64_t raw_id{0}; raw_id < m_next; ++raw_id) {
            const NodeId id{static_cast<NodeId>(raw_id)};
            const NodeType type{Type(id)};
            if (type == NodeType::FREE) {
                m_free.push_back(id);
                if (Mapped()) m_free_set.insert(id);
            } else {
                ++m_live;
                if (type == NodeType::LEAF) ++leaves;
            }
        }
        return Result<uint64_t>::Ok(leaves);
    }

    std::vector<NodeId> SortedFreeIds() const
    {
        std::vector<NodeId> ids;
        if (Mapped()) {
            ids.reserve(m_free_set.size());
            for (const NodeId id : m_free_set) ids.push_back(id);
        } else {
            ids = m_free;
        }
        std::ranges::sort(ids);
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        return ids;
    }

    Result<void> LoadBookkeeping(NodeId next, std::vector<NodeId> free_ids)
    {
        if (!Mapped() || next >= NO_NODE ||
            !std::ranges::is_sorted(free_ids) ||
            std::adjacent_find(free_ids.begin(), free_ids.end()) !=
                free_ids.end() ||
            (!free_ids.empty() && free_ids.back() >= next)) {
            return Result<void>::Err(
                "validated startup cache has invalid free-node bookkeeping");
        }
        m_next = next;
        m_free = std::move(free_ids);
        m_free_set.clear();
        try {
            m_free_set.reserve(m_free.size() * 2);
            for (const NodeId id : m_free) m_free_set.insert(id);
        } catch (const std::bad_alloc&) {
            return Result<void>::Err(
                "could not allocate validated free-node bookkeeping");
        }
        m_live = static_cast<uint64_t>(m_next) - m_free.size();
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

    uint64_t TransactionNodeCount() const
    {
        return m_transaction ? static_cast<uint64_t>(m_transaction->size()) : 0;
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

    Result<void> RestoreBase(
        std::span<const std::pair<NodeId, NodeRecord>> ordered_records)
    {
        if (!Mapped() || !m_files.Writable()) {
            return Result<void>::Err("forest mmap base is read-only");
        }
        std::vector<NodeId> ids;
        ids.reserve(ordered_records.size());
        NodeId previous{NO_NODE};
        for (const auto& [id, record] : ordered_records) {
            static_cast<void>(record);
            if (id >= m_files.Capacity() || (previous != NO_NODE && id <= previous)) {
                return Result<void>::Err("flush undo records are outside the base or unsorted");
            }
            ids.push_back(id);
            previous = id;
        }
        for (const auto& [id, record] : ordered_records) {
            m_files.Hash(id) = record.hash;
        }
        for (const auto& [id, record] : ordered_records) {
            m_files.Meta(id) = DiskMeta{record.parent, record.left, record.right,
                                        static_cast<uint8_t>(record.type), {}};
        }
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
            if (const auto* delta{FindDeltaRecord(id)}) return FromDisk(*delta);
            return ReadPhysicalBase(id);
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

    static NodeRecord FromDisk(const DeltaDiskRecord& record)
    {
        return NodeRecord{record.hash, record.parent, record.left, record.right,
                          static_cast<NodeType>(record.type)};
    }

    const DeltaDiskRecord* FindDeltaRecord(NodeId id) const
    {
        for (auto run{m_delta_runs.rbegin()}; run != m_delta_runs.rend(); ++run) {
            if (const auto* record{(*run)->Find(id)}) return record;
        }
        return nullptr;
    }

    NodeRecord ReadPhysicalBase(NodeId id) const
    {
        if (id >= m_base_next || id >= m_files.Capacity()) return NodeRecord{};
        const auto& meta{m_files.Meta(id)};
        return NodeRecord{m_files.Hash(id), meta.parent, meta.left, meta.right,
                          static_cast<NodeType>(meta.type)};
    }

    Chunk& Get(NodeId id) { return *m_chunks.at(id >> CHUNK_SHIFT); }
    const Chunk& Get(NodeId id) const { return *m_chunks.at(id >> CHUNK_SHIFT); }

    std::vector<std::unique_ptr<Chunk>> m_chunks;
    std::vector<NodeId> m_free;
    std::unordered_set<NodeId> m_free_set;
    MappedArenaFiles m_files;
    std::unordered_map<NodeId, NodeRecord> m_dirty;
    std::vector<std::unique_ptr<MappedDeltaRun>> m_delta_runs;
    std::optional<std::unordered_map<NodeId, OriginalRecord>> m_transaction;
    std::vector<std::pair<bool, NodeId>> m_free_operations;
    NodeId m_transaction_next{0};
    uint64_t m_transaction_live{0};
    NodeId m_next{0};
    uint64_t m_live{0};
    NodeId m_base_next{0};
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

    static uint32_t ValidationHome(const Hash256& hash)
    {
        // The validation-cache table has at most 2^32 buckets, so the low 32
        // bits retain every bit used to select a home bucket.
        return static_cast<uint32_t>(Bucket(hash));
    }

    bool LoadValidationSlot(uint32_t slot, NodeId id, bool changed)
    {
        if (slot >= m_slots.size() || m_control[slot] != EMPTY) return false;
        if (changed) {
            m_control[slot] = DELETED;
            ++m_tombstones;
        } else {
            m_slots[slot] = id;
            m_control[slot] = FULL;
            ++m_size;
        }
        return true;
    }

    bool InsertValidationHome(uint32_t home, NodeId id)
    {
        if (m_slots.empty()) return false;
        const std::size_t mask{m_slots.size() - 1};
        std::size_t slot{static_cast<std::size_t>(home) & mask};
        for (std::size_t probes{0}; probes < m_slots.size(); ++probes) {
            if (m_control[slot] == EMPTY) {
                m_slots[slot] = id;
                m_control[slot] = FULL;
                ++m_size;
                return true;
            }
            slot = (slot + 1) & mask;
        }
        return false;
    }

    bool RepairValidationDeletions()
    {
        if (m_tombstones == 0) return true;
        const std::size_t mask{m_slots.size() - 1};
        const auto empty{std::ranges::find(m_control, EMPTY)};
        if (empty == m_control.end()) return false;
        std::size_t slot{
            (static_cast<std::size_t>(empty - m_control.begin()) + 1) & mask};
        std::size_t remaining{m_slots.size() - 1};
        std::vector<NodeId> survivors;
        while (remaining != 0) {
            if (m_control[slot] == EMPTY) {
                slot = (slot + 1) & mask;
                --remaining;
                continue;
            }

            const std::size_t first{slot};
            std::size_t cluster_size{0};
            std::size_t deleted{0};
            survivors.clear();
            while (remaining != 0 && m_control[slot] != EMPTY) {
                if (m_control[slot] == FULL) survivors.push_back(m_slots[slot]);
                else ++deleted;
                slot = (slot + 1) & mask;
                --remaining;
                ++cluster_size;
            }
            if (deleted == 0) continue;

            std::size_t clear_slot{first};
            for (std::size_t item{0}; item < cluster_size; ++item) {
                m_slots[clear_slot] = NO_NODE;
                m_control[clear_slot] = EMPTY;
                clear_slot = (clear_slot + 1) & mask;
            }
            m_size -= survivors.size();
            m_tombstones -= deleted;
            for (const NodeId id : survivors) {
                if (!InsertValidationHome(ValidationHome(m_arena.Hash(id)), id)) {
                    return false;
                }
            }
        }
        return m_tombstones == 0;
    }

    template <typename Callback>
    bool ForEachValidationEntry(Callback&& callback) const
    {
        for (std::size_t slot{0}; slot < m_slots.size(); ++slot) {
            if (m_control[slot] != FULL) continue;
            if (!callback(m_slots[slot], static_cast<uint32_t>(slot))) {
                return false;
            }
        }
        return true;
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
// Version 2 pairs each superblock generation with an immutable-at-publication
// chain-hash snapshot. Version-1 state/WAL remains readable for migration.
constexpr uint32_t ONLINE_FORMAT_VERSION{2};
constexpr uint32_t LEGACY_ONLINE_FORMAT_VERSION{1};

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

constexpr uint64_t CHECKSUM_OFFSET{14695981039346656037ULL};
constexpr uint64_t CHECKSUM_PRIME{1099511628211ULL};

void ExtendChecksum(uint64_t& value, std::span<const std::byte> bytes)
{
    for (const std::byte byte : bytes) {
        value ^= std::to_integer<uint8_t>(byte);
        value *= CHECKSUM_PRIME;
    }
}

uint64_t Checksum(std::span<const std::byte> bytes)
{
    uint64_t value{CHECKSUM_OFFSET};
    ExtendChecksum(value, bytes);
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

Result<void> PreadAll(int descriptor, std::span<std::byte> bytes,
                      uint64_t file_offset)
{
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t count{::pread(descriptor, bytes.data() + offset,
            bytes.size() - offset, static_cast<off_t>(file_offset + offset))};
        if (count < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("read online-state range"));
        }
        if (count == 0) {
            return Result<void>::Err("online-state file was truncated while reading");
        }
        offset += static_cast<std::size_t>(count);
    }
    return Result<void>::Ok();
}

Result<void> SyncDirectory(const std::filesystem::path& directory)
{
    const int descriptor{::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC |
        NoFollowFlag())};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open online-state directory"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoMessage("fsync online-state directory"));
    return Result<void>::Ok();
}

Result<void> WriteOnlineOwnerMarker(const std::filesystem::path& directory)
{
    const auto path{directory / ONLINE_OWNER_FILE};
    const int descriptor{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                                              O_CLOEXEC | NoFollowFlag(), 0600)};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("create online-state format marker"));
    auto inspected{InspectOwnedRegularFile(descriptor, path, "online-state format marker")};
    if (!inspected) {
        ::close(descriptor);
        return inspected;
    }
    auto written{WriteAll(descriptor, std::as_bytes(std::span<const char>{
        ONLINE_OWNER_CONTENT.data(), ONLINE_OWNER_CONTENT.size()}))};
    if (written) written = SyncDescriptor(descriptor, "online-state format marker");
    const int close_result{::close(descriptor)};
    if (!written) return written;
    if (close_result != 0) return Result<void>::Err(ErrnoMessage("close online-state format marker"));
    return SyncDirectory(directory);
}

Result<void> ValidateOnlineOwnerMarker(const std::filesystem::path& directory)
{
    const auto path{directory / ONLINE_OWNER_FILE};
    const int descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC | NoFollowFlag())};
    if (descriptor < 0) {
        return Result<void>::Err(ErrnoMessage("open online-state format marker"));
    }
    auto inspected{InspectOwnedRegularFile(descriptor, path, "online-state format marker")};
    if (!inspected) {
        ::close(descriptor);
        return inspected;
    }
    struct stat status{};
    if (::fstat(descriptor, &status) != 0) {
        const auto error{ErrnoMessage("stat online-state format marker")};
        ::close(descriptor);
        return Result<void>::Err(error);
    }
    if (status.st_size != static_cast<off_t>(ONLINE_OWNER_CONTENT.size())) {
        ::close(descriptor);
        return Result<void>::Err(
            "online-state format marker has an unrecognized size: " + path.string());
    }
    std::array<char, ONLINE_OWNER_CONTENT.size()> content{};
    const ssize_t count{::read(descriptor, content.data(), content.size())};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (count != static_cast<ssize_t>(content.size()) ||
        std::string_view{content.data(), content.size()} != ONLINE_OWNER_CONTENT) {
        return Result<void>::Err("online-state format marker is unrecognized: " + path.string());
    }
    return Result<void>::Ok();
}

class OnlineImportGuard
{
public:
    OnlineImportGuard(std::filesystem::path directory, OnlineStateLock lock)
        : m_directory{std::move(directory)}, m_lock{std::move(lock)}
    {
    }
    ~OnlineImportGuard()
    {
        if (!m_cleanup) return;
        std::error_code ignored;
        std::filesystem::remove_all(m_directory, ignored);
    }
    OnlineImportGuard(const OnlineImportGuard&) = delete;
    OnlineImportGuard& operator=(const OnlineImportGuard&) = delete;
    OnlineImportGuard(OnlineImportGuard&& other) noexcept
        : m_directory{std::move(other.m_directory)}, m_lock{std::move(other.m_lock)},
          m_cleanup{std::exchange(other.m_cleanup, false)}
    {
    }
    OnlineImportGuard& operator=(OnlineImportGuard&&) = delete;

    const std::filesystem::path& Directory() const { return m_directory; }
    OnlineStateLock ReleaseLock()
    {
        m_cleanup = false;
        return std::move(m_lock);
    }

private:
    std::filesystem::path m_directory;
    OnlineStateLock m_lock;
    bool m_cleanup{true};
};

Result<OnlineImportGuard> PrepareOnlineImport(const std::filesystem::path& directory)
{
    std::error_code status_error;
    if (std::filesystem::exists(directory, status_error)) {
        return Result<OnlineImportGuard>::Err("online-state directory already exists");
    }
    if (status_error) {
        return Result<OnlineImportGuard>::Err(
            "inspect online-state directory: " + status_error.message());
    }
    const auto parent{directory.has_parent_path() ? directory.parent_path() :
                                                   std::filesystem::path{"."}};
    std::error_code create_parent_error;
    std::filesystem::create_directories(parent, create_parent_error);
    if (create_parent_error) {
        return Result<OnlineImportGuard>::Err(
            "create online-state parent directory: " + create_parent_error.message());
    }

    const std::filesystem::path temporary{directory.string() + ".tmp"};
    status_error.clear();
    if (std::filesystem::exists(temporary, status_error)) {
        auto stale_lock{OnlineStateLock::Acquire(temporary, false)};
        if (!stale_lock) {
            return Result<OnlineImportGuard>::Err(
                "refusing to remove active or ambiguous online-state temporary directory: " +
                stale_lock.Error());
        }
        auto owned{ValidateOnlineOwnerMarker(temporary)};
        if (!owned) {
            return Result<OnlineImportGuard>::Err(
                "refusing to remove ambiguous online-state temporary directory: " +
                owned.Error());
        }
        std::error_code cleanup_error;
        std::filesystem::remove_all(temporary, cleanup_error);
        if (cleanup_error) {
            return Result<OnlineImportGuard>::Err(
                "remove stale online-state temporary directory: " + cleanup_error.message());
        }
        auto parent_synced{SyncDirectory(parent)};
        if (!parent_synced) return Result<OnlineImportGuard>::Err(parent_synced.Error());
    } else if (status_error) {
        return Result<OnlineImportGuard>::Err(
            "inspect online-state temporary directory: " + status_error.message());
    }

    std::error_code create_error;
    const bool created{std::filesystem::create_directory(temporary, create_error)};
    if (create_error || !created) {
        return Result<OnlineImportGuard>::Err(
            "create online-state temporary directory: " +
            (create_error ? create_error.message() : std::string{"already exists"}));
    }
    auto lock{OnlineStateLock::Acquire(temporary, true)};
    if (!lock) {
        std::error_code ignored;
        std::filesystem::remove_all(temporary, ignored);
        return Result<OnlineImportGuard>::Err(lock.Error());
    }
    auto marker{WriteOnlineOwnerMarker(temporary)};
    if (!marker) {
        std::error_code ignored;
        std::filesystem::remove_all(temporary, ignored);
        return Result<OnlineImportGuard>::Err(marker.Error());
    }
    return Result<OnlineImportGuard>::Ok(
        OnlineImportGuard{temporary, lock.Take()});
}

struct OnlineSuperblock {
    uint32_t format_version{ONLINE_FORMAT_VERSION};
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

std::filesystem::path ChainHashesPath(const std::filesystem::path& directory,
                                      uint64_t generation)
{
    return directory /
        (generation % 2 == 0 ? "chain.0.hashes" : "chain.1.hashes");
}

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
        (version != LEGACY_ONLINE_FORMAT_VERSION && version != ONLINE_FORMAT_VERSION) ||
        !reader.ReadUnsigned(state.generation) ||
        !reader.ReadUnsigned(state.base_lsn) || !reader.ReadUnsigned(state.point.height) ||
        !reader.ReadHash(state.point.block_hash) || !reader.ReadUnsigned(state.num_leaves) ||
        !reader.ReadUnsigned(state.next) || !reader.ReadUnsigned(state.live_nodes) ||
        !reader.ReadUnsigned(state.capacity_slots) || !reader.ReadUnsigned(state.chain_hash_count)) {
        return Result<OnlineSuperblock>::Err("invalid online superblock");
    }
    state.format_version = version;
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
    auto opened{CreateFreshTemporaryFile(temporary, "online superblock temporary file")};
    if (!opened) return Result<void>::Err(opened.Error());
    auto written{WriteAll(opened.Value().Get(), bytes)};
    if (written) written = SyncDescriptor(opened.Value().Get(), "online superblock");
    if (!written) return written;
    auto inspected{InspectOwnedRegularFile(opened.Value().Get(), temporary,
                                           "online superblock temporary file")};
    if (!inspected) return inspected;
    auto replaceable{ValidateReplaceableOwnedFile(final_path, "online superblock")};
    if (!replaceable) return replaceable;
    std::error_code rename_error;
    std::filesystem::rename(temporary, final_path, rename_error);
    if (rename_error) return Result<void>::Err("publish online superblock: " + rename_error.message());
    inspected = InspectOwnedRegularFile(opened.Value().Get(), final_path,
                                        "published online superblock");
    if (!inspected) return inspected;
    return SyncDirectory(directory);
}

struct OwnedFileContents {
    ScopedDescriptor descriptor;
    std::vector<std::byte> bytes;
};

Result<OwnedFileContents> ReadOwnedFile(const std::filesystem::path& path,
                                       bool writable = false)
{
    auto opened{OpenOwnedRegularFile(path, writable ? O_RDWR : O_RDONLY,
                                     "online-state file " + path.filename().string())};
    if (!opened) return Result<OwnedFileContents>::Err(opened.Error());
    struct stat status{};
    if (::fstat(opened.Value().Get(), &status) != 0 || status.st_size < 0 ||
        static_cast<uint64_t>(status.st_size) > std::numeric_limits<std::size_t>::max()) {
        return Result<OwnedFileContents>::Err("could not size " + path.string());
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(status.st_size));
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t count{::pread(opened.Value().Get(), bytes.data() + offset,
                                    bytes.size() - offset, static_cast<off_t>(offset))};
        if (count < 0) {
            if (errno == EINTR) continue;
            return Result<OwnedFileContents>::Err(ErrnoMessage("read " + path.string()));
        }
        if (count == 0) {
            return Result<OwnedFileContents>::Err("online-state file was truncated while reading: " +
                                                  path.string());
        }
        offset += static_cast<std::size_t>(count);
    }
    auto inspected{InspectOwnedRegularFile(opened.Value().Get(), path,
        "online-state file " + path.filename().string())};
    if (!inspected) return Result<OwnedFileContents>::Err(inspected.Error());
    return Result<OwnedFileContents>::Ok(OwnedFileContents{
        .descriptor = opened.Take(),
        .bytes = std::move(bytes),
    });
}

Result<std::vector<std::byte>> ReadFile(const std::filesystem::path& path)
{
    auto read{ReadOwnedFile(path)};
    if (!read) return Result<std::vector<std::byte>>::Err(read.Error());
    return Result<std::vector<std::byte>>::Ok(std::move(read.Value().bytes));
}

constexpr std::array<std::byte, 8> FLUSH_UNDO_MAGIC{
    std::byte{'U'}, std::byte{'T'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'L'}, std::byte{'S'}, std::byte{'H'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> FLUSH_UNDO_COMMIT{
    std::byte{'F'}, std::byte{'L'}, std::byte{'U'}, std::byte{'S'},
    std::byte{'H'}, std::byte{'E'}, std::byte{'D'}, std::byte{'1'}};
constexpr uint32_t FLUSH_UNDO_VERSION{1};
constexpr std::string_view FLUSH_UNDO_NAME{"flush.undo"};
constexpr std::size_t FLUSH_UNDO_HEADER_SIZE{
    FLUSH_UNDO_MAGIC.size() + sizeof(uint32_t) + sizeof(uint64_t) * 3 +
    sizeof(uint32_t) + Hash256::SIZE + sizeof(uint64_t)};
constexpr std::size_t FLUSH_UNDO_RECORD_SIZE{sizeof(NodeId) + 48};
constexpr std::size_t FLUSH_UNDO_TRAILER_SIZE{
    sizeof(uint64_t) + FLUSH_UNDO_COMMIT.size()};

struct FlushUndoFile {
    ScopedDescriptor descriptor;
    uint64_t base_generation{0};
    uint64_t target_generation{0};
    uint64_t target_base_lsn{0};
    ChainPoint target_point;
    std::vector<std::pair<NodeId, NodeRecord>> records;
};

Result<std::optional<FlushUndoFile>> ReadFlushUndo(
    const std::filesystem::path& directory)
{
    const auto path{directory / FLUSH_UNDO_NAME};
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        if (errno == ENOENT) {
            return Result<std::optional<FlushUndoFile>>::Ok(std::nullopt);
        }
        return Result<std::optional<FlushUndoFile>>::Err(
            ErrnoMessage("inspect flush undo journal"));
    }
    auto owned{ReadOwnedFile(path)};
    if (!owned) return Result<std::optional<FlushUndoFile>>::Err(owned.Error());
    const auto& bytes{owned.Value().bytes};
    if (bytes.size() < FLUSH_UNDO_HEADER_SIZE + FLUSH_UNDO_TRAILER_SIZE) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal is truncated");
    }
    std::array<std::byte, FLUSH_UNDO_COMMIT.size()> commit{};
    std::copy(bytes.end() - static_cast<std::ptrdiff_t>(commit.size()),
              bytes.end(), commit.begin());
    if (commit != FLUSH_UNDO_COMMIT) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal commit marker is missing");
    }
    const std::size_t checksum_offset{bytes.size() - FLUSH_UNDO_TRAILER_SIZE};
    uint64_t expected_checksum{0};
    ByteReader checksum_reader{
        std::span<const std::byte>{bytes}.subspan(checksum_offset, sizeof(uint64_t))};
    if (!checksum_reader.ReadUnsigned(expected_checksum) ||
        Checksum(std::span<const std::byte>{bytes}.first(checksum_offset)) !=
            expected_checksum) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal checksum mismatch");
    }

    ByteReader reader{std::span<const std::byte>{bytes}.first(checksum_offset)};
    std::array<std::byte, FLUSH_UNDO_MAGIC.size()> magic{};
    uint32_t version{0};
    uint64_t record_count{0};
    FlushUndoFile journal;
    if (!reader.ReadBytes(magic) || magic != FLUSH_UNDO_MAGIC ||
        !reader.ReadUnsigned(version) || version != FLUSH_UNDO_VERSION ||
        !reader.ReadUnsigned(journal.base_generation) ||
        !reader.ReadUnsigned(journal.target_generation) ||
        !reader.ReadUnsigned(journal.target_base_lsn) ||
        !reader.ReadUnsigned(journal.target_point.height) ||
        !reader.ReadHash(journal.target_point.block_hash) ||
        !reader.ReadUnsigned(record_count) || record_count >= NO_NODE ||
        journal.target_generation != journal.base_generation + 1) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal header is invalid");
    }
    if (record_count >
        (std::numeric_limits<std::size_t>::max() - FLUSH_UNDO_HEADER_SIZE -
         FLUSH_UNDO_TRAILER_SIZE) / FLUSH_UNDO_RECORD_SIZE ||
        bytes.size() != FLUSH_UNDO_HEADER_SIZE +
            static_cast<std::size_t>(record_count) * FLUSH_UNDO_RECORD_SIZE +
            FLUSH_UNDO_TRAILER_SIZE) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal size is inconsistent");
    }
    journal.records.reserve(static_cast<std::size_t>(record_count));
    NodeId previous{NO_NODE};
    for (uint64_t index{0}; index < record_count; ++index) {
        NodeId id{NO_NODE};
        NodeRecord record;
        if (!reader.ReadUnsigned(id) || !reader.ReadRecord(record) ||
            (previous != NO_NODE && id <= previous)) {
            return Result<std::optional<FlushUndoFile>>::Err(
                "flush undo journal records are invalid or unsorted");
        }
        journal.records.emplace_back(id, record);
        previous = id;
    }
    if (!reader.Done()) {
        return Result<std::optional<FlushUndoFile>>::Err(
            "flush undo journal has trailing payload data");
    }
    journal.descriptor = std::move(owned.Value().descriptor);
    return Result<std::optional<FlushUndoFile>>::Ok(
        std::optional<FlushUndoFile>{std::move(journal)});
}

Result<void> RemoveFlushUndo(const std::filesystem::path& directory,
                             const FlushUndoFile& journal)
{
    const auto path{directory / FLUSH_UNDO_NAME};
    auto inspected{InspectOwnedRegularFile(journal.descriptor.Get(), path,
                                           "flush undo journal")};
    if (!inspected) return inspected;
    if (::unlink(path.c_str()) != 0) {
        return Result<void>::Err(ErrnoMessage("remove flush undo journal"));
    }
    return SyncDirectory(directory);
}

Result<OnlineSuperblock> ReadBestSuperblock(const std::filesystem::path& directory)
{
    std::optional<OnlineSuperblock> best;
    std::string errors;
    for (const std::string_view name : {"state.0", "state.1"}) {
        const auto path{directory / name};
        struct stat state_status{};
        if (::lstat(path.c_str(), &state_status) != 0) {
            if (errno == ENOENT) continue;
            errors += ErrnoMessage("inspect online superblock") + "; ";
            continue;
        }
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
        const auto chain_path{parsed.Value().format_version >= ONLINE_FORMAT_VERSION ?
            ChainHashesPath(directory, parsed.Value().generation) :
            directory / "chain.hashes"};
        auto chain_bytes{ReadFile(chain_path)};
        const uint64_t required_size{parsed.Value().chain_hash_count * Hash256::SIZE};
        if (!chain_bytes) {
            errors += chain_bytes.Error() + "; ";
            continue;
        }
        if (chain_bytes.Value().size() % Hash256::SIZE != 0 ||
            (parsed.Value().format_version >= ONLINE_FORMAT_VERSION ?
                chain_bytes.Value().size() != required_size :
                chain_bytes.Value().size() < required_size)) {
            errors += "state has no complete matching chain-hash snapshot; ";
            continue;
        }
        Hash256::Storage tip_bytes{};
        const std::size_t tip_offset{static_cast<std::size_t>(
            (parsed.Value().chain_hash_count - 1) * Hash256::SIZE)};
        std::copy_n(chain_bytes.Value().begin() + static_cast<std::ptrdiff_t>(tip_offset),
                    Hash256::SIZE, tip_bytes.begin());
        if (Hash256{tip_bytes} != parsed.Value().point.block_hash) {
            errors += "state chain-hash snapshot has the wrong tip; ";
            continue;
        }
        if (!best || parsed.Value().generation > best->generation) best = parsed.Take();
    }
    if (!best) return Result<OnlineSuperblock>::Err("no valid online superblock: " + errors);
    return Result<OnlineSuperblock>::Ok(*best);
}

Result<Hash256> OnlineBaseFingerprint(const OnlineSuperblock& state,
                                      const NodeArena& arena)
{
    auto bytes{SerializeSuperblock(state)};
    bytes.reserve(bytes.size() + state.roots.size() * Hash256::SIZE);
    for (const NodeId root : state.roots) {
        if (root == NO_NODE) {
            bytes.insert(bytes.end(), Hash256::SIZE, std::byte{0});
            continue;
        }
        auto record{arena.BaseRecord(root)};
        if (!record) return Result<Hash256>::Err(record.Error());
        AppendHash(bytes, record.Value().hash);
    }
    return Result<Hash256>::Ok(Sha512_256(bytes));
}

struct OwnedFileIdentity {
    uint64_t device{0};
    uint64_t inode{0};
    uint64_t size{0};
    uint64_t modified_seconds{0};
    uint64_t modified_nanoseconds{0};
    uint64_t changed_seconds{0};
    uint64_t changed_nanoseconds{0};
    auto operator<=>(const OwnedFileIdentity&) const = default;
};

Result<OwnedFileIdentity> ReadOwnedFileIdentity(
    const std::filesystem::path& path, std::string_view description)
{
    auto opened{OpenOwnedRegularFile(path, O_RDONLY | O_NONBLOCK, description)};
    if (!opened) return Result<OwnedFileIdentity>::Err(opened.Error());
    struct stat status{};
    if (::fstat(opened.Value().Get(), &status) != 0 || status.st_size < 0) {
        return Result<OwnedFileIdentity>::Err(
            ErrnoMessage(std::string{"stat "} + std::string{description}));
    }
#if defined(__APPLE__)
    const auto modified{status.st_mtimespec};
    const auto changed{status.st_ctimespec};
#else
    const auto modified{status.st_mtim};
    const auto changed{status.st_ctim};
#endif
    return Result<OwnedFileIdentity>::Ok(OwnedFileIdentity{
        .device = static_cast<uint64_t>(status.st_dev),
        .inode = static_cast<uint64_t>(status.st_ino),
        .size = static_cast<uint64_t>(status.st_size),
        .modified_seconds = static_cast<uint64_t>(modified.tv_sec),
        .modified_nanoseconds = static_cast<uint64_t>(modified.tv_nsec),
        .changed_seconds = static_cast<uint64_t>(changed.tv_sec),
        .changed_nanoseconds = static_cast<uint64_t>(changed.tv_nsec),
    });
}

constexpr std::array<std::byte, 8> VALIDATED_CACHE_MAGIC{
    std::byte{'U'}, std::byte{'T'}, std::byte{'R'}, std::byte{'V'},
    std::byte{'A'}, std::byte{'L'}, std::byte{'0'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> VALIDATED_CACHE_COMMIT{
    std::byte{'V'}, std::byte{'A'}, std::byte{'L'}, std::byte{'I'},
    std::byte{'D'}, std::byte{'O'}, std::byte{'K'}, std::byte{'1'}};
constexpr uint32_t VALIDATED_CACHE_VERSION{1};
constexpr std::string_view VALIDATED_CACHE_NAME{"validated-state.cache"};
constexpr std::size_t VALIDATED_CACHE_ENTRY_SIZE{
    sizeof(NodeId) + sizeof(uint32_t)};
constexpr std::size_t VALIDATED_CACHE_HEADER_SIZE{824};
constexpr std::size_t VALIDATED_CACHE_TRAILER_SIZE{
    sizeof(uint64_t) + VALIDATED_CACHE_COMMIT.size()};

std::optional<uint64_t> ValidatedIndexCapacity(uint64_t entries)
{
    constexpr uint64_t MAX_CAPACITY{uint64_t{1} << 32};
    if (entries > (MAX_CAPACITY * 8 - 7) / 10) return std::nullopt;
    const uint64_t required{
        std::max<uint64_t>(16, (entries * 10 + 7) / 8)};
    if (required > MAX_CAPACITY) return std::nullopt;
    return std::bit_ceil(required);
}

uint64_t MaximumValidatedIndexCapacity(NodeId next)
{
    return std::bit_ceil(std::max<uint64_t>(16, next));
}

struct ValidationAnchor {
    uint64_t generation{0};
    uint64_t lsn{0};
    ChainPoint point;
    uint64_t num_leaves{0};
    NodeId next{0};
    uint64_t live_nodes{0};
    std::array<NodeId, 64> roots{};
};

struct ValidatedCacheHeader {
    OnlineSuperblock base;
    OwnedFileIdentity hashes_identity;
    OwnedFileIdentity metadata_identity;
    ValidationAnchor anchor;
    uint64_t index_capacity{0};
    uint64_t index_entries{0};
    uint64_t free_nodes{0};
};

void AppendFileIdentity(std::vector<std::byte>& bytes,
                        const OwnedFileIdentity& identity)
{
    AppendUnsigned(bytes, identity.device);
    AppendUnsigned(bytes, identity.inode);
    AppendUnsigned(bytes, identity.size);
    AppendUnsigned(bytes, identity.modified_seconds);
    AppendUnsigned(bytes, identity.modified_nanoseconds);
    AppendUnsigned(bytes, identity.changed_seconds);
    AppendUnsigned(bytes, identity.changed_nanoseconds);
}

bool ReadFileIdentity(ByteReader& reader, OwnedFileIdentity& identity)
{
    return reader.ReadUnsigned(identity.device) &&
        reader.ReadUnsigned(identity.inode) &&
        reader.ReadUnsigned(identity.size) &&
        reader.ReadUnsigned(identity.modified_seconds) &&
        reader.ReadUnsigned(identity.modified_nanoseconds) &&
        reader.ReadUnsigned(identity.changed_seconds) &&
        reader.ReadUnsigned(identity.changed_nanoseconds);
}

std::vector<std::byte> SerializeValidatedCacheHeader(
    const ValidatedCacheHeader& header)
{
    std::vector<std::byte> bytes;
    bytes.reserve(VALIDATED_CACHE_HEADER_SIZE);
    bytes.insert(bytes.end(), VALIDATED_CACHE_MAGIC.begin(),
                 VALIDATED_CACHE_MAGIC.end());
    AppendUnsigned(bytes, VALIDATED_CACHE_VERSION);
    AppendUnsigned(bytes, header.base.format_version);
    AppendUnsigned(bytes, header.base.generation);
    AppendUnsigned(bytes, header.base.base_lsn);
    AppendUnsigned(bytes, header.base.point.height);
    AppendHash(bytes, header.base.point.block_hash);
    AppendUnsigned(bytes, header.base.num_leaves);
    AppendUnsigned(bytes, header.base.next);
    AppendUnsigned(bytes, header.base.live_nodes);
    AppendUnsigned(bytes, header.base.capacity_slots);
    AppendUnsigned(bytes, header.base.chain_hash_count);
    for (const NodeId root : header.base.roots) AppendUnsigned(bytes, root);
    AppendFileIdentity(bytes, header.hashes_identity);
    AppendFileIdentity(bytes, header.metadata_identity);
    AppendUnsigned(bytes, header.anchor.generation);
    AppendUnsigned(bytes, header.anchor.lsn);
    AppendUnsigned(bytes, header.anchor.point.height);
    AppendHash(bytes, header.anchor.point.block_hash);
    AppendUnsigned(bytes, header.anchor.num_leaves);
    AppendUnsigned(bytes, header.anchor.next);
    AppendUnsigned(bytes, header.anchor.live_nodes);
    for (const NodeId root : header.anchor.roots) AppendUnsigned(bytes, root);
    AppendUnsigned(bytes, header.index_capacity);
    AppendUnsigned(bytes, header.index_entries);
    AppendUnsigned(bytes, header.free_nodes);
    return bytes;
}

Result<ValidatedCacheHeader> ParseValidatedCacheHeader(
    std::span<const std::byte> bytes)
{
    if (bytes.size() != VALIDATED_CACHE_HEADER_SIZE) {
        return Result<ValidatedCacheHeader>::Err(
            "validated startup cache header has an unexpected size");
    }
    ByteReader reader{bytes};
    std::array<std::byte, VALIDATED_CACHE_MAGIC.size()> magic{};
    uint32_t version{0};
    ValidatedCacheHeader header;
    if (!reader.ReadBytes(magic) || magic != VALIDATED_CACHE_MAGIC ||
        !reader.ReadUnsigned(version) || version != VALIDATED_CACHE_VERSION ||
        !reader.ReadUnsigned(header.base.format_version) ||
        !reader.ReadUnsigned(header.base.generation) ||
        !reader.ReadUnsigned(header.base.base_lsn) ||
        !reader.ReadUnsigned(header.base.point.height) ||
        !reader.ReadHash(header.base.point.block_hash) ||
        !reader.ReadUnsigned(header.base.num_leaves) ||
        !reader.ReadUnsigned(header.base.next) ||
        !reader.ReadUnsigned(header.base.live_nodes) ||
        !reader.ReadUnsigned(header.base.capacity_slots) ||
        !reader.ReadUnsigned(header.base.chain_hash_count)) {
        return Result<ValidatedCacheHeader>::Err(
            "validated startup cache header is invalid");
    }
    for (NodeId& root : header.base.roots) {
        if (!reader.ReadUnsigned(root)) {
            return Result<ValidatedCacheHeader>::Err(
                "validated startup cache base roots are truncated");
        }
    }
    if (!ReadFileIdentity(reader, header.hashes_identity) ||
        !ReadFileIdentity(reader, header.metadata_identity) ||
        !reader.ReadUnsigned(header.anchor.generation) ||
        !reader.ReadUnsigned(header.anchor.lsn) ||
        !reader.ReadUnsigned(header.anchor.point.height) ||
        !reader.ReadHash(header.anchor.point.block_hash) ||
        !reader.ReadUnsigned(header.anchor.num_leaves) ||
        !reader.ReadUnsigned(header.anchor.next) ||
        !reader.ReadUnsigned(header.anchor.live_nodes)) {
        return Result<ValidatedCacheHeader>::Err(
            "validated startup cache anchor is truncated");
    }
    for (NodeId& root : header.anchor.roots) {
        if (!reader.ReadUnsigned(root)) {
            return Result<ValidatedCacheHeader>::Err(
                "validated startup cache anchor roots are truncated");
        }
    }
    if (!reader.ReadUnsigned(header.index_capacity) ||
        !reader.ReadUnsigned(header.index_entries) ||
        !reader.ReadUnsigned(header.free_nodes) || !reader.Done()) {
        return Result<ValidatedCacheHeader>::Err(
            "validated startup cache fields are truncated");
    }
    const auto minimum_index_capacity{
        ValidatedIndexCapacity(header.index_entries)};
    if ((header.base.format_version != LEGACY_ONLINE_FORMAT_VERSION &&
         header.base.format_version != ONLINE_FORMAT_VERSION) ||
        header.base.next >= NO_NODE ||
        header.base.live_nodes > header.base.next ||
        header.base.capacity_slots < header.base.next ||
        header.base.capacity_slots >= NO_NODE ||
        header.base.chain_hash_count !=
            static_cast<uint64_t>(header.base.point.height) + 1 ||
        header.anchor.next >= NO_NODE ||
        header.anchor.live_nodes > header.anchor.next ||
        header.anchor.point.height == std::numeric_limits<uint32_t>::max() ||
        !minimum_index_capacity ||
        !std::has_single_bit(header.index_capacity) ||
        header.index_capacity < *minimum_index_capacity ||
        header.index_capacity >
            MaximumValidatedIndexCapacity(header.anchor.next) ||
        header.index_entries >= header.index_capacity ||
        header.free_nodes !=
            static_cast<uint64_t>(header.anchor.next) -
                header.anchor.live_nodes) {
        return Result<ValidatedCacheHeader>::Err(
            "validated startup cache fields are inconsistent");
    }
    return Result<ValidatedCacheHeader>::Ok(header);
}

bool SameBaseState(const OnlineSuperblock& left,
                   const OnlineSuperblock& right)
{
    return left.format_version == right.format_version &&
        left.generation == right.generation &&
        left.base_lsn == right.base_lsn && left.point == right.point &&
        left.num_leaves == right.num_leaves && left.next == right.next &&
        left.live_nodes == right.live_nodes &&
        left.capacity_slots == right.capacity_slots &&
        left.chain_hash_count == right.chain_hash_count &&
        left.roots == right.roots;
}

Result<uint64_t> WriteValidatedStartupCache(
    const std::filesystem::path& directory, const OnlineSuperblock& base,
    const ValidationAnchor& anchor, const NodeArena& arena,
    const KeylessLeafIndex& index)
{
    const auto hashes_identity{ReadOwnedFileIdentity(
        directory / "forest.hashes", "forest hashes")};
    if (!hashes_identity) return Result<uint64_t>::Err(hashes_identity.Error());
    const auto metadata_identity{ReadOwnedFileIdentity(
        directory / "forest.meta", "forest metadata")};
    if (!metadata_identity) {
        return Result<uint64_t>::Err(metadata_identity.Error());
    }
    auto free_ids{arena.SortedFreeIds()};
    const auto minimum_index_capacity{ValidatedIndexCapacity(index.Size())};
    if (anchor.next != arena.Next() || anchor.live_nodes != arena.LiveCount() ||
        anchor.live_nodes + free_ids.size() != anchor.next ||
        !minimum_index_capacity ||
        !std::has_single_bit(index.Capacity()) ||
        index.Capacity() < *minimum_index_capacity ||
        index.Capacity() > MaximumValidatedIndexCapacity(anchor.next)) {
        return Result<uint64_t>::Err(
            "cannot cache inconsistent validated online bookkeeping");
    }
    const ValidatedCacheHeader header{
        .base = base,
        .hashes_identity = hashes_identity.Value(),
        .metadata_identity = metadata_identity.Value(),
        .anchor = anchor,
        .index_capacity = index.Capacity(),
        .index_entries = index.Size(),
        .free_nodes = free_ids.size(),
    };
    const auto header_bytes{SerializeValidatedCacheHeader(header)};
    if (header_bytes.size() != VALIDATED_CACHE_HEADER_SIZE) {
        return Result<uint64_t>::Err(
            "validated startup cache header size changed unexpectedly");
    }
    if (header.index_entries >
            (std::numeric_limits<uint64_t>::max() -
             VALIDATED_CACHE_HEADER_SIZE - VALIDATED_CACHE_TRAILER_SIZE) /
                VALIDATED_CACHE_ENTRY_SIZE ||
        header.free_nodes >
            (std::numeric_limits<uint64_t>::max() -
             VALIDATED_CACHE_HEADER_SIZE - VALIDATED_CACHE_TRAILER_SIZE -
             header.index_entries * VALIDATED_CACHE_ENTRY_SIZE) /
                sizeof(NodeId)) {
        return Result<uint64_t>::Err(
            "validated startup cache size overflows");
    }

    const auto final_path{directory / VALIDATED_CACHE_NAME};
    const std::filesystem::path temporary{final_path.string() + ".tmp"};
    auto opened{CreateFreshTemporaryFile(
        temporary, "validated startup cache temporary file")};
    if (!opened) return Result<uint64_t>::Err(opened.Error());
    uint64_t checksum{CHECKSUM_OFFSET};
    ExtendChecksum(checksum, header_bytes);
    auto written{WriteAll(opened.Value().Get(), header_bytes)};
    if (!written) return Result<uint64_t>::Err(written.Error());

    constexpr std::size_t BUFFER_BYTES{1024 * 1024};
    std::vector<std::byte> buffer;
    buffer.reserve(BUFFER_BYTES);
    const auto flush = [&]() -> Result<void> {
        if (buffer.empty()) return Result<void>::Ok();
        ExtendChecksum(checksum, buffer);
        auto result{WriteAll(opened.Value().Get(), buffer)};
        buffer.clear();
        return result;
    };
    Result<void> payload_result{Result<void>::Ok()};
    uint64_t entries_written{0};
    index.ForEachValidationEntry([&](NodeId id, uint32_t slot) {
        if (!payload_result) return false;
        AppendUnsigned(buffer, id);
        AppendUnsigned(buffer, slot);
        ++entries_written;
        if (buffer.size() >= BUFFER_BYTES) payload_result = flush();
        return static_cast<bool>(payload_result);
    });
    if (payload_result && entries_written != header.index_entries) {
        payload_result = Result<void>::Err(
            "validated leaf index changed while it was cached");
    }
    NodeId previous{NO_NODE};
    for (const NodeId id : free_ids) {
        if (!payload_result) break;
        if (id >= anchor.next || (previous != NO_NODE && id <= previous)) {
            payload_result = Result<void>::Err(
                "validated free-node list is not sorted and unique");
            break;
        }
        AppendUnsigned(buffer, id);
        previous = id;
        if (buffer.size() >= BUFFER_BYTES) payload_result = flush();
    }
    if (payload_result) payload_result = flush();
    if (!payload_result) return Result<uint64_t>::Err(payload_result.Error());

    std::vector<std::byte> trailer;
    trailer.reserve(VALIDATED_CACHE_TRAILER_SIZE);
    AppendUnsigned(trailer, checksum);
    trailer.insert(trailer.end(), VALIDATED_CACHE_COMMIT.begin(),
                   VALIDATED_CACHE_COMMIT.end());
    written = WriteAll(opened.Value().Get(), trailer);
    if (written) {
        written = SyncDescriptor(opened.Value().Get(),
                                 "validated startup cache");
    }
    if (!written) return Result<uint64_t>::Err(written.Error());
    auto inspected{InspectOwnedRegularFile(
        opened.Value().Get(), temporary,
        "validated startup cache temporary file")};
    if (!inspected) return Result<uint64_t>::Err(inspected.Error());
    auto replaceable{ValidateReplaceableOwnedFile(
        final_path, "validated startup cache")};
    if (!replaceable) return Result<uint64_t>::Err(replaceable.Error());
    std::error_code rename_error;
    std::filesystem::rename(temporary, final_path, rename_error);
    if (rename_error) {
        return Result<uint64_t>::Err(
            "publish validated startup cache: " + rename_error.message());
    }
    inspected = InspectOwnedRegularFile(opened.Value().Get(), final_path,
                                        "published validated startup cache");
    if (!inspected) return Result<uint64_t>::Err(inspected.Error());
    auto synced{SyncDirectory(directory)};
    if (!synced) return Result<uint64_t>::Err(synced.Error());
    return Result<uint64_t>::Ok(
        VALIDATED_CACHE_HEADER_SIZE +
        header.index_entries * VALIDATED_CACHE_ENTRY_SIZE +
        header.free_nodes * sizeof(NodeId) +
        VALIDATED_CACHE_TRAILER_SIZE);
}

std::filesystem::path DeltaPath(const std::filesystem::path& directory,
                                uint64_t generation)
{
    std::ostringstream name;
    name << "delta-" << std::setw(20) << std::setfill('0') << generation
         << ".run";
    return directory / name.str();
}

std::optional<uint64_t> DeltaGeneration(std::string_view name)
{
    constexpr std::size_t PREFIX_SIZE{6};
    constexpr std::size_t DIGITS{20};
    constexpr std::string_view SUFFIX{".run"};
    if (name.size() != PREFIX_SIZE + DIGITS + SUFFIX.size() ||
        !name.starts_with("delta-") || !name.ends_with(SUFFIX)) {
        return std::nullopt;
    }
    uint64_t generation{0};
    for (const char digit : name.substr(PREFIX_SIZE, DIGITS)) {
        if (digit < '0' || digit > '9') return std::nullopt;
        const uint64_t value{static_cast<uint64_t>(digit - '0')};
        if (generation > (std::numeric_limits<uint64_t>::max() - value) / 10) {
            return std::nullopt;
        }
        generation = generation * 10 + value;
    }
    return generation == 0 ? std::nullopt : std::optional<uint64_t>{generation};
}

std::vector<std::byte> SerializeDeltaHeader(const DeltaState& state)
{
    std::vector<std::byte> bytes;
    bytes.reserve(DELTA_HEADER_SIZE);
    bytes.insert(bytes.end(), DELTA_MAGIC.begin(), DELTA_MAGIC.end());
    AppendUnsigned(bytes, DELTA_FORMAT_VERSION);
    AppendUnsigned(bytes, state.snapshot ? DELTA_FLAG_SNAPSHOT : 0U);
    AppendUnsigned(bytes, state.generation);
    AppendUnsigned(bytes, state.previous_generation);
    AppendUnsigned(bytes, state.base_generation);
    AppendUnsigned(bytes, state.physical_base_lsn);
    AppendHash(bytes, state.base_fingerprint);
    AppendUnsigned(bytes, state.previous_lsn);
    AppendUnsigned(bytes, state.end_lsn);
    AppendUnsigned(bytes, state.base_chain_count);
    AppendUnsigned(bytes, state.point.height);
    AppendHash(bytes, state.point.block_hash);
    AppendUnsigned(bytes, state.num_leaves);
    AppendUnsigned(bytes, state.next);
    AppendUnsigned(bytes, state.live_nodes);
    AppendUnsigned(bytes, state.chain_hash_count);
    AppendUnsigned(bytes, state.record_count);
    for (const NodeId root : state.roots) AppendUnsigned(bytes, root);
    return bytes;
}

struct DeltaWriteMetrics {
    uint64_t file_bytes{0};
    uint64_t chain_bytes{0};
    uint64_t write_us{0};
    uint64_t sync_us{0};
};

struct WrittenDelta {
    std::unique_ptr<MappedDeltaRun> run;
    DeltaWriteMetrics metrics;
};

template <typename VisitRecords>
Result<WrittenDelta> WriteDeltaRun(const std::filesystem::path& directory,
                                   const DeltaState& state,
                                   std::span<const Hash256> chain_hashes,
                                   VisitRecords&& visit_records)
{
    if (state.generation == 0 || state.record_count >= NO_NODE ||
        state.base_chain_count == 0 ||
        state.chain_hash_count != chain_hashes.size() ||
        state.base_chain_count > chain_hashes.size() || chain_hashes.empty() ||
        chain_hashes.back() != state.point.block_hash) {
        return Result<WrittenDelta>::Err("invalid forest delta publication state");
    }
    const auto final_path{DeltaPath(directory, state.generation)};
    const std::filesystem::path temporary{final_path.string() + ".tmp"};
    struct stat existing{};
    if (::lstat(final_path.c_str(), &existing) == 0) {
        return Result<WrittenDelta>::Err(
            "forest delta generation already exists: " + final_path.string());
    }
    if (errno != ENOENT) {
        return Result<WrittenDelta>::Err(
            ErrnoMessage("inspect forest delta destination"));
    }
    auto opened{CreateFreshTemporaryFile(temporary,
                                         "forest delta temporary file")};
    if (!opened) return Result<WrittenDelta>::Err(opened.Error());

    const auto write_start{std::chrono::steady_clock::now()};
    const auto header{SerializeDeltaHeader(state)};
    if (header.size() != DELTA_HEADER_SIZE) {
        return Result<WrittenDelta>::Err(
            "forest delta header has an unexpected size");
    }
    uint64_t checksum{CHECKSUM_OFFSET};
    ExtendChecksum(checksum, header);
    auto written{WriteAll(opened.Value().Get(), header)};
    if (!written) return Result<WrittenDelta>::Err(written.Error());

    constexpr std::size_t RECORD_BUFFER_BYTES{1024 * 1024};
    std::vector<DeltaDiskRecord> buffer;
    buffer.reserve(RECORD_BUFFER_BYTES / sizeof(DeltaDiskRecord));
    uint64_t records_written{0};
    NodeId previous{NO_NODE};
    Result<void> record_result{Result<void>::Ok()};
    const auto flush_records = [&]() -> Result<void> {
        if (buffer.empty()) return Result<void>::Ok();
        const auto bytes{std::as_bytes(std::span<const DeltaDiskRecord>{buffer})};
        ExtendChecksum(checksum, bytes);
        auto result{WriteAll(opened.Value().Get(), bytes)};
        buffer.clear();
        return result;
    };
    visit_records([&](NodeId id, const NodeRecord& record) {
        if (!record_result) return false;
        if (id >= state.next || (previous != NO_NODE && id <= previous)) {
            record_result = Result<void>::Err(
                "forest delta records are outside the arena or unsorted");
            return false;
        }
        buffer.push_back(DeltaDiskRecord{
            .id = id,
            .hash = record.hash,
            .parent = record.parent,
            .left = record.left,
            .right = record.right,
            .type = static_cast<uint8_t>(record.type),
            .reserved = {},
        });
        previous = id;
        ++records_written;
        if (buffer.size() * sizeof(DeltaDiskRecord) >= RECORD_BUFFER_BYTES) {
            record_result = flush_records();
        }
        return static_cast<bool>(record_result);
    });
    if (record_result) record_result = flush_records();
    if (!record_result) {
        return Result<WrittenDelta>::Err(record_result.Error());
    }
    if (records_written != state.record_count) {
        return Result<WrittenDelta>::Err(
            "forest delta record count changed during publication");
    }

    const auto suffix{chain_hashes.subspan(
        static_cast<std::size_t>(state.base_chain_count))};
    const auto suffix_bytes{std::as_bytes(suffix)};
    ExtendChecksum(checksum, suffix_bytes);
    written = WriteAll(opened.Value().Get(), suffix_bytes);
    if (!written) return Result<WrittenDelta>::Err(written.Error());
    std::vector<std::byte> trailer;
    trailer.reserve(DELTA_TRAILER_SIZE);
    AppendUnsigned(trailer, checksum);
    trailer.insert(trailer.end(), DELTA_COMMIT.begin(), DELTA_COMMIT.end());
    written = WriteAll(opened.Value().Get(), trailer);
    if (!written) return Result<WrittenDelta>::Err(written.Error());
    DeltaWriteMetrics metrics{
        .file_bytes = DELTA_HEADER_SIZE +
            state.record_count * sizeof(DeltaDiskRecord) + suffix_bytes.size() +
            DELTA_TRAILER_SIZE,
        .chain_bytes = suffix_bytes.size(),
        .write_us = ElapsedMicros(write_start),
    };

    const auto sync_start{std::chrono::steady_clock::now()};
    auto synced{SyncDescriptor(opened.Value().Get(), "forest delta run")};
    if (!synced) return Result<WrittenDelta>::Err(synced.Error());
    auto inspected{InspectOwnedRegularFile(opened.Value().Get(), temporary,
                                           "forest delta temporary file")};
    if (!inspected) return Result<WrittenDelta>::Err(inspected.Error());
    std::error_code rename_error;
    std::filesystem::rename(temporary, final_path, rename_error);
    if (rename_error) {
        return Result<WrittenDelta>::Err(
            "publish forest delta run: " + rename_error.message());
    }
    inspected = InspectOwnedRegularFile(opened.Value().Get(), final_path,
                                        "published forest delta run");
    if (!inspected) return Result<WrittenDelta>::Err(inspected.Error());
    synced = SyncDirectory(directory);
    metrics.sync_us = ElapsedMicros(sync_start);
    if (!synced) return Result<WrittenDelta>::Err(synced.Error());

    auto mapped{MappedDeltaRun::Open(final_path)};
    if (!mapped) return Result<WrittenDelta>::Err(mapped.Error());
    return Result<WrittenDelta>::Ok(WrittenDelta{
        .run = mapped.Take(),
        .metrics = metrics,
    });
}

enum class WalKind : uint8_t { CONNECT = 1, DISCONNECT = 2 };

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
    if (!reader.ReadUnsigned(version) ||
        (version != LEGACY_ONLINE_FORMAT_VERSION && version != ONLINE_FORMAT_VERSION) ||
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
                OnlineSuperblock base, std::vector<Hash256> chain_hashes,
                OnlineStateLock lock,
                std::optional<std::filesystem::path> publish_target = std::nullopt)
        : m_directory{std::move(directory)}, m_config{config}, m_base{base},
          m_point{base.point}, m_chain_hashes{std::move(chain_hashes)},
          m_current_lsn{base.base_lsn}, m_durable_lsn{base.base_lsn},
          m_durable_live_nodes{base.live_nodes},
          m_lock{std::move(lock)},
          m_publish_target{std::move(publish_target)}
    {
    }

    ~OnlineStore()
    {
        if (m_wal_fd >= 0) ::close(m_wal_fd);
        if (m_publish_target) {
            std::error_code ignored;
            std::filesystem::remove_all(m_directory, ignored);
        }
    }

    const std::filesystem::path& Directory() const { return m_directory; }
    const OnlineForestConfig& Config() const { return m_config; }
    const ChainPoint& Point() const { return m_point; }
    const std::vector<Hash256>& ChainHashes() const { return m_chain_hashes; }
    uint64_t BaseLsn() const { return m_durable_lsn; }
    uint64_t PhysicalBaseLsn() const { return m_base.base_lsn; }
    uint64_t CurrentLsn() const { return m_current_lsn; }
    uint64_t DeltaGenerationValue() const { return m_delta_generation; }
    const OnlineSuperblock& PhysicalBase() const { return m_base; }
    uint64_t DurableLiveNodes() const { return m_durable_live_nodes; }
    uint64_t DeltaBytes() const { return m_delta_bytes; }
    uint64_t DeltaRuns() const { return m_delta_runs; }
    uint64_t DeltaRecords() const { return m_delta_records; }
    uint64_t DeltaUniqueRecords() const { return m_delta_unique_records; }
    uint64_t DeltaObsoleteRecords() const
    {
        return m_delta_records - m_delta_unique_records;
    }
    uint64_t WalBytes() const { return m_wal_bytes; }
    uint64_t RedoWalBytes() const { return m_redo_wal_bytes; }
    uint64_t WalSegmentDirectorySyncs() const { return m_wal_segment_directory_syncs; }
    uint64_t LastTransactionNodes() const { return m_last_transaction_nodes; }
    uint64_t LastTransactionWalBytes() const { return m_last_transaction_wal_bytes; }
    uint64_t LastTransactionSerializeUs() const { return m_last_transaction_serialize_us; }
    uint64_t LastTransactionSegmentUs() const { return m_last_transaction_segment_us; }
    uint64_t LastTransactionWriteUs() const { return m_last_transaction_write_us; }
    uint64_t LastTransactionSyncUs() const { return m_last_transaction_sync_us; }
    uint64_t LastTransactionPublishUs() const { return m_last_transaction_publish_us; }
    uint64_t LastTransactionTotalUs() const { return m_last_transaction_total_us; }
    uint64_t LastFlushDirtyNodes() const { return m_last_flush_dirty_nodes; }
    uint64_t LastFlushSortUs() const { return m_last_flush_sort_us; }
    uint64_t LastFlushCleanupUs() const { return m_last_flush_cleanup_us; }
    uint64_t LastFlushTotalUs() const { return m_last_flush_total_us; }
    uint64_t LastFlushDeltaBytes() const { return m_last_flush_delta_bytes; }
    uint64_t LastFlushChainBytes() const { return m_last_flush_chain_bytes; }
    uint64_t LastFlushWriteUs() const { return m_last_flush_write_us; }
    uint64_t LastFlushSyncUs() const { return m_last_flush_sync_us; }
    uint64_t LastFlushCompactionInputRecords() const
    {
        return m_last_flush_compaction_input_records;
    }
    uint64_t LastFlushCompactionOutputRecords() const
    {
        return m_last_flush_compaction_output_records;
    }
    bool LastFlushCompacted() const { return m_last_flush_compacted; }
    bool WalEnabled() const { return m_config.sync_wal; }
    bool IsPendingPublication() const { return m_publish_target.has_value(); }
    uint64_t StartupCacheBytes() const { return m_startup_cache_bytes; }
    uint64_t StartupCacheReplayedRecords() const
    {
        return m_startup_cache_replayed_records;
    }
    uint64_t StartupValidationUs() const { return m_startup_validation_us; }
    bool StartupCacheHit() const { return m_startup_cache_hit; }
    bool StartupFullScan() const { return m_startup_full_scan; }

    void SetStartupValidation(uint64_t cache_bytes, uint64_t replayed_records,
                              uint64_t elapsed_us, bool cache_hit,
                              bool full_scan)
    {
        m_startup_cache_bytes = cache_bytes;
        m_startup_cache_replayed_records = replayed_records;
        m_startup_validation_us = elapsed_us;
        m_startup_cache_hit = cache_hit;
        m_startup_full_scan = full_scan;
    }

    void SetValidationCacheBytes(uint64_t cache_bytes)
    {
        m_startup_cache_bytes = cache_bytes;
    }

    Result<void> Publish()
    {
        if (!m_publish_target) {
            return Result<void>::Err("online forest has no pending generation to publish");
        }
        if (std::filesystem::exists(*m_publish_target)) {
            return Result<void>::Err("online-state directory appeared before publication: " +
                                     m_publish_target->string());
        }
        const std::filesystem::path target{*m_publish_target};
        std::error_code rename_error;
        std::filesystem::rename(m_directory, target, rename_error);
        if (rename_error) {
            return Result<void>::Err("publish online-state directory: " +
                                     rename_error.message());
        }
        m_directory = target;
        m_publish_target.reset();
        const auto parent{target.has_parent_path() ? target.parent_path() :
                                                   std::filesystem::path{"."}};
        return SyncDirectory(parent);
    }

    Result<void> Append(WalTransaction& transaction, uint64_t changed_nodes)
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
        const auto bytes{m_config.sync_wal ? SerializeWal(transaction) :
                                            std::vector<std::byte>{}};
        const uint64_t serialize_us{ElapsedMicros(serialize_start)};
        uint64_t segment_us{0};
        uint64_t write_us{0};
        uint64_t sync_us{0};
        if (m_config.sync_wal) {
            const auto segment_start{std::chrono::steady_clock::now()};
            auto opened{OpenAppendSegment(bytes.size())};
            if (!opened) return opened;
            segment_us = ElapsedMicros(segment_start);
            const auto write_start{std::chrono::steady_clock::now()};
            auto written{WriteAll(m_wal_fd, bytes)};
            if (!written) return written;
            write_us = ElapsedMicros(write_start);
            const auto sync_start{std::chrono::steady_clock::now()};
            auto synced{SyncDescriptor(m_wal_fd, "forest WAL")};
            if (!synced) return synced;
            sync_us = ElapsedMicros(sync_start);
        }
        const auto publish_start{std::chrono::steady_clock::now()};
        if (m_config.sync_wal) {
            m_wal_segment_size += bytes.size();
            m_wal_bytes += bytes.size();
            m_redo_wal_bytes += bytes.size();
        }
        m_last_transaction_nodes = changed_nodes;
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

    Result<void> RecoverDeltas(NodeArena& arena,
                               std::array<NodeId, 64>& roots,
                               uint64_t& num_leaves)
    {
        std::vector<std::pair<uint64_t, std::filesystem::path>> paths;
        std::error_code iterator_error;
        for (std::filesystem::directory_iterator iterator{m_directory, iterator_error}, end;
             !iterator_error && iterator != end; iterator.increment(iterator_error)) {
            const auto name{iterator->path().filename().string()};
            if (!name.starts_with("delta-") || !name.ends_with(".run")) continue;
            const auto generation{DeltaGeneration(name)};
            if (!generation) {
                return Result<void>::Err(
                    "forest delta filename is malformed: " + name);
            }
            paths.emplace_back(*generation, iterator->path());
        }
        if (iterator_error) {
            return Result<void>::Err(
                "scan forest delta directory: " + iterator_error.message());
        }
        std::ranges::sort(paths, {}, &std::pair<uint64_t,
                                                std::filesystem::path>::first);
        std::vector<std::unique_ptr<MappedDeltaRun>> runs;
        runs.reserve(paths.size());
        std::optional<std::size_t> latest_snapshot;
        uint64_t prior_generation{0};
        for (const auto& [generation, path] : paths) {
            if (generation == prior_generation) {
                return Result<void>::Err("duplicate forest delta generation");
            }
            auto run{MappedDeltaRun::Open(path)};
            if (!run) return Result<void>::Err(run.Error());
            if (run.Value()->State().generation != generation) {
                return Result<void>::Err(
                    "forest delta filename does not match its generation");
            }
            if (run.Value()->State().snapshot) latest_snapshot = runs.size();
            runs.push_back(run.Take());
            prior_generation = generation;
        }
        if (runs.empty()) return Result<void>::Ok();
        auto base_fingerprint{OnlineBaseFingerprint(m_base, arena)};
        if (!base_fingerprint) {
            return Result<void>::Err(base_fingerprint.Error());
        }

        const std::size_t first{latest_snapshot.value_or(0)};
        uint64_t expected_generation{0};
        uint64_t expected_lsn{m_base.base_lsn};
        for (std::size_t index{first}; index < runs.size(); ++index) {
            const auto& state{runs[index]->State()};
            if (state.base_generation != m_base.generation ||
                state.physical_base_lsn != m_base.base_lsn ||
                state.end_lsn < m_base.base_lsn ||
                state.base_fingerprint != base_fingerprint.Value() ||
                state.base_chain_count != m_base.chain_hash_count) {
                return Result<void>::Err(
                    "forest delta is anchored to a different mmap base");
            }
            if (index == first && state.snapshot) {
                // A compacted snapshot is complete relative to the physical
                // base, so predecessors may already have been unlinked.
            } else if (state.previous_generation != expected_generation ||
                       state.generation != expected_generation + 1 ||
                       state.previous_lsn != expected_lsn) {
                return Result<void>::Err(
                    "forest delta generations or LSNs are not contiguous");
            }
            if (index != first && state.snapshot) {
                return Result<void>::Err(
                    "unexpected forest delta snapshot after recovery start");
            }

            std::vector<Hash256> recovered_chain{
                m_chain_hashes.begin(),
                m_chain_hashes.begin() +
                    static_cast<std::ptrdiff_t>(m_base.chain_hash_count)};
            const uint64_t suffix_count{
                state.chain_hash_count - state.base_chain_count};
            recovered_chain.reserve(
                static_cast<std::size_t>(state.chain_hash_count));
            for (uint64_t suffix{0}; suffix < suffix_count; ++suffix) {
                recovered_chain.push_back(runs[index]->ChainSuffixHash(
                    static_cast<std::size_t>(suffix)));
            }
            if (recovered_chain.empty() ||
                recovered_chain.back() != state.point.block_hash ||
                (suffix_count == 0 && state.point != m_base.point)) {
                return Result<void>::Err(
                    "forest delta chain does not extend its mmap base");
            }

            roots = state.roots;
            num_leaves = state.num_leaves;
            arena.SetRecoveredNext(state.next);
            m_chain_hashes = std::move(recovered_chain);
            m_point = state.point;
            m_current_lsn = state.end_lsn;
            m_durable_lsn = state.end_lsn;
            m_durable_live_nodes = state.live_nodes;
            m_delta_generation = state.generation;
            expected_generation = state.generation;
            expected_lsn = state.end_lsn;
            arena.AppendDeltaRun(std::move(runs[index]));
        }
        RefreshDeltaStats(arena);
        return Result<void>::Ok();
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
        uint64_t last_seen_lsn{m_durable_lsn};
        for (const auto& path : segments) {
            auto recovered{RecoverSegment(path, arena, roots, num_leaves, last_seen_lsn)};
            if (!recovered) return recovered;
        }
        m_current_lsn = std::max(m_durable_lsn, last_seen_lsn);
        return Result<void>::Ok();
    }

    Result<void> SealDelta(NodeArena& arena,
                           const std::array<NodeId, 64>& roots,
                           uint64_t num_leaves)
    {
        const auto total_start{std::chrono::steady_clock::now()};
        ResetFlushMetrics(arena.DirtyNodes());
        const auto sort_start{std::chrono::steady_clock::now()};
        const auto ordered_ids{arena.SortedVisibleDirtyIds()};
        m_last_flush_sort_us = ElapsedMicros(sort_start);
        auto base_fingerprint{OnlineBaseFingerprint(m_base, arena)};
        if (!base_fingerprint) {
            return Result<void>::Err(base_fingerprint.Error());
        }
        const DeltaState state{
            .snapshot = false,
            .generation = m_delta_generation + 1,
            .previous_generation = m_delta_generation,
            .base_generation = m_base.generation,
            .physical_base_lsn = m_base.base_lsn,
            .base_fingerprint = base_fingerprint.Value(),
            .previous_lsn = m_durable_lsn,
            .end_lsn = m_current_lsn,
            .base_chain_count = m_base.chain_hash_count,
            .point = m_point,
            .num_leaves = num_leaves,
            .next = static_cast<NodeId>(arena.Next()),
            .live_nodes = arena.LiveCount(),
            .chain_hash_count = m_chain_hashes.size(),
            .record_count = ordered_ids.size(),
            .roots = roots,
        };
        auto written{WriteDeltaRun(m_directory, state, m_chain_hashes,
            [&](auto&& emit) {
                for (const NodeId id : ordered_ids) {
                    if (!emit(id, arena.DirtyRecord(id))) break;
                }
            })};
        if (!written) return Result<void>::Err(written.Error());
        AccumulateDeltaWriteMetrics(written.Value().metrics);
        arena.AppendDeltaRun(std::move(written.Value().run));
        arena.ClearDirty();
        m_delta_generation = state.generation;
        m_durable_lsn = state.end_lsn;
        m_durable_live_nodes = state.live_nodes;
        m_redo_wal_bytes = 0;
        RefreshDeltaStats(arena);

        const bool run_pressure{m_delta_runs >= m_config.max_delta_runs};
        const bool garbage_pressure{
            m_delta_runs >= m_config.delta_compaction_min_runs &&
            m_delta_records != 0 &&
            static_cast<long double>(DeltaObsoleteRecords()) * 100.0L >=
                static_cast<long double>(m_delta_records) *
                    m_config.delta_compaction_garbage_percent};
        if (run_pressure || garbage_pressure) {
            auto compacted{CompactDeltas(arena, roots, num_leaves)};
            if (!compacted) return compacted;
        }
        const auto cleanup_start{std::chrono::steady_clock::now()};
        auto pruned{PruneWal()};
        m_last_flush_cleanup_us += ElapsedMicros(cleanup_start);
        m_last_flush_total_us = ElapsedMicros(total_start);
        return pruned;
    }

private:
    void ResetFlushMetrics(uint64_t dirty_nodes)
    {
        m_last_flush_dirty_nodes = dirty_nodes;
        m_last_flush_sort_us = 0;
        m_last_flush_cleanup_us = 0;
        m_last_flush_total_us = 0;
        m_last_flush_delta_bytes = 0;
        m_last_flush_chain_bytes = 0;
        m_last_flush_write_us = 0;
        m_last_flush_sync_us = 0;
        m_last_flush_compaction_input_records = 0;
        m_last_flush_compaction_output_records = 0;
        m_last_flush_compacted = false;
    }

    void AccumulateDeltaWriteMetrics(const DeltaWriteMetrics& metrics)
    {
        m_last_flush_delta_bytes += metrics.file_bytes;
        m_last_flush_chain_bytes += metrics.chain_bytes;
        m_last_flush_write_us += metrics.write_us;
        m_last_flush_sync_us += metrics.sync_us;
    }

    void RefreshDeltaStats(const NodeArena& arena)
    {
        m_delta_bytes = arena.DeltaBytes();
        m_delta_runs = arena.DeltaRunCount();
        m_delta_records = arena.DeltaRecords();
        m_delta_unique_records = arena.UniqueDeltaRecords();
    }

    Result<void> CompactDeltas(NodeArena& arena,
                               const std::array<NodeId, 64>& roots,
                               uint64_t num_leaves)
    {
        const uint64_t input_records{m_delta_records};
        uint64_t output_records{0};
        arena.ForEachLatestDeltaRecord(
            [&](NodeId id, const NodeRecord& record) {
                if (!arena.EqualsPhysicalBase(id, record)) ++output_records;
                return true;
            });
        auto base_fingerprint{OnlineBaseFingerprint(m_base, arena)};
        if (!base_fingerprint) {
            return Result<void>::Err(base_fingerprint.Error());
        }
        const DeltaState snapshot{
            .snapshot = true,
            .generation = m_delta_generation + 1,
            .previous_generation = m_delta_generation,
            .base_generation = m_base.generation,
            .physical_base_lsn = m_base.base_lsn,
            .base_fingerprint = base_fingerprint.Value(),
            .previous_lsn = m_durable_lsn,
            .end_lsn = m_durable_lsn,
            .base_chain_count = m_base.chain_hash_count,
            .point = m_point,
            .num_leaves = num_leaves,
            .next = static_cast<NodeId>(arena.Next()),
            .live_nodes = arena.LiveCount(),
            .chain_hash_count = m_chain_hashes.size(),
            .record_count = output_records,
            .roots = roots,
        };
        std::vector<std::filesystem::path> obsolete_paths;
        obsolete_paths.reserve(arena.DeltaRuns().size());
        for (const auto& run : arena.DeltaRuns()) {
            obsolete_paths.push_back(run->Path());
        }
        auto written{WriteDeltaRun(m_directory, snapshot, m_chain_hashes,
            [&](auto&& emit) {
                arena.ForEachLatestDeltaRecord(
                    [&](NodeId id, const NodeRecord& record) {
                        return arena.EqualsPhysicalBase(id, record) ||
                            emit(id, record);
                    });
            })};
        if (!written) return Result<void>::Err(written.Error());
        AccumulateDeltaWriteMetrics(written.Value().metrics);
        arena.ReplaceDeltaRuns(std::move(written.Value().run));
        m_delta_generation = snapshot.generation;
        m_last_flush_compacted = true;
        m_last_flush_compaction_input_records = input_records;
        m_last_flush_compaction_output_records = output_records;
        RefreshDeltaStats(arena);

        bool removed_any{false};
        for (const auto& path : obsolete_paths) {
            auto owned{OpenOwnedRegularFile(path, O_RDONLY | O_NONBLOCK,
                                            "obsolete forest delta run")};
            if (!owned) return Result<void>::Err(owned.Error());
            if (::unlink(path.c_str()) != 0) {
                return Result<void>::Err(
                    ErrnoMessage("remove obsolete forest delta run"));
            }
            removed_any = true;
        }
        return removed_any ? SyncDirectory(m_directory) : Result<void>::Ok();
    }

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
        auto opened{OpenOwnedRegularFile(path, O_WRONLY | O_CREAT | O_APPEND,
                                         "forest WAL segment")};
        if (!opened) return Result<void>::Err(opened.Error());
        m_wal_fd = opened.Value().Release();
        struct stat status{};
        if (::fstat(m_wal_fd, &status) != 0) {
            const auto error{ErrnoMessage("stat WAL segment")};
            ::close(m_wal_fd);
            m_wal_fd = -1;
            return Result<void>::Err(error);
        }
        // A transaction cannot be published until the segment's directory entry
        // is durable.  Re-sync empty pre-existing segments as well: one can remain
        // after a previous directory-sync failure or a crash before the first write.
        if (status.st_size == 0) {
            auto directory_synced{SyncDirectory(m_directory)};
            if (!directory_synced) {
                ::close(m_wal_fd);
                m_wal_fd = -1;
                return directory_synced;
            }
            ++m_wal_segment_directory_syncs;
        }
        m_wal_segment_size = static_cast<uint64_t>(status.st_size);
        return Result<void>::Ok();
    }

    Result<void> RecoverSegment(const std::filesystem::path& path, NodeArena& arena,
                                std::array<NodeId, 64>& roots, uint64_t& num_leaves,
                                uint64_t& last_seen_lsn)
    {
        auto file_result{ReadOwnedFile(path, true)};
        if (!file_result) return Result<void>::Err(file_result.Error());
        auto file{file_result.Take()};
        const auto& bytes{file.bytes};
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
            if (transaction.Value().lsn > m_durable_lsn) {
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
            auto inspected{InspectOwnedRegularFile(file.descriptor.Get(), path,
                                                   "forest WAL segment")};
            if (!inspected) return inspected;
            if (::ftruncate(file.descriptor.Get(), static_cast<off_t>(valid_size)) != 0) {
                return Result<void>::Err(ErrnoMessage("truncate incomplete WAL tail"));
            }
            auto synced{SyncDescriptor(file.descriptor.Get(), "truncated forest WAL")};
            if (!synced) return synced;
        }
        return Result<void>::Ok();
    }

    Result<void> PruneWal()
    {
        // Retain complete segments covering the reorg window. Segment-granular
        // pruning avoids rewriting live WAL data merely to save a partial file.
        const uint32_t floor{m_point.height > m_config.undo_depth ?
            m_point.height - m_config.undo_depth : 0};
        bool removed_any{false};
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
            const bool outside_retention{!m_config.sync_wal || max_height < floor};
            if (valid && outside_retention && max_lsn <= m_durable_lsn) {
                std::error_code remove_error;
                const uint64_t size{std::filesystem::file_size(path, remove_error)};
                if (!remove_error && std::filesystem::remove(path, remove_error) && !remove_error) {
                    m_wal_bytes = size > m_wal_bytes ? 0 : m_wal_bytes - size;
                    removed_any = true;
                }
            }
        }
        if (iterator_error) return Result<void>::Err("prune WAL directory: " + iterator_error.message());
        return removed_any ? SyncDirectory(m_directory) : Result<void>::Ok();
    }

    std::filesystem::path m_directory;
    OnlineForestConfig m_config;
    OnlineSuperblock m_base;
    ChainPoint m_point;
    std::vector<Hash256> m_chain_hashes;
    uint64_t m_current_lsn{0};
    uint64_t m_durable_lsn{0};
    uint64_t m_durable_live_nodes{0};
    uint64_t m_delta_generation{0};
    uint64_t m_delta_bytes{0};
    uint64_t m_delta_runs{0};
    uint64_t m_delta_records{0};
    uint64_t m_delta_unique_records{0};
    uint64_t m_wal_bytes{0};
    uint64_t m_redo_wal_bytes{0};
    uint64_t m_wal_segment_directory_syncs{0};
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
    uint64_t m_last_flush_dirty_nodes{0};
    uint64_t m_last_flush_sort_us{0};
    uint64_t m_last_flush_cleanup_us{0};
    uint64_t m_last_flush_total_us{0};
    uint64_t m_last_flush_delta_bytes{0};
    uint64_t m_last_flush_chain_bytes{0};
    uint64_t m_last_flush_write_us{0};
    uint64_t m_last_flush_sync_us{0};
    uint64_t m_last_flush_compaction_input_records{0};
    uint64_t m_last_flush_compaction_output_records{0};
    bool m_last_flush_compacted{false};
    uint64_t m_startup_cache_bytes{0};
    uint64_t m_startup_cache_replayed_records{0};
    uint64_t m_startup_validation_us{0};
    bool m_startup_cache_hit{false};
    bool m_startup_full_scan{false};
    OnlineStateLock m_lock;
    std::optional<std::filesystem::path> m_publish_target;
};

class NodeIdBits
{
public:
    explicit NodeIdBits(uint64_t size)
        : m_size{size}, m_words(static_cast<std::size_t>((size + 63) / 64), 0)
    {
    }

    bool Test(NodeId id) const
    {
        return id < m_size &&
            (m_words[id / 64] & (uint64_t{1} << (id % 64))) != 0;
    }

    void Set(NodeId id)
    {
        if (id < m_size) m_words[id / 64] |= uint64_t{1} << (id % 64);
    }

    void Clear(NodeId id)
    {
        if (id < m_size) m_words[id / 64] &= ~(uint64_t{1} << (id % 64));
    }

    uint64_t Count() const
    {
        uint64_t count{0};
        for (const uint64_t word : m_words) {
            count += static_cast<uint64_t>(std::popcount(word));
        }
        return count;
    }

    template <typename Callback>
    void ForEachSet(Callback&& callback) const
    {
        for (std::size_t word_index{0}; word_index < m_words.size();
             ++word_index) {
            uint64_t word{m_words[word_index]};
            while (word != 0) {
                const auto bit{static_cast<unsigned>(std::countr_zero(word))};
                const uint64_t raw_id{word_index * 64 + bit};
                if (raw_id < m_size) callback(static_cast<NodeId>(raw_id));
                word &= word - 1;
            }
        }
    }

private:
    uint64_t m_size{0};
    std::vector<uint64_t> m_words;
};

} // namespace

class PackedForest::Impl
{
public:
    struct StartupCacheLoad {
        bool hit{false};
        bool base_anchored{false};
        uint64_t bytes{0};
        uint64_t replayed_records{0};
        uint64_t index_capacity{0};
    };

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
            branches += static_cast<uint64_t>(std::countr_one(num_leaves + i));
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

    Result<void> RebuildIndexAndValidate(
        std::optional<uint64_t> counted_leaves = std::nullopt)
    {
        uint64_t leaf_count{counted_leaves.value_or(0)};
        if (!counted_leaves) {
            for (uint64_t raw_id{0}; raw_id < arena.Next(); ++raw_id) {
                if (arena.Type(static_cast<NodeId>(raw_id)) == NodeType::LEAF) {
                    ++leaf_count;
                }
            }
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

    Result<StartupCacheLoad> LoadValidatedStartupCache(
        const std::filesystem::path& directory,
        const OnlineSuperblock& base)
    {
        const auto miss = [] {
            return Result<StartupCacheLoad>::Ok(StartupCacheLoad{});
        };
        const auto path{directory / VALIDATED_CACHE_NAME};
        struct stat path_status{};
        if (::lstat(path.c_str(), &path_status) != 0) {
            if (errno == ENOENT) return miss();
            return Result<StartupCacheLoad>::Err(
                ErrnoMessage("inspect validated startup cache"));
        }
        auto opened{OpenOwnedRegularFile(
            path, O_RDONLY | O_NONBLOCK, "validated startup cache")};
        if (!opened) return Result<StartupCacheLoad>::Err(opened.Error());
        struct stat status{};
        if (::fstat(opened.Value().Get(), &status) != 0 || status.st_size < 0 ||
            static_cast<uint64_t>(status.st_size) <
                VALIDATED_CACHE_HEADER_SIZE + VALIDATED_CACHE_TRAILER_SIZE) {
            return miss();
        }

        std::array<std::byte, VALIDATED_CACHE_HEADER_SIZE> header_bytes{};
        auto read{PreadAll(opened.Value().Get(), header_bytes, 0)};
        if (!read) return miss();
        auto parsed{ParseValidatedCacheHeader(header_bytes)};
        if (!parsed || !SameBaseState(parsed.Value().base, base)) return miss();
        const auto& header{parsed.Value()};
        auto hashes_identity{ReadOwnedFileIdentity(
            directory / "forest.hashes", "forest hashes")};
        if (!hashes_identity) {
            return Result<StartupCacheLoad>::Err(hashes_identity.Error());
        }
        auto metadata_identity{ReadOwnedFileIdentity(
            directory / "forest.meta", "forest metadata")};
        if (!metadata_identity) {
            return Result<StartupCacheLoad>::Err(metadata_identity.Error());
        }
        if (hashes_identity.Value() != header.hashes_identity ||
            metadata_identity.Value() != header.metadata_identity) {
            return miss();
        }
        const uint64_t expected_size{
            VALIDATED_CACHE_HEADER_SIZE +
            header.index_entries * VALIDATED_CACHE_ENTRY_SIZE +
            header.free_nodes * sizeof(NodeId) +
            VALIDATED_CACHE_TRAILER_SIZE};
        if (static_cast<uint64_t>(status.st_size) != expected_size) return miss();

        std::size_t first_patch_run{0};
        bool anchor_matches{false};
        if (header.anchor.generation == 0) {
            anchor_matches = header.anchor.lsn == base.base_lsn &&
                header.anchor.point == base.point &&
                header.anchor.num_leaves == base.num_leaves &&
                header.anchor.next == base.next &&
                header.anchor.live_nodes == base.live_nodes &&
                header.anchor.roots == base.roots;
        } else {
            const auto& runs{arena.DeltaRuns()};
            for (std::size_t run_index{0}; run_index < runs.size(); ++run_index) {
                const auto& state{runs[run_index]->State()};
                if (state.generation != header.anchor.generation) continue;
                anchor_matches = header.anchor.lsn == state.end_lsn &&
                    header.anchor.point == state.point &&
                    header.anchor.num_leaves == state.num_leaves &&
                    header.anchor.next == state.next &&
                    header.anchor.live_nodes == state.live_nodes &&
                    header.anchor.roots == state.roots;
                first_patch_run = run_index + 1;
                break;
            }
        }
        if (!anchor_matches) return miss();

        const uint64_t current_next{arena.Next()};
        if (current_next >= NO_NODE) return miss();
        NodeIdBits changed{current_next};
        NodeIdBits dirty{current_next};
        uint64_t replayed_records{0};
        arena.ForEachLatestDeltaRecordFrom(first_patch_run,
            [&](NodeId id, const NodeRecord&) {
                changed.Set(id);
                ++replayed_records;
                return true;
            });
        const auto dirty_ids{arena.SortedVisibleDirtyIds()};
        for (const NodeId id : dirty_ids) {
            changed.Set(id);
            dirty.Set(id);
            ++replayed_records;
        }

        NodeIdBits seen_anchor_leaves{header.anchor.next};
        NodeIdBits free_nodes{current_next};
        index.Clear(static_cast<std::size_t>(header.index_capacity));
        uint64_t checksum{CHECKSUM_OFFSET};
        ExtendChecksum(checksum, header_bytes);
        uint64_t offset{VALIDATED_CACHE_HEADER_SIZE};
        constexpr uint64_t RECORDS_PER_READ{16 * 1024};
        std::vector<std::byte> buffer;
        uint64_t remaining{header.index_entries};
        uint64_t entries_read{0};
        while (remaining != 0) {
            const uint64_t records{std::min<uint64_t>(remaining,
                                                      RECORDS_PER_READ)};
            buffer.resize(static_cast<std::size_t>(
                records * VALIDATED_CACHE_ENTRY_SIZE));
            read = PreadAll(opened.Value().Get(), buffer, offset);
            if (!read) return miss();
            ExtendChecksum(checksum, buffer);
            ByteReader reader{buffer};
            for (uint64_t record{0}; record < records; ++record) {
                NodeId id{NO_NODE};
                uint32_t slot{0};
                if (!reader.ReadUnsigned(id) || !reader.ReadUnsigned(slot) ||
                    id >= header.anchor.next || seen_anchor_leaves.Test(id)) {
                    return miss();
                }
                seen_anchor_leaves.Set(id);
                if (!index.LoadValidationSlot(
                        slot, id, id >= current_next || changed.Test(id))) {
                    return miss();
                }
                ++entries_read;
            }
            if (!reader.Done()) return miss();
            offset += buffer.size();
            remaining -= records;
        }
        if (entries_read != header.index_entries) return miss();

        remaining = header.free_nodes;
        NodeId previous_free{NO_NODE};
        uint64_t free_read{0};
        while (remaining != 0) {
            const uint64_t records{std::min<uint64_t>(remaining,
                                                      RECORDS_PER_READ)};
            buffer.resize(static_cast<std::size_t>(records * sizeof(NodeId)));
            read = PreadAll(opened.Value().Get(), buffer, offset);
            if (!read) return miss();
            ExtendChecksum(checksum, buffer);
            ByteReader reader{buffer};
            for (uint64_t record{0}; record < records; ++record) {
                NodeId id{NO_NODE};
                if (!reader.ReadUnsigned(id) || id >= header.anchor.next ||
                    (previous_free != NO_NODE && id <= previous_free) ||
                    seen_anchor_leaves.Test(id)) {
                    return miss();
                }
                if (id < current_next) free_nodes.Set(id);
                previous_free = id;
                ++free_read;
            }
            if (!reader.Done()) return miss();
            offset += buffer.size();
            remaining -= records;
        }
        if (free_read != header.free_nodes) return miss();

        std::array<std::byte, VALIDATED_CACHE_TRAILER_SIZE> trailer{};
        read = PreadAll(opened.Value().Get(), trailer, offset);
        if (!read) return miss();
        ByteReader trailer_reader{trailer};
        uint64_t expected_checksum{0};
        std::array<std::byte, VALIDATED_CACHE_COMMIT.size()> commit{};
        if (!trailer_reader.ReadUnsigned(expected_checksum) ||
            !trailer_reader.ReadBytes(commit) || !trailer_reader.Done() ||
            commit != VALIDATED_CACHE_COMMIT || expected_checksum != checksum) {
            return miss();
        }

        if (!index.RepairValidationDeletions()) return miss();

        for (uint64_t raw_id{header.anchor.next}; raw_id < current_next;
             ++raw_id) {
            free_nodes.Set(static_cast<NodeId>(raw_id));
        }
        bool index_valid{true};
        arena.ForEachLatestDeltaRecordFrom(first_patch_run,
            [&](NodeId id, const NodeRecord& record) {
                if (record.type == NodeType::FREE) free_nodes.Set(id);
                else free_nodes.Clear(id);
                if (record.type == NodeType::LEAF && !dirty.Test(id)) {
                    index_valid = index.InsertValidationHome(
                        KeylessLeafIndex::ValidationHome(record.hash), id);
                }
                return index_valid;
            });
        if (!index_valid) return miss();
        for (const NodeId id : dirty_ids) {
            const NodeRecord& record{arena.DirtyRecord(id)};
            if (record.type == NodeType::FREE) free_nodes.Set(id);
            else free_nodes.Clear(id);
            if (record.type == NodeType::LEAF &&
                !index.InsertValidationHome(
                    KeylessLeafIndex::ValidationHome(record.hash), id)) {
                return miss();
            }
        }
        const auto current_minimum_capacity{
            ValidatedIndexCapacity(index.Size())};
        if (!current_minimum_capacity ||
            index.Capacity() < *current_minimum_capacity) {
            return miss();
        }

        std::vector<NodeId> free_ids;
        free_ids.reserve(static_cast<std::size_t>(free_nodes.Count()));
        free_nodes.ForEachSet(
            [&](NodeId id) { free_ids.push_back(id); });
        auto bookkeeping{arena.LoadBookkeeping(
            static_cast<NodeId>(current_next), std::move(free_ids))};
        if (!bookkeeping) return miss();
        for (const NodeId root : roots) {
            if (root != NO_NODE &&
                (root >= arena.Next() || !arena.Live(root) ||
                 arena.Parent(root) != NO_NODE)) {
                return miss();
            }
        }
        return Result<StartupCacheLoad>::Ok(StartupCacheLoad{
            .hit = true,
            .base_anchored = header.anchor.generation == 0,
            .bytes = expected_size,
            .replayed_records = replayed_records,
            .index_capacity = header.index_capacity,
        });
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
    uint64_t validated_cache_capacity{0};
    bool validated_cache_base_anchored{false};
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
    if (m_impl->online->IsPendingPublication()) {
        return Result<void>::Err("publish the validated online generation before modifying it");
    }
    const ChainPoint previous{m_impl->online->Point()};
    if (point.height != previous.height + 1) {
        return Result<void>::Err("online block height does not extend the durable tip");
    }
    constexpr uint64_t MAX_REDO_WAL_BYTES{1024ULL * 1024 * 1024};
    if (m_impl->arena.DirtyBytes() >= m_impl->online->Config().max_dirty_bytes ||
        (m_impl->online->WalEnabled() &&
         m_impl->online->RedoWalBytes() >= MAX_REDO_WAL_BYTES)) {
        auto flushed{FlushOnline()};
        if (!flushed) return Result<void>::Err("online delta seal required before block: " + flushed.Error());
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
        const uint64_t changed_nodes{m_impl->arena.TransactionNodeCount()};
        if (m_impl->online->WalEnabled()) {
            transaction.changes = m_impl->arena.TransactionChanges();
        }
        appended = m_impl->online->Append(transaction, changed_nodes);
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
        config.undo_depth == 0 || config.delta_compaction_min_runs < 2 ||
        config.max_delta_runs < config.delta_compaction_min_runs ||
        config.max_delta_runs > 1024 ||
        config.delta_compaction_garbage_percent == 0 ||
        config.delta_compaction_garbage_percent > 100) {
        return Result<void>::Err("invalid online forest configuration");
    }
    if (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
        chain_hashes.empty() || chain_hashes.back() != point.block_hash) {
        return Result<void>::Err("online chain-hash index does not match its chain point");
    }
    auto prepared_result{PrepareOnlineImport(directory)};
    if (!prepared_result) return Result<void>::Err(prepared_result.Error());
    auto prepared{prepared_result.Take()};
    const std::filesystem::path temporary{prepared.Directory()};

    uint64_t capacity{NodeArena::CHUNK_SIZE};
    while (capacity < m_impl->arena.Next()) capacity += NodeArena::CHUNK_SIZE;
    auto native_written{m_impl->arena.WriteNative(temporary / "forest.hashes",
                                                   temporary / "forest.meta", capacity)};
    if (!native_written) return native_written;

    const auto chain_path{ChainHashesPath(temporary, 0)};
    const int chain_fd{::open(chain_path.c_str(), O_WRONLY | O_CREAT | O_EXCL |
        O_CLOEXEC | NoFollowFlag(), 0600)};
    if (chain_fd < 0) return Result<void>::Err(ErrnoMessage("create online chain hashes"));
    auto chain_inspected{InspectOwnedRegularFile(chain_fd, chain_path, "online chain hashes")};
    if (!chain_inspected) {
        ::close(chain_fd);
        return chain_inspected;
    }
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
    auto cache_written{WriteValidatedStartupCache(
        temporary, state,
        ValidationAnchor{
            .generation = 0,
            .lsn = state.base_lsn,
            .point = state.point,
            .num_leaves = state.num_leaves,
            .next = state.next,
            .live_nodes = state.live_nodes,
            .roots = state.roots,
        },
        m_impl->arena, m_impl->index)};
    if (!cache_written) return Result<void>::Err(cache_written.Error());

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
    m_impl->online = std::make_unique<OnlineStore>(directory, config, state,
        std::move(chain_copy), prepared.ReleaseLock());
    m_impl->validated_cache_capacity = m_impl->index.Capacity();
    m_impl->validated_cache_base_anchored = true;
    m_impl->online->SetValidationCacheBytes(cache_written.Value());
    return Result<void>::Ok();
}

Result<PackedForest> PackedForest::OpenOnline(const std::filesystem::path& directory,
                                              std::vector<Hash256>& chain_hashes,
                                              ChainPoint& point,
                                              OnlineForestConfig config)
{
    if (config.max_dirty_bytes == 0 || config.wal_segment_bytes < 1024 * 1024 ||
        config.undo_depth == 0 || config.delta_compaction_min_runs < 2 ||
        config.max_delta_runs < config.delta_compaction_min_runs ||
        config.max_delta_runs > 1024 ||
        config.delta_compaction_garbage_percent == 0 ||
        config.delta_compaction_garbage_percent > 100) {
        return Result<PackedForest>::Err("invalid online forest configuration");
    }
    auto directory_lock{OnlineStateLock::Acquire(directory, true)};
    if (!directory_lock) return Result<PackedForest>::Err(directory_lock.Error());
    const auto owner_path{directory / ONLINE_OWNER_FILE};
    struct stat owner_status{};
    if (::lstat(owner_path.c_str(), &owner_status) == 0) {
        auto owner{ValidateOnlineOwnerMarker(directory)};
        if (!owner) return Result<PackedForest>::Err(owner.Error());
    } else if (errno != ENOENT) {
        return Result<PackedForest>::Err(ErrnoMessage(
            "inspect online-state format marker"));
    }
    auto state{ReadBestSuperblock(directory)};
    if (!state) return Result<PackedForest>::Err(state.Error());
    auto pending_flush{ReadFlushUndo(directory)};
    if (!pending_flush) return Result<PackedForest>::Err(pending_flush.Error());
    bool restore_base{false};
    if (pending_flush.Value()) {
        const auto& journal{*pending_flush.Value()};
        if (state.Value().generation == journal.target_generation) {
            if (state.Value().base_lsn != journal.target_base_lsn ||
                state.Value().point != journal.target_point) {
                return Result<PackedForest>::Err(
                    "published superblock does not match the pending flush undo journal");
            }
            auto removed{RemoveFlushUndo(directory, journal)};
            if (!removed) return Result<PackedForest>::Err(removed.Error());
            pending_flush.Value().reset();
        } else if (state.Value().generation == journal.base_generation) {
            restore_base = true;
            for (const auto& [id, record] : journal.records) {
                static_cast<void>(record);
                if (id >= state.Value().next) {
                    return Result<PackedForest>::Err(
                        "flush undo journal contains a node outside its base generation");
                }
            }
        } else {
            return Result<PackedForest>::Err(
                "flush undo journal does not match either durable superblock generation");
        }
    }
    const auto chain_path{state.Value().format_version >= ONLINE_FORMAT_VERSION ?
        ChainHashesPath(directory, state.Value().generation) :
        directory / "chain.hashes"};
    auto chain_bytes{ReadFile(chain_path)};
    const uint64_t required_chain_bytes{state.Value().chain_hash_count * Hash256::SIZE};
    if (!chain_bytes) return Result<PackedForest>::Err(chain_bytes.Error());
    if (chain_bytes.Value().size() < required_chain_bytes ||
        chain_bytes.Value().size() % Hash256::SIZE != 0) {
        return Result<PackedForest>::Err("online chain-hash file is truncated or malformed");
    }
    std::vector<Hash256> recovered_chain;
    recovered_chain.reserve(static_cast<std::size_t>(state.Value().chain_hash_count));
    for (uint64_t i{0}; i < state.Value().chain_hash_count; ++i) {
        Hash256::Storage bytes{};
        const auto begin{chain_bytes.Value().begin() + static_cast<std::ptrdiff_t>(
            i * Hash256::SIZE)};
        std::copy_n(begin, Hash256::SIZE, bytes.begin());
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
                                                state.Value().next,
                                                false, restore_base)};
    if (!mapped) return Result<PackedForest>::Err(mapped.Error());
    if (restore_base) {
        auto restored{forest.m_impl->arena.RestoreBase(
            pending_flush.Value()->records)};
        if (!restored) return Result<PackedForest>::Err(restored.Error());
        auto removed{RemoveFlushUndo(directory, *pending_flush.Value())};
        if (!removed) return Result<PackedForest>::Err(removed.Error());
        pending_flush.Value().reset();
        auto read_only{forest.m_impl->arena.ReopenBaseReadOnly(
            directory / "forest.hashes", directory / "forest.meta")};
        if (!read_only) return Result<PackedForest>::Err(read_only.Error());
    }
    auto online{std::make_unique<OnlineStore>(directory, config, state.Value(),
                                               std::move(recovered_chain),
                                               directory_lock.Take())};
    auto deltas_recovered{online->RecoverDeltas(forest.m_impl->arena,
                                                forest.m_impl->roots,
                                                forest.m_impl->num_leaves)};
    if (!deltas_recovered) {
        return Result<PackedForest>::Err(deltas_recovered.Error());
    }
    auto recovered{online->Recover(forest.m_impl->arena, forest.m_impl->roots,
                                   forest.m_impl->num_leaves)};
    if (!recovered) return Result<PackedForest>::Err(recovered.Error());
    const auto validation_start{std::chrono::steady_clock::now()};
    auto cache_loaded{forest.m_impl->LoadValidatedStartupCache(
        directory, state.Value())};
    if (!cache_loaded) {
        return Result<PackedForest>::Err(cache_loaded.Error());
    }
    bool cache_hit{cache_loaded.Value().hit};
    if (cache_hit && online->CurrentLsn() == online->BaseLsn() &&
        forest.m_impl->arena.LiveCount() != online->DurableLiveNodes()) {
        cache_hit = false;
    }
    bool full_scan{false};
    uint64_t cache_bytes{cache_loaded.Value().bytes};
    uint64_t replayed_records{cache_loaded.Value().replayed_records};
    uint64_t cache_capacity{
        cache_hit ? cache_loaded.Value().index_capacity : 0};
    bool cache_base_anchored{
        cache_hit && cache_loaded.Value().base_anchored};
    if (!cache_hit) {
        auto bookkeeping{
            forest.m_impl->arena.RebuildBookkeepingAndCountLeaves()};
        if (!bookkeeping) {
            return Result<PackedForest>::Err(bookkeeping.Error());
        }
        if (online->CurrentLsn() == online->BaseLsn() &&
            forest.m_impl->arena.LiveCount() != online->DurableLiveNodes()) {
            return Result<PackedForest>::Err(
                "online arena live-node count does not match its durable state");
        }
        auto rebuilt{forest.m_impl->RebuildIndexAndValidate(
            bookkeeping.Value())};
        if (!rebuilt) return Result<PackedForest>::Err(rebuilt.Error());
        full_scan = true;

        // A cache is derived state. Failure to publish it must not make an
        // otherwise valid forest unavailable. WAL-replayed dirty state is not
        // cached until it has first been sealed into a delta.
        if (online->CurrentLsn() == online->BaseLsn() &&
            forest.m_impl->arena.DirtyNodes() == 0) {
            auto saved{WriteValidatedStartupCache(
                directory, online->PhysicalBase(),
                ValidationAnchor{
                    .generation = online->DeltaGenerationValue(),
                    .lsn = online->BaseLsn(),
                    .point = online->Point(),
                    .num_leaves = forest.m_impl->num_leaves,
                    .next = static_cast<NodeId>(forest.m_impl->arena.Next()),
                    .live_nodes = forest.m_impl->arena.LiveCount(),
                    .roots = forest.m_impl->roots,
                },
                forest.m_impl->arena, forest.m_impl->index)};
            if (saved) {
                cache_bytes = saved.Value();
                cache_capacity = forest.m_impl->index.Capacity();
                cache_base_anchored =
                    online->DeltaGenerationValue() == 0;
            }
        }
    }
    online->SetStartupValidation(
        cache_bytes, replayed_records, ElapsedMicros(validation_start),
        cache_hit, full_scan);
    forest.m_impl->validated_cache_capacity = cache_capacity;
    forest.m_impl->validated_cache_base_anchored = cache_base_anchored;
    chain_hashes = online->ChainHashes();
    point = online->Point();
    if (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
        chain_hashes.back() != point.block_hash) {
        return Result<PackedForest>::Err("recovered WAL chain does not match its online point");
    }
    forest.m_impl->online = std::move(online);
    return Result<PackedForest>::Ok(std::move(forest));
}

Result<void> PackedForest::PublishOnline()
{
    if (!m_impl->online) return Result<void>::Err("forest is not using online storage");
    return m_impl->online->Publish();
}

Result<void> PackedForest::FlushOnline()
{
    if (!m_impl->online) return Result<void>::Err("forest is not using online storage");
    if (m_impl->online->IsPendingPublication()) {
        return Result<void>::Err("publish the validated online generation before flushing it");
    }
    if (m_impl->arena.DirtyNodes() == 0 &&
        m_impl->online->BaseLsn() == m_impl->online->CurrentLsn()) {
        return Result<void>::Ok();
    }
    auto sealed{m_impl->online->SealDelta(m_impl->arena, m_impl->roots,
                                          m_impl->num_leaves)};
    if (!sealed) return sealed;
    const bool refresh_cache{
        m_impl->validated_cache_capacity != m_impl->index.Capacity() ||
        (!m_impl->validated_cache_base_anchored &&
         m_impl->online->LastFlushCompacted())};
    if (!refresh_cache) return Result<void>::Ok();

    auto saved{WriteValidatedStartupCache(
        m_impl->online->Directory(), m_impl->online->PhysicalBase(),
        ValidationAnchor{
            .generation = m_impl->online->DeltaGenerationValue(),
            .lsn = m_impl->online->BaseLsn(),
            .point = m_impl->online->Point(),
            .num_leaves = m_impl->num_leaves,
            .next = static_cast<NodeId>(m_impl->arena.Next()),
            .live_nodes = m_impl->arena.LiveCount(),
            .roots = m_impl->roots,
        },
        m_impl->arena, m_impl->index)};
    if (!saved) {
        m_impl->validated_cache_capacity = 0;
        return Result<void>::Ok();
    }
    m_impl->validated_cache_capacity = m_impl->index.Capacity();
    m_impl->validated_cache_base_anchored =
        m_impl->online->DeltaGenerationValue() == 0;
    m_impl->online->SetValidationCacheBytes(saved.Value());
    return Result<void>::Ok();
}

Result<ChainPoint> PackedForest::RollbackOnlineBlock()
{
    if (!m_impl->online) return Result<ChainPoint>::Err("forest is not using online storage");
    if (m_impl->online->IsPendingPublication()) {
        return Result<ChainPoint>::Err(
            "publish the validated online generation before rolling it back");
    }
    if (!m_impl->online->WalEnabled()) {
        return Result<ChainPoint>::Err(
            "online forest WAL is disabled; restart from the last base and replay Bitcoin Core");
    }
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
        applied = m_impl->online->Append(rollback, rollback.changes.size());
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
        .delta_bytes = m_impl->online->DeltaBytes(),
        .delta_filter_bytes = m_impl->arena.DeltaFilterBytes(),
        .delta_index_bytes = m_impl->arena.DeltaIndexBytes(),
        .delta_runs = m_impl->online->DeltaRuns(),
        .delta_records = m_impl->online->DeltaRecords(),
        .delta_unique_records = m_impl->online->DeltaUniqueRecords(),
        .delta_obsolete_records = m_impl->online->DeltaObsoleteRecords(),
        .startup_cache_bytes = m_impl->online->StartupCacheBytes(),
        .startup_cache_replayed_records =
            m_impl->online->StartupCacheReplayedRecords(),
        .startup_validation_us = m_impl->online->StartupValidationUs(),
        .startup_cache_hit = m_impl->online->StartupCacheHit(),
        .startup_full_scan = m_impl->online->StartupFullScan(),
        .dirty_nodes = m_impl->arena.DirtyNodes(),
        .dirty_bytes = m_impl->arena.DirtyBytes(),
        .wal_bytes = m_impl->online->WalBytes(),
        .redo_wal_bytes = m_impl->online->RedoWalBytes(),
        .base_lsn = m_impl->online->BaseLsn(),
        .physical_base_lsn = m_impl->online->PhysicalBaseLsn(),
        .current_lsn = m_impl->online->CurrentLsn(),
        .wal_segment_directory_syncs = m_impl->online->WalSegmentDirectorySyncs(),
        .last_transaction_nodes = m_impl->online->LastTransactionNodes(),
        .last_transaction_wal_bytes = m_impl->online->LastTransactionWalBytes(),
        .last_transaction_serialize_us = m_impl->online->LastTransactionSerializeUs(),
        .last_transaction_segment_us = m_impl->online->LastTransactionSegmentUs(),
        .last_transaction_write_us = m_impl->online->LastTransactionWriteUs(),
        .last_transaction_sync_us = m_impl->online->LastTransactionSyncUs(),
        .last_transaction_publish_us = m_impl->online->LastTransactionPublishUs(),
        .last_transaction_total_us = m_impl->online->LastTransactionTotalUs(),
        .last_flush_dirty_nodes = m_impl->online->LastFlushDirtyNodes(),
        .last_flush_sort_us = m_impl->online->LastFlushSortUs(),
        .last_flush_cleanup_us = m_impl->online->LastFlushCleanupUs(),
        .last_flush_total_us = m_impl->online->LastFlushTotalUs(),
        .last_flush_delta_bytes = m_impl->online->LastFlushDeltaBytes(),
        .last_flush_chain_bytes = m_impl->online->LastFlushChainBytes(),
        .last_flush_write_us = m_impl->online->LastFlushWriteUs(),
        .last_flush_sync_us = m_impl->online->LastFlushSyncUs(),
        .last_flush_compaction_input_records =
            m_impl->online->LastFlushCompactionInputRecords(),
        .last_flush_compaction_output_records =
            m_impl->online->LastFlushCompactionOutputRecords(),
        .last_flush_compacted = m_impl->online->LastFlushCompacted(),
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

Result<PackedForest> ReadForestOnline(std::istream& input,
                                      const std::filesystem::path& directory,
                                      const ChainPoint& point,
                                      std::span<const Hash256> chain_hashes,
                                      OnlineForestConfig config)
{
    if (config.max_dirty_bytes == 0 || config.wal_segment_bytes < 1024 * 1024 ||
        config.undo_depth == 0 || config.delta_compaction_min_runs < 2 ||
        config.max_delta_runs < config.delta_compaction_min_runs ||
        config.max_delta_runs > 1024 ||
        config.delta_compaction_garbage_percent == 0 ||
        config.delta_compaction_garbage_percent > 100) {
        return Result<PackedForest>::Err("invalid online forest configuration");
    }
    if (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
        chain_hashes.empty() || chain_hashes.back() != point.block_hash) {
        return Result<PackedForest>::Err("online chain-hash index does not match its chain point");
    }
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
    if (version != PackedForest::FORMAT_VERSION) {
        return Result<PackedForest>::Err("unsupported forest version");
    }
    if (slots >= NO_NODE) {
        return Result<PackedForest>::Err("forest node count exceeds the NodeId range");
    }

    std::array<NodeId, 64> roots{};
    for (NodeId& root : roots) {
        if (!ReadLE(input, root)) return Result<PackedForest>::Err("truncated forest roots");
        if (root != NO_NODE && root >= slots) {
            return Result<PackedForest>::Err("forest root is out of range");
        }
    }

    uint64_t capacity{NodeArena::CHUNK_SIZE};
    while (capacity < slots) capacity += NodeArena::CHUNK_SIZE;
    if (capacity >= NO_NODE) {
        return Result<PackedForest>::Err("forest capacity exceeds the NodeId range");
    }

    auto prepared_result{PrepareOnlineImport(directory)};
    if (!prepared_result) return Result<PackedForest>::Err(prepared_result.Error());
    auto prepared{prepared_result.Take()};
    const std::filesystem::path temporary{prepared.Directory()};

    int hash_fd{-1};
    int meta_fd{-1};
    const auto fail = [&](std::string error) -> Result<PackedForest> {
        if (hash_fd >= 0) ::close(hash_fd);
        if (meta_fd >= 0) ::close(meta_fd);
        return Result<PackedForest>::Err(std::move(error));
    };

    const auto hashes_path{temporary / "forest.hashes"};
    const auto meta_path{temporary / "forest.meta"};
    hash_fd = ::open(hashes_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
        NoFollowFlag(), 0600);
    if (hash_fd < 0) return fail(ErrnoMessage("create forest hashes"));
    auto hashes_inspected{InspectOwnedRegularFile(hash_fd, hashes_path, "forest hashes")};
    if (!hashes_inspected) return fail(hashes_inspected.Error());
    meta_fd = ::open(meta_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
        NoFollowFlag(), 0600);
    if (meta_fd < 0) return fail(ErrnoMessage("create forest metadata"));
    auto metadata_inspected{InspectOwnedRegularFile(meta_fd, meta_path, "forest metadata")};
    if (!metadata_inspected) return fail(metadata_inspected.Error());
    if (::ftruncate(hash_fd, static_cast<off_t>(capacity * sizeof(Hash256))) != 0 ||
        ::ftruncate(meta_fd, static_cast<off_t>(capacity * sizeof(DiskMeta))) != 0) {
        return fail(ErrnoMessage("size native forest files"));
    }

    constexpr uint64_t RECORD_BYTES{1 + Hash256::SIZE + sizeof(NodeId) * 3};
    constexpr std::size_t IMPORT_BATCH{64 * 1024};
    std::vector<unsigned char> serialized(IMPORT_BATCH * RECORD_BYTES);
    std::vector<Hash256> hashes(IMPORT_BATCH);
    std::vector<DiskMeta> metadata(IMPORT_BATCH);
    uint64_t live_nodes{0};
    for (uint64_t first{0}; first < slots; first += IMPORT_BATCH) {
        const std::size_t count{static_cast<std::size_t>(
            std::min<uint64_t>(IMPORT_BATCH, slots - first))};
        const std::size_t byte_count{count * static_cast<std::size_t>(RECORD_BYTES)};
        input.read(reinterpret_cast<char*>(serialized.data()),
                   static_cast<std::streamsize>(byte_count));
        if (!input) return fail("truncated node record");

        for (std::size_t i{0}; i < count; ++i) {
            const unsigned char* record{serialized.data() + i * RECORD_BYTES};
            const uint8_t raw_type{record[0]};
            if (raw_type > static_cast<uint8_t>(NodeType::BRANCH)) {
                return fail("invalid node type");
            }
            Hash256::Storage hash_bytes{};
            std::memcpy(hash_bytes.data(), record + 1, Hash256::SIZE);
            hashes[i] = Hash256{hash_bytes};
            const auto read_id = [&](std::size_t offset) {
                uint32_t value{0};
                for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
                    value |= static_cast<uint32_t>(record[offset + byte]) << (byte * 8);
                }
                return static_cast<NodeId>(value);
            };
            const NodeId parent{read_id(1 + Hash256::SIZE)};
            const NodeId left{read_id(1 + Hash256::SIZE + sizeof(NodeId))};
            const NodeId right{read_id(1 + Hash256::SIZE + sizeof(NodeId) * 2)};
            const auto valid_link{[slots](NodeId link) {
                return link == NO_NODE || link < slots;
            }};
            if (!valid_link(parent) || !valid_link(left) || !valid_link(right)) {
                return fail("node link is out of range");
            }
            metadata[i] = DiskMeta{parent, left, right, raw_type, {}};
            if (raw_type != static_cast<uint8_t>(NodeType::FREE)) ++live_nodes;
        }

        auto hashes_written{PwriteAll(hash_fd,
            std::as_bytes(std::span<const Hash256>{hashes.data(), count}),
            first * sizeof(Hash256))};
        if (!hashes_written) return fail(hashes_written.Error());
        auto metadata_written{PwriteAll(meta_fd,
            std::as_bytes(std::span<const DiskMeta>{metadata.data(), count}),
            first * sizeof(DiskMeta))};
        if (!metadata_written) return fail(metadata_written.Error());
    }

    auto hash_synced{SyncDescriptor(hash_fd, "native forest hashes")};
    if (!hash_synced) return fail(hash_synced.Error());
    auto meta_synced{SyncDescriptor(meta_fd, "native forest metadata")};
    if (!meta_synced) return fail(meta_synced.Error());
    if (::close(hash_fd) != 0) {
        hash_fd = -1;
        return fail(ErrnoMessage("close native forest hashes"));
    }
    hash_fd = -1;
    if (::close(meta_fd) != 0) {
        meta_fd = -1;
        return fail(ErrnoMessage("close native forest metadata"));
    }
    meta_fd = -1;

    const auto chain_path{ChainHashesPath(temporary, 0)};
    const int chain_fd{::open(chain_path.c_str(), O_WRONLY | O_CREAT | O_EXCL |
        O_CLOEXEC | NoFollowFlag(), 0600)};
    if (chain_fd < 0) return fail(ErrnoMessage("create online chain hashes"));
    auto chain_inspected{InspectOwnedRegularFile(chain_fd, chain_path, "online chain hashes")};
    if (!chain_inspected) {
        ::close(chain_fd);
        return fail(chain_inspected.Error());
    }
    auto chain_written{WriteAll(chain_fd, std::as_bytes(chain_hashes))};
    if (chain_written) chain_written = SyncDescriptor(chain_fd, "online chain hashes");
    const int chain_close{::close(chain_fd)};
    if (!chain_written) return fail(chain_written.Error());
    if (chain_close != 0) return fail(ErrnoMessage("close online chain hashes"));

    const OnlineSuperblock state{
        .generation = 0,
        .base_lsn = 0,
        .point = point,
        .num_leaves = leaves,
        .next = static_cast<NodeId>(slots),
        .live_nodes = live_nodes,
        .capacity_slots = capacity,
        .chain_hash_count = chain_hashes.size(),
        .roots = roots,
    };
    auto state_written{WriteSuperblock(temporary, state)};
    if (!state_written) return fail(state_written.Error());

    PackedForest forest;
    forest.m_impl->roots = roots;
    forest.m_impl->num_leaves = leaves;
    auto mapped{forest.m_impl->arena.OpenMapped(hashes_path, meta_path, capacity,
                                                static_cast<NodeId>(slots))};
    if (!mapped) return fail(mapped.Error());
    if (forest.m_impl->arena.LiveCount() != live_nodes) {
        return fail("online arena live-node count does not match its superblock");
    }
    auto rebuilt{forest.m_impl->RebuildIndexAndValidate()};
    if (!rebuilt) return fail(rebuilt.Error());
    auto cache_written{WriteValidatedStartupCache(
        temporary, state,
        ValidationAnchor{
            .generation = 0,
            .lsn = state.base_lsn,
            .point = state.point,
            .num_leaves = state.num_leaves,
            .next = state.next,
            .live_nodes = state.live_nodes,
            .roots = state.roots,
        },
        forest.m_impl->arena, forest.m_impl->index)};
    if (!cache_written) return fail(cache_written.Error());

    std::vector<Hash256> chain_copy{chain_hashes.begin(), chain_hashes.end()};
    forest.m_impl->online = std::make_unique<OnlineStore>(temporary, config, state,
        std::move(chain_copy), prepared.ReleaseLock(), directory);
    forest.m_impl->validated_cache_capacity = forest.m_impl->index.Capacity();
    forest.m_impl->validated_cache_base_anchored = true;
    forest.m_impl->online->SetValidationCacheBytes(cache_written.Value());
    if (!config.defer_publish) {
        auto published{forest.PublishOnline()};
        if (!published) return Result<PackedForest>::Err(published.Error());
    }
    return Result<PackedForest>::Ok(std::move(forest));
}

} // namespace utreexo
