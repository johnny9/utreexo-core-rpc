// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/proof_store.h>

#include <utreexo/hash.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <vector>

namespace utreexo {
namespace {

constexpr std::array<std::byte, 8> DATA_MAGIC{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'D'}, std::byte{'A'}, std::byte{'T'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> DATA_COMMIT{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'D'}, std::byte{'O'}, std::byte{'N'}, std::byte{'E'}};
constexpr std::array<std::byte, 8> WAL_MAGIC{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'W'}, std::byte{'A'}, std::byte{'L'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> WAL_COMMIT{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'C'}, std::byte{'M'}, std::byte{'T'}, std::byte{'1'}};
constexpr uint32_t STORE_FORMAT{ProofStore::FORMAT_VERSION};
constexpr std::size_t DATA_HEADER_SIZE{88};
constexpr std::size_t DATA_FOOTER_SIZE{Hash256::SIZE + DATA_COMMIT.size()};
constexpr std::size_t WAL_PREFIX_SIZE{136};
constexpr std::size_t WAL_RECORD_SIZE{WAL_PREFIX_SIZE + Hash256::SIZE + WAL_COMMIT.size()};
constexpr uint64_t INDEX_GROWTH_ENTRIES{4'096};

enum class WalKind : uint32_t { BASE = 1, CONNECT = 2, TRUNCATE = 3 };

std::string ErrnoMessage(std::string_view action)
{
    return std::string{action} + ": " + std::strerror(errno);
}

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & static_cast<T>(0xffU)));
        value >>= 8;
    }
}

void AppendHash(std::vector<std::byte>& output, const Hash256& hash)
{
    output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
}

class ByteReader
{
public:
    explicit ByteReader(std::span<const std::byte> bytes) : m_bytes{bytes} {}

    template <typename T>
    bool ReadLE(T& value)
    {
        static_assert(std::is_unsigned_v<T>);
        if (m_offset + sizeof(T) > m_bytes.size()) return false;
        uint64_t decoded{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            decoded |= static_cast<uint64_t>(std::to_integer<uint8_t>(m_bytes[m_offset++])) <<
                       (8 * i);
        }
        value = static_cast<T>(decoded);
        return true;
    }

    bool ReadBytes(std::span<std::byte> output)
    {
        if (m_offset + output.size() > m_bytes.size()) return false;
        std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(m_offset), output.size(),
                    output.begin());
        m_offset += output.size();
        return true;
    }

    bool ReadHash(Hash256& hash)
    {
        Hash256::Storage bytes{};
        if (!ReadBytes(bytes)) return false;
        hash = Hash256{bytes};
        return true;
    }

    bool Done() const { return m_offset == m_bytes.size(); }

private:
    std::span<const std::byte> m_bytes;
    std::size_t m_offset{0};
};

Result<void> PwriteAll(int descriptor, std::span<const std::byte> bytes, uint64_t file_offset)
{
    const uint64_t max_offset{static_cast<uint64_t>(std::numeric_limits<off_t>::max())};
    if (file_offset > max_offset || bytes.size() > max_offset - file_offset) {
        return Result<void>::Err("proof-store write offset exceeds the platform file limit");
    }
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t written{::pwrite(descriptor, bytes.data() + offset, bytes.size() - offset,
                                       static_cast<off_t>(file_offset + offset))};
        if (written < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("write proof store"));
        }
        if (written == 0) return Result<void>::Err("short proof-store write");
        offset += static_cast<std::size_t>(written);
    }
    return Result<void>::Ok();
}

Result<void> PreadExact(int descriptor, std::span<std::byte> bytes, uint64_t file_offset)
{
    const uint64_t max_offset{static_cast<uint64_t>(std::numeric_limits<off_t>::max())};
    if (file_offset > max_offset || bytes.size() > max_offset - file_offset) {
        return Result<void>::Err("proof-store read offset exceeds the platform file limit");
    }
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t received{::pread(descriptor, bytes.data() + offset, bytes.size() - offset,
                                       static_cast<off_t>(file_offset + offset))};
        if (received < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("read proof store"));
        }
        if (received == 0) return Result<void>::Err("proof-store file is truncated");
        offset += static_cast<std::size_t>(received);
    }
    return Result<void>::Ok();
}

Result<void> SyncFile(int descriptor, std::string_view description)
{
    if (::fdatasync(descriptor) != 0) {
        return Result<void>::Err(ErrnoMessage(std::string{"sync "} + std::string{description}));
    }
    return Result<void>::Ok();
}

Result<void> SyncDirectory(const std::filesystem::path& directory)
{
    const int descriptor{::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open proof-store directory"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoMessage("sync proof-store directory"));
    return Result<void>::Ok();
}

uint64_t FileSize(int descriptor, bool& ok)
{
    struct stat status{};
    ok = ::fstat(descriptor, &status) == 0 && status.st_size >= 0;
    return ok ? static_cast<uint64_t>(status.st_size) : 0;
}

struct WalEvent {
    WalKind kind{WalKind::BASE};
    ChainPoint point;
    Hash256 previous_hash;
    uint64_t data_offset{0};
    uint64_t data_size{0};
    Hash256 data_digest;
};

std::vector<std::byte> SerializeWal(const WalEvent& event)
{
    std::vector<std::byte> bytes;
    bytes.reserve(WAL_RECORD_SIZE);
    bytes.insert(bytes.end(), WAL_MAGIC.begin(), WAL_MAGIC.end());
    AppendLE(bytes, STORE_FORMAT);
    AppendLE(bytes, static_cast<uint32_t>(event.kind));
    AppendLE(bytes, event.point.height);
    AppendLE(bytes, uint32_t{0});
    AppendHash(bytes, event.point.block_hash);
    AppendHash(bytes, event.previous_hash);
    AppendLE(bytes, event.data_offset);
    AppendLE(bytes, event.data_size);
    AppendHash(bytes, event.data_digest);
    const Hash256 digest{Sha256(bytes)};
    AppendHash(bytes, digest);
    bytes.insert(bytes.end(), WAL_COMMIT.begin(), WAL_COMMIT.end());
    return bytes;
}

Result<WalEvent> ParseWal(std::span<const std::byte> bytes)
{
    if (bytes.size() != WAL_RECORD_SIZE) return Result<WalEvent>::Err("invalid proof WAL record size");
    if (!std::equal(WAL_COMMIT.begin(), WAL_COMMIT.end(), bytes.end() -
                    static_cast<std::ptrdiff_t>(WAL_COMMIT.size()))) {
        return Result<WalEvent>::Err("proof WAL commit marker is missing");
    }
    Hash256::Storage expected_bytes{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(WAL_PREFIX_SIZE), Hash256::SIZE,
                expected_bytes.begin());
    if (Sha256(bytes.first(WAL_PREFIX_SIZE)) != Hash256{expected_bytes}) {
        return Result<WalEvent>::Err("committed proof WAL checksum mismatch");
    }
    ByteReader reader{bytes.first(WAL_PREFIX_SIZE)};
    std::array<std::byte, WAL_MAGIC.size()> magic{};
    uint32_t version{0};
    uint32_t kind{0};
    uint32_t reserved{0};
    WalEvent event;
    if (!reader.ReadBytes(magic) || magic != WAL_MAGIC || !reader.ReadLE(version) ||
        version != STORE_FORMAT || !reader.ReadLE(kind) ||
        kind < static_cast<uint32_t>(WalKind::BASE) ||
        kind > static_cast<uint32_t>(WalKind::TRUNCATE) ||
        !reader.ReadLE(event.point.height) || !reader.ReadLE(reserved) || reserved != 0 ||
        !reader.ReadHash(event.point.block_hash) || !reader.ReadHash(event.previous_hash) ||
        !reader.ReadLE(event.data_offset) || !reader.ReadLE(event.data_size) ||
        !reader.ReadHash(event.data_digest) || !reader.Done()) {
        return Result<WalEvent>::Err("invalid proof WAL fields");
    }
    event.kind = static_cast<WalKind>(kind);
    return Result<WalEvent>::Ok(std::move(event));
}

struct PreparedProof {
    ChainPoint point;
    Hash256 previous_hash;
    std::vector<std::byte> record;
    Hash256 digest;
    uint64_t accounted_bytes{0};
};

Result<PreparedProof> PrepareProof(BlockDelta delta, Proof proof,
                                   uint64_t accounted_bytes, uint64_t max_record_bytes)
{
    const ChainPoint point{delta.point};
    const Hash256 previous_hash{delta.previous_block_hash};
    CachedBlockProof cached{
        .point = point,
        .proof = std::move(proof),
        .leaves = std::move(delta.proof_leaves),
    };
    auto payload{SerializeUtreexoProof(cached, GetUtreexoProofRequest{
        .block_hash = point.block_hash,
        .request_bitmap = 0x07,
        .proof_indexes = {},
        .leaf_indexes = {},
    })};
    if (!payload) return Result<PreparedProof>::Err(payload.Error());
    if (payload.Value().size() > max_record_bytes ||
        payload.Value().size() > std::numeric_limits<uint64_t>::max() -
                                     DATA_HEADER_SIZE - DATA_FOOTER_SIZE) {
        return Result<PreparedProof>::Err("serialized block proof exceeds the proof-store record limit");
    }
    std::vector<std::byte> record;
    record.reserve(DATA_HEADER_SIZE + payload.Value().size() + DATA_FOOTER_SIZE);
    record.insert(record.end(), DATA_MAGIC.begin(), DATA_MAGIC.end());
    AppendLE(record, STORE_FORMAT);
    AppendLE(record, point.height);
    AppendHash(record, point.block_hash);
    AppendHash(record, previous_hash);
    AppendLE(record, static_cast<uint64_t>(payload.Value().size()));
    record.insert(record.end(), payload.Value().begin(), payload.Value().end());
    const Hash256 digest{Sha256(record)};
    AppendHash(record, digest);
    record.insert(record.end(), DATA_COMMIT.begin(), DATA_COMMIT.end());
    return Result<PreparedProof>::Ok(PreparedProof{
        .point = point,
        .previous_hash = previous_hash,
        .record = std::move(record),
        .digest = digest,
        .accounted_bytes = accounted_bytes,
    });
}

struct alignas(8) DiskIndexEntry {
    uint64_t data_offset{0};
    uint64_t data_size{0};
    Hash256::Storage block_hash{};
    Hash256::Storage data_digest{};
};
static_assert(sizeof(DiskIndexEntry) == 80);

bool EntryPresent(const DiskIndexEntry& entry) { return entry.data_size != 0; }

DiskIndexEntry EntryFromEvent(const WalEvent& event)
{
    return DiskIndexEntry{
        .data_offset = event.data_offset,
        .data_size = event.data_size,
        .block_hash = event.point.block_hash.Bytes(),
        .data_digest = event.data_digest.Bytes(),
    };
}

Hash256 EntryHash(const DiskIndexEntry& entry) { return Hash256{entry.block_hash}; }
Hash256 EntryDigest(const DiskIndexEntry& entry) { return Hash256{entry.data_digest}; }

uint64_t AccountedBytes(const BlockDelta& delta, const Proof& proof)
{
    uint64_t bytes{1'024};
    const auto add = [&bytes](uint64_t amount) {
        bytes = amount > std::numeric_limits<uint64_t>::max() - bytes ?
                    std::numeric_limits<uint64_t>::max() : bytes + amount;
    };
    add(static_cast<uint64_t>(proof.targets.size()) * sizeof(uint64_t));
    add(static_cast<uint64_t>(proof.hashes.size()) * Hash256::SIZE);
    add(static_cast<uint64_t>(delta.deletions.size()) * Hash256::SIZE);
    add(static_cast<uint64_t>(delta.proof_leaves.size()) * sizeof(CompactLeafData));
    for (const auto& leaf : delta.proof_leaves) add(leaf.script.size());
    return bytes > std::numeric_limits<uint64_t>::max() / 4 ?
               std::numeric_limits<uint64_t>::max() : bytes * 4;
}

} // namespace

class ProofStore::Impl
{
public:
    explicit Impl(ProofStoreConfig store_config) : config{std::move(store_config)} {}

    ~Impl()
    {
        static_cast<void>(Drain());
        {
            std::lock_guard lock{mutex};
            stopping = true;
        }
        input_ready.notify_all();
        output_ready.notify_all();
        space_available.notify_all();
        durable_changed.notify_all();
        for (auto& worker : serializers) if (worker.joinable()) worker.join();
        if (writer.joinable()) writer.join();
        if (index_map != nullptr) {
            static_cast<void>(::msync(index_map, static_cast<std::size_t>(index_bytes), MS_ASYNC));
            ::munmap(index_map, static_cast<std::size_t>(index_bytes));
        }
        if (index_fd >= 0) ::close(index_fd);
        if (data_fd >= 0) ::close(data_fd);
        if (wal_fd >= 0) ::close(wal_fd);
    }

    Result<void> Initialize()
    {
        if (config.directory.empty() || config.serializer_threads == 0 ||
            config.serializer_threads > 64 || config.group_commit_blocks == 0 ||
            config.group_commit_blocks > 4'096 || config.group_commit_delay_ms > 10'000 ||
            config.max_queued_blocks == 0 || config.max_queued_bytes == 0 ||
            config.max_record_bytes < 1'024 ||
            config.max_record_bytes > std::numeric_limits<uint32_t>::max()) {
            return Result<void>::Err("invalid proof-store configuration");
        }
        std::error_code directory_error;
        std::filesystem::create_directories(config.directory, directory_error);
        if (directory_error) return Result<void>::Err("create proof-store directory: " + directory_error.message());

        const auto data_path{config.directory / "proofs.dat"};
        const auto wal_path{config.directory / "index.wal"};
        const auto index_path{config.directory / "height.index"};
        data_fd = ::open(data_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (data_fd < 0) return Result<void>::Err(ErrnoMessage("open proof data"));
        wal_fd = ::open(wal_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (wal_fd < 0) return Result<void>::Err(ErrnoMessage("open proof index WAL"));
        if (::flock(wal_fd, LOCK_EX | LOCK_NB) != 0) {
            return Result<void>::Err(ErrnoMessage("lock proof store"));
        }
        index_fd = ::open(index_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (index_fd < 0) return Result<void>::Err(ErrnoMessage("open proof mmap index"));

        bool wal_size_ok{false};
        wal_end = FileSize(wal_fd, wal_size_ok);
        if (!wal_size_ok) return Result<void>::Err(ErrnoMessage("stat proof index WAL"));
        bool data_size_ok{false};
        const uint64_t stored_data_size{FileSize(data_fd, data_size_ok)};
        if (!data_size_ok) return Result<void>::Err(ErrnoMessage("stat proof data"));

        if (wal_end != 0 && stored_data_size == 0 && wal_end <= WAL_RECORD_SIZE) {
            bool incomplete_base{wal_end < WAL_RECORD_SIZE};
            if (!incomplete_base) {
                std::array<std::byte, WAL_COMMIT.size()> marker{};
                auto marker_read{PreadExact(wal_fd, marker, WAL_RECORD_SIZE - WAL_COMMIT.size())};
                if (!marker_read) return marker_read;
                incomplete_base = marker != WAL_COMMIT;
            }
            if (incomplete_base) {
                if (::ftruncate(wal_fd, 0) != 0) {
                    return Result<void>::Err(ErrnoMessage("truncate incomplete proof-store base"));
                }
                auto synced{SyncFile(wal_fd, "recovered empty proof index WAL")};
                if (!synced) return synced;
                wal_end = 0;
            }
        }

        std::vector<DiskIndexEntry> recovered;
        if (wal_end == 0) {
            if (!config.create_base) {
                return Result<void>::Err("a new proof store requires a checkpoint base point");
            }
            if (stored_data_size != 0) {
                return Result<void>::Err("proof data exists without an index WAL");
            }
            base_point = *config.create_base;
            durable_point = base_point;
            enqueued_point = base_point;
            WalEvent base_event{
                .kind = WalKind::BASE,
                .point = base_point,
                .previous_hash = {},
                .data_offset = 0,
                .data_size = 0,
                .data_digest = {},
            };
            const auto bytes{SerializeWal(base_event)};
            auto written{PwriteAll(wal_fd, bytes, 0)};
            if (!written) return written;
            auto synced{SyncFile(wal_fd, "proof index WAL")};
            if (!synced) return synced;
            wal_end = bytes.size();
            wal_syncs = 1;
            auto directory_synced{SyncDirectory(config.directory)};
            if (!directory_synced) return directory_synced;
        } else {
            auto recovered_result{RecoverWal(recovered, stored_data_size)};
            if (!recovered_result) return recovered_result;
        }
        auto mapped{MapIndex(recovered)};
        if (!mapped) return mapped;
        for (uint32_t index{0}; index < recovered.size(); ++index) {
            if (EntryPresent(recovered[index])) hash_to_height.emplace(EntryHash(recovered[index]), index);
        }
        for (uint32_t i{0}; i < config.serializer_threads; ++i) {
            serializers.emplace_back([this] { SerializerLoop(); });
        }
        writer = std::thread{[this] { WriterLoop(); }};
        return Result<void>::Ok();
    }

    Result<void> Enqueue(const BlockDelta& delta, Proof proof)
    {
        const auto wait_start{std::chrono::steady_clock::now()};
        std::unique_lock operation_lock{operation_mutex};
        if (proof.targets.size() != delta.deletions.size() ||
            delta.proof_leaves.size() != delta.deletions.size()) {
            return Result<void>::Err("block proof does not align with its deletion leaves");
        }
        const uint64_t accounted{AccountedBytes(delta, proof)};
        if (accounted > config.max_queued_bytes) {
            return Result<void>::Err("one proof exceeds the proof pipeline byte limit");
        }
        std::unique_lock lock{mutex};
        const auto has_capacity = [&] {
            return queued_blocks < config.max_queued_blocks &&
                   queued_bytes <= config.max_queued_bytes - accounted;
        };
        if (!failure && !stopping && !has_capacity() &&
            enqueued_point.height > durable_point.height) {
            flush_height = !flush_height ? enqueued_point.height :
                           std::max(*flush_height, enqueued_point.height);
            output_ready.notify_one();
        }
        space_available.wait(lock, [&] {
            return failure.has_value() || stopping || has_capacity();
        });
        if (failure) return Result<void>::Err(*failure);
        if (stopping) return Result<void>::Err("proof store is stopping");
        if (delta.point.height != enqueued_point.height + 1 ||
            delta.previous_block_hash != enqueued_point.block_hash) {
            return Result<void>::Err("proof does not extend the enqueued archive tip");
        }
        if (hash_to_height.contains(delta.point.block_hash)) {
            return Result<void>::Err("proof archive already contains this block hash");
        }
        try {
            input.push_back(WorkItem{
                .delta = BlockDelta{
                    .point = delta.point,
                    .previous_block_hash = delta.previous_block_hash,
                    .additions = {},
                    .deletions = delta.deletions,
                    .proof_leaves = delta.proof_leaves,
                },
                .proof = std::move(proof),
                .accounted_bytes = accounted,
            });
        } catch (const std::bad_alloc&) {
            return Result<void>::Err("proof pipeline allocation failed while enqueueing a block");
        } catch (const std::exception& exception) {
            return Result<void>::Err("proof pipeline enqueue failed: " +
                                     std::string{exception.what()});
        }
        ++queued_blocks;
        queued_bytes += accounted;
        peak_queued_blocks = std::max(peak_queued_blocks, queued_blocks);
        peak_queued_bytes = std::max(peak_queued_bytes, queued_bytes);
        enqueue_wait_us += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - wait_start).count());
        enqueued_point = delta.point;
        lock.unlock();
        input_ready.notify_one();
        return Result<void>::Ok();
    }

    Result<void> WaitDurable(uint32_t height)
    {
        std::unique_lock lock{mutex};
        if (height > enqueued_point.height) {
            return Result<void>::Err("cannot wait beyond the enqueued proof tip");
        }
        if (height <= durable_point.height) return Result<void>::Ok();
        flush_height = !flush_height ? height : std::max(*flush_height, height);
        output_ready.notify_one();
        durable_changed.wait(lock, [&] {
            return failure.has_value() || durable_point.height >= height;
        });
        if (failure) return Result<void>::Err(*failure);
        return Result<void>::Ok();
    }

    Result<void> Drain()
    {
        uint32_t height{0};
        {
            std::lock_guard lock{mutex};
            if (failure) return Result<void>::Err(*failure);
            height = enqueued_point.height;
        }
        return WaitDurable(height);
    }

    Result<void> Truncate(const ChainPoint& point)
    {
        std::unique_lock operation_lock{operation_mutex};
        auto drained{Drain()};
        if (!drained) return drained;
        WalEvent event;
        {
            std::lock_guard lock{mutex};
            if (point.height < base_point.height || point.height > durable_point.height) {
                return Result<void>::Err("proof-store truncation point is outside the active archive");
            }
            auto expected{HashAtLocked(point.height)};
            if (!expected || *expected != point.block_hash) {
                return Result<void>::Err("proof-store truncation hash does not match the archive");
            }
            if (point == durable_point) return Result<void>::Ok();
            event = WalEvent{
                .kind = WalKind::TRUNCATE,
                .point = point,
                .previous_hash = durable_point.block_hash,
                .data_offset = 0,
                .data_size = 0,
                .data_digest = {},
            };
        }
        const auto bytes{SerializeWal(event)};
        uint64_t write_offset{0};
        {
            std::lock_guard lock{mutex};
            write_offset = wal_end;
        }
        auto written{PwriteAll(wal_fd, bytes, write_offset)};
        if (!written) return written;
        const auto wal_sync_start{std::chrono::steady_clock::now()};
        auto synced{SyncFile(wal_fd, "proof index WAL truncation")};
        if (!synced) return synced;
        const uint64_t truncate_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - wal_sync_start).count())};
        {
            std::lock_guard lock{mutex};
            wal_end += bytes.size();
            ++wal_syncs;
            wal_sync_us += truncate_sync_us;
            const uint64_t keep{point.height - base_point.height};
            const uint64_t old{durable_point.height - base_point.height};
            for (uint64_t index{keep}; index < old; ++index) {
                if (EntryPresent(index_map[index])) hash_to_height.erase(EntryHash(index_map[index]));
                index_map[index] = {};
            }
            durable_point = point;
            enqueued_point = point;
        }
        return Result<void>::Ok();
    }

    Result<std::shared_ptr<const CachedBlockProof>> Read(const Hash256& block_hash) const
    {
        try {
            DiskIndexEntry entry;
            uint32_t height{0};
            Hash256 expected_previous;
            {
                std::lock_guard lock{mutex};
                const auto found{hash_to_height.find(block_hash)};
                if (found == hash_to_height.end()) {
                    ++misses;
                    return Result<std::shared_ptr<const CachedBlockProof>>::Ok({});
                }
                const uint64_t relative{found->second};
                entry = index_map[relative];
                height = base_point.height + 1 + found->second;
                expected_previous = found->second == 0 ? base_point.block_hash :
                                    EntryHash(index_map[relative - 1]);
                ++hits;
            }
            if (entry.data_size > config.max_record_bytes + DATA_HEADER_SIZE + DATA_FOOTER_SIZE ||
                entry.data_size < DATA_HEADER_SIZE + DATA_FOOTER_SIZE) {
                return Result<std::shared_ptr<const CachedBlockProof>>::Err(
                    "proof index contains an invalid record size");
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(entry.data_size));
            auto read{PreadExact(data_fd, bytes, entry.data_offset)};
            if (!read) return Result<std::shared_ptr<const CachedBlockProof>>::Err(read.Error());
            auto parsed{ParseDataRecord(height, block_hash, expected_previous,
                                        EntryDigest(entry), bytes)};
            if (!parsed) return Result<std::shared_ptr<const CachedBlockProof>>::Err(parsed.Error());
            std::shared_ptr<const CachedBlockProof> result{
                std::make_shared<CachedBlockProof>(parsed.Take())};
            return Result<std::shared_ptr<const CachedBlockProof>>::Ok(std::move(result));
        } catch (const std::bad_alloc&) {
            return Result<std::shared_ptr<const CachedBlockProof>>::Err(
                "proof archive allocation failed while reading a record");
        }
    }

    Result<std::optional<Hash256>> HashAt(uint32_t height) const
    {
        std::lock_guard lock{mutex};
        return Result<std::optional<Hash256>>::Ok(HashAtLocked(height));
    }

    ChainPoint BasePoint() const { std::lock_guard lock{mutex}; return base_point; }
    ChainPoint DurablePoint() const { std::lock_guard lock{mutex}; return durable_point; }
    ChainPoint EnqueuedPoint() const { std::lock_guard lock{mutex}; return enqueued_point; }

    ProofStoreStats Stats() const
    {
        std::lock_guard lock{mutex};
        return ProofStoreStats{
            .base_height = base_point.height,
            .durable_height = durable_point.height,
            .enqueued_height = enqueued_point.height,
            .active_proofs = durable_point.height - base_point.height,
            .data_bytes = data_end,
            .wal_bytes = wal_end,
            .index_bytes = index_bytes,
            .queued_blocks = queued_blocks,
            .queued_bytes = queued_bytes,
            .peak_queued_blocks = peak_queued_blocks,
            .peak_queued_bytes = peak_queued_bytes,
            .serialized_proofs = serialized_proofs,
            .serialized_bytes = serialized_bytes,
            .largest_record_bytes = largest_record_bytes,
            .enqueue_wait_us = enqueue_wait_us,
            .serialization_us = serialization_us,
            .committed_batches = committed_batches,
            .commit_us = commit_us,
            .data_syncs = data_syncs,
            .data_sync_us = data_sync_us,
            .wal_syncs = wal_syncs,
            .wal_sync_us = wal_sync_us,
            .hits = hits,
            .misses = misses,
        };
    }

private:
    struct WorkItem {
        BlockDelta delta;
        Proof proof;
        uint64_t accounted_bytes{0};
    };

    Result<void> RecoverWal(std::vector<DiskIndexEntry>& recovered, uint64_t stored_data_size)
    {
        const uint64_t complete_wal_size{wal_end - (wal_end % WAL_RECORD_SIZE)};
        if (complete_wal_size == 0) return Result<void>::Err("proof index WAL has no complete base record");
        uint64_t offset{0};
        uint64_t valid_wal_size{complete_wal_size};
        uint64_t recovered_data_end{0};
        bool saw_base{false};
        while (offset < complete_wal_size) {
            std::array<std::byte, WAL_RECORD_SIZE> bytes{};
            auto read{PreadExact(wal_fd, bytes, offset)};
            if (!read) return read;
            const bool committed{std::equal(
                WAL_COMMIT.begin(), WAL_COMMIT.end(),
                bytes.end() - static_cast<std::ptrdiff_t>(WAL_COMMIT.size()))};
            if (!committed && offset + WAL_RECORD_SIZE == complete_wal_size) {
                valid_wal_size = offset;
                break;
            }
            auto event{ParseWal(bytes)};
            if (!event) {
                return Result<void>::Err("proof index WAL offset " + std::to_string(offset) +
                                         ": " + event.Error());
            }
            if (!saw_base) {
                if (event.Value().kind != WalKind::BASE || event.Value().data_offset != 0 ||
                    event.Value().data_size != 0 || !event.Value().previous_hash.IsNull() ||
                    !event.Value().data_digest.IsNull()) {
                    return Result<void>::Err("proof index WAL does not begin with a valid base");
                }
                base_point = event.Value().point;
                durable_point = base_point;
                enqueued_point = base_point;
                saw_base = true;
            } else if (event.Value().kind == WalKind::CONNECT) {
                if (event.Value().point.height != durable_point.height + 1 ||
                    event.Value().previous_hash != durable_point.block_hash ||
                    event.Value().data_offset != recovered_data_end ||
                    event.Value().data_size < DATA_HEADER_SIZE + DATA_FOOTER_SIZE ||
                    event.Value().data_size > config.max_record_bytes + DATA_HEADER_SIZE + DATA_FOOTER_SIZE ||
                    event.Value().data_offset > stored_data_size ||
                    event.Value().data_size > stored_data_size - event.Value().data_offset) {
                    return Result<void>::Err("proof CONNECT WAL record is not contiguous");
                }
                auto envelope{ValidateDataEnvelope(event.Value())};
                if (!envelope) return envelope;
                const uint64_t relative{event.Value().point.height - base_point.height - 1};
                if (relative >= recovered.size()) recovered.resize(static_cast<std::size_t>(relative + 1));
                recovered[relative] = EntryFromEvent(event.Value());
                durable_point = event.Value().point;
                enqueued_point = durable_point;
                recovered_data_end += event.Value().data_size;
            } else if (event.Value().kind == WalKind::TRUNCATE) {
                if (event.Value().point.height < base_point.height ||
                    event.Value().point.height >= durable_point.height ||
                    event.Value().previous_hash != durable_point.block_hash ||
                    event.Value().data_offset != 0 || event.Value().data_size != 0 ||
                    !event.Value().data_digest.IsNull()) {
                    return Result<void>::Err("invalid proof TRUNCATE WAL record");
                }
                const Hash256 expected{event.Value().point.height == base_point.height ?
                    base_point.block_hash : EntryHash(recovered[event.Value().point.height -
                                                               base_point.height - 1])};
                if (expected != event.Value().point.block_hash) {
                    return Result<void>::Err("proof TRUNCATE WAL hash does not match active history");
                }
                recovered.resize(static_cast<std::size_t>(event.Value().point.height - base_point.height));
                durable_point = event.Value().point;
                enqueued_point = durable_point;
            } else {
                return Result<void>::Err("proof WAL contains a second base record");
            }
            offset += WAL_RECORD_SIZE;
        }
        if (!saw_base) return Result<void>::Err("proof index WAL has no committed base record");
        if (valid_wal_size != wal_end) {
            if (::ftruncate(wal_fd, static_cast<off_t>(valid_wal_size)) != 0) {
                return Result<void>::Err(ErrnoMessage("truncate incomplete proof WAL tail"));
            }
            auto synced{SyncFile(wal_fd, "recovered proof index WAL")};
            if (!synced) return synced;
            wal_end = valid_wal_size;
        }
        data_end = recovered_data_end;
        if (stored_data_size < data_end) return Result<void>::Err("proof data is shorter than its durable WAL");
        if (stored_data_size != data_end) {
            if (::ftruncate(data_fd, static_cast<off_t>(data_end)) != 0) {
                return Result<void>::Err(ErrnoMessage("truncate uncommitted proof data tail"));
            }
            auto synced{SyncFile(data_fd, "recovered proof data")};
            if (!synced) return synced;
        }
        return Result<void>::Ok();
    }

    Result<void> ValidateDataEnvelope(const WalEvent& event) const
    {
        std::array<std::byte, DATA_HEADER_SIZE> header{};
        auto read{PreadExact(data_fd, header, event.data_offset)};
        if (!read) return read;
        ByteReader reader{header};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 block_hash;
        Hash256 previous_hash;
        uint64_t payload_size{0};
        if (!reader.ReadBytes(magic) || magic != DATA_MAGIC || !reader.ReadLE(version) ||
            version != STORE_FORMAT || !reader.ReadLE(height) || !reader.ReadHash(block_hash) ||
            !reader.ReadHash(previous_hash) || !reader.ReadLE(payload_size) || !reader.Done() ||
            height != event.point.height || block_hash != event.point.block_hash ||
            previous_hash != event.previous_hash ||
            payload_size + DATA_HEADER_SIZE + DATA_FOOTER_SIZE != event.data_size) {
            return Result<void>::Err("proof data header does not match its WAL record");
        }
        std::array<std::byte, DATA_FOOTER_SIZE> footer{};
        read = PreadExact(data_fd, footer, event.data_offset + event.data_size - DATA_FOOTER_SIZE);
        if (!read) return read;
        Hash256::Storage digest{};
        std::copy_n(footer.begin(), Hash256::SIZE, digest.begin());
        if (Hash256{digest} != event.data_digest ||
            !std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(),
                        footer.begin() + static_cast<std::ptrdiff_t>(Hash256::SIZE))) {
            return Result<void>::Err("proof data footer does not match its WAL record");
        }
        return Result<void>::Ok();
    }

    Result<void> MapIndex(const std::vector<DiskIndexEntry>& recovered)
    {
        const uint64_t needed{std::max<uint64_t>(INDEX_GROWTH_ENTRIES, recovered.size())};
        index_capacity = ((needed + INDEX_GROWTH_ENTRIES - 1) / INDEX_GROWTH_ENTRIES) *
                         INDEX_GROWTH_ENTRIES;
        if (index_capacity > std::numeric_limits<uint64_t>::max() / sizeof(DiskIndexEntry)) {
            return Result<void>::Err("proof mmap index is too large");
        }
        index_bytes = index_capacity * sizeof(DiskIndexEntry);
        if (::ftruncate(index_fd, static_cast<off_t>(index_bytes)) != 0) {
            return Result<void>::Err(ErrnoMessage("size proof mmap index"));
        }
        void* mapping{::mmap(nullptr, static_cast<std::size_t>(index_bytes),
                             PROT_READ | PROT_WRITE, MAP_SHARED, index_fd, 0)};
        if (mapping == MAP_FAILED) return Result<void>::Err(ErrnoMessage("mmap proof height index"));
        index_map = static_cast<DiskIndexEntry*>(mapping);
        std::fill_n(index_map, static_cast<std::size_t>(index_capacity), DiskIndexEntry{});
        std::copy(recovered.begin(), recovered.end(), index_map);
        return Result<void>::Ok();
    }

    Result<void> EnsureIndexCapacityLocked(uint64_t entries)
    {
        if (entries <= index_capacity) return Result<void>::Ok();
        const uint64_t capacity{((entries + INDEX_GROWTH_ENTRIES - 1) / INDEX_GROWTH_ENTRIES) *
                                INDEX_GROWTH_ENTRIES};
        if (capacity > std::numeric_limits<uint64_t>::max() / sizeof(DiskIndexEntry)) {
            return Result<void>::Err("proof mmap index capacity overflow");
        }
        const uint64_t bytes{capacity * sizeof(DiskIndexEntry)};
        if (::ftruncate(index_fd, static_cast<off_t>(bytes)) != 0) {
            return Result<void>::Err(ErrnoMessage("grow proof height index"));
        }
        void* mapping{::mmap(nullptr, static_cast<std::size_t>(bytes),
                             PROT_READ | PROT_WRITE, MAP_SHARED, index_fd, 0)};
        if (mapping == MAP_FAILED) return Result<void>::Err(ErrnoMessage("remap proof height index"));
        auto* grown_map{static_cast<DiskIndexEntry*>(mapping)};
        std::fill_n(grown_map + index_capacity,
                    static_cast<std::size_t>(capacity - index_capacity),
                    DiskIndexEntry{});
        if (::munmap(index_map, static_cast<std::size_t>(index_bytes)) != 0) {
            const int saved_errno{errno};
            static_cast<void>(::munmap(grown_map, static_cast<std::size_t>(bytes)));
            errno = saved_errno;
            return Result<void>::Err(ErrnoMessage("unmap old proof height index"));
        }
        index_map = grown_map;
        index_capacity = capacity;
        index_bytes = bytes;
        return Result<void>::Ok();
    }

    Result<CachedBlockProof> ParseDataRecord(uint32_t expected_height,
                                             const Hash256& expected_hash,
                                             const Hash256& expected_previous,
                                             const Hash256& expected_digest,
                                             std::span<const std::byte> bytes) const
    {
        if (bytes.size() < DATA_HEADER_SIZE + DATA_FOOTER_SIZE) {
            return Result<CachedBlockProof>::Err("stored proof record is truncated");
        }
        if (!std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(), bytes.end() -
                        static_cast<std::ptrdiff_t>(DATA_COMMIT.size()))) {
            return Result<CachedBlockProof>::Err("stored proof commit marker is missing");
        }
        Hash256::Storage digest_bytes{};
        std::copy_n(bytes.end() - static_cast<std::ptrdiff_t>(DATA_FOOTER_SIZE),
                    Hash256::SIZE, digest_bytes.begin());
        const Hash256 stored_digest{digest_bytes};
        if (stored_digest != expected_digest ||
            Sha256(bytes.first(bytes.size() - DATA_FOOTER_SIZE)) != stored_digest) {
            return Result<CachedBlockProof>::Err("stored proof checksum mismatch");
        }
        ByteReader reader{bytes.first(DATA_HEADER_SIZE)};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 hash;
        Hash256 previous;
        uint64_t payload_size{0};
        if (!reader.ReadBytes(magic) || magic != DATA_MAGIC || !reader.ReadLE(version) ||
            version != STORE_FORMAT || !reader.ReadLE(height) || !reader.ReadHash(hash) ||
            !reader.ReadHash(previous) || !reader.ReadLE(payload_size) || !reader.Done() ||
            height != expected_height || hash != expected_hash || previous != expected_previous ||
            payload_size + DATA_HEADER_SIZE + DATA_FOOTER_SIZE != bytes.size()) {
            return Result<CachedBlockProof>::Err("stored proof header is inconsistent");
        }
        auto proof{ParseFullUtreexoProof(height,
            bytes.subspan(DATA_HEADER_SIZE, static_cast<std::size_t>(payload_size)))};
        if (!proof) return proof;
        if (proof.Value().point.block_hash != expected_hash) {
            return Result<CachedBlockProof>::Err("stored proof payload hash does not match its record");
        }
        return proof;
    }

    std::optional<Hash256> HashAtLocked(uint32_t height) const
    {
        if (height == base_point.height) return base_point.block_hash;
        if (height < base_point.height || height > durable_point.height) return std::nullopt;
        const uint64_t relative{height - base_point.height - 1};
        if (relative >= index_capacity || !EntryPresent(index_map[relative])) return std::nullopt;
        return EntryHash(index_map[relative]);
    }

    void SetFailure(std::string error)
    {
        {
            std::lock_guard lock{mutex};
            if (!failure) failure = std::move(error);
        }
        input_ready.notify_all();
        output_ready.notify_all();
        space_available.notify_all();
        durable_changed.notify_all();
    }

    void SerializerLoop()
    {
        while (true) {
            WorkItem item;
            {
                std::unique_lock lock{mutex};
                input_ready.wait(lock, [&] { return failure.has_value() || stopping || !input.empty(); });
                if (failure || (stopping && input.empty())) return;
                item = std::move(input.front());
                input.pop_front();
            }
            try {
                const uint32_t height{item.delta.point.height};
                const auto serialization_start{std::chrono::steady_clock::now()};
                auto prepared{PrepareProof(std::move(item.delta), std::move(item.proof),
                                           item.accounted_bytes, config.max_record_bytes)};
                if (!prepared) {
                    SetFailure("proof serialization failed at height " +
                               std::to_string(height) + ": " + prepared.Error());
                    return;
                }
                {
                    std::lock_guard lock{mutex};
                    if (failure) return;
                    ++serialized_proofs;
                    serialized_bytes += prepared.Value().record.size();
                    largest_record_bytes = std::max<uint64_t>(largest_record_bytes,
                                                               prepared.Value().record.size());
                    serialization_us += static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - serialization_start).count());
                    ready.emplace(prepared.Value().point.height, prepared.Take());
                }
                output_ready.notify_one();
            } catch (const std::bad_alloc&) {
                SetFailure("proof serializer allocation failed");
                return;
            } catch (const std::exception& exception) {
                SetFailure("proof serializer exception: " + std::string{exception.what()});
                return;
            }
        }
    }

    std::size_t ContiguousReadyLocked() const
    {
        std::size_t count{0};
        uint32_t height{durable_point.height + 1};
        while (count < config.group_commit_blocks && ready.contains(height)) {
            ++count;
            ++height;
        }
        return count;
    }

    void WriterLoop()
    {
        while (true) {
            try {
                std::vector<PreparedProof> batch;
                {
                    std::unique_lock lock{mutex};
                    output_ready.wait(lock, [&] {
                        return failure.has_value() ||
                               ready.contains(durable_point.height + 1) || stopping;
                    });
                    if (failure) return;
                    if (stopping && durable_point.height == enqueued_point.height) return;
                    if (!ready.contains(durable_point.height + 1)) continue;
                    const auto deadline{std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(config.group_commit_delay_ms)};
                    while (ContiguousReadyLocked() < config.group_commit_blocks &&
                           !(flush_height && *flush_height >= durable_point.height + 1) && !stopping) {
                        if (config.group_commit_delay_ms == 0) {
                            output_ready.wait(lock);
                        } else {
                            if (output_ready.wait_until(lock, deadline) == std::cv_status::timeout) break;
                        }
                        if (failure) return;
                    }
                    const std::size_t count{ContiguousReadyLocked()};
                    for (std::size_t i{0}; i < count; ++i) {
                        const uint32_t height{durable_point.height + 1 + static_cast<uint32_t>(i)};
                        auto found{ready.find(height)};
                        batch.push_back(std::move(found->second));
                        ready.erase(found);
                    }
                }
                auto committed{CommitBatch(batch)};
                if (!committed) {
                    SetFailure("proof-store commit failed: " + committed.Error());
                    return;
                }
            } catch (const std::bad_alloc&) {
                SetFailure("proof writer allocation failed");
                return;
            } catch (const std::exception& exception) {
                SetFailure("proof writer exception: " + std::string{exception.what()});
                return;
            }
        }
    }

    Result<void> CommitBatch(const std::vector<PreparedProof>& batch)
    {
        if (batch.empty()) return Result<void>::Ok();
        const auto commit_start{std::chrono::steady_clock::now()};
        std::vector<WalEvent> events;
        events.reserve(batch.size());
        uint64_t next_data_offset{0};
        uint64_t next_wal_offset{0};
        {
            std::lock_guard lock{mutex};
            next_data_offset = data_end;
            next_wal_offset = wal_end;
        }
        for (const auto& proof : batch) {
            auto written{PwriteAll(data_fd, proof.record, next_data_offset)};
            if (!written) return written;
            events.push_back(WalEvent{
                .kind = WalKind::CONNECT,
                .point = proof.point,
                .previous_hash = proof.previous_hash,
                .data_offset = next_data_offset,
                .data_size = proof.record.size(),
                .data_digest = proof.digest,
            });
            next_data_offset += proof.record.size();
        }
        const auto data_sync_start{std::chrono::steady_clock::now()};
        auto data_synced{SyncFile(data_fd, "proof data")};
        if (!data_synced) return data_synced;
        const uint64_t batch_data_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - data_sync_start).count())};

        std::vector<std::byte> wal_bytes;
        wal_bytes.reserve(events.size() * WAL_RECORD_SIZE);
        for (const auto& event : events) {
            auto serialized{SerializeWal(event)};
            wal_bytes.insert(wal_bytes.end(), serialized.begin(), serialized.end());
        }
        auto wal_written{PwriteAll(wal_fd, wal_bytes, next_wal_offset)};
        if (!wal_written) return wal_written;
        const auto wal_sync_start{std::chrono::steady_clock::now()};
        auto wal_synced{SyncFile(wal_fd, "proof index WAL")};
        if (!wal_synced) return wal_synced;
        const uint64_t batch_wal_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - wal_sync_start).count())};
        {
            std::lock_guard lock{mutex};
            const uint64_t required{events.back().point.height - base_point.height};
            auto capacity{EnsureIndexCapacityLocked(required)};
            if (!capacity) return capacity;
            data_end = next_data_offset;
            wal_end = next_wal_offset + wal_bytes.size();
            ++data_syncs;
            ++wal_syncs;
            for (std::size_t i{0}; i < events.size(); ++i) {
                const auto& event{events[i]};
                const uint64_t relative{event.point.height - base_point.height - 1};
                index_map[relative] = EntryFromEvent(event);
                hash_to_height[event.point.block_hash] = static_cast<uint32_t>(relative);
                durable_point = event.point;
                --queued_blocks;
                queued_bytes -= batch[i].accounted_bytes;
            }
            ++committed_batches;
            commit_us += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - commit_start).count());
            if (flush_height && durable_point.height >= *flush_height) flush_height.reset();
            data_sync_us += batch_data_sync_us;
            wal_sync_us += batch_wal_sync_us;
        }
        durable_changed.notify_all();
        space_available.notify_all();
        return Result<void>::Ok();
    }

    ProofStoreConfig config;
    int data_fd{-1};
    int wal_fd{-1};
    int index_fd{-1};
    DiskIndexEntry* index_map{nullptr};
    uint64_t index_capacity{0};
    uint64_t index_bytes{0};
    uint64_t data_end{0};
    uint64_t wal_end{0};

    mutable std::mutex mutex;
    std::mutex operation_mutex;
    std::condition_variable input_ready;
    std::condition_variable output_ready;
    std::condition_variable space_available;
    std::condition_variable durable_changed;
    std::deque<WorkItem> input;
    std::map<uint32_t, PreparedProof> ready;
    std::vector<std::thread> serializers;
    std::thread writer;
    bool stopping{false};
    std::optional<std::string> failure;
    std::optional<uint32_t> flush_height;
    ChainPoint base_point;
    ChainPoint durable_point;
    ChainPoint enqueued_point;
    std::unordered_map<Hash256, uint32_t, Hash256Hasher> hash_to_height;
    uint64_t queued_blocks{0};
    uint64_t queued_bytes{0};
    uint64_t peak_queued_blocks{0};
    uint64_t peak_queued_bytes{0};
    uint64_t serialized_proofs{0};
    uint64_t serialized_bytes{0};
    uint64_t largest_record_bytes{0};
    uint64_t enqueue_wait_us{0};
    uint64_t serialization_us{0};
    uint64_t committed_batches{0};
    uint64_t commit_us{0};
    uint64_t data_syncs{0};
    uint64_t data_sync_us{0};
    uint64_t wal_syncs{0};
    uint64_t wal_sync_us{0};
    mutable uint64_t hits{0};
    mutable uint64_t misses{0};
};

ProofStore::ProofStore(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}
ProofStore::~ProofStore() = default;

Result<std::shared_ptr<ProofStore>> ProofStore::Open(ProofStoreConfig config)
{
    try {
        auto impl{std::make_unique<Impl>(std::move(config))};
        auto initialized{impl->Initialize()};
        if (!initialized) return Result<std::shared_ptr<ProofStore>>::Err(initialized.Error());
        return Result<std::shared_ptr<ProofStore>>::Ok(
            std::shared_ptr<ProofStore>{new ProofStore{std::move(impl)}});
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<ProofStore>>::Err(
            "proof-store allocation failed while opening");
    } catch (const std::exception& exception) {
        return Result<std::shared_ptr<ProofStore>>::Err(
            "proof-store open failed: " + std::string{exception.what()});
    }
}

Result<void> ProofStore::Enqueue(const BlockDelta& delta, Proof proof)
{
    return m_impl->Enqueue(delta, std::move(proof));
}

Result<void> ProofStore::WaitDurable(uint32_t height) { return m_impl->WaitDurable(height); }
Result<void> ProofStore::Drain() { return m_impl->Drain(); }
Result<void> ProofStore::Truncate(const ChainPoint& point) { return m_impl->Truncate(point); }

Result<std::shared_ptr<const CachedBlockProof>> ProofStore::Read(const Hash256& block_hash) const
{
    return m_impl->Read(block_hash);
}

Result<std::optional<Hash256>> ProofStore::HashAt(uint32_t height) const
{
    return m_impl->HashAt(height);
}

ChainPoint ProofStore::BasePoint() const { return m_impl->BasePoint(); }
ChainPoint ProofStore::DurablePoint() const { return m_impl->DurablePoint(); }
ChainPoint ProofStore::EnqueuedPoint() const { return m_impl->EnqueuedPoint(); }
ProofStoreStats ProofStore::Stats() const { return m_impl->Stats(); }

} // namespace utreexo
