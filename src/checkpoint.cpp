// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/checkpoint.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace utreexo {
namespace {

using Clock = std::chrono::steady_clock;

uint64_t Micros(Clock::time_point start)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
}

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
    for (std::size_t i{0}; i < bytes.size(); ++i) accumulator |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    value = static_cast<T>(accumulator);
    return true;
}

std::string ErrnoString(const std::string& prefix)
{
    return prefix + ": " + std::strerror(errno);
}

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
        return Result<void>::Err(ErrnoString("inspect " + std::string{description}));
    }
    if (!S_ISREG(descriptor_status.st_mode) || !S_ISREG(path_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        return Result<void>::Err(
            std::string{description} + " must be an unaliased regular file");
    }
    if (descriptor_status.st_nlink != 1) {
        return Result<void>::Err(
            std::string{description} + " must not be hard-linked to another path");
    }
    return Result<void>::Ok();
}

Result<void> RemoveSafeStaleTemporary(const std::filesystem::path& temporary,
                                      const std::filesystem::path& destination)
{
    struct stat temporary_status{};
    if (::lstat(temporary.c_str(), &temporary_status) != 0) {
        if (errno == ENOENT) return Result<void>::Ok();
        return Result<void>::Err(ErrnoString("inspect checkpoint temporary file"));
    }
    if (S_ISLNK(temporary_status.st_mode)) {
        return Result<void>::Err("checkpoint temporary file must not be a symbolic link");
    }
    if (!S_ISREG(temporary_status.st_mode)) {
        return Result<void>::Err("checkpoint temporary file must be a regular file");
    }
    struct stat destination_status{};
    if (::lstat(destination.c_str(), &destination_status) == 0) {
        if (destination_status.st_dev == temporary_status.st_dev &&
            destination_status.st_ino == temporary_status.st_ino) {
            return Result<void>::Err(
                "checkpoint temporary file must not alias the destination");
        }
    } else if (errno != ENOENT) {
        return Result<void>::Err(ErrnoString("inspect checkpoint destination"));
    }
    if (temporary_status.st_nlink != 1) {
        return Result<void>::Err(
            "checkpoint temporary file must not be hard-linked to another path");
    }
    const int descriptor{::open(temporary.c_str(), O_RDONLY | O_CLOEXEC |
        O_NONBLOCK | NoFollowFlag())};
    if (descriptor < 0) {
        return Result<void>::Err(ErrnoString("open checkpoint temporary file"));
    }
    ScopedDescriptor scoped{descriptor};
    auto inspected{InspectOwnedRegularFile(descriptor, temporary,
                                           "checkpoint temporary file")};
    if (!inspected) return inspected;
    if (::unlink(temporary.c_str()) != 0) {
        return Result<void>::Err(ErrnoString("remove stale checkpoint temporary file"));
    }
    return Result<void>::Ok();
}

Result<ScopedDescriptor> CreateCheckpointTemporary(
    const std::filesystem::path& temporary,
    const std::filesystem::path& destination)
{
    int descriptor{::open(temporary.c_str(), O_RDWR | O_CREAT | O_EXCL |
        O_CLOEXEC | NoFollowFlag(), 0600)};
    if (descriptor < 0 && errno == EEXIST) {
        auto removed{RemoveSafeStaleTemporary(temporary, destination)};
        if (!removed) return Result<ScopedDescriptor>::Err(removed.Error());
        descriptor = ::open(temporary.c_str(), O_RDWR | O_CREAT | O_EXCL |
            O_CLOEXEC | NoFollowFlag(), 0600);
    }
    if (descriptor < 0) {
        return Result<ScopedDescriptor>::Err(
            ErrnoString("create checkpoint temporary file"));
    }
    ScopedDescriptor scoped{descriptor};
    auto inspected{InspectOwnedRegularFile(descriptor, temporary,
                                           "checkpoint temporary file")};
    if (!inspected) return Result<ScopedDescriptor>::Err(inspected.Error());
    return Result<ScopedDescriptor>::Ok(std::move(scoped));
}

class DescriptorStreamBuffer final : public std::streambuf
{
public:
    explicit DescriptorStreamBuffer(int descriptor) : m_descriptor{descriptor}
    {
        setp(m_buffer.data(), m_buffer.data() + m_buffer.size());
    }

protected:
    int_type overflow(int_type character) override
    {
        if (!FlushBuffer()) return traits_type::eof();
        if (!traits_type::eq_int_type(character, traits_type::eof())) {
            *pptr() = traits_type::to_char_type(character);
            pbump(1);
        }
        return traits_type::not_eof(character);
    }

    std::streamsize xsputn(const char* data, std::streamsize count) override
    {
        std::streamsize completed{0};
        while (completed < count) {
            const auto available{static_cast<std::streamsize>(epptr() - pptr())};
            if (available == 0 && !FlushBuffer()) break;
            const auto take{std::min(count - completed,
                static_cast<std::streamsize>(epptr() - pptr()))};
            std::memcpy(pptr(), data + completed, static_cast<std::size_t>(take));
            pbump(static_cast<int>(take));
            completed += take;
        }
        return completed;
    }

    int sync() override { return FlushBuffer() ? 0 : -1; }

private:
    bool FlushBuffer()
    {
        const std::size_t size{static_cast<std::size_t>(pptr() - pbase())};
        std::size_t offset{0};
        while (offset < size) {
            const ssize_t written{::write(m_descriptor, pbase() + offset, size - offset)};
            if (written < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (written == 0) return false;
            offset += static_cast<std::size_t>(written);
        }
        setp(m_buffer.data(), m_buffer.data() + m_buffer.size());
        return true;
    }

    int m_descriptor;
    std::array<char, 1024U * 1024U> m_buffer{};
};

Result<void> SyncFile(int descriptor)
{
    if (::fsync(descriptor) != 0) {
        return Result<void>::Err(ErrnoString("fsync checkpoint failed"));
    }
    return Result<void>::Ok();
}

Result<void> SyncDirectory(const std::filesystem::path& path)
{
    const auto directory{path.has_parent_path() ? path.parent_path() : std::filesystem::path{"."}};
    const int descriptor{::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (descriptor < 0) return Result<void>::Err(ErrnoString("opening checkpoint directory failed"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoString("fsync checkpoint directory failed"));
    return Result<void>::Ok();
}

Result<uint64_t> FileChecksum(int descriptor, uint64_t byte_count)
{
    constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
    constexpr uint64_t FNV_PRIME{1099511628211ULL};
    uint64_t checksum{FNV_OFFSET};
    std::array<char, 1024U * 1024U> buffer{};
    uint64_t remaining{byte_count};
    while (remaining != 0) {
        const auto requested{static_cast<std::streamsize>(std::min<uint64_t>(remaining, buffer.size()))};
        std::streamsize received{0};
        while (received < requested) {
            const ssize_t count{::pread(descriptor, buffer.data() + received,
                static_cast<std::size_t>(requested - received),
                static_cast<off_t>(byte_count - remaining +
                                   static_cast<uint64_t>(received)))};
            if (count < 0) {
                if (errno == EINTR) continue;
                return Result<uint64_t>::Err(ErrnoString("read checkpoint for checksum"));
            }
            if (count == 0) {
                return Result<uint64_t>::Err("checkpoint truncated during checksum");
            }
            received += count;
        }
        for (std::streamsize i{0}; i < requested; ++i) {
            checksum ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]);
            checksum *= FNV_PRIME;
        }
        remaining -= static_cast<uint64_t>(requested);
    }
    return Result<uint64_t>::Ok(checksum);
}

Result<uint64_t> FileChecksum(const std::filesystem::path& path, uint64_t byte_count)
{
    const int descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (descriptor < 0) {
        return Result<uint64_t>::Err(ErrnoString("open checkpoint for checksum"));
    }
    ScopedDescriptor scoped{descriptor};
    return FileChecksum(descriptor, byte_count);
}

} // namespace

Result<void> SaveCheckpoint(const std::filesystem::path& path,
                            const ChainPoint& point, const PackedForest& forest,
                            std::span<const Hash256> chain_hashes,
                            CheckpointMetrics* metrics)
{
    if (metrics) *metrics = {};
    const auto total_start{Clock::now()};
    if (!chain_hashes.empty() &&
        (chain_hashes.size() != static_cast<std::size_t>(point.height) + 1 ||
         chain_hashes.back() != point.block_hash)) {
        return Result<void>::Err("checkpoint chain-hash index does not match its chain point");
    }
    const std::filesystem::path temporary{path.string() + ".tmp"};
    auto temporary_descriptor{CreateCheckpointTemporary(temporary, path)};
    if (!temporary_descriptor) return Result<void>::Err(temporary_descriptor.Error());
    ScopedDescriptor descriptor{temporary_descriptor.Take()};
    DescriptorStreamBuffer stream_buffer{descriptor.Get()};
    std::ostream output{&stream_buffer};
    const auto write_start{Clock::now()};
    constexpr std::array<char, 8> magic{'U', 'T', 'R', 'C', 'H', 'K', 'P', 'T'};
    output.write(magic.data(), static_cast<std::streamsize>(magic.size()));
    if (!WriteLE(output, CHECKPOINT_FORMAT_VERSION) || !WriteLE(output, point.height)) {
        return Result<void>::Err("failed to write checkpoint metadata");
    }
    output.write(reinterpret_cast<const char*>(point.block_hash.Bytes().data()), Hash256::SIZE);
    if (!WriteLE(output, static_cast<uint64_t>(chain_hashes.size()))) {
        return Result<void>::Err("failed to write checkpoint chain-hash count");
    }
    for (const auto& hash : chain_hashes) {
        output.write(reinterpret_cast<const char*>(hash.Bytes().data()), Hash256::SIZE);
    }
    auto written{WriteForest(output, forest)};
    if (!written) return written;
    output.flush();
    if (!output) return Result<void>::Err("failed to flush checkpoint");
    if (metrics) metrics->write_us = Micros(write_start);
    struct stat file_status{};
    if (::fstat(descriptor.Get(), &file_status) != 0 || file_status.st_size < 0) {
        return Result<void>::Err(ErrnoString("could not stat checkpoint"));
    }
    const uint64_t payload_size{static_cast<uint64_t>(file_status.st_size)};
    if (metrics) metrics->payload_bytes = payload_size;
    const auto checksum_start{Clock::now()};
    auto checksum{FileChecksum(descriptor.Get(), payload_size)};
    if (!checksum) return Result<void>::Err(checksum.Error());
    if (metrics) metrics->checksum_us = Micros(checksum_start);
    const auto checksum_append_start{Clock::now()};
    if (!WriteLE(output, checksum.Value())) {
        return Result<void>::Err("failed to append checkpoint checksum");
    }
    output.flush();
    if (!output) return Result<void>::Err("failed to flush checkpoint checksum");
    if (metrics) {
        metrics->checksum_append_us = Micros(checksum_append_start);
        metrics->final_bytes = payload_size + sizeof(uint64_t);
    }
    const auto file_sync_start{Clock::now()};
    auto synced{SyncFile(descriptor.Get())};
    if (!synced) return synced;
    if (metrics) metrics->file_sync_us = Micros(file_sync_start);
    auto inspected{InspectOwnedRegularFile(descriptor.Get(), temporary,
                                           "checkpoint temporary file")};
    if (!inspected) return inspected;

    const auto rename_start{Clock::now()};
    std::error_code error;
    std::filesystem::rename(temporary, path, error);
    if (error) return Result<void>::Err("atomic checkpoint rename failed: " + error.message());
    inspected = InspectOwnedRegularFile(descriptor.Get(), path, "published checkpoint");
    if (!inspected) return inspected;
    if (metrics) metrics->rename_us = Micros(rename_start);
    const auto directory_sync_start{Clock::now()};
    const auto directory_synced{SyncDirectory(path)};
    if (metrics) {
        metrics->directory_sync_us = Micros(directory_sync_start);
        metrics->total_us = Micros(total_start);
    }
    return directory_synced;
}

namespace {

Result<LoadedCheckpoint> LoadCheckpointImpl(
    const std::filesystem::path& path,
    const std::optional<std::filesystem::path>& online_directory,
    OnlineForestConfig online_config,
    CheckpointMetrics* metrics)
{
    if (metrics) *metrics = {};
    const auto total_start{Clock::now()};
    std::error_code size_error;
    const uint64_t file_size{std::filesystem::file_size(path, size_error)};
    if (size_error || file_size < sizeof(uint64_t)) {
        return Result<LoadedCheckpoint>::Err("could not stat checkpoint or file is too short");
    }
    if (metrics) {
        metrics->final_bytes = file_size;
        metrics->payload_bytes = file_size - sizeof(uint64_t);
    }
    std::ifstream input{path, std::ios::binary};
    if (!input) return Result<LoadedCheckpoint>::Err("could not open checkpoint");
    input.seekg(static_cast<std::streamoff>(file_size - sizeof(uint64_t)));
    uint64_t expected_checksum{0};
    if (!ReadLE(input, expected_checksum)) return Result<LoadedCheckpoint>::Err("truncated checkpoint checksum");
    const auto checksum_start{Clock::now()};
    auto actual_checksum{FileChecksum(path, file_size - sizeof(uint64_t))};
    if (metrics) metrics->checksum_us = Micros(checksum_start);
    if (!actual_checksum || actual_checksum.Value() != expected_checksum) {
        return Result<LoadedCheckpoint>::Err("checkpoint checksum mismatch");
    }
    const auto deserialize_start{Clock::now()};
    input.clear();
    input.seekg(0);
    constexpr std::array<char, 8> expected{'U', 'T', 'R', 'C', 'H', 'K', 'P', 'T'};
    std::array<char, expected.size()> magic{};
    input.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    uint32_t version{0};
    uint32_t height{0};
    Hash256::Storage block_hash{};
    if (!input || magic != expected || !ReadLE(input, version) || !ReadLE(input, height)) {
        return Result<LoadedCheckpoint>::Err("invalid or truncated checkpoint header");
    }
    if (version != CHECKPOINT_FORMAT_VERSION) {
        return Result<LoadedCheckpoint>::Err(
            "unsupported checkpoint version; pre-BIP30-fix checkpoints require reconstruction");
    }
    input.read(reinterpret_cast<char*>(block_hash.data()), Hash256::SIZE);
    if (!input) return Result<LoadedCheckpoint>::Err("truncated checkpoint chain point");
    uint64_t chain_hash_count{0};
    if (!ReadLE(input, chain_hash_count) || chain_hash_count > static_cast<uint64_t>(height) + 1) {
        return Result<LoadedCheckpoint>::Err("invalid checkpoint chain-hash count");
    }
    std::vector<Hash256> chain_hashes;
    chain_hashes.reserve(static_cast<std::size_t>(chain_hash_count));
    for (uint64_t i{0}; i < chain_hash_count; ++i) {
        Hash256::Storage hash{};
        input.read(reinterpret_cast<char*>(hash.data()), Hash256::SIZE);
        if (!input) return Result<LoadedCheckpoint>::Err("truncated checkpoint chain-hash index");
        chain_hashes.emplace_back(hash);
    }
    if (!chain_hashes.empty() &&
        (chain_hashes.size() != static_cast<std::size_t>(height) + 1 ||
         chain_hashes.back() != Hash256{block_hash})) {
        return Result<LoadedCheckpoint>::Err("checkpoint chain-hash index does not match its chain point");
    }
    const ChainPoint point{height, Hash256{block_hash}};
    OnlineForestConfig import_config{online_config};
    if (online_directory) import_config.defer_publish = true;
    auto forest{online_directory ?
        ReadForestOnline(input, *online_directory, point, chain_hashes, import_config) :
        ReadForest(input)};
    if (!forest) return Result<LoadedCheckpoint>::Err(forest.Error());
    const auto payload_end{input.tellg()};
    if (payload_end < 0 || static_cast<uint64_t>(payload_end) != file_size - sizeof(uint64_t)) {
        return Result<LoadedCheckpoint>::Err("checkpoint contains trailing or missing forest data");
    }
    if (online_directory && !online_config.defer_publish) {
        auto published{forest.Value().PublishOnline()};
        if (!published) return Result<LoadedCheckpoint>::Err(published.Error());
    }
    if (metrics) {
        metrics->deserialize_us = Micros(deserialize_start);
        metrics->total_us = Micros(total_start);
    }
    return Result<LoadedCheckpoint>::Ok(LoadedCheckpoint{
        .point = point,
        .chain_hashes = std::move(chain_hashes),
        .forest = forest.Take(),
    });
}

} // namespace

Result<LoadedCheckpoint> LoadCheckpoint(const std::filesystem::path& path,
                                        CheckpointMetrics* metrics)
{
    return LoadCheckpointImpl(path, std::nullopt, {}, metrics);
}

Result<LoadedCheckpoint> LoadCheckpointOnline(const std::filesystem::path& path,
                                              const std::filesystem::path& online_directory,
                                              OnlineForestConfig config,
                                              CheckpointMetrics* metrics)
{
    return LoadCheckpointImpl(path, online_directory, config, metrics);
}

} // namespace utreexo
