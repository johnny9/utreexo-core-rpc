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
#include <string>
#include <system_error>
#include <type_traits>
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

std::string ErrnoString(std::string prefix)
{
    return prefix + ": " + std::strerror(errno);
}

Result<void> SyncFile(const std::filesystem::path& path)
{
    const int descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (descriptor < 0) return Result<void>::Err(ErrnoString("opening checkpoint for fsync failed"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoString("fsync checkpoint failed"));
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

Result<uint64_t> FileChecksum(const std::filesystem::path& path, uint64_t byte_count)
{
    std::ifstream input{path, std::ios::binary};
    if (!input) return Result<uint64_t>::Err("could not open checkpoint for checksum");
    constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
    constexpr uint64_t FNV_PRIME{1099511628211ULL};
    uint64_t checksum{FNV_OFFSET};
    std::array<char, 1024U * 1024U> buffer{};
    uint64_t remaining{byte_count};
    while (remaining != 0) {
        const auto requested{static_cast<std::streamsize>(std::min<uint64_t>(remaining, buffer.size()))};
        input.read(buffer.data(), requested);
        if (input.gcount() != requested) return Result<uint64_t>::Err("checkpoint truncated during checksum");
        for (std::streamsize i{0}; i < requested; ++i) {
            checksum ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]);
            checksum *= FNV_PRIME;
        }
        remaining -= static_cast<uint64_t>(requested);
    }
    return Result<uint64_t>::Ok(checksum);
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
    const auto write_start{Clock::now()};
    {
        std::ofstream output{temporary, std::ios::binary | std::ios::trunc};
        if (!output) return Result<void>::Err("could not create checkpoint temporary file");
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
        const auto written{WriteForest(output, forest)};
        if (!written) return written;
        output.flush();
        if (!output) return Result<void>::Err("failed to flush checkpoint");
    }
    if (metrics) metrics->write_us = Micros(write_start);
    std::error_code size_error;
    const uint64_t payload_size{std::filesystem::file_size(temporary, size_error)};
    if (size_error) return Result<void>::Err("could not stat checkpoint: " + size_error.message());
    if (metrics) metrics->payload_bytes = payload_size;
    const auto checksum_start{Clock::now()};
    auto checksum{FileChecksum(temporary, payload_size)};
    if (!checksum) return Result<void>::Err(checksum.Error());
    if (metrics) metrics->checksum_us = Micros(checksum_start);
    const auto checksum_append_start{Clock::now()};
    {
        std::ofstream output{temporary, std::ios::binary | std::ios::app};
        if (!output || !WriteLE(output, checksum.Value())) {
            return Result<void>::Err("failed to append checkpoint checksum");
        }
        output.flush();
        if (!output) return Result<void>::Err("failed to flush checkpoint checksum");
    }
    if (metrics) {
        metrics->checksum_append_us = Micros(checksum_append_start);
        metrics->final_bytes = payload_size + sizeof(uint64_t);
    }
    const auto file_sync_start{Clock::now()};
    const auto synced{SyncFile(temporary)};
    if (!synced) return synced;
    if (metrics) metrics->file_sync_us = Micros(file_sync_start);

    const auto rename_start{Clock::now()};
    std::error_code error;
    std::filesystem::rename(temporary, path, error);
    if (error) return Result<void>::Err("atomic checkpoint rename failed: " + error.message());
    if (metrics) metrics->rename_us = Micros(rename_start);
    const auto directory_sync_start{Clock::now()};
    const auto directory_synced{SyncDirectory(path)};
    if (metrics) {
        metrics->directory_sync_us = Micros(directory_sync_start);
        metrics->total_us = Micros(total_start);
    }
    return directory_synced;
}

Result<LoadedCheckpoint> LoadCheckpoint(const std::filesystem::path& path,
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
    auto forest{ReadForest(input)};
    if (!forest) return Result<LoadedCheckpoint>::Err(forest.Error());
    const auto payload_end{input.tellg()};
    if (payload_end < 0 || static_cast<uint64_t>(payload_end) != file_size - sizeof(uint64_t)) {
        return Result<LoadedCheckpoint>::Err("checkpoint contains trailing or missing forest data");
    }
    if (metrics) {
        metrics->deserialize_us = Micros(deserialize_start);
        metrics->total_us = Micros(total_start);
    }
    return Result<LoadedCheckpoint>::Ok(LoadedCheckpoint{
        .point = ChainPoint{height, Hash256{block_hash}},
        .chain_hashes = std::move(chain_hashes),
        .forest = forest.Take(),
    });
}

} // namespace utreexo
