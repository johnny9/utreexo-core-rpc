// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/forest.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

using utreexo::ChainPoint;
using utreexo::Hash256;
using utreexo::OnlineForestConfig;
using utreexo::PackedForest;

Hash256 BenchHash(uint64_t value)
{
    std::array<std::byte, 8> input{};
    for (std::size_t i{0}; i < input.size(); ++i) {
        input[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
    return utreexo::Sha512_256(input);
}

bool ParseUnsigned(std::string_view text, uint64_t& value)
{
    const auto [end, error]{
        std::from_chars(text.data(), text.data() + text.size(), value)};
    return error == std::errc{} && end == text.data() + text.size();
}

uint64_t FileChecksum(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    if (!input) return 0;
    uint64_t checksum{14695981039346656037ULL};
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count{input.gcount()};
        for (std::streamsize i{0}; i < count; ++i) {
            checksum ^= static_cast<unsigned char>(
                buffer[static_cast<std::size_t>(i)]);
            checksum *= 1099511628211ULL;
        }
    }
    return input.eof() ? checksum : 0;
}

std::optional<uint64_t> ProcessWriteBytes()
{
#if defined(__linux__)
    std::ifstream input{"/proc/self/io"};
    std::string key;
    uint64_t value{0};
    while (input >> key >> value) {
        if (key == "write_bytes:") return value;
    }
#endif
    return std::nullopt;
}

uint64_t MicrosSince(std::chrono::steady_clock::time_point start)
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count());
}

int Fail(std::string_view message)
{
    std::cerr << "verification_error=" << message << '\n';
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    uint64_t leaf_count{32'768};
    uint64_t block_count{200};
    uint64_t churn_per_block{32};
    uint64_t flush_blocks{25};
    uint64_t* values[]{&leaf_count, &block_count, &churn_per_block,
                       &flush_blocks};
    if (argc > 6) {
        std::cerr << "usage: utreexo-online-storage-benchmark"
                     " [leaves] [blocks] [churn-per-block] [flush-blocks]"
                     " [directory-parent]\n";
        return 1;
    }
    for (int argument{1}; argument < std::min(argc, 5); ++argument) {
        if (!ParseUnsigned(argv[argument], *values[argument - 1]) ||
            *values[argument - 1] == 0) {
            return Fail("arguments must be positive integers");
        }
    }
    if (leaf_count > 2'000'000 || block_count > 100'000 ||
        churn_per_block > leaf_count || flush_blocks > block_count) {
        return Fail("arguments exceed the benchmark safety bounds");
    }

    const auto nonce{static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count())};
    const std::filesystem::path parent{argc == 6 ?
        std::filesystem::path{argv[5]} :
        std::filesystem::temp_directory_path()};
    std::error_code parent_error;
    std::filesystem::create_directories(parent, parent_error);
    if (parent_error) return Fail("could not create benchmark parent directory");
    const auto directory{parent /
        ("utreexo-online-benchmark-" + std::to_string(::getpid()) + "-" +
         std::to_string(nonce))};
    std::error_code cleanup_error;
    std::filesystem::remove_all(directory, cleanup_error);
    std::filesystem::remove_all(directory.string() + ".tmp", cleanup_error);
    const auto cleanup = [&] {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        std::filesystem::remove_all(directory.string() + ".tmp", ignored);
    };

    std::vector<Hash256> live;
    live.reserve(static_cast<std::size_t>(leaf_count));
    for (uint64_t value{1}; value <= leaf_count; ++value) {
        live.push_back(BenchHash(value));
    }
    PackedForest reference;
    PackedForest online;
    auto modified{reference.Modify(live, {})};
    if (!modified) {
        cleanup();
        return Fail(modified.Error());
    }
    modified = online.Modify(live, {});
    if (!modified) {
        cleanup();
        return Fail(modified.Error());
    }
    const Hash256 genesis{BenchHash(10'000'000'000ULL)};
    std::vector<Hash256> chain{genesis};
    const OnlineForestConfig config{
        .max_dirty_bytes = 512ULL * 1024 * 1024,
        .wal_segment_bytes = 256ULL * 1024 * 1024,
        .undo_depth = 1'008,
        .sync_wal = false,
        .delta_compaction_min_runs = 4,
        .max_delta_runs = 128,
        .delta_compaction_garbage_percent = 50,
    };
    auto enabled{online.EnableOnline(directory, ChainPoint{0, genesis}, chain,
                                      config)};
    if (!enabled) {
        cleanup();
        return Fail(enabled.Error());
    }
    const auto hashes_path{directory / "forest.hashes"};
    const auto metadata_path{directory / "forest.meta"};
    const uint64_t base_hashes_before{FileChecksum(hashes_path)};
    const uint64_t base_metadata_before{FileChecksum(metadata_path)};
    if (base_hashes_before == 0 || base_metadata_before == 0) {
        cleanup();
        return Fail("could not checksum mmap base");
    }

    const auto process_writes_before{ProcessWriteBytes()};
    const auto update_start{std::chrono::steady_clock::now()};
    std::mt19937_64 random{0x7574726565786fULL};
    uint64_t next_hash{leaf_count + 1};
    uint64_t cumulative_delta_bytes{0};
    uint64_t cumulative_dirty_records{0};
    uint64_t compactions{0};
    for (uint64_t height{1}; height <= block_count; ++height) {
        std::vector<Hash256> deletions;
        deletions.reserve(static_cast<std::size_t>(churn_per_block));
        for (uint64_t item{0}; item < churn_per_block; ++item) {
            const std::size_t index{static_cast<std::size_t>(random() % live.size())};
            deletions.push_back(live[index]);
            live[index] = live.back();
            live.pop_back();
        }
        std::vector<Hash256> additions;
        additions.reserve(static_cast<std::size_t>(churn_per_block));
        for (uint64_t item{0}; item < churn_per_block; ++item) {
            additions.push_back(BenchHash(next_hash++));
            live.push_back(additions.back());
        }
        const ChainPoint point{static_cast<uint32_t>(height),
                               BenchHash(10'000'000'000ULL + height)};
        chain.push_back(point.block_hash);
        modified = reference.Modify(additions, deletions);
        if (!modified) {
            cleanup();
            return Fail(modified.Error());
        }
        modified = online.ModifyBlock(additions, deletions, point);
        if (!modified) {
            cleanup();
            return Fail(modified.Error());
        }
        if (height % flush_blocks == 0 || height == block_count) {
            const auto dirty_before{online.OnlineUsage().dirty_nodes};
            auto flushed{online.FlushOnline()};
            if (!flushed) {
                cleanup();
                return Fail(flushed.Error());
            }
            const auto usage{online.OnlineUsage()};
            cumulative_dirty_records += dirty_before;
            cumulative_delta_bytes += usage.last_flush_delta_bytes;
            if (usage.last_flush_compacted) ++compactions;
        }
    }
    const uint64_t update_us{MicrosSince(update_start)};
    const auto process_writes_after{ProcessWriteBytes()};
    const auto final_usage{online.OnlineUsage()};
    const uint64_t base_hashes_after{FileChecksum(hashes_path)};
    const uint64_t base_metadata_after{FileChecksum(metadata_path)};
    if (base_hashes_before != base_hashes_after ||
        base_metadata_before != base_metadata_after) {
        cleanup();
        return Fail("mmap base changed during delta operation");
    }

    std::vector<Hash256> targets;
    constexpr std::size_t TARGET_COUNT{16};
    for (std::size_t i{0}; i < TARGET_COUNT && i < live.size(); ++i) {
        targets.push_back(live[(i * live.size()) /
                               std::min(TARGET_COUNT, live.size())]);
    }
    auto reference_proof{reference.Prove(targets)};
    if (!reference_proof) {
        cleanup();
        return Fail(reference_proof.Error());
    }

    online = PackedForest{};
    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    const auto reopen_start{std::chrono::steady_clock::now()};
    auto reopened{PackedForest::OpenOnline(directory, recovered_chain,
                                            recovered_point, config)};
    const uint64_t reopen_us{MicrosSince(reopen_start)};
    if (!reopened) {
        cleanup();
        return Fail(reopened.Error());
    }
    online = reopened.Take();
    const auto startup_usage{online.OnlineUsage()};
    if (!startup_usage.startup_cache_hit || startup_usage.startup_full_scan) {
        cleanup();
        return Fail("reopen did not use the validated startup cache");
    }
    if (online.Roots() != reference.Roots() || recovered_chain != chain ||
        recovered_point != ChainPoint{static_cast<uint32_t>(block_count),
                                      chain.back()}) {
        cleanup();
        return Fail("reopened forest state differs from the RAM reference");
    }
    auto online_proof{online.Prove(targets)};
    if (!online_proof || online_proof.Value().targets !=
                             reference_proof.Value().targets ||
        online_proof.Value().hashes != reference_proof.Value().hashes) {
        cleanup();
        return Fail("reopened delta forest produced a different proof");
    }
    std::vector<Hash256> concrete_roots;
    for (const auto& root : online.Roots()) {
        concrete_roots.push_back(root.value_or(Hash256{}));
    }
    auto verified{utreexo::VerifyProof(online_proof.Value(), targets,
                                       concrete_roots, online.NumLeaves())};
    if (!verified || !verified.Value()) {
        cleanup();
        return Fail("reopened delta proof did not verify");
    }

    constexpr uint64_t PROOF_ITERATIONS{200};
    const auto ram_proof_start{std::chrono::steady_clock::now()};
    for (uint64_t iteration{0}; iteration < PROOF_ITERATIONS; ++iteration) {
        auto proof{reference.Prove(targets)};
        if (!proof) {
            cleanup();
            return Fail(proof.Error());
        }
    }
    const uint64_t ram_proof_us{MicrosSince(ram_proof_start)};
    const auto proof_start{std::chrono::steady_clock::now()};
    for (uint64_t iteration{0}; iteration < PROOF_ITERATIONS; ++iteration) {
        auto proof{online.Prove(targets)};
        if (!proof) {
            cleanup();
            return Fail(proof.Error());
        }
    }
    const uint64_t delta_proof_us{MicrosSince(proof_start)};
    const uint64_t observed_write_bytes{
        process_writes_before && process_writes_after &&
                *process_writes_after >= *process_writes_before
            ? *process_writes_after - *process_writes_before
            : 0};
    constexpr uint64_t DELTA_RECORD_BYTES{52};
    const uint64_t dirty_record_payload_bytes{
        cumulative_dirty_records * DELTA_RECORD_BYTES};
    const uint64_t logical_write_amplification_ppm{
        dirty_record_payload_bytes == 0 ? 0 :
        cumulative_delta_bytes * 1'000'000 / dirty_record_payload_bytes};
    const uint64_t process_write_amplification_ppm{
        dirty_record_payload_bytes == 0 || observed_write_bytes == 0 ? 0 :
        observed_write_bytes * 1'000'000 / dirty_record_payload_bytes};
    const uint64_t filesystem_write_amplification_ppm{
        cumulative_delta_bytes == 0 || observed_write_bytes == 0 ? 0 :
        observed_write_bytes * 1'000'000 / cumulative_delta_bytes};

    std::cout << "leaves=" << leaf_count << '\n'
              << "blocks=" << block_count << '\n'
              << "churn_per_block=" << churn_per_block << '\n'
              << "flush_blocks=" << flush_blocks << '\n'
              << "update_us=" << update_us << '\n'
              << "reopen_us=" << reopen_us << '\n'
              << "startup_validation_us="
              << startup_usage.startup_validation_us << '\n'
              << "startup_cache_bytes=" << startup_usage.startup_cache_bytes
              << '\n'
              << "startup_cache_replayed_records="
              << startup_usage.startup_cache_replayed_records << '\n'
              << "startup_cache_hit=1\n"
              << "proof_iterations=" << PROOF_ITERATIONS << '\n'
              << "ram_proof_us=" << ram_proof_us << '\n'
              << "delta_proof_us=" << delta_proof_us << '\n'
              << "proof_slowdown_ppm="
              << (ram_proof_us == 0 ? 0 : delta_proof_us * 1'000'000 /
                                              ram_proof_us) << '\n'
              << "cumulative_dirty_records=" << cumulative_dirty_records << '\n'
              << "dirty_record_payload_bytes=" << dirty_record_payload_bytes << '\n'
              << "cumulative_delta_bytes=" << cumulative_delta_bytes << '\n'
              << "process_write_bytes=" << observed_write_bytes << '\n'
              << "logical_write_amplification_ppm="
              << logical_write_amplification_ppm << '\n'
              << "process_write_amplification_ppm="
              << process_write_amplification_ppm << '\n'
              << "filesystem_write_amplification_ppm="
              << filesystem_write_amplification_ppm << '\n'
              << "active_delta_bytes=" << final_usage.delta_bytes << '\n'
              << "active_delta_filter_bytes="
              << final_usage.delta_filter_bytes << '\n'
              << "active_delta_index_bytes="
              << final_usage.delta_index_bytes << '\n'
              << "active_delta_runs=" << final_usage.delta_runs << '\n'
              << "active_delta_records=" << final_usage.delta_records << '\n'
              << "active_delta_obsolete_records="
              << final_usage.delta_obsolete_records << '\n'
              << "compactions=" << compactions << '\n'
              << "base_unchanged=1\n"
              << "proof_equivalent=1\n";
    cleanup();
    return 0;
}
