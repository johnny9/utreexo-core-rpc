#include <test_framework.h>
#include <utreexo/forest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace utreexo;

namespace {

Hash256 OnlineHash(uint8_t value)
{
    std::array<std::byte, 1> input{static_cast<std::byte>(value)};
    return Sha512_256(input);
}

Hash256 OnlineHash64(uint64_t value)
{
    std::array<std::byte, 8> input{};
    for (std::size_t i{0}; i < input.size(); ++i) {
        input[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
    return Sha512_256(input);
}

std::filesystem::path OnlinePath(std::string_view name)
{
    return std::filesystem::temp_directory_path() /
        ("utreexo-online-" + std::string{name} + "-" + std::to_string(::getpid()));
}

void Cleanup(const std::filesystem::path& path)
{
    std::error_code error;
    std::filesystem::remove_all(path, error);
    std::filesystem::remove_all(path.string() + ".tmp", error);
}

std::filesystem::path WalPath(const std::filesystem::path& directory)
{
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const auto name{entry.path().filename().string()};
        if (name.starts_with("wal-") && name.ends_with(".log")) return entry.path();
    }
    return {};
}

std::filesystem::path ValidatedCachePath(
    const std::filesystem::path& directory)
{
    return directory / "validated-state.cache";
}

std::filesystem::path DeltaPathForTest(const std::filesystem::path& directory,
                                       uint64_t generation,
                                       bool temporary = false)
{
    std::ostringstream name;
    name << "delta-" << std::setw(20) << std::setfill('0') << generation
         << ".run";
    if (temporary) name << ".tmp";
    return directory / name.str();
}

std::vector<std::filesystem::path> DeltaPaths(
    const std::filesystem::path& directory)
{
    std::vector<std::filesystem::path> paths;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        const auto name{entry.path().filename().string()};
        if (name.starts_with("delta-") && name.ends_with(".run")) {
            paths.push_back(entry.path());
        }
    }
    std::ranges::sort(paths);
    return paths;
}

uint64_t FileChecksum(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    CHECK(input.good());
    uint64_t checksum{14695981039346656037ULL};
    std::array<char, 64 * 1024> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count{input.gcount()};
        for (std::streamsize i{0}; i < count; ++i) {
            checksum ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]);
            checksum *= 1099511628211ULL;
        }
    }
    CHECK(input.eof());
    return checksum;
}

void FlipByte(const std::filesystem::path& path, std::streamoff offset)
{
    std::fstream file{path, std::ios::binary | std::ios::in | std::ios::out};
    CHECK(file.good());
    file.seekg(offset);
    char value{0};
    file.read(&value, 1);
    CHECK(file.good());
    value = static_cast<char>(static_cast<unsigned char>(value) ^ 0x80U);
    file.seekp(offset);
    file.write(&value, 1);
    CHECK(file.good());
}

std::string ReadText(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

std::vector<Hash256> ConcreteRoots(const PackedForest& forest)
{
    std::vector<Hash256> roots;
    for (const auto& root : forest.Roots()) roots.push_back(root.value_or(Hash256{}));
    return roots;
}

void CheckEquivalent(const PackedForest& reference, const PackedForest& online,
                     std::span<const Hash256> live)
{
    CHECK_EQ(online.NumLeaves(), reference.NumLeaves());
    CHECK_EQ(online.Roots(), reference.Roots());
    CHECK_EQ(online.Usage().live_nodes, reference.Usage().live_nodes);
    CHECK_EQ(online.Usage().index_entries, reference.Usage().index_entries);
    CHECK_EQ(online.Usage().index_tombstones, 0U);
    for (const auto& hash : live) {
        CHECK(reference.Contains(hash));
        CHECK(online.Contains(hash));
    }

    if (live.empty()) return;
    std::vector<Hash256> targets;
    targets.push_back(live.front());
    if (live.size() > 2) targets.push_back(live[live.size() / 2]);
    if (live.size() > 1) targets.push_back(live.back());
    auto reference_proof{reference.Prove(targets)};
    auto online_proof{online.Prove(targets)};
    CHECK(reference_proof);
    CHECK(online_proof);
    CHECK_EQ(online_proof.Value().targets, reference_proof.Value().targets);
    CHECK_EQ(online_proof.Value().hashes, reference_proof.Value().hashes);
    auto verified{VerifyProof(online_proof.Value(), targets, ConcreteRoots(online),
                              online.NumLeaves())};
    CHECK(verified);
    CHECK(verified.Value());
}

PackedForest ReopenOnline(const std::filesystem::path& path,
                          std::span<const Hash256> expected_chain,
                          const ChainPoint& expected_point,
                          OnlineForestConfig config)
{
    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    auto recovered{PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
    CHECK(recovered);
    CHECK_EQ(recovered_chain,
             std::vector<Hash256>(expected_chain.begin(), expected_chain.end()));
    CHECK_EQ(recovered_point, expected_point);
    return recovered.Take();
}

struct TestDelta {
    std::vector<Hash256> additions;
    std::vector<Hash256> deletions;
    ChainPoint point;
};

} // namespace

TEST(online_forest_defaults_to_wal_free_overlay)
{
    CHECK(!OnlineForestConfig{}.sync_wal);
}

TEST(online_forest_reuses_validated_startup_cache_and_replays_newer_state)
{
    const auto path{OnlinePath("validated-startup-cache")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash64(890'000)};
    const Hash256 block_one{OnlineHash64(890'001)};
    const ChainPoint genesis_point{0, genesis};
    const ChainPoint next_point{1, block_one};
    const std::array<Hash256, 1> base_chain{genesis};
    const std::array<Hash256, 8> initial{
        OnlineHash64(891), OnlineHash64(892), OnlineHash64(893),
        OnlineHash64(894), OnlineHash64(895), OnlineHash64(896),
        OnlineHash64(897), OnlineHash64(898)};
    const std::array<Hash256, 2> deletions{initial[1], initial[6]};
    const std::array<Hash256, 2> additions{
        OnlineHash64(899), OnlineHash64(900)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    std::vector<Hash256> live{initial.begin(), initial.end()};
    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, genesis_point, base_chain, config));
    }

    const auto cache_path{ValidatedCachePath(path)};
    CHECK(std::filesystem::is_regular_file(cache_path));
    const uint64_t initial_cache_bytes{std::filesystem::file_size(cache_path)};
    CHECK(initial_cache_bytes > 0U);

    {
        auto online{ReopenOnline(path, base_chain, genesis_point, config)};
        const auto usage{online.OnlineUsage()};
        CHECK(usage.startup_cache_hit);
        CHECK(!usage.startup_full_scan);
        CHECK_EQ(usage.startup_cache_replayed_records, 0U);
        CHECK_EQ(usage.startup_cache_bytes, initial_cache_bytes);
        CheckEquivalent(reference, online, live);

        CHECK(online.ModifyBlock(additions, deletions, next_point));
        CHECK(reference.Modify(additions, deletions));
        std::erase(live, deletions[0]);
        std::erase(live, deletions[1]);
        live.insert(live.end(), additions.begin(), additions.end());
    }

    const std::array<Hash256, 2> next_chain{genesis, block_one};
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        const auto usage{online.OnlineUsage()};
        CHECK(usage.startup_cache_hit);
        CHECK(!usage.startup_full_scan);
        CHECK(usage.startup_cache_replayed_records > 0U);
        CheckEquivalent(reference, online, live);
        CHECK(online.FlushOnline());
    }
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        const auto usage{online.OnlineUsage()};
        CHECK(usage.startup_cache_hit);
        CHECK(!usage.startup_full_scan);
        CHECK(usage.startup_cache_replayed_records > 0U);
        CheckEquivalent(reference, online, live);
    }

    FlipByte(cache_path, 824);
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        const auto usage{online.OnlineUsage()};
        CHECK(!usage.startup_cache_hit);
        CHECK(usage.startup_full_scan);
        CheckEquivalent(reference, online, live);
    }
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        CHECK(online.OnlineUsage().startup_cache_hit);
        CHECK(!online.OnlineUsage().startup_full_scan);
        CHECK_EQ(online.OnlineUsage().startup_cache_replayed_records, 0U);
        CheckEquivalent(reference, online, live);
    }

    CHECK(std::filesystem::remove(cache_path));
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        CHECK(!online.OnlineUsage().startup_cache_hit);
        CHECK(online.OnlineUsage().startup_full_scan);
        CHECK(std::filesystem::is_regular_file(cache_path));
        CheckEquivalent(reference, online, live);
    }

    const auto hashes_path{path / "forest.hashes"};
    const auto modified{std::filesystem::last_write_time(hashes_path) -
                        std::chrono::seconds{2}};
    std::filesystem::last_write_time(hashes_path, modified);
    {
        auto online{ReopenOnline(path, next_chain, next_point, config)};
        CHECK(!online.OnlineUsage().startup_cache_hit);
        CHECK(online.OnlineUsage().startup_full_scan);
        CheckEquivalent(reference, online, live);
    }
    Cleanup(path);
}

TEST(online_forest_switch_wal_recovery_and_delta_seal)
{
    const auto path{OnlinePath("recovery")};
    Cleanup(path);

    const std::array<Hash256, 4> initial{
        OnlineHash(0), OnlineHash(1), OnlineHash(2), OnlineHash(3)};
    const Hash256 genesis{OnlineHash(100)};
    const Hash256 block_one{OnlineHash(101)};
    const ChainPoint genesis_point{0, genesis};
    const ChainPoint next_point{1, block_one};
    const std::array<Hash256, 1> base_chain{genesis};
    const std::array<Hash256, 1> deletion{initial[1]};
    const std::array<Hash256, 1> addition{OnlineHash(4)};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify(addition, deletion));
    const auto expected_roots{reference.Roots()};

    {
        PackedForest forest;
        CHECK(forest.Modify(initial, {}));
        CHECK(forest.EnableOnline(path, genesis_point, base_chain,
            OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                               .wal_segment_bytes = 1024 * 1024,
                               .undo_depth = 8,
                               .sync_wal = true}));
        CHECK(forest.IsOnline());
        CHECK(forest.ModifyBlock(addition, deletion, next_point));
        CHECK_EQ(forest.Roots(), expected_roots);
        CHECK(forest.Contains(addition[0]));
        CHECK(!forest.Contains(deletion[0]));
        CHECK_EQ(forest.OnlinePoint(), std::optional<ChainPoint>{next_point});
        CHECK_EQ(forest.OnlineUsage().current_lsn, 1U);
        CHECK_EQ(forest.OnlineUsage().base_lsn, 0U);
        CHECK(forest.OnlineUsage().dirty_nodes > 0U);
        CHECK(forest.OnlineUsage().wal_bytes > 0U);
    }

    // Preserve recovery compatibility with a legacy crash after a base resize
    // but before its new superblock was published. The old superblock maps only
    // its declared prefix and replays the already durable WAL.
    const auto hashes_path{path / "forest.hashes"};
    const auto metadata_path{path / "forest.meta"};
    std::filesystem::resize_file(
        hashes_path, std::filesystem::file_size(hashes_path) * 2);
    std::filesystem::resize_file(
        metadata_path, std::filesystem::file_size(metadata_path) * 2);

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    {
        auto recovered{PackedForest::OpenOnline(path, recovered_chain, recovered_point,
            OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                               .wal_segment_bytes = 1024 * 1024,
                               .undo_depth = 8,
                               .sync_wal = true})};
        CHECK(recovered);
        CHECK_EQ(recovered_point, next_point);
        CHECK_EQ(recovered_chain, std::vector<Hash256>({genesis, block_one}));
        CHECK_EQ(recovered.Value().Roots(), expected_roots);
        CHECK(recovered.Value().Contains(addition[0]));
        CHECK(!recovered.Value().Contains(deletion[0]));
        CHECK_EQ(recovered.Value().OnlineUsage().base_lsn, 0U);
        CHECK_EQ(recovered.Value().OnlineUsage().current_lsn, 1U);
        CHECK(recovered.Value().FlushOnline());
        CHECK_EQ(recovered.Value().OnlineUsage().base_lsn, 1U);
        CHECK_EQ(recovered.Value().OnlineUsage().dirty_nodes, 0U);
    }
    recovered_chain.clear();
    recovered_point = {};
    {
        auto flushed{PackedForest::OpenOnline(path, recovered_chain, recovered_point,
            OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                               .wal_segment_bytes = 1024 * 1024,
                               .undo_depth = 8,
                               .sync_wal = true})};
        CHECK(flushed);
        CHECK_EQ(flushed.Value().Roots(), expected_roots);
        CHECK_EQ(flushed.Value().OnlineUsage().base_lsn, 1U);
        CHECK_EQ(flushed.Value().OnlineUsage().current_lsn, 1U);
    }

    Cleanup(path);
}

TEST(online_forest_without_wal_replays_from_last_base_after_restart)
{
    const auto path{OnlinePath("no-wal-replay")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash64(900'000)};
    const ChainPoint next_point{1, OnlineHash64(900'001)};
    const std::array<Hash256, 1> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(901), OnlineHash64(902), OnlineHash64(903), OnlineHash64(904)};
    const std::array<Hash256, 1> deletion{initial[1]};
    const std::array<Hash256, 1> addition{OnlineHash64(905)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };

    PackedForest base;
    CHECK(base.Modify(initial, {}));
    const auto base_roots{base.Roots()};
    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition, deletion, next_point));
        CHECK_EQ(online.OnlinePoint(), std::optional<ChainPoint>{next_point});
        CHECK(online.OnlineUsage().dirty_nodes > 0U);
        CHECK_EQ(online.OnlineUsage().wal_bytes, 0U);
        CHECK(WalPath(path).empty());
    }

    auto recovered{ReopenOnline(path, chain, ChainPoint{0, genesis}, config)};
    CHECK_EQ(recovered.Roots(), base_roots);
    CHECK(recovered.Contains(deletion[0]));
    CHECK(!recovered.Contains(addition[0]));
    CHECK_EQ(recovered.OnlineUsage().base_lsn, 0U);
    CHECK_EQ(recovered.OnlineUsage().current_lsn, 0U);
    Cleanup(path);
}

TEST(online_forest_without_wal_publishes_delta_atomically_and_keeps_base_immutable)
{
    const auto path{OnlinePath("no-wal-flush-recovery")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash64(910'000)};
    const ChainPoint next_point{1, OnlineHash64(910'001)};
    std::vector<Hash256> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(911), OnlineHash64(912), OnlineHash64(913), OnlineHash64(914)};
    const std::array<Hash256, 1> deletion{initial[2]};
    const std::array<Hash256, 2> additions{OnlineHash64(915), OnlineHash64(916)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };

    PackedForest base;
    CHECK(base.Modify(initial, {}));
    const auto base_roots{base.Roots()};
    PackedForest expected;
    CHECK(expected.Modify(initial, {}));
    CHECK(expected.Modify(additions, deletion));
    uint64_t base_hashes_checksum{0};
    uint64_t base_meta_checksum{0};

    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        base_hashes_checksum = FileChecksum(path / "forest.hashes");
        base_meta_checksum = FileChecksum(path / "forest.meta");
        CHECK(online.ModifyBlock(additions, deletion, next_point));

        // A failed temporary-file publication must leave both the immutable
        // mmap base and the previous durable point untouched.
        std::filesystem::create_directory(DeltaPathForTest(path, 1, true));
        const auto flushed{online.FlushOnline()};
        CHECK(!flushed);
        CHECK(DeltaPaths(path).empty());
        CHECK_EQ(FileChecksum(path / "forest.hashes"), base_hashes_checksum);
        CHECK_EQ(FileChecksum(path / "forest.meta"), base_meta_checksum);
    }

    std::error_code cleanup_error;
    std::filesystem::remove_all(DeltaPathForTest(path, 1, true), cleanup_error);
    CHECK(!cleanup_error);
    {
        auto recovered{ReopenOnline(path, chain, ChainPoint{0, genesis}, config)};
        CHECK_EQ(recovered.Roots(), base_roots);
        CHECK(recovered.Contains(deletion[0]));
        CHECK(!recovered.Contains(additions[0]));

        CHECK(recovered.ModifyBlock(additions, deletion, next_point));
        CHECK(recovered.FlushOnline());
        CHECK_EQ(recovered.Roots(), expected.Roots());
        const auto usage{recovered.OnlineUsage()};
        CHECK_EQ(usage.wal_bytes, 0U);
        CHECK(usage.last_flush_dirty_nodes > 0U);
        CHECK_EQ(usage.delta_runs, 1U);
        CHECK(usage.delta_records > 0U);
        CHECK(usage.delta_bytes > 0U);
        CHECK(usage.delta_filter_bytes > 0U);
        CHECK(usage.delta_filter_bytes < usage.delta_bytes);
        CHECK(usage.delta_index_bytes > 0U);
        CHECK(usage.delta_index_bytes < usage.delta_filter_bytes);
        CHECK_EQ(usage.last_flush_delta_bytes, usage.delta_bytes);
        CHECK(usage.last_flush_total_us >= usage.last_flush_sort_us);
        CHECK(usage.last_flush_total_us >= usage.last_flush_write_us);
        CHECK(usage.last_flush_total_us >= usage.last_flush_sync_us);
        CHECK_EQ(FileChecksum(path / "forest.hashes"), base_hashes_checksum);
        CHECK_EQ(FileChecksum(path / "forest.meta"), base_meta_checksum);
    }

    chain.push_back(next_point.block_hash);
    auto durable{ReopenOnline(path, chain, next_point, config)};
    CHECK_EQ(durable.Roots(), expected.Roots());
    CHECK(!durable.Contains(deletion[0]));
    CHECK(durable.Contains(additions[0]));
    CHECK(WalPath(path).empty());
    CHECK_EQ(durable.OnlineUsage().physical_base_lsn, 0U);
    CHECK_EQ(durable.OnlineUsage().base_lsn, 1U);
    CHECK(durable.OnlineUsage().delta_filter_bytes > 0U);
    CHECK(durable.OnlineUsage().delta_index_bytes > 0U);
    CHECK_EQ(FileChecksum(path / "forest.hashes"), base_hashes_checksum);
    CHECK_EQ(FileChecksum(path / "forest.meta"), base_meta_checksum);
    Cleanup(path);
}

TEST(online_forest_rejects_corrupt_committed_delta_before_recovery)
{
    const auto path{OnlinePath("corrupt-flush-undo")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash64(920'000)};
    const ChainPoint next_point{1, OnlineHash64(920'001)};
    const std::array<Hash256, 1> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(921), OnlineHash64(922), OnlineHash64(923), OnlineHash64(924)};
    const std::array<Hash256, 1> deletion{initial[0]};
    const std::array<Hash256, 1> addition{OnlineHash64(925)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };

    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition, deletion, next_point));
        CHECK(online.FlushOnline());
        CHECK(std::filesystem::exists(DeltaPathForTest(path, 1)));
    }
    FlipByte(DeltaPathForTest(path, 1), 80);
    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    const auto recovered{
        PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
    CHECK(!recovered);
    CHECK(recovered.Error().find("forest delta checksum mismatch") !=
          std::string::npos);
    CHECK(std::filesystem::exists(DeltaPathForTest(path, 1)));
    Cleanup(path);
}

TEST(online_forest_rejects_valid_delta_from_a_different_base)
{
    const auto source_path{OnlinePath("delta-source-base")};
    const auto target_path{OnlinePath("delta-target-base")};
    Cleanup(source_path);
    Cleanup(target_path);
    const Hash256 genesis{OnlineHash64(925'000)};
    const std::array<Hash256, 1> chain{genesis};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };
    {
        PackedForest source;
        const std::array<Hash256, 4> leaves{
            OnlineHash64(1), OnlineHash64(2), OnlineHash64(3), OnlineHash64(4)};
        const std::array<Hash256, 1> addition{OnlineHash64(5)};
        CHECK(source.Modify(leaves, {}));
        CHECK(source.EnableOnline(source_path, ChainPoint{0, genesis}, chain,
                                  config));
        CHECK(source.ModifyBlock(addition, {},
                                 ChainPoint{1, OnlineHash64(925'001)}));
        CHECK(source.FlushOnline());
    }
    {
        PackedForest target;
        const std::array<Hash256, 4> leaves{
            OnlineHash64(11), OnlineHash64(12), OnlineHash64(13), OnlineHash64(14)};
        CHECK(target.Modify(leaves, {}));
        CHECK(target.EnableOnline(target_path, ChainPoint{0, genesis}, chain,
                                  config));
    }
    std::error_code copy_error;
    CHECK(std::filesystem::copy_file(DeltaPathForTest(source_path, 1),
                                     DeltaPathForTest(target_path, 1),
                                     copy_error));
    CHECK(!copy_error);
    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    const auto recovered{PackedForest::OpenOnline(
        target_path, recovered_chain, recovered_point, config)};
    CHECK(!recovered);
    CHECK(recovered.Error().find("anchored to a different mmap base") !=
          std::string::npos);
    Cleanup(source_path);
    Cleanup(target_path);
}

TEST(online_forest_wal_free_mode_commits_and_prunes_recovered_wal)
{
    const auto path{OnlinePath("disable-existing-wal")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash64(930'000)};
    const ChainPoint next_point{1, OnlineHash64(930'001)};
    const std::array<Hash256, 1> base_chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(931), OnlineHash64(932), OnlineHash64(933), OnlineHash64(934)};
    const std::array<Hash256, 1> deletion{initial[3]};
    const std::array<Hash256, 1> addition{OnlineHash64(935)};
    const OnlineForestConfig wal_config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    auto no_wal_config{wal_config};
    no_wal_config.sync_wal = false;

    PackedForest expected;
    CHECK(expected.Modify(initial, {}));
    CHECK(expected.Modify(addition, deletion));
    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, base_chain,
                                  wal_config));
        CHECK(online.ModifyBlock(addition, deletion, next_point));
    }
    CHECK(!WalPath(path).empty());

    const std::array<Hash256, 2> next_chain{genesis, next_point.block_hash};
    {
        auto migrated{ReopenOnline(path, next_chain, next_point, no_wal_config)};
        CHECK_EQ(migrated.Roots(), expected.Roots());
        CHECK(migrated.OnlineUsage().wal_bytes > 0U);
        CHECK(migrated.FlushOnline());
        CHECK(WalPath(path).empty());
    }
    auto durable{ReopenOnline(path, next_chain, next_point, no_wal_config)};
    CHECK_EQ(durable.Roots(), expected.Roots());
    CHECK_EQ(durable.OnlineUsage().wal_bytes, 0U);
    Cleanup(path);
}

TEST(online_forest_holds_exclusive_lock_for_lifetime)
{
    const auto path{OnlinePath("exclusive-lock")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash(201)};
    const std::array<Hash256, 1> chain{genesis};
    const std::array<Hash256, 2> leaves{OnlineHash(21), OnlineHash(22)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };

    {
        PackedForest owner;
        CHECK(owner.Modify(leaves, {}));
        CHECK(owner.EnableOnline(path, ChainPoint{0, genesis}, chain, config));

        std::vector<Hash256> duplicate_chain;
        ChainPoint duplicate_point;
        const auto duplicate{
            PackedForest::OpenOnline(path, duplicate_chain, duplicate_point, config)};
        CHECK(!duplicate);
        CHECK(duplicate.Error().find("locked by another process") != std::string::npos);

        CHECK(owner.ModifyBlock({}, {}, ChainPoint{1, OnlineHash(202)}));
    }

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    {
        const auto reopened{PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
        CHECK(reopened);
        CHECK_EQ(recovered_point, (ChainPoint{1, OnlineHash(202)}));
    }
    Cleanup(path);
}

TEST(online_forest_truncates_uncommitted_wal_tail)
{
    const auto path{OnlinePath("tail")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash(110)};
    const Hash256 block_one{OnlineHash(111)};
    const std::array<Hash256, 1> chain{genesis};
    const std::array<Hash256, 2> leaves{OnlineHash(10), OnlineHash(11)};

    {
        PackedForest forest;
        CHECK(forest.Modify(leaves, {}));
        CHECK(forest.EnableOnline(path, ChainPoint{0, genesis}, chain,
            OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                               .wal_segment_bytes = 1024 * 1024,
                               .undo_depth = 8,
                               .sync_wal = true}));
        const std::array<Hash256, 1> addition{OnlineHash(12)};
        CHECK(forest.ModifyBlock(addition, {}, ChainPoint{1, block_one}));
    }

    std::filesystem::path wal_path;
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        if (entry.path().filename().string().starts_with("wal-")) wal_path = entry.path();
    }
    CHECK(!wal_path.empty());
    const auto committed_size{std::filesystem::file_size(wal_path)};
    {
        std::ofstream output{wal_path, std::ios::binary | std::ios::app};
        output << "incomplete";
    }
    CHECK(std::filesystem::file_size(wal_path) > committed_size);

    std::vector<Hash256> recovered_chain;
    ChainPoint point;
    auto recovered{PackedForest::OpenOnline(path, recovered_chain, point,
        OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                           .wal_segment_bytes = 1024 * 1024,
                           .undo_depth = 8,
                           .sync_wal = true})};
    CHECK(recovered);
    const ChainPoint expected_point{1, block_one};
    CHECK_EQ(point, expected_point);
    CHECK_EQ(std::filesystem::file_size(wal_path), committed_size);
    Cleanup(path);
}

TEST(online_forest_rejects_hard_linked_wal_before_tail_truncation)
{
    const auto path{OnlinePath("wal-external-hardlink")};
    const auto external{OnlinePath("wal-external-hardlink-sentinel")};
    Cleanup(path);
    std::error_code cleanup_error;
    std::filesystem::remove(external, cleanup_error);
    const Hash256 genesis{OnlineHash(112)};
    const std::array<Hash256, 1> chain{genesis};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    {
        PackedForest forest;
        const std::array<Hash256, 2> leaves{OnlineHash(13), OnlineHash(14)};
        CHECK(forest.Modify(leaves, {}));
        CHECK(forest.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        const std::array<Hash256, 1> addition{OnlineHash(15)};
        CHECK(forest.ModifyBlock(addition, {}, ChainPoint{1, OnlineHash(113)}));
    }

    const auto wal_path{WalPath(path)};
    CHECK(!wal_path.empty());
    {
        std::ofstream output{wal_path, std::ios::binary | std::ios::app};
        output << "incomplete external tail";
    }
    std::filesystem::create_hard_link(wal_path, external);
    const auto size{std::filesystem::file_size(wal_path)};

    std::vector<Hash256> recovered_chain;
    ChainPoint point;
    const auto recovered{
        PackedForest::OpenOnline(path, recovered_chain, point, config)};
    CHECK(!recovered);
    CHECK(recovered.Error().find("hard-linked") != std::string::npos);
    CHECK_EQ(std::filesystem::file_size(wal_path), size);
    CHECK_EQ(std::filesystem::file_size(external), size);

    std::filesystem::remove(external, cleanup_error);
    Cleanup(path);
}

TEST(online_forest_rejects_hard_linked_owned_files_on_recovery)
{
    const auto path{OnlinePath("arena-external-hardlink")};
    const auto external{OnlinePath("arena-external-hardlink-sentinel")};
    Cleanup(path);
    std::error_code cleanup_error;
    std::filesystem::remove(external, cleanup_error);
    const Hash256 genesis{OnlineHash(114)};
    const std::array<Hash256, 1> chain{genesis};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    {
        PackedForest forest;
        const std::array<Hash256, 2> leaves{OnlineHash(16), OnlineHash(17)};
        CHECK(forest.Modify(leaves, {}));
        CHECK(forest.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(forest.ModifyBlock({}, {}, ChainPoint{1, OnlineHash(115)}));
        CHECK(forest.FlushOnline());
    }
    const std::vector<std::string> owned_names{
        "LOCK", "FORMAT", "state.0", "chain.0.hashes", "forest.hashes",
        "forest.meta", "validated-state.cache",
        DeltaPathForTest(path, 1).filename().string()};
    for (const std::string& name : owned_names) {
        std::filesystem::create_hard_link(path / name, external);
        const auto size{std::filesystem::file_size(external)};
        std::vector<Hash256> recovered_chain;
        ChainPoint point;
        const auto recovered{
            PackedForest::OpenOnline(path, recovered_chain, point, config)};
        CHECK(!recovered);
        CHECK(recovered.Error().find("hard-linked") != std::string::npos);
        CHECK_EQ(std::filesystem::file_size(external), size);
        std::filesystem::remove(external, cleanup_error);
        CHECK(!cleanup_error);
    }
    Cleanup(path);
}

TEST(online_forest_flush_rejects_hard_linked_temporary_files_without_clobbering)
{
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    const std::string sentinel_content{"external online-state sentinel\n"};
    for (const std::string_view temporary_name :
         {std::string_view{"delta-00000000000000000001.run.tmp"}}) {
        const auto path{OnlinePath(std::string{"flush-temp-"} +
                                   std::string{temporary_name})};
        const auto external{OnlinePath(std::string{"flush-temp-sentinel-"} +
                                       std::string{temporary_name})};
        Cleanup(path);
        std::error_code cleanup_error;
        std::filesystem::remove(external, cleanup_error);
        {
            std::ofstream output{external, std::ios::binary};
            output << sentinel_content;
        }
        const Hash256 genesis{OnlineHash(118)};
        const std::array<Hash256, 1> chain{genesis};
        PackedForest forest;
        const std::array<Hash256, 2> leaves{OnlineHash(18), OnlineHash(19)};
        CHECK(forest.Modify(leaves, {}));
        CHECK(forest.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(forest.ModifyBlock({}, {}, ChainPoint{1, OnlineHash(119)}));
        std::filesystem::create_hard_link(external, path / temporary_name);

        const auto flushed{forest.FlushOnline()};
        CHECK(!flushed);
        CHECK(flushed.Error().find("hard-linked") != std::string::npos);
        CHECK_EQ(ReadText(external), sentinel_content);

        std::filesystem::remove(path / temporary_name, cleanup_error);
        CHECK(forest.FlushOnline());
        forest = PackedForest{};
        std::filesystem::remove(external, cleanup_error);
        Cleanup(path);
    }
}

TEST(online_forest_disconnect_is_durable_after_delta_seal)
{
    const auto path{OnlinePath("disconnect")};
    Cleanup(path);
    const Hash256 genesis{OnlineHash(120)};
    const Hash256 block_one{OnlineHash(121)};
    const std::array<Hash256, 1> chain{genesis};
    const std::array<Hash256, 3> leaves{OnlineHash(20), OnlineHash(21), OnlineHash(22)};
    const std::array<Hash256, 1> addition{OnlineHash(23)};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    std::vector<std::optional<Hash256>> base_roots;

    {
        PackedForest forest;
        CHECK(forest.Modify(leaves, {}));
        base_roots = forest.Roots();
        CHECK(forest.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(forest.ModifyBlock(addition, {}, ChainPoint{1, block_one}));
        CHECK(forest.FlushOnline());
        CHECK_EQ(forest.OnlineUsage().base_lsn, 1U);
        const auto rolled_back{forest.RollbackOnlineBlock()};
        CHECK(rolled_back);
        const ChainPoint expected{0, genesis};
        CHECK_EQ(rolled_back.Value(), expected);
        CHECK_EQ(forest.Roots(), base_roots);
        CHECK(!forest.Contains(addition[0]));
        CHECK_EQ(forest.OnlineUsage().current_lsn, 2U);
        CHECK_EQ(forest.OnlineUsage().base_lsn, 1U);
    }

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    {
        auto recovered{PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
        CHECK(recovered);
        const ChainPoint expected{0, genesis};
        CHECK_EQ(recovered_point, expected);
        CHECK_EQ(recovered_chain, std::vector<Hash256>{genesis});
        CHECK_EQ(recovered.Value().Roots(), base_roots);
        CHECK(!recovered.Value().Contains(addition[0]));
        CHECK_EQ(recovered.Value().OnlineUsage().current_lsn, 2U);
    }
    Cleanup(path);
}

TEST(online_forest_randomized_differential_reopen_flush_and_proofs)
{
    const auto path{OnlinePath("differential")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 16 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 32,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(1'000'000)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> live;
    for (uint64_t value{1}; value <= 64; ++value) live.push_back(OnlineHash64(value));

    PackedForest reference;
    PackedForest online;
    CHECK(reference.Modify(live, {}));
    CHECK(online.Modify(live, {}));
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));

    std::mt19937 random{0x5eed1234U};
    uint64_t next_hash{10'000};
    uint64_t previous_base_lsn{0};
    for (uint32_t height{1}; height <= 120; ++height) {
        std::shuffle(live.begin(), live.end(), random);
        const std::size_t maximum_deletions{std::min<std::size_t>(4, live.size() / 3)};
        const std::size_t deletion_count{maximum_deletions == 0 ? 0 :
            static_cast<std::size_t>(random()) % (maximum_deletions + 1)};
        std::vector<Hash256> deletions{
            live.begin(), live.begin() + static_cast<std::ptrdiff_t>(deletion_count)};
        live.erase(live.begin(), live.begin() + static_cast<std::ptrdiff_t>(deletion_count));

        const std::size_t addition_count{1 + static_cast<std::size_t>(random()) % 5};
        std::vector<Hash256> additions;
        additions.reserve(addition_count);
        for (std::size_t i{0}; i < addition_count; ++i) {
            additions.push_back(OnlineHash64(next_hash++));
            live.push_back(additions.back());
        }
        const ChainPoint point{height, OnlineHash64(1'000'000 + height)};
        chain.push_back(point.block_hash);
        CHECK(reference.Modify(additions, deletions));
        CHECK(online.ModifyBlock(additions, deletions, point));
        CHECK_EQ(online.OnlineUsage().current_lsn, height);
        CHECK(online.OnlineUsage().base_lsn >= previous_base_lsn);
        previous_base_lsn = online.OnlineUsage().base_lsn;
        CheckEquivalent(reference, online, live);

        if (height % 10 == 0) {
            if (height % 20 == 0) CHECK(online.FlushOnline());
            online = PackedForest{};
            online = ReopenOnline(path, chain, point, config);
            CHECK(online.OnlineUsage().startup_cache_hit);
            CHECK(!online.OnlineUsage().startup_full_scan);
            CheckEquivalent(reference, online, live);
        }
    }
    CHECK(online.FlushOnline());
    CHECK_EQ(online.OnlineUsage().base_lsn, 120U);
    online = PackedForest{};
    online = ReopenOnline(path, chain, ChainPoint{120, chain.back()}, config);
    CHECK(online.OnlineUsage().startup_cache_hit);
    CHECK(!online.OnlineUsage().startup_full_scan);
    CheckEquivalent(reference, online, live);
    Cleanup(path);
}

TEST(online_forest_compacts_from_measured_obsolete_records_without_rewriting_base)
{
    const auto path{OnlinePath("delta-compaction")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
        .delta_compaction_min_runs = 3,
        .max_delta_runs = 16,
        .delta_compaction_garbage_percent = 1,
    };
    const Hash256 genesis{OnlineHash64(1'500'000)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> live;
    for (uint64_t value{1}; value <= 8; ++value) {
        live.push_back(OnlineHash64(value));
    }
    PackedForest reference;
    PackedForest online;
    CHECK(reference.Modify(live, {}));
    CHECK(online.Modify(live, {}));
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
    const uint64_t hashes_checksum{FileChecksum(path / "forest.hashes")};
    const uint64_t metadata_checksum{FileChecksum(path / "forest.meta")};

    Hash256 rolling{live.front()};
    uint64_t next_value{100'000};
    for (uint32_t height{1}; height <= 3; ++height) {
        const Hash256 replacement{OnlineHash64(next_value++)};
        const std::array<Hash256, 1> deletions{rolling};
        const std::array<Hash256, 1> additions{replacement};
        const auto found{std::ranges::find(live, rolling)};
        CHECK(found != live.end());
        *found = replacement;
        rolling = replacement;
        const ChainPoint point{height, OnlineHash64(1'500'000 + height)};
        chain.push_back(point.block_hash);
        CHECK(reference.Modify(additions, deletions));
        CHECK(online.ModifyBlock(additions, deletions, point));
        CHECK(online.FlushOnline());
        CheckEquivalent(reference, online, live);
    }

    const auto usage{online.OnlineUsage()};
    CHECK(usage.last_flush_compacted);
    CHECK_EQ(usage.delta_runs, 1U);
    CHECK(usage.last_flush_compaction_input_records >
          usage.last_flush_compaction_output_records);
    CHECK_EQ(usage.delta_records, usage.delta_unique_records);
    CHECK_EQ(DeltaPaths(path).size(), 1U);
    CHECK_EQ(DeltaPaths(path).front().filename().string(),
             DeltaPathForTest(path, 4).filename().string());
    CHECK_EQ(FileChecksum(path / "forest.hashes"), hashes_checksum);
    CHECK_EQ(FileChecksum(path / "forest.meta"), metadata_checksum);

    // A normal successor run must link to and override a compacted snapshot.
    // Keep it below min_runs so this checks the mixed snapshot/run recovery path.
    const Hash256 replacement{OnlineHash64(next_value++)};
    const std::array<Hash256, 1> deletions{rolling};
    const std::array<Hash256, 1> additions{replacement};
    const auto found{std::ranges::find(live, rolling)};
    CHECK(found != live.end());
    *found = replacement;
    const ChainPoint point_four{4, OnlineHash64(1'500'004)};
    chain.push_back(point_four.block_hash);
    CHECK(reference.Modify(additions, deletions));
    CHECK(online.ModifyBlock(additions, deletions, point_four));
    CHECK(online.FlushOnline());
    CHECK(!online.OnlineUsage().last_flush_compacted);
    CHECK_EQ(online.OnlineUsage().delta_runs, 2U);
    CheckEquivalent(reference, online, live);

    online = PackedForest{};
    online = ReopenOnline(path, chain, point_four, config);
    CheckEquivalent(reference, online, live);
    CHECK_EQ(online.OnlineUsage().physical_base_lsn, 0U);
    CHECK_EQ(online.OnlineUsage().base_lsn, 4U);
    CHECK_EQ(online.OnlineUsage().delta_runs, 2U);
    Cleanup(path);
}

TEST(online_forest_compacts_at_run_count_safety_cap)
{
    const auto path{OnlinePath("delta-run-cap")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
        .delta_compaction_min_runs = 2,
        .max_delta_runs = 3,
        .delta_compaction_garbage_percent = 100,
    };
    const Hash256 genesis{OnlineHash64(1'600'000)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> live;
    for (uint64_t value{1}; value <= 16; ++value) {
        live.push_back(OnlineHash64(1'610'000 + value));
    }
    PackedForest reference;
    PackedForest online;
    CHECK(reference.Modify(live, {}));
    CHECK(online.Modify(live, {}));
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
    const uint64_t hashes_checksum{FileChecksum(path / "forest.hashes")};
    const uint64_t metadata_checksum{FileChecksum(path / "forest.meta")};

    for (uint32_t height{1}; height <= 3; ++height) {
        const std::array<Hash256, 1> addition{
            OnlineHash64(1'620'000 + height)};
        live.push_back(addition[0]);
        const ChainPoint point{height, OnlineHash64(1'600'000 + height)};
        chain.push_back(point.block_hash);
        CHECK(reference.Modify(addition, {}));
        CHECK(online.ModifyBlock(addition, {}, point));
        CHECK(online.FlushOnline());
        CheckEquivalent(reference, online, live);
        if (height < 3) CHECK(!online.OnlineUsage().last_flush_compacted);
    }

    const auto usage{online.OnlineUsage()};
    CHECK(usage.last_flush_compacted);
    CHECK_EQ(usage.delta_runs, 1U);
    CHECK_EQ(usage.delta_records, usage.delta_unique_records);
    CHECK_EQ(usage.delta_obsolete_records, 0U);
    CHECK_EQ(DeltaPaths(path).size(), 1U);
    CHECK_EQ(DeltaPaths(path).front().filename().string(),
             DeltaPathForTest(path, 4).filename().string());
    CHECK_EQ(FileChecksum(path / "forest.hashes"), hashes_checksum);
    CHECK_EQ(FileChecksum(path / "forest.meta"), metadata_checksum);

    online = PackedForest{};
    online = ReopenOnline(path, chain, ChainPoint{3, chain.back()}, config);
    CheckEquivalent(reference, online, live);
    Cleanup(path);
}

TEST(online_forest_delta_extends_node_ids_past_the_fixed_mmap_base)
{
    const auto path{OnlinePath("delta-growth")};
    Cleanup(path);
    constexpr uint64_t INITIAL_LEAVES{uint64_t{1} << 19};
    std::vector<Hash256> initial;
    initial.reserve(INITIAL_LEAVES);
    for (uint64_t value{1}; value <= INITIAL_LEAVES; ++value) {
        initial.push_back(OnlineHash64(20'000'000 + value));
    }
    PackedForest reference;
    PackedForest online;
    CHECK(reference.Modify(initial, {}));
    CHECK(online.Modify(initial, {}));
    const Hash256 genesis{OnlineHash64(21'000'000)};
    std::vector<Hash256> chain{genesis};
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
    const uint64_t physical_slots{
        std::filesystem::file_size(path / "forest.hashes") / sizeof(Hash256)};
    const uint64_t hashes_checksum{FileChecksum(path / "forest.hashes")};
    const uint64_t metadata_checksum{FileChecksum(path / "forest.meta")};
    const std::array<Hash256, 2> additions{
        OnlineHash64(22'000'001), OnlineHash64(22'000'002)};
    const ChainPoint point{1, OnlineHash64(21'000'001)};
    chain.push_back(point.block_hash);
    CHECK(reference.Modify(additions, {}));
    CHECK(online.ModifyBlock(additions, {}, point));
    CHECK(online.Usage().allocated_slots > physical_slots);
    CHECK(online.FlushOnline());
    CHECK_EQ(std::filesystem::file_size(path / "forest.hashes"),
             physical_slots * sizeof(Hash256));
    CHECK_EQ(FileChecksum(path / "forest.hashes"), hashes_checksum);
    CHECK_EQ(FileChecksum(path / "forest.meta"), metadata_checksum);

    online = PackedForest{};
    online = ReopenOnline(path, chain, point, config);
    CHECK_EQ(online.Roots(), reference.Roots());
    CHECK(online.Contains(additions[0]));
    CHECK(online.Contains(additions[1]));
    const std::array<Hash256, 3> targets{
        initial.front(), additions[0], additions[1]};
    const auto reference_proof{reference.Prove(targets)};
    const auto online_proof{online.Prove(targets)};
    CHECK(reference_proof);
    CHECK(online_proof);
    CHECK_EQ(online_proof.Value().targets, reference_proof.Value().targets);
    CHECK_EQ(online_proof.Value().hashes, reference_proof.Value().hashes);
    Cleanup(path);
}

TEST(online_forest_multiblock_reorg_reopen_and_alternate_branch)
{
    const auto path{OnlinePath("multireorg")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 16,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(2'000'000)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> initial;
    for (uint64_t value{1}; value <= 32; ++value) initial.push_back(OnlineHash64(value));
    std::vector<Hash256> live{initial};
    std::vector<std::vector<Hash256>> live_at_height{live};
    std::vector<std::vector<std::optional<Hash256>>> roots_at_height;
    std::vector<TestDelta> original_blocks;

    PackedForest reference;
    PackedForest online;
    CHECK(reference.Modify(initial, {}));
    CHECK(online.Modify(initial, {}));
    roots_at_height.push_back(reference.Roots());
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));

    uint64_t next_hash{50'000};
    for (uint32_t height{1}; height <= 12; ++height) {
        const std::size_t delete_index{(static_cast<std::size_t>(height) * 7) % live.size()};
        std::vector<Hash256> deletions{live[delete_index]};
        live.erase(live.begin() + static_cast<std::ptrdiff_t>(delete_index));
        std::vector<Hash256> additions{OnlineHash64(next_hash++), OnlineHash64(next_hash++)};
        live.insert(live.end(), additions.begin(), additions.end());
        const ChainPoint point{height, OnlineHash64(2'000'000 + height)};
        chain.push_back(point.block_hash);
        original_blocks.push_back(TestDelta{additions, deletions, point});
        CHECK(reference.Modify(additions, deletions));
        CHECK(online.ModifyBlock(additions, deletions, point));
        roots_at_height.push_back(reference.Roots());
        live_at_height.push_back(live);
    }
    CHECK(online.FlushOnline());

    for (uint32_t expected_height{11}; expected_height >= 7; --expected_height) {
        const auto rolled_back{online.RollbackOnlineBlock()};
        CHECK(rolled_back);
        CHECK_EQ(rolled_back.Value(), (ChainPoint{expected_height, chain[expected_height]}));
        CHECK_EQ(online.Roots(), roots_at_height[expected_height]);
        chain.pop_back();
        online = PackedForest{};
        online = ReopenOnline(path, chain, ChainPoint{expected_height, chain.back()}, config);
        CHECK_EQ(online.Roots(), roots_at_height[expected_height]);
        if (expected_height == 7) break;
    }

    reference = PackedForest{};
    CHECK(reference.Modify(initial, {}));
    for (std::size_t i{0}; i < 7; ++i) {
        CHECK(reference.Modify(original_blocks[i].additions, original_blocks[i].deletions));
    }
    live = live_at_height[7];
    for (uint32_t height{8}; height <= 12; ++height) {
        const std::size_t delete_index{(static_cast<std::size_t>(height) * 11) % live.size()};
        std::vector<Hash256> deletions{live[delete_index]};
        live.erase(live.begin() + static_cast<std::ptrdiff_t>(delete_index));
        std::vector<Hash256> additions{
            OnlineHash64(next_hash++), OnlineHash64(next_hash++), OnlineHash64(next_hash++)};
        live.insert(live.end(), additions.begin(), additions.end());
        const ChainPoint point{height, OnlineHash64(3'000'000 + height)};
        chain.push_back(point.block_hash);
        CHECK(reference.Modify(additions, deletions));
        CHECK(online.ModifyBlock(additions, deletions, point));
        CheckEquivalent(reference, online, live);
    }
    // Replacing hashes at existing heights must publish the alternate chain,
    // rather than treating the old chain file length as a valid prefix.
    CHECK(online.FlushOnline());
    online = PackedForest{};
    online = ReopenOnline(path, chain, ChainPoint{12, chain.back()}, config);
    CheckEquivalent(reference, online, live);
    Cleanup(path);
}

TEST(online_forest_recovers_reorg_when_delta_publication_is_blocked)
{
    const auto path{OnlinePath("reorg-flush-boundary")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 16,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(7'000'000)};
    const ChainPoint point_one{1, OnlineHash64(7'000'001)};
    const ChainPoint point_two{2, OnlineHash64(7'000'002)};
    std::vector<Hash256> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(71), OnlineHash64(72), OnlineHash64(73), OnlineHash64(74)};
    const std::array<Hash256, 1> addition_one{OnlineHash64(75)};
    const std::array<Hash256, 1> addition_two{OnlineHash64(76)};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify(addition_one, {}));
    const auto expected_roots{reference.Roots()};

    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition_one, {}, point_one));
        chain.push_back(point_one.block_hash);
        CHECK(online.FlushOnline());
        CHECK(online.ModifyBlock(addition_two, {}, point_two));
        chain.push_back(point_two.block_hash);
        CHECK(online.FlushOnline());
        CHECK(online.RollbackOnlineBlock());
        chain.pop_back();
        CHECK_EQ(online.Roots(), expected_roots);

        // The rollback WAL is already durable. Blocking delta generation 3
        // must not alter either prior immutable run or the mmap base.
        std::filesystem::create_directory(DeltaPathForTest(path, 3, true));
        const auto flushed{online.FlushOnline()};
        CHECK(!flushed);
    }

    auto recovered{ReopenOnline(path, chain, point_one, config)};
    CHECK_EQ(recovered.Roots(), expected_roots);
    std::error_code cleanup_error;
    std::filesystem::remove_all(DeltaPathForTest(path, 3, true), cleanup_error);
    CHECK(!cleanup_error);
    CHECK(recovered.FlushOnline());
    recovered = PackedForest{};
    recovered = ReopenOnline(path, chain, point_one, config);
    CHECK_EQ(recovered.Roots(), expected_roots);
    Cleanup(path);
}

TEST(online_forest_ignores_incomplete_delta_temporary_file)
{
    const auto path{OnlinePath("incomplete-delta")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };
    const Hash256 genesis{OnlineHash64(4'000'000)};
    const ChainPoint point_one{1, OnlineHash64(4'000'001)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> initial;
    for (uint64_t value{1}; value <= 8; ++value) initial.push_back(OnlineHash64(value));
    const std::array<Hash256, 1> addition_one{OnlineHash64(60'001)};
    const std::array<Hash256, 1> addition_two{OnlineHash64(60'002)};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify(addition_one, {}));
    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition_one, {}, point_one));
        chain.push_back(point_one.block_hash);
        CHECK(online.FlushOnline());
        CHECK_EQ(online.OnlineUsage().base_lsn, 1U);
    }

    // A crash can leave an arbitrary .tmp tail. Only fsync-and-renamed .run
    // files are candidates for recovery.
    {
        std::ofstream output{DeltaPathForTest(path, 2, true), std::ios::binary};
        output << "incomplete delta";
        CHECK(output.good());
    }
    auto recovered{ReopenOnline(path, chain, point_one, config)};
    std::vector<Hash256> live{initial.begin(), initial.end()};
    live.push_back(addition_one[0]);
    CheckEquivalent(reference, recovered, live);
    CHECK(std::filesystem::exists(DeltaPathForTest(path, 2, true)));

    // The next seal safely reclaims an unaliased regular temporary file, so a
    // crash tail cannot permanently block publication of its generation.
    const ChainPoint point_two{2, OnlineHash64(4'000'002)};
    CHECK(reference.Modify(addition_two, {}));
    live.push_back(addition_two[0]);
    chain.push_back(point_two.block_hash);
    CHECK(recovered.ModifyBlock(addition_two, {}, point_two));
    CHECK(recovered.FlushOnline());
    CHECK(!std::filesystem::exists(DeltaPathForTest(path, 2, true)));
    CHECK(std::filesystem::exists(DeltaPathForTest(path, 2)));
    recovered = PackedForest{};
    recovered = ReopenOnline(path, chain, point_two, config);
    CheckEquivalent(reference, recovered, live);
    Cleanup(path);
}

TEST(online_forest_rejects_missing_delta_predecessor)
{
    const auto path{OnlinePath("delta-gap")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = false,
    };
    const Hash256 genesis{OnlineHash64(4'100'000)};
    const ChainPoint point_one{1, OnlineHash64(4'100'001)};
    const ChainPoint point_two{2, OnlineHash64(4'100'002)};
    std::vector<Hash256> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(81), OnlineHash64(82), OnlineHash64(83), OnlineHash64(84)};
    const std::array<Hash256, 1> addition_one{OnlineHash64(85)};
    const std::array<Hash256, 1> addition_two{OnlineHash64(86)};

    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition_one, {}, point_one));
        chain.push_back(point_one.block_hash);
        CHECK(online.FlushOnline());
        CHECK(online.ModifyBlock(addition_two, {}, point_two));
        chain.push_back(point_two.block_hash);
        CHECK(online.FlushOnline());
    }

    CHECK_EQ(DeltaPaths(path).size(), 2U);
    std::error_code remove_error;
    CHECK(std::filesystem::remove(DeltaPathForTest(path, 1), remove_error));
    CHECK(!remove_error);
    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    const auto recovered{
        PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
    CHECK(!recovered);
    CHECK(recovered.Error().find("not contiguous") != std::string::npos);
    Cleanup(path);
}

TEST(online_forest_rejects_corrupt_committed_wal)
{
    const auto path{OnlinePath("wal-corruption")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(5'000'000)};
    const Hash256 block_one{OnlineHash64(5'000'001)};
    const std::vector<Hash256> chain{genesis};
    {
        PackedForest online;
        const std::array<Hash256, 4> initial{
            OnlineHash64(1), OnlineHash64(2), OnlineHash64(3), OnlineHash64(4)};
        const std::array<Hash256, 1> addition{OnlineHash64(70'000)};
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition, {}, ChainPoint{1, block_one}));
    }
    const auto wal{WalPath(path)};
    CHECK(!wal.empty());
    const auto size{std::filesystem::file_size(wal)};
    CHECK(size > 32U);
    FlipByte(wal, static_cast<std::streamoff>(size - 17));

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    auto recovered{PackedForest::OpenOnline(path, recovered_chain, recovered_point, config)};
    CHECK(!recovered);
    CHECK(recovered.Error().find("checksum") != std::string::npos);
    Cleanup(path);
}

TEST(online_forest_discards_incomplete_first_wal_transaction)
{
    const auto path{OnlinePath("first-tail")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(6'000'000)};
    const std::vector<Hash256> chain{genesis};
    std::vector<std::optional<Hash256>> base_roots;
    {
        PackedForest online;
        const std::array<Hash256, 4> initial{
            OnlineHash64(1), OnlineHash64(2), OnlineHash64(3), OnlineHash64(4)};
        const std::array<Hash256, 1> addition{OnlineHash64(80'000)};
        CHECK(online.Modify(initial, {}));
        base_roots = online.Roots();
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition, {}, ChainPoint{1, OnlineHash64(6'000'001)}));
    }
    const auto wal{WalPath(path)};
    CHECK(!wal.empty());
    const auto committed_size{std::filesystem::file_size(wal)};
    CHECK(committed_size > 1U);
    std::filesystem::resize_file(wal, committed_size - 1);

    auto recovered{ReopenOnline(path, chain, ChainPoint{0, genesis}, config)};
    CHECK_EQ(recovered.Roots(), base_roots);
    CHECK_EQ(recovered.OnlineUsage().current_lsn, 0U);
    CHECK_EQ(std::filesystem::file_size(wal), 0U);
    Cleanup(path);
}

TEST(online_forest_rotates_prunes_and_enforces_undo_window)
{
    const auto path{OnlinePath("retention")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 64 * 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 1,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(7'000'000)};
    const std::vector<Hash256> chain{genesis};
    std::vector<Hash256> initial;
    initial.reserve(8'192);
    for (uint64_t value{1}; value <= 8'192; ++value) initial.push_back(OnlineHash64(value));

    PackedForest online;
    CHECK(online.Modify(initial, {}));
    CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
    uint64_t next_hash{100'000};
    for (uint32_t height{1}; height <= 3; ++height) {
        std::vector<Hash256> additions;
        additions.reserve(8'192);
        for (std::size_t i{0}; i < 8'192; ++i) additions.push_back(OnlineHash64(next_hash++));
        CHECK(online.ModifyBlock(additions, {},
                                 ChainPoint{height, OnlineHash64(7'000'000 + height)}));
        const auto transaction{online.OnlineUsage()};
        CHECK(transaction.last_transaction_wal_bytes > config.wal_segment_bytes);
        CHECK(transaction.last_transaction_total_us >= transaction.last_transaction_serialize_us);
        CHECK(transaction.last_transaction_total_us >= transaction.last_transaction_segment_us);
        CHECK(transaction.last_transaction_total_us >= transaction.last_transaction_write_us);
        CHECK(transaction.last_transaction_total_us >= transaction.last_transaction_sync_us);
        CHECK(transaction.last_transaction_total_us >= transaction.last_transaction_publish_us);
        CHECK_EQ(transaction.wal_segment_directory_syncs, height);
        CHECK(online.FlushOnline());
    }

    // Segment 1 is older than the configured window after the third flush.
    // The two newest connects remain available, while the third rollback must
    // fail closed instead of synthesizing an invalid previous state.
    CHECK(online.RollbackOnlineBlock());
    CHECK(online.RollbackOnlineBlock());
    const auto outside_window{online.RollbackOnlineBlock()};
    CHECK(!outside_window);
    CHECK(outside_window.Error().find("outside the retained WAL window") != std::string::npos);
    Cleanup(path);
}
