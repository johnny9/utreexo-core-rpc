#include <test_framework.h>
#include <utreexo/forest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <random>
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

TEST(online_forest_switch_wal_recovery_and_flush)
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

    // Model a crash after a capacity-growing base flush resized the arena files
    // but before its new superblock was published. The old superblock must map
    // only its declared prefix and replay the already durable WAL.
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
    }
    for (const std::string_view name : {std::string_view{"LOCK"},
                                       std::string_view{"FORMAT"},
                                       std::string_view{"state.0"},
                                       std::string_view{"chain.0.hashes"},
                                       std::string_view{"forest.hashes"},
                                       std::string_view{"forest.meta"}}) {
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
         {std::string_view{"chain.1.hashes.tmp"}, std::string_view{"state.1.tmp"}}) {
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

TEST(online_forest_disconnect_is_durable_after_base_flush)
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
            CheckEquivalent(reference, online, live);
        }
    }
    CHECK(online.FlushOnline());
    CHECK_EQ(online.OnlineUsage().base_lsn, 120U);
    online = PackedForest{};
    online = ReopenOnline(path, chain, ChainPoint{120, chain.back()}, config);
    CheckEquivalent(reference, online, live);
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
        CHECK_EQ(rolled_back.Value(), ChainPoint(expected_height, chain[expected_height]));
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

TEST(online_forest_recovers_reorg_when_base_flush_stops_before_superblock)
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

        // Generation 3 would publish state.1. Blocking its temporary file makes
        // FlushBase stop after syncing the inactive chain snapshot and mmap base,
        // exactly where a power loss previously made the old superblock unusable.
        std::filesystem::create_directory(path / "state.1.tmp");
        const auto flushed{online.FlushOnline()};
        CHECK(!flushed);
    }

    auto recovered{ReopenOnline(path, chain, point_one, config)};
    CHECK_EQ(recovered.Roots(), expected_roots);
    std::error_code cleanup_error;
    std::filesystem::remove_all(path / "state.1.tmp", cleanup_error);
    CHECK(!cleanup_error);
    CHECK(recovered.FlushOnline());
    recovered = PackedForest{};
    recovered = ReopenOnline(path, chain, point_one, config);
    CHECK_EQ(recovered.Roots(), expected_roots);
    Cleanup(path);
}

TEST(online_forest_recovers_from_corrupt_newest_superblock)
{
    const auto path{OnlinePath("superblock")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(4'000'000)};
    const ChainPoint point_one{1, OnlineHash64(4'000'001)};
    const ChainPoint point_two{2, OnlineHash64(4'000'002)};
    std::vector<Hash256> chain{genesis};
    std::vector<Hash256> initial;
    for (uint64_t value{1}; value <= 8; ++value) initial.push_back(OnlineHash64(value));
    const std::array<Hash256, 1> addition_one{OnlineHash64(60'001)};
    const std::array<Hash256, 1> addition_two{OnlineHash64(60'002)};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify(addition_one, {}));
    CHECK(reference.Modify(addition_two, {}));
    {
        PackedForest online;
        CHECK(online.Modify(initial, {}));
        CHECK(online.EnableOnline(path, ChainPoint{0, genesis}, chain, config));
        CHECK(online.ModifyBlock(addition_one, {}, point_one));
        chain.push_back(point_one.block_hash);
        CHECK(online.FlushOnline());
        CHECK_EQ(online.OnlineUsage().base_lsn, 1U);
        CHECK(online.ModifyBlock(addition_two, {}, point_two));
        chain.push_back(point_two.block_hash);
        CHECK(online.FlushOnline());
        CHECK_EQ(online.OnlineUsage().base_lsn, 2U);
    }

    // Generation 2 is state.0. Corrupt it so recovery must select generation
    // 1 from state.1 and replay transaction 2 from the retained WAL.
    FlipByte(path / "state.0", 24);
    auto recovered{ReopenOnline(path, chain, point_two, config)};
    CHECK_EQ(recovered.Roots(), reference.Roots());
    CHECK_EQ(recovered.OnlineUsage().base_lsn, 1U);
    CHECK_EQ(recovered.OnlineUsage().current_lsn, 2U);
    CHECK(recovered.OnlineUsage().dirty_nodes > 0U);
    Cleanup(path);
}

TEST(online_forest_falls_back_from_corrupt_newest_chain_snapshot)
{
    const auto path{OnlinePath("chain-superblock-pair")};
    Cleanup(path);
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
    };
    const Hash256 genesis{OnlineHash64(4'100'000)};
    const ChainPoint point_one{1, OnlineHash64(4'100'001)};
    const ChainPoint point_two{2, OnlineHash64(4'100'002)};
    std::vector<Hash256> chain{genesis};
    const std::array<Hash256, 4> initial{
        OnlineHash64(81), OnlineHash64(82), OnlineHash64(83), OnlineHash64(84)};
    const std::array<Hash256, 1> addition_one{OnlineHash64(85)};
    const std::array<Hash256, 1> addition_two{OnlineHash64(86)};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify(addition_one, {}));
    CHECK(reference.Modify(addition_two, {}));
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

    // Generation 2 uses state.0 + chain.0.hashes. Corrupting only its chain
    // snapshot must select generation 1 and replay block 2 from retained WAL.
    FlipByte(path / "chain.0.hashes", 2 * static_cast<std::streamoff>(Hash256::SIZE));
    auto recovered{ReopenOnline(path, chain, point_two, config)};
    CHECK_EQ(recovered.Roots(), reference.Roots());
    CHECK_EQ(recovered.OnlineUsage().base_lsn, 1U);
    CHECK_EQ(recovered.OnlineUsage().current_lsn, 2U);
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
