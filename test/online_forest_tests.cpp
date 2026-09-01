#include <test_framework.h>
#include <utreexo/forest.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
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
