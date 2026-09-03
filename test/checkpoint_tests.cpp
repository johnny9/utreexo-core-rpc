#include <test_framework.h>
#include <utreexo/checkpoint.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

using namespace utreexo;

namespace {

uint64_t CheckpointChecksum(std::span<const unsigned char> bytes)
{
    constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
    constexpr uint64_t FNV_PRIME{1099511628211ULL};
    uint64_t checksum{FNV_OFFSET};
    for (const unsigned char byte : bytes) {
        checksum ^= byte;
        checksum *= FNV_PRIME;
    }
    return checksum;
}

void AddCheckpointTrailingByteWithValidChecksum(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    std::vector<unsigned char> bytes{
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    CHECK(bytes.size() >= sizeof(uint64_t));
    bytes.resize(bytes.size() - sizeof(uint64_t));
    bytes.push_back(0x5aU);
    uint64_t checksum{CheckpointChecksum(bytes)};
    for (std::size_t i{0}; i < sizeof(checksum); ++i) {
        bytes.push_back(static_cast<unsigned char>(checksum & 0xffU));
        checksum >>= 8;
    }
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    CHECK(output.good());
}

} // namespace

TEST(checkpoint_roundtrip)
{
    const auto leaf_a{Hash256::FromHex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value()};
    const auto leaf_b{Hash256::FromHex("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").Value()};
    PackedForest forest;
    const std::array<Hash256, 2> leaves{leaf_a, leaf_b};
    CHECK(forest.Modify(leaves, {}));

    const auto path{std::filesystem::temp_directory_path() / "utreexo-checkpoint-test.dat"};
    const ChainPoint point{123, Hash256::FromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").Value()};
    std::vector<Hash256> chain_hashes(124, Hash256{});
    chain_hashes.back() = point.block_hash;
    CheckpointMetrics save_metrics;
    CHECK(SaveCheckpoint(path, point, forest, chain_hashes, &save_metrics));
    CHECK(save_metrics.payload_bytes > 0U);
    CHECK_EQ(save_metrics.final_bytes, save_metrics.payload_bytes + sizeof(uint64_t));
    CHECK_EQ(save_metrics.final_bytes, std::filesystem::file_size(path));
    CheckpointMetrics load_metrics;
    auto loaded{LoadCheckpoint(path, &load_metrics)};
    CHECK(loaded);
    CHECK_EQ(load_metrics.payload_bytes, save_metrics.payload_bytes);
    CHECK_EQ(load_metrics.final_bytes, save_metrics.final_bytes);
    CHECK_EQ(loaded.Value().point, point);
    CHECK_EQ(loaded.Value().chain_hashes, chain_hashes);
    CHECK_EQ(loaded.Value().forest.NumLeaves(), 2U);
    CHECK_EQ(loaded.Value().forest.Roots(), forest.Roots());
    CHECK(loaded.Value().forest.Contains(leaf_a));
    std::filesystem::remove(path);
}

TEST(checkpoint_save_rejects_symbolic_link_temporary_file)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-symlink-" + suffix + ".dat")};
    const auto temporary{std::filesystem::path{path.string() + ".tmp"}};
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(temporary, error);

    PackedForest forest;
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));
    std::filesystem::create_symlink(path, temporary);
    const auto saved{SaveCheckpoint(path, point, forest, chain)};
    CHECK(!saved);
    CHECK(saved.Error().find("symbolic link") != std::string::npos);
    CHECK(LoadCheckpoint(path));

    std::filesystem::remove(temporary, error);
    std::filesystem::remove(path, error);
}

TEST(checkpoint_save_rejects_hard_link_temporary_alias)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-hardlink-" + suffix + ".dat")};
    const auto temporary{std::filesystem::path{path.string() + ".tmp"}};
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(temporary, error);

    PackedForest forest;
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));
    std::filesystem::create_hard_link(path, temporary);
    const auto saved{SaveCheckpoint(path, point, forest, chain)};
    CHECK(!saved);
    CHECK(saved.Error().find("alias the destination") != std::string::npos);
    CHECK(LoadCheckpoint(path));

    std::filesystem::remove(temporary, error);
    std::filesystem::remove(path, error);
}

TEST(checkpoint_save_rejects_external_hard_link_temporary_without_clobbering)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-external-hardlink-" + suffix + ".dat")};
    const auto temporary{std::filesystem::path{path.string() + ".tmp"}};
    const auto sentinel{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-external-sentinel-" + suffix + ".dat")};
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(temporary, error);
    std::filesystem::remove(sentinel, error);
    {
        std::ofstream output{sentinel, std::ios::binary};
        output << "external checkpoint sentinel\n";
    }
    std::filesystem::create_hard_link(sentinel, temporary);

    PackedForest forest;
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    const auto saved{SaveCheckpoint(path, point, forest, chain)};
    CHECK(!saved);
    CHECK(saved.Error().find("hard-linked") != std::string::npos);
    std::ifstream input{sentinel, std::ios::binary};
    const std::string content{std::istreambuf_iterator<char>{input},
                              std::istreambuf_iterator<char>{}};
    CHECK_EQ(content, std::string{"external checkpoint sentinel\n"});
    CHECK(!std::filesystem::exists(path));

    std::filesystem::remove(temporary, error);
    std::filesystem::remove(sentinel, error);
}

TEST(checkpoint_save_reclaims_unaliased_stale_temporary_file)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-stale-file-" + suffix + ".dat")};
    const auto temporary{std::filesystem::path{path.string() + ".tmp"}};
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(temporary, error);
    {
        std::ofstream output{temporary, std::ios::binary};
        output << "abandoned partial checkpoint\n";
    }

    PackedForest forest;
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));
    CHECK(LoadCheckpoint(path));
    CHECK(!std::filesystem::exists(temporary));

    std::filesystem::remove(path, error);
}

TEST(checkpoint_streams_directly_to_online_state)
{
    const auto checkpoint_path{
        std::filesystem::temp_directory_path() / "utreexo-checkpoint-online-test.dat"};
    const auto online_path{
        std::filesystem::temp_directory_path() / "utreexo-checkpoint-online-test-state"};
    std::error_code cleanup_error;
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(online_path.string() + ".tmp", cleanup_error);

    const auto leaf_a{Hash256::FromHex(
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value()};
    const auto leaf_b{Hash256::FromHex(
        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").Value()};
    const auto leaf_c{Hash256::FromHex(
        "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986").Value()};
    const std::array<Hash256, 3> initial{leaf_a, leaf_b, leaf_c};
    const std::array<Hash256, 1> deletion{leaf_b};
    const std::array<Hash256, 1> addition{Hash256::FromHex(
        "084fed08b978af4d7d196a7446a86b58009e636b6117e7f3187e3b156dd6e938").Value()};

    PackedForest reference;
    CHECK(reference.Modify(initial, {}));
    CHECK(reference.Modify({}, deletion));
    const ChainPoint point{1, Hash256::FromHex(
        "010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").Value()};
    const std::array<Hash256, 2> chain{Hash256{}, point.block_hash};
    CHECK(SaveCheckpoint(checkpoint_path, point, reference, chain));

    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 16,
    };
    const ChainPoint next_point{2, Hash256::FromHex(
        "020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").Value()};
    std::vector<Hash256> expected_chain{chain.begin(), chain.end()};
    expected_chain.push_back(next_point.block_hash);
    std::vector<std::optional<Hash256>> expected_roots;
    {
        auto loaded{LoadCheckpointOnline(checkpoint_path, online_path, config)};
        CHECK(loaded);
        CHECK(loaded.Value().forest.IsOnline());
        CHECK_EQ(loaded.Value().point, point);
        CHECK_EQ(loaded.Value().chain_hashes, std::vector<Hash256>(chain.begin(), chain.end()));
        CHECK_EQ(loaded.Value().forest.Roots(), reference.Roots());
        CHECK(loaded.Value().forest.Contains(leaf_a));
        CHECK(!loaded.Value().forest.Contains(leaf_b));

        CHECK(reference.Modify(addition, {}));
        CHECK(loaded.Value().forest.ModifyBlock(addition, {}, next_point));
        expected_roots = reference.Roots();
        CHECK_EQ(loaded.Value().forest.Roots(), expected_roots);
    }

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    auto reopened{PackedForest::OpenOnline(online_path, recovered_chain, recovered_point, config)};
    CHECK(reopened);
    CHECK_EQ(recovered_point, next_point);
    CHECK_EQ(recovered_chain, expected_chain);
    CHECK_EQ(reopened.Value().Roots(), expected_roots);

    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
}

TEST(checkpoint_online_import_stays_private_until_explicit_publication)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto checkpoint_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-staged-" + suffix + ".dat")};
    const auto online_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-staged-state-" + suffix)};
    const auto temporary_path{std::filesystem::path{online_path.string() + ".tmp"}};
    std::error_code cleanup_error;
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(temporary_path, cleanup_error);

    const std::array<Hash256, 2> leaves{
        Hash256::FromHex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value(),
        Hash256::FromHex("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a").Value(),
    };
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    PackedForest source;
    CHECK(source.Modify(leaves, {}));
    CHECK(SaveCheckpoint(checkpoint_path, point, source, chain));
    const OnlineForestConfig config{
        .max_dirty_bytes = 1024 * 1024,
        .wal_segment_bytes = 1024 * 1024,
        .undo_depth = 8,
        .sync_wal = true,
        .defer_publish = true,
    };

    {
        auto staged{LoadCheckpointOnline(checkpoint_path, online_path, config)};
        CHECK(staged);
        CHECK(!std::filesystem::exists(online_path));
        CHECK(std::filesystem::exists(temporary_path));

        const auto competing{LoadCheckpointOnline(checkpoint_path, online_path, config)};
        CHECK(!competing);
        CHECK(competing.Error().find("active or ambiguous") != std::string::npos);
        CHECK(std::filesystem::exists(temporary_path));

        const auto premature_modify{staged.Value().forest.ModifyBlock(
            {}, {}, ChainPoint{1, Hash256::FromHex(
                "010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").Value()})};
        CHECK(!premature_modify);
        CHECK(premature_modify.Error().find("before modifying") != std::string::npos);

        CHECK(staged.Value().forest.PublishOnline());
        CHECK(std::filesystem::exists(online_path));
        CHECK(!std::filesystem::exists(temporary_path));

        std::vector<Hash256> duplicate_chain;
        ChainPoint duplicate_point;
        const auto duplicate{PackedForest::OpenOnline(
            online_path, duplicate_chain, duplicate_point, config)};
        CHECK(!duplicate);
        CHECK(duplicate.Error().find("locked by another process") != std::string::npos);
    }

    std::vector<Hash256> recovered_chain;
    ChainPoint recovered_point;
    {
        auto reopened{PackedForest::OpenOnline(
            online_path, recovered_chain, recovered_point, config)};
        CHECK(reopened);
        CHECK_EQ(recovered_point, point);
        CHECK_EQ(reopened.Value().Roots(), source.Roots());
    }
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
}

TEST(checkpoint_rejected_staged_state_is_not_published)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto checkpoint_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-rejected-" + suffix + ".dat")};
    const auto online_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-rejected-state-" + suffix)};
    const auto temporary_path{std::filesystem::path{online_path.string() + ".tmp"}};
    std::error_code cleanup_error;
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(temporary_path, cleanup_error);

    PackedForest source;
    const std::array<Hash256, 1> leaves{Hash256::FromHex(
        "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986").Value()};
    CHECK(source.Modify(leaves, {}));
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(checkpoint_path, point, source, chain));
    {
        auto staged{LoadCheckpointOnline(checkpoint_path, online_path,
            OnlineForestConfig{.defer_publish = true})};
        CHECK(staged);
        CHECK(std::filesystem::exists(temporary_path));
        // Model a trusted-state validator rejecting the loaded roots: dropping
        // the staged forest must remove its private generation.
    }
    CHECK(!std::filesystem::exists(online_path));
    CHECK(!std::filesystem::exists(temporary_path));

    std::filesystem::create_directories(temporary_path);
    {
        std::ofstream sentinel{temporary_path / "operator-data"};
        sentinel << "not an owned online-state import";
    }
    const auto ambiguous{LoadCheckpointOnline(checkpoint_path, online_path)};
    CHECK(!ambiguous);
    CHECK(ambiguous.Error().find("ambiguous") != std::string::npos);
    CHECK(std::filesystem::exists(temporary_path / "operator-data"));

    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(temporary_path, cleanup_error);
}

TEST(checkpoint_online_import_validates_complete_payload_before_publication)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto checkpoint_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-trailing-" + suffix + ".dat")};
    const auto online_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-trailing-state-" + suffix)};
    const auto temporary_path{std::filesystem::path{online_path.string() + ".tmp"}};
    std::error_code cleanup_error;
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(temporary_path, cleanup_error);

    PackedForest source;
    const std::array<Hash256, 1> leaves{Hash256::FromHex(
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value()};
    CHECK(source.Modify(leaves, {}));
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(checkpoint_path, point, source, chain));
    AddCheckpointTrailingByteWithValidChecksum(checkpoint_path);

    const auto loaded{LoadCheckpointOnline(checkpoint_path, online_path)};
    CHECK(!loaded);
    CHECK(loaded.Error().find("trailing or missing") != std::string::npos);
    CHECK(!std::filesystem::exists(online_path));
    CHECK(!std::filesystem::exists(temporary_path));

    std::filesystem::remove(checkpoint_path, cleanup_error);
}

TEST(checkpoint_online_import_reclaims_only_recognized_stale_temporary_state)
{
    const std::string suffix{std::to_string(::getpid())};
    const auto checkpoint_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-stale-" + suffix + ".dat")};
    const auto online_path{std::filesystem::temp_directory_path() /
        ("utreexo-checkpoint-stale-state-" + suffix)};
    const auto temporary_path{std::filesystem::path{online_path.string() + ".tmp"}};
    std::error_code cleanup_error;
    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(temporary_path, cleanup_error);

    PackedForest source;
    const std::array<Hash256, 1> leaves{Hash256::FromHex(
        "084fed08b978af4d7d196a7446a86b58009e636b6117e7f3187e3b156dd6e938").Value()};
    CHECK(source.Modify(leaves, {}));
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(checkpoint_path, point, source, chain));
    {
        auto first{LoadCheckpointOnline(checkpoint_path, online_path)};
        CHECK(first);
    }
    std::filesystem::rename(online_path, temporary_path);
    std::filesystem::remove(temporary_path / "state.0", cleanup_error);
    CHECK(!cleanup_error);

    {
        auto recovered_import{LoadCheckpointOnline(checkpoint_path, online_path)};
        CHECK(recovered_import);
        CHECK(std::filesystem::exists(online_path / "state.0"));
        CHECK(!std::filesystem::exists(temporary_path));
    }

    std::filesystem::remove(checkpoint_path, cleanup_error);
    std::filesystem::remove_all(online_path, cleanup_error);
}

TEST(checkpoint_roundtrip_preserves_duplicate_leaf_hashes)
{
    const auto leaf{Hash256::FromHex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value()};
    const std::array<Hash256, 2> leaves{leaf, leaf};
    PackedForest forest;
    CHECK(forest.Modify(leaves, {}));

    const auto path{std::filesystem::temp_directory_path() / "utreexo-duplicate-checkpoint-test.dat"};
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));

    auto loaded{LoadCheckpoint(path)};
    CHECK(loaded);
    CHECK_EQ(loaded.Value().forest.NumLeaves(), 2U);
    CHECK_EQ(loaded.Value().forest.Roots(), forest.Roots());
    CHECK(loaded.Value().forest.Contains(leaf));
    CHECK(loaded.Value().forest.Delete(leaf));
    CHECK_EQ(loaded.Value().forest.NumLeaves(), 2U);
    CHECK(loaded.Value().forest.Contains(leaf));
    CHECK(loaded.Value().forest.Delete(leaf));
    CHECK_EQ(loaded.Value().forest.NumLeaves(), 2U);
    CHECK(!loaded.Value().forest.Contains(leaf));
    std::filesystem::remove(path);
}

TEST(checkpoint_rejects_corruption)
{
    const auto path{std::filesystem::temp_directory_path() / "utreexo-bad-checkpoint.dat"};
    {
        std::ofstream output{path, std::ios::binary | std::ios::trunc};
        output << "not a checkpoint";
    }
    CHECK(!LoadCheckpoint(path));
    std::filesystem::remove(path);
}

TEST(checkpoint_rejects_pre_bip30_fix_format)
{
    const auto path{std::filesystem::temp_directory_path() / "utreexo-old-policy-checkpoint.dat"};
    PackedForest forest;
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));

    std::vector<unsigned char> bytes(static_cast<std::size_t>(std::filesystem::file_size(path)));
    {
        std::ifstream input{path, std::ios::binary};
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        CHECK(input.good());
    }
    CHECK(bytes.size() > 20U);
    bytes[8] = 2;
    bytes[9] = bytes[10] = bytes[11] = 0;

    constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
    constexpr uint64_t FNV_PRIME{1099511628211ULL};
    uint64_t checksum{FNV_OFFSET};
    for (std::size_t i{0}; i < bytes.size() - sizeof(checksum); ++i) {
        checksum ^= bytes[i];
        checksum *= FNV_PRIME;
    }
    for (std::size_t i{0}; i < sizeof(checksum); ++i) {
        bytes[bytes.size() - sizeof(checksum) + i] =
            static_cast<unsigned char>((checksum >> (i * 8)) & 0xffU);
    }
    {
        std::ofstream output{path, std::ios::binary | std::ios::trunc};
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        CHECK(output.good());
    }

    const auto loaded{LoadCheckpoint(path)};
    CHECK(!loaded);
    CHECK(loaded.Error().find("pre-BIP30-fix") != std::string::npos);
    std::filesystem::remove(path);
}

TEST(checkpoint_checksum_detects_bit_rot)
{
    const auto path{std::filesystem::temp_directory_path() / "utreexo-corrupt-checkpoint.dat"};
    const auto online_path{
        std::filesystem::temp_directory_path() / "utreexo-corrupt-checkpoint-online"};
    std::error_code cleanup_error;
    std::filesystem::remove_all(online_path, cleanup_error);
    std::filesystem::remove_all(online_path.string() + ".tmp", cleanup_error);
    PackedForest forest;
    const auto leaf{Hash256::FromHex("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").Value()};
    CHECK(forest.Add(leaf));
    const ChainPoint point{0, Hash256{}};
    const std::array<Hash256, 1> chain{point.block_hash};
    CHECK(SaveCheckpoint(path, point, forest, chain));
    {
        std::fstream file{path, std::ios::binary | std::ios::in | std::ios::out};
        file.seekp(20);
        file.put(static_cast<char>(0x5a));
    }
    const auto loaded{LoadCheckpoint(path)};
    CHECK(!loaded);
    CHECK(loaded.Error().find("checksum") != std::string::npos);
    const auto loaded_online{LoadCheckpointOnline(path, online_path)};
    CHECK(!loaded_online);
    CHECK(loaded_online.Error().find("checksum") != std::string::npos);
    CHECK(!std::filesystem::exists(online_path));
    CHECK(!std::filesystem::exists(online_path.string() + ".tmp"));
    std::filesystem::remove(path);
}
