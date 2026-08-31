#include <test_framework.h>
#include <utreexo/checkpoint.h>

#include <array>
#include <filesystem>
#include <fstream>

using namespace utreexo;

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
    std::filesystem::remove(path);
}
