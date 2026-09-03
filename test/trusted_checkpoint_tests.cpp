#include <test_framework.h>
#include <utreexo/trusted_checkpoint.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

using namespace utreexo;

TEST(trusted_mainnet_943013_constants)
{
    const auto* trusted{FindTrustedCheckpoint("mainnet-943013")};
    CHECK(trusted != nullptr);
    CHECK_EQ(FindTrustedCheckpoint(943'013), trusted);
    CHECK(FindTrustedCheckpoint("unknown") == nullptr);
    CHECK(FindTrustedCheckpoint(943'012) == nullptr);
    CHECK_EQ(trusted->point.height, 943'013U);
    CHECK_EQ(trusted->point.block_hash.ToBitcoinHex(),
             "00000000000000000001c595730bd4a5fb0e2b35af70882962ce7ae602f48aff");
    CHECK_EQ(trusted->num_leaves, 3'082'565'786ULL);
    CHECK_EQ(trusted->roots.size(), 18U);
    CHECK_EQ(trusted->roots.front().ToHex(),
             "58903d7b8f355710ddb5d8dfaf17f240af6a3a14c1d606422dcd6362f8a338e3");
    CHECK_EQ(trusted->roots.back().ToHex(),
             "a25a97e938c05b554de2e3102622c4b4f6a66152f6d2cb2c6445d20a97e28013");
    CHECK_EQ(trusted->file_size, 14'893'913'136ULL);
    CHECK_EQ(trusted->file_sha256.ToHex(),
             "e869cb2eaf6a42d71010464b1dac7d0cd5cc7ed237ba78d2c653d2c8efa5a492");
}

TEST(trusted_checkpoint_state_validation)
{
    const auto& trusted{*FindTrustedCheckpoint("mainnet-943013")};
    std::vector<std::optional<Hash256>> roots;
    for (const auto& root : trusted.roots) roots.emplace_back(root);

    CHECK(ValidateTrustedCheckpointState(
        trusted, trusted.point, trusted.num_leaves, roots));

    auto wrong_point{trusted.point};
    ++wrong_point.height;
    auto result{ValidateTrustedCheckpointState(
        trusted, wrong_point, trusted.num_leaves, roots)};
    CHECK(!result);
    CHECK(result.Error().find("height mismatch") != std::string::npos);

    wrong_point = trusted.point;
    wrong_point.block_hash = Hash256{};
    result = ValidateTrustedCheckpointState(
        trusted, wrong_point, trusted.num_leaves, roots);
    CHECK(!result);
    CHECK(result.Error().find("block_hash mismatch") != std::string::npos);

    result = ValidateTrustedCheckpointState(
        trusted, trusted.point, trusted.num_leaves + 1, roots);
    CHECK(!result);
    CHECK(result.Error().find("num_leaves mismatch") != std::string::npos);

    roots.front() = Hash256{};
    result = ValidateTrustedCheckpointState(
        trusted, trusted.point, trusted.num_leaves, roots);
    CHECK(!result);
    CHECK(result.Error().find("root mismatch") != std::string::npos);

    roots.front() = std::nullopt;
    result = ValidateTrustedCheckpointState(
        trusted, trusted.point, trusted.num_leaves, roots);
    CHECK(!result);
    CHECK(result.Error().find("root missing") != std::string::npos);

    roots.pop_back();
    result = ValidateTrustedCheckpointState(
        trusted, trusted.point, trusted.num_leaves, roots);
    CHECK(!result);
    CHECK(result.Error().find("root_count mismatch") != std::string::npos);
}

TEST(trusted_checkpoint_file_identity_validation)
{
    const auto& trusted{*FindTrustedCheckpoint("mainnet-943013")};
    const CheckpointFileIdentity expected{
        .size = trusted.file_size,
        .sha256 = trusted.file_sha256,
    };
    CHECK(ValidateTrustedCheckpointFile(trusted, expected));

    auto wrong{expected};
    ++wrong.size;
    auto result{ValidateTrustedCheckpointFile(trusted, wrong)};
    CHECK(!result);
    CHECK(result.Error().find("file_size mismatch") != std::string::npos);

    wrong = expected;
    wrong.sha256 = Hash256{};
    result = ValidateTrustedCheckpointFile(trusted, wrong);
    CHECK(!result);
    CHECK(result.Error().find("file_sha256 mismatch") != std::string::npos);
}

TEST(checkpoint_file_identity_hashes_complete_file)
{
    const auto path{std::filesystem::temp_directory_path() /
                    "utreexo-checkpoint-identity-test.dat"};
    {
        std::ofstream output{path, std::ios::binary | std::ios::trunc};
        output << "abc";
    }
    const auto identity{ReadCheckpointFileIdentity(path)};
    CHECK(identity);
    CHECK_EQ(identity.Value().size, 3U);
    CHECK_EQ(identity.Value().sha256.ToHex(),
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::filesystem::remove(path);
}
