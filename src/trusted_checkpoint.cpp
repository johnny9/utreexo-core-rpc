// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/trusted_checkpoint.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace utreexo {
namespace {

Hash256 TrustedHash(std::string_view hex)
{
    auto parsed{Hash256::FromHex(hex)};
    if (!parsed) std::terminate();
    return parsed.Take();
}

Hash256 TrustedBitcoinHash(std::string_view hex)
{
    auto parsed{Hash256::FromBitcoinHex(hex)};
    if (!parsed) std::terminate();
    return parsed.Take();
}

const TrustedCheckpoint& Mainnet943013()
{
    // Utreexod mainnet AssumeUtreexo state at commit
    // 25deba281b612f8b87f734b0ac169d8a46ede988. The full proving forest was
    // independently rebuilt from genesis and matched this state before compaction;
    // compaction then re-verified the same ordered roots.
    static const std::array<Hash256, 18> roots{
        TrustedHash("58903d7b8f355710ddb5d8dfaf17f240af6a3a14c1d606422dcd6362f8a338e3"),
        TrustedHash("10d6640db81dae22a18b99d8f1179ebcf7f39d8758a9183b02762a244e68099e"),
        TrustedHash("430e732e0d30717765e7128b6a5fe70eb22b4b3e6dc772a40b46846d9333800d"),
        TrustedHash("3dc7194b8069bd841aed28b33791e01297c05e46e2eb8eed8ea93f7202388980"),
        TrustedHash("eb41827f548a811e6dcd259f8a486e2233757d100f0e9ac63b2d9fd1559b010d"),
        TrustedHash("33ed5b7b9f71bee8f2e8ab03d4bc8544f362600819f13e6267b72d8a9a8fd36d"),
        TrustedHash("a51fa39fb261c4ba5596e7239b257241545889428cbd8e8f49c70e24645fe756"),
        TrustedHash("db4326c816eea0eafa495b33195a56c696f5a4ef8fdec62f85f8b756b794d53a"),
        TrustedHash("091f556e7803e4136025fa5d518a6c88dadd926451b90b5739483bbe49f3d090"),
        TrustedHash("7e770db3ace3c6298eb2a64282d57db6aed78fc8b9a4efd7c1714a3a8e23fb74"),
        TrustedHash("e62ea173baecb1ea1e51985cfa56dc2ffbd22161be9b10d77467e61f95e5a86e"),
        TrustedHash("fd2ab9a7c539d9f1e5dc94879c690980ebc710b431a367eff166792c90963545"),
        TrustedHash("a47bc57aea513f1a58d1e9510f61b96ec27fa9bd5cab4c532e72df9507b8641a"),
        TrustedHash("a88dc84b5dc1c5392191f066201849274e6cbf4e86b8f0dbce90ce3aaeab07ed"),
        TrustedHash("bb7c6dd45d49a024fef17dd043370bcc93e5ca969b2256a38b5a0e96220ff0ab"),
        TrustedHash("194411f2b062acb34454bb7f48859a6300df07ad04d8d63f39b6e34275de2e19"),
        TrustedHash("539fea58450d5142766460d4c40b9cde097fa18264dae636c38bda061e3f22ac"),
        TrustedHash("a25a97e938c05b554de2e3102622c4b4f6a66152f6d2cb2c6445d20a97e28013"),
    };
    static const TrustedCheckpoint checkpoint{
        .name = "mainnet-943013",
        .point = ChainPoint{
            943'013,
            TrustedBitcoinHash(
                "00000000000000000001c595730bd4a5fb0e2b35af70882962ce7ae602f48aff"),
        },
        .num_leaves = 3'082'565'786ULL,
        .roots = roots,
        .file_size = 14'893'913'136ULL,
        .file_sha256 = TrustedHash(
            "e869cb2eaf6a42d71010464b1dac7d0cd5cc7ed237ba78d2c653d2c8efa5a492"),
    };
    return checkpoint;
}

std::string ErrorWithValues(std::string_view field, std::string expected,
                            std::string actual)
{
    return "trusted checkpoint " + std::string{field} + " mismatch: expected=" +
           std::move(expected) + " actual=" + std::move(actual);
}

} // namespace

const TrustedCheckpoint* FindTrustedCheckpoint(std::string_view name)
{
    const auto& checkpoint{Mainnet943013()};
    return name == checkpoint.name ? &checkpoint : nullptr;
}

const TrustedCheckpoint* FindTrustedCheckpoint(uint32_t height)
{
    const auto& checkpoint{Mainnet943013()};
    return height == checkpoint.point.height ? &checkpoint : nullptr;
}

Result<void> ValidateTrustedCheckpointState(const TrustedCheckpoint& trusted,
                                            const LoadedCheckpoint& loaded)
{
    const auto roots{loaded.forest.Roots()};
    return ValidateTrustedCheckpointState(trusted, loaded.point,
                                          loaded.forest.NumLeaves(), roots);
}

Result<void> ValidateTrustedCheckpointState(
    const TrustedCheckpoint& trusted, const ChainPoint& point, uint64_t num_leaves,
    std::span<const std::optional<Hash256>> roots)
{
    if (point.height != trusted.point.height) {
        return Result<void>::Err(ErrorWithValues("height",
            std::to_string(trusted.point.height), std::to_string(point.height)));
    }
    if (point.block_hash != trusted.point.block_hash) {
        return Result<void>::Err(ErrorWithValues("block_hash",
            trusted.point.block_hash.ToBitcoinHex(), point.block_hash.ToBitcoinHex()));
    }
    if (num_leaves != trusted.num_leaves) {
        return Result<void>::Err(ErrorWithValues("num_leaves",
            std::to_string(trusted.num_leaves), std::to_string(num_leaves)));
    }
    if (roots.size() != trusted.roots.size()) {
        return Result<void>::Err(ErrorWithValues("root_count",
            std::to_string(trusted.roots.size()), std::to_string(roots.size())));
    }
    for (std::size_t i{0}; i < trusted.roots.size(); ++i) {
        if (!roots[i]) {
            return Result<void>::Err("trusted checkpoint root missing: index=" +
                                     std::to_string(i));
        }
        if (*roots[i] != trusted.roots[i]) {
            return Result<void>::Err("trusted checkpoint root mismatch: index=" +
                std::to_string(i) + " expected=" + trusted.roots[i].ToHex() +
                " actual=" + roots[i]->ToHex());
        }
    }
    return Result<void>::Ok();
}

Result<CheckpointFileIdentity> ReadCheckpointFileIdentity(
    const std::filesystem::path& path)
{
    std::error_code size_error;
    const uint64_t size{std::filesystem::file_size(path, size_error)};
    if (size_error) {
        return Result<CheckpointFileIdentity>::Err(
            "could not stat trusted checkpoint: " + size_error.message());
    }
    if (size > static_cast<uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return Result<CheckpointFileIdentity>::Err(
            "trusted checkpoint is too large for this platform");
    }

    const int descriptor{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (descriptor < 0) {
        return Result<CheckpointFileIdentity>::Err(
            "could not open trusted checkpoint: " + std::string{std::strerror(errno)});
    }
    if (size == 0) {
        ::close(descriptor);
        const std::array<std::byte, 0> empty{};
        return Result<CheckpointFileIdentity>::Ok(
            CheckpointFileIdentity{.size = 0, .sha256 = Sha256(empty)});
    }

    void* mapping{::mmap(nullptr, static_cast<std::size_t>(size), PROT_READ, MAP_PRIVATE,
                         descriptor, 0)};
    const int map_errno{errno};
    ::close(descriptor);
    if (mapping == MAP_FAILED) {
        return Result<CheckpointFileIdentity>::Err(
            "could not map trusted checkpoint for SHA-256: " +
            std::string{std::strerror(map_errno)});
    }
    const auto bytes{std::span<const std::byte>{static_cast<const std::byte*>(mapping),
                                                static_cast<std::size_t>(size)}};
    const Hash256 sha256{Sha256(bytes)};
    if (::munmap(mapping, static_cast<std::size_t>(size)) != 0) {
        return Result<CheckpointFileIdentity>::Err(
            "could not unmap trusted checkpoint: " + std::string{std::strerror(errno)});
    }
    return Result<CheckpointFileIdentity>::Ok(
        CheckpointFileIdentity{.size = size, .sha256 = sha256});
}

Result<void> ValidateTrustedCheckpointFile(const TrustedCheckpoint& trusted,
                                           const CheckpointFileIdentity& actual)
{
    if (actual.size != trusted.file_size) {
        return Result<void>::Err(ErrorWithValues("file_size",
            std::to_string(trusted.file_size), std::to_string(actual.size)));
    }
    if (actual.sha256 != trusted.file_sha256) {
        return Result<void>::Err(ErrorWithValues("file_sha256",
            trusted.file_sha256.ToHex(), actual.sha256.ToHex()));
    }
    return Result<void>::Ok();
}

} // namespace utreexo
