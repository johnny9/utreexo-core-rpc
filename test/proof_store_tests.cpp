#include <test_framework.h>
#include <utreexo/proof_store.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace utreexo;

namespace {

Hash256 StoreHash(uint64_t value)
{
    std::array<std::byte, 8> bytes{};
    for (std::size_t i{0}; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
    return Sha512_256(bytes);
}

std::filesystem::path StorePath(std::string_view name)
{
    return std::filesystem::temp_directory_path() /
        ("utreexo-proof-store-" + std::string{name} + "-" + std::to_string(::getpid()));
}

void Cleanup(const std::filesystem::path& path)
{
    std::error_code error;
    std::filesystem::remove_all(path, error);
}

ProofStoreConfig StoreConfig(const std::filesystem::path& path, const ChainPoint& base)
{
    return ProofStoreConfig{
        .directory = path,
        .create_base = base,
        .serializer_threads = 3,
        .group_commit_blocks = 4,
        .group_commit_delay_ms = 2,
        .max_queued_blocks = 16,
        .max_queued_bytes = 4 * 1024 * 1024,
        .max_record_bytes = 1024 * 1024,
    };
}

struct StoreBlock {
    BlockDelta delta;
    Proof proof;
};

StoreBlock MakeStoreBlock(uint32_t height, const Hash256& previous, uint64_t branch = 0)
{
    const Hash256 block_hash{StoreHash((branch << 32) | height)};
    Hash256::Storage proof_hash_bytes{};
    proof_hash_bytes.fill(static_cast<std::byte>(height & 0xffU));
    return StoreBlock{
        .delta = BlockDelta{
            .point = ChainPoint{height, block_hash},
            .previous_block_hash = previous,
            .additions = {},
            .deletions = {StoreHash(height * 2), StoreHash(height * 2 + 1)},
            .proof_leaves = {
                CompactLeafData{.header_code = height, .amount = height * 10,
                    .script_type = ScriptPubkeyType::OTHER,
                    .script = {std::byte{0x51}, static_cast<std::byte>(height & 0xffU)}},
                CompactLeafData{.header_code = height + 1, .amount = height * 10 + 1,
                    .script_type = ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH, .script = {}},
            },
        },
        .proof = Proof{{height * 3, height * 3 + 1}, {Hash256{proof_hash_bytes}}},
    };
}

void FlipByte(const std::filesystem::path& path, std::streamoff offset)
{
    std::fstream file{path, std::ios::binary | std::ios::in | std::ios::out};
    CHECK(file.good());
    file.seekg(offset);
    char byte{0};
    file.read(&byte, 1);
    CHECK(file.good());
    byte = static_cast<char>(static_cast<unsigned char>(byte) ^ 0x40U);
    file.seekp(offset);
    file.write(&byte, 1);
    CHECK(file.good());
}

} // namespace

TEST(proof_store_pipeline_commits_in_height_order_and_reopens)
{
    const auto path{StorePath("pipeline")};
    Cleanup(path);
    const ChainPoint base{100, StoreHash(100)};
    std::array<StoreBlock, 10> blocks{};
    Hash256 previous{base.block_hash};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        auto store{opened.Take()};
        for (uint32_t i{0}; i < blocks.size(); ++i) {
            blocks[i] = MakeStoreBlock(base.height + i + 1, previous);
            previous = blocks[i].delta.point.block_hash;
            CHECK(store->Enqueue(blocks[i].delta, blocks[i].proof));
        }
        CHECK(store->Drain());
        CHECK_EQ(store->BasePoint(), base);
        CHECK_EQ(store->DurablePoint(), blocks.back().delta.point);
        CHECK_EQ(store->Stats().active_proofs, blocks.size());
        CHECK_EQ(store->Stats().queued_blocks, 0U);
        CHECK(store->Stats().committed_batches >= 1U);
        for (const auto& block : blocks) {
            auto read{store->Read(block.delta.point.block_hash)};
            CHECK(read);
            CHECK(read.Value());
            CHECK_EQ(read.Value()->point, block.delta.point);
            CHECK_EQ(read.Value()->proof.targets, block.proof.targets);
            CHECK_EQ(read.Value()->proof.hashes, block.proof.hashes);
            CHECK_EQ(read.Value()->leaves, block.delta.proof_leaves);
        }
    }
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        CHECK_EQ(reopened.Value()->DurablePoint(), blocks.back().delta.point);
        for (const auto& block : blocks) {
            auto hash{reopened.Value()->HashAt(block.delta.point.height)};
            CHECK(hash);
            CHECK_EQ(hash.Value(), std::optional<Hash256>{block.delta.point.block_hash});
        }
        auto missing{reopened.Value()->Read(StoreHash(999'999))};
        CHECK(missing);
        CHECK(!missing.Value());
    }
    Cleanup(path);
}

TEST(proof_store_zero_delay_flushes_on_queue_backpressure)
{
    const auto path{StorePath("backpressure")};
    Cleanup(path);
    const ChainPoint base{200, StoreHash(200)};
    auto config{StoreConfig(path, base)};
    config.group_commit_blocks = 8;
    config.group_commit_delay_ms = 0;
    config.max_queued_blocks = 2;
    auto opened{ProofStore::Open(config)};
    CHECK(opened);
    auto store{opened.Take()};
    Hash256 previous{base.block_hash};
    for (uint32_t height{201}; height <= 205; ++height) {
        const auto block{MakeStoreBlock(height, previous)};
        CHECK(store->Enqueue(block.delta, block.proof));
        previous = block.delta.point.block_hash;
    }
    CHECK(store->Drain());
    const ChainPoint expected{205, previous};
    CHECK_EQ(store->DurablePoint(), expected);
    CHECK_EQ(store->Stats().queued_blocks, 0U);
    CHECK(store->Stats().committed_batches >= 2U);
    Cleanup(path);
}

TEST(proof_store_truncation_is_wal_durable_and_accepts_another_branch)
{
    const auto path{StorePath("reorg")};
    Cleanup(path);
    const ChainPoint base{20, StoreHash(20)};
    StoreBlock one{MakeStoreBlock(21, base.block_hash)};
    StoreBlock two{MakeStoreBlock(22, one.delta.point.block_hash)};
    StoreBlock old_three{MakeStoreBlock(23, two.delta.point.block_hash)};
    StoreBlock new_three{MakeStoreBlock(23, two.delta.point.block_hash, 7)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        auto store{opened.Take()};
        CHECK(store->Enqueue(one.delta, one.proof));
        CHECK(store->Enqueue(two.delta, two.proof));
        CHECK(store->Enqueue(old_three.delta, old_three.proof));
        CHECK(store->Drain());
        CHECK(store->Truncate(two.delta.point));
        CHECK(store->Enqueue(new_three.delta, new_three.proof));
        CHECK(store->Drain());
        auto old_read{store->Read(old_three.delta.point.block_hash)};
        CHECK(old_read);
        CHECK(!old_read.Value());
        auto new_read{store->Read(new_three.delta.point.block_hash)};
        CHECK(new_read);
        CHECK(new_read.Value());
    }
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(reopened);
    CHECK_EQ(reopened.Value()->DurablePoint(), new_three.delta.point);
    CHECK(!reopened.Value()->Read(old_three.delta.point.block_hash).Value());
    CHECK(reopened.Value()->Read(new_three.delta.point.block_hash).Value());
    Cleanup(path);
}

TEST(proof_store_recovers_torn_wal_and_uncommitted_data_tails)
{
    const auto path{StorePath("tails")};
    Cleanup(path);
    const ChainPoint base{5, StoreHash(5)};
    const StoreBlock block{MakeStoreBlock(6, base.block_hash)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        CHECK(opened.Value()->Enqueue(block.delta, block.proof));
        CHECK(opened.Value()->Drain());
    }
    const auto wal{path / "index.wal"};
    const auto data{path / "proofs.dat"};
    const auto wal_size{std::filesystem::file_size(wal)};
    const auto data_size{std::filesystem::file_size(data)};
    {
        std::ofstream output{wal, std::ios::binary | std::ios::app};
        output << "torn-wal";
    }
    {
        std::ofstream output{data, std::ios::binary | std::ios::app};
        output << "uncommitted-data";
    }
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(reopened);
    CHECK_EQ(std::filesystem::file_size(wal), wal_size);
    CHECK_EQ(std::filesystem::file_size(data), data_size);
    CHECK(reopened.Value()->Read(block.delta.point.block_hash).Value());
    Cleanup(path);
}

TEST(proof_store_recovers_full_sized_wal_record_without_commit_marker)
{
    const auto path{StorePath("missing-commit")};
    Cleanup(path);
    const ChainPoint base{8, StoreHash(8)};
    const StoreBlock block{MakeStoreBlock(9, base.block_hash)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        CHECK(opened.Value()->Enqueue(block.delta, block.proof));
        CHECK(opened.Value()->Drain());
    }
    const auto wal{path / "index.wal"};
    const auto committed_size{std::filesystem::file_size(wal)};
    {
        std::array<char, 176> incomplete{};
        std::ofstream output{wal, std::ios::binary | std::ios::app};
        output.write(incomplete.data(), static_cast<std::streamsize>(incomplete.size()));
    }
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        CHECK_EQ(std::filesystem::file_size(wal), committed_size);
        CHECK(reopened.Value()->Read(block.delta.point.block_hash).Value());
    }
    Cleanup(path);
}

TEST(proof_store_recreates_an_incomplete_first_base_record)
{
    const auto path{StorePath("base-tail")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    {
        std::ofstream output{path / "index.wal", std::ios::binary};
        output << "partial-base";
    }
    const ChainPoint base{11, StoreHash(11)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        CHECK_EQ(opened.Value()->BasePoint(), base);
        CHECK_EQ(opened.Value()->DurablePoint(), base);
        CHECK(std::filesystem::file_size(path / "index.wal") > 12U);
    }
    Cleanup(path);
}

TEST(proof_store_rebuilds_mmap_index_and_detects_payload_corruption)
{
    const auto path{StorePath("corruption")};
    Cleanup(path);
    const ChainPoint base{30, StoreHash(30)};
    const StoreBlock block{MakeStoreBlock(31, base.block_hash)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        CHECK(opened.Value()->Enqueue(block.delta, block.proof));
        CHECK(opened.Value()->Drain());
    }
    FlipByte(path / "height.index", 0);
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        CHECK(reopened.Value()->Read(block.delta.point.block_hash).Value());
    }
    FlipByte(path / "proofs.dat", 90);
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        auto corrupt{reopened.Value()->Read(block.delta.point.block_hash)};
        CHECK(!corrupt);
        CHECK(corrupt.Error().find("checksum") != std::string::npos);
    }
    Cleanup(path);
}

TEST(proof_store_rejects_committed_wal_corruption_and_concurrent_open)
{
    const auto path{StorePath("wal-corruption")};
    Cleanup(path);
    const ChainPoint base{40, StoreHash(40)};
    {
        auto first{ProofStore::Open(StoreConfig(path, base))};
        CHECK(first);
        auto second{ProofStore::Open(StoreConfig(path, base))};
        CHECK(!second);
    }
    FlipByte(path / "index.wal", 12);
    auto corrupt{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!corrupt);
    CHECK(corrupt.Error().find("checksum") != std::string::npos ||
          corrupt.Error().find("invalid") != std::string::npos);
    Cleanup(path);
}
