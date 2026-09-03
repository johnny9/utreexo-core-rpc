#include <test_framework.h>
#include <utreexo/proof_store.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>

using namespace utreexo;

namespace {

constexpr std::string_view PROOF_STORE_OWNER_CONTENT{"utreexo-proof-store-v1\n"};

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
        .create_base_state = AccumulatorState{
            .point = base,
            .num_leaves = 0,
            .roots = {},
        },
        .serializer_threads = 3,
        .group_commit_blocks = 4,
        .group_commit_delay_ms = 2,
        .max_queued_blocks = 16,
        .max_queued_bytes = 4 * 1024 * 1024,
        .max_record_bytes = 1024 * 1024,
    };
}

AccumulatorState StoreState(const ChainPoint& point)
{
    return AccumulatorState{
        .point = point,
        .num_leaves = 1,
        .roots = {StoreHash(10'000 + point.height)},
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

std::string ReadFile(const std::filesystem::path& path)
{
    std::ifstream input{path, std::ios::binary};
    CHECK(input.good());
    return std::string{std::istreambuf_iterator<char>{input},
                       std::istreambuf_iterator<char>{}};
}

void WriteFile(const std::filesystem::path& path, std::string_view bytes)
{
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    CHECK(output.good());
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    CHECK(output.good());
}

void OverwriteFile(const std::filesystem::path& path, std::streamoff offset,
                   std::string_view bytes)
{
    std::fstream file{path, std::ios::binary | std::ios::in | std::ios::out};
    CHECK(file.good());
    file.seekp(offset);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    CHECK(file.good());
}

template <typename T>
void AppendLegacyLE(std::vector<std::byte>& output, T value)
{
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & static_cast<T>(0xffU)));
        value >>= 8;
    }
}

void AppendLegacyHash(std::vector<std::byte>& output, const Hash256& hash)
{
    output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
}

std::vector<std::byte> LegacyWal(uint32_t kind, const ChainPoint& point,
                                 const Hash256& previous, uint64_t data_offset,
                                 uint64_t data_size, const Hash256& data_digest)
{
    constexpr std::array<std::byte, 8> magic{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'W'}, std::byte{'A'}, std::byte{'L'}, std::byte{'1'}};
    constexpr std::array<std::byte, 8> commit{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'C'}, std::byte{'M'}, std::byte{'T'}, std::byte{'1'}};
    std::vector<std::byte> bytes;
    bytes.insert(bytes.end(), magic.begin(), magic.end());
    AppendLegacyLE(bytes, uint32_t{1});
    AppendLegacyLE(bytes, kind);
    AppendLegacyLE(bytes, point.height);
    AppendLegacyLE(bytes, uint32_t{0});
    AppendLegacyHash(bytes, point.block_hash);
    AppendLegacyHash(bytes, previous);
    AppendLegacyLE(bytes, data_offset);
    AppendLegacyLE(bytes, data_size);
    AppendLegacyHash(bytes, data_digest);
    AppendLegacyHash(bytes, Sha256(bytes));
    bytes.insert(bytes.end(), commit.begin(), commit.end());
    return bytes;
}

std::vector<std::byte> LegacyBaseWal(const ChainPoint& base)
{
    return LegacyWal(1, base, {}, 0, 0, {});
}

std::pair<std::vector<std::byte>, Hash256> LegacyProofRecord(const StoreBlock& block)
{
    constexpr std::array<std::byte, 8> magic{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'D'}, std::byte{'A'}, std::byte{'T'}, std::byte{'1'}};
    constexpr std::array<std::byte, 8> commit{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'D'}, std::byte{'O'}, std::byte{'N'}, std::byte{'E'}};
    auto payload{SerializeUtreexoProof(CachedBlockProof{
        .point = block.delta.point,
        .proof = block.proof,
        .leaves = block.delta.proof_leaves,
    }, GetUtreexoProofRequest{
        .block_hash = block.delta.point.block_hash,
        .request_bitmap = 0x07,
        .proof_indexes = {},
        .leaf_indexes = {},
    })};
    CHECK(payload);
    std::vector<std::byte> bytes;
    bytes.insert(bytes.end(), magic.begin(), magic.end());
    AppendLegacyLE(bytes, uint32_t{1});
    AppendLegacyLE(bytes, block.delta.point.height);
    AppendLegacyHash(bytes, block.delta.point.block_hash);
    AppendLegacyHash(bytes, block.delta.previous_block_hash);
    AppendLegacyLE(bytes, static_cast<uint64_t>(payload.Value().size()));
    bytes.insert(bytes.end(), payload.Value().begin(), payload.Value().end());
    const Hash256 digest{Sha256(bytes)};
    AppendLegacyHash(bytes, digest);
    bytes.insert(bytes.end(), commit.begin(), commit.end());
    return {std::move(bytes), digest};
}

void WriteBytes(const std::filesystem::path& path, std::span<const std::byte> bytes)
{
    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    CHECK(output.good());
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    CHECK(output.good());
}

void WriteOwnerMarker(const std::filesystem::path& path)
{
    WriteFile(path / "FORMAT", PROOF_STORE_OWNER_CONTENT);
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
            CHECK(store->Enqueue(blocks[i].delta, blocks[i].proof,
                                 StoreState(blocks[i].delta.point)));
        }
        CHECK(store->Drain());
        CHECK_EQ(store->BasePoint(), base);
        CHECK_EQ(store->DurablePoint(), blocks.back().delta.point);
        const auto stats{store->Stats()};
        CHECK_EQ(stats.active_proofs, blocks.size());
        CHECK_EQ(stats.queued_blocks, 0U);
        CHECK_EQ(stats.committed_proofs, blocks.size());
        CHECK_EQ(stats.full_batches + stats.partial_batches, stats.committed_batches);
        CHECK(stats.committed_batches >= 1U);
        CHECK(stats.largest_batch_proofs >= 1U);
        CHECK(stats.largest_batch_proofs <= 4U);
        CHECK(stats.peak_input_blocks >= 1U);
        CHECK(stats.peak_ready_blocks >= 1U);
        CHECK_EQ(store->StateAt(base.height).Value(),
                 std::optional<AccumulatorState>{*StoreConfig(path, base).create_base_state});
        for (const auto& block : blocks) {
            auto read{store->Read(block.delta.point.block_hash)};
            CHECK(read);
            CHECK(read.Value());
            CHECK_EQ(read.Value()->point, block.delta.point);
            CHECK_EQ(read.Value()->proof.targets, block.proof.targets);
            CHECK_EQ(read.Value()->proof.hashes, block.proof.hashes);
            CHECK_EQ(read.Value()->leaves, block.delta.proof_leaves);
            CHECK_EQ(store->StateAt(block.delta.point.height).Value(),
                     std::optional<AccumulatorState>{StoreState(block.delta.point)});
        }
        const auto coverage{store->Coverage()};
        CHECK_EQ(coverage.state_start_height, std::optional<uint32_t>{base.height});
        CHECK(!coverage.full_history);
        auto scrubbed{store->Scrub()};
        CHECK(scrubbed);
        CHECK_EQ(scrubbed.Value().proofs_verified, blocks.size());
        CHECK_EQ(scrubbed.Value().states_verified, blocks.size() + 1);
        CHECK(!scrubbed.Value().full_history);
        bool cancellation_checked{false};
        auto cancelled{store->Scrub([&] {
            cancellation_checked = true;
            return true;
        })};
        CHECK(cancellation_checked);
        CHECK(!cancelled);
        CHECK(cancelled.Error().find("cancelled") != std::string::npos);
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

TEST(proof_store_accepts_one_record_larger_than_the_regular_queue_budget)
{
    const auto path{StorePath("oversized-queue-item")};
    Cleanup(path);
    const ChainPoint base{110, StoreHash(110)};
    auto config{StoreConfig(path, base)};
    config.max_queued_bytes = 1;
    const auto block{MakeStoreBlock(111, base.block_hash)};

    auto opened{ProofStore::Open(config)};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
    CHECK(store->Drain());
    CHECK_EQ(store->DurablePoint(), block.delta.point);
    CHECK(store->Read(block.delta.point.block_hash).Value());
    CHECK(store->Stats().peak_queued_bytes > config.max_queued_bytes);
    Cleanup(path);
}

TEST(proof_store_online_catchup_batches_within_recovery_window)
{
    const auto path{StorePath("online-batches")};
    Cleanup(path);
    const ChainPoint base{300, StoreHash(300)};
    auto config{StoreConfig(path, base)};
    config.serializer_threads = 1;
    config.group_commit_blocks = 16;
    config.group_commit_delay_ms = 0;
    config.max_queued_blocks = 16;
    auto opened{ProofStore::Open(config)};
    CHECK(opened);
    auto store{opened.Take()};
    Hash256 previous{base.block_hash};
    for (uint32_t height{301}; height <= 308; ++height) {
        const auto block{MakeStoreBlock(height, previous)};
        CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
        auto bounded{store->EnforceRecoveryWindow(height, 4)};
        CHECK(bounded);
        if (height == 304 || height == 308) {
            CHECK(bounded.Value());
            CHECK(store->DurablePoint().height >= height);
        } else {
            CHECK(!bounded.Value());
        }
        previous = block.delta.point.block_hash;
    }
    CHECK(store->Drain());
    const auto stats{store->Stats()};
    CHECK_EQ(stats.committed_proofs, 8U);
    CHECK_EQ(stats.committed_batches, 2U);
    CHECK_EQ(stats.full_batches, 0U);
    CHECK_EQ(stats.partial_batches, 2U);
    CHECK_EQ(stats.largest_batch_proofs, 4U);
    Cleanup(path);
}

TEST(proof_store_genesis_base_has_full_state_and_proof_coverage)
{
    const auto path{StorePath("genesis")};
    Cleanup(path);
    const ChainPoint genesis{0, StoreHash(0)};
    auto opened{ProofStore::Open(StoreConfig(path, genesis))};
    CHECK(opened);
    auto store{opened.Take()};
    auto one{MakeStoreBlock(1, genesis.block_hash)};
    auto two{MakeStoreBlock(2, one.delta.point.block_hash)};
    CHECK(store->Enqueue(one.delta, one.proof, StoreState(one.delta.point)));
    CHECK(store->Enqueue(two.delta, two.proof, StoreState(two.delta.point)));
    CHECK(store->Drain());
    CHECK_EQ(store->StateAt(0).Value(),
             std::optional<AccumulatorState>{*StoreConfig(path, genesis).create_base_state});
    CHECK(!store->Read(genesis.block_hash).Value());
    CHECK(store->Read(one.delta.point.block_hash).Value());
    CHECK(store->Read(two.delta.point.block_hash).Value());
    const auto coverage{store->Coverage()};
    CHECK_EQ(coverage.state_start_height, std::optional<uint32_t>{0});
    CHECK(coverage.full_history);
    auto scrubbed{store->Scrub()};
    CHECK(scrubbed);
    CHECK_EQ(scrubbed.Value().proofs_verified, 2U);
    CHECK_EQ(scrubbed.Value().states_verified, 3U);
    CHECK(scrubbed.Value().full_history);
    Cleanup(path);
}

TEST(proof_store_opens_legacy_base_and_appends_state_bearing_records)
{
    const auto path{StorePath("legacy-upgrade")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    const ChainPoint base{400, StoreHash(400)};
    const auto legacy_block{MakeStoreBlock(401, base.block_hash)};
    const auto [legacy_data, legacy_digest]{LegacyProofRecord(legacy_block)};
    auto legacy_wal{LegacyBaseWal(base)};
    const auto connect_wal{LegacyWal(2, legacy_block.delta.point, base.block_hash,
                                           0, legacy_data.size(), legacy_digest)};
    legacy_wal.insert(legacy_wal.end(), connect_wal.begin(), connect_wal.end());
    CHECK_EQ(legacy_wal.size(), 352U);
    WriteBytes(path / "index.wal", legacy_wal);
    WriteBytes(path / "proofs.dat", legacy_data);
    auto config{StoreConfig(path, base)};
    {
        auto opened{ProofStore::Open(config)};
        CHECK(opened);
        CHECK_EQ(ReadFile(path / "FORMAT"), PROOF_STORE_OWNER_CONTENT);
        CHECK(!opened.Value()->StateAt(base.height).Value());
        CHECK(opened.Value()->Read(legacy_block.delta.point.block_hash).Value());
        CHECK(!opened.Value()->StateAt(legacy_block.delta.point.height).Value());
        const auto block{MakeStoreBlock(402, legacy_block.delta.point.block_hash)};
        CHECK(opened.Value()->Enqueue(block.delta, block.proof,
                                      StoreState(block.delta.point)));
        CHECK(opened.Value()->Drain());
        const auto coverage{opened.Value()->Coverage()};
        CHECK_EQ(coverage.state_start_height, std::optional<uint32_t>{402});
        CHECK(!coverage.full_history);
    }
    auto reopened{ProofStore::Open(config)};
    CHECK(reopened);
    CHECK_EQ(ReadFile(path / "FORMAT"), PROOF_STORE_OWNER_CONTENT);
    CHECK(!reopened.Value()->StateAt(base.height).Value());
    CHECK(reopened.Value()->Read(legacy_block.delta.point.block_hash).Value());
    CHECK(!reopened.Value()->StateAt(401).Value());
    CHECK(reopened.Value()->StateAt(402).Value());
    CHECK(reopened.Value()->Scrub());
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
        CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
        previous = block.delta.point.block_hash;
    }
    CHECK(store->Drain());
    const ChainPoint expected{205, previous};
    CHECK_EQ(store->DurablePoint(), expected);
    const auto stats{store->Stats()};
    CHECK_EQ(stats.queued_blocks, 0U);
    CHECK_EQ(stats.committed_proofs, 5U);
    CHECK(stats.committed_batches >= 2U);
    CHECK(stats.enqueue_blocked >= 1U);
    CHECK(stats.backpressure_flushes >= 1U);
    CHECK(stats.durability_waits >= 1U);
    CHECK(stats.partial_batches >= 1U);
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
        CHECK(store->Enqueue(one.delta, one.proof, StoreState(one.delta.point)));
        CHECK(store->Enqueue(two.delta, two.proof, StoreState(two.delta.point)));
        CHECK(store->Enqueue(old_three.delta, old_three.proof,
                             StoreState(old_three.delta.point)));
        CHECK(store->Drain());
        CHECK(store->Truncate(two.delta.point));
        CHECK(store->Enqueue(new_three.delta, new_three.proof,
                             StoreState(new_three.delta.point)));
        CHECK(store->Drain());
        auto old_read{store->Read(old_three.delta.point.block_hash)};
        CHECK(old_read);
        CHECK(!old_read.Value());
        auto new_read{store->Read(new_three.delta.point.block_hash)};
        CHECK(new_read);
        CHECK(new_read.Value());
        CHECK_EQ(store->StateAt(new_three.delta.point.height).Value(),
                 std::optional<AccumulatorState>{StoreState(new_three.delta.point)});
    }
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(reopened);
    CHECK_EQ(reopened.Value()->DurablePoint(), new_three.delta.point);
    CHECK(!reopened.Value()->Read(old_three.delta.point.block_hash).Value());
    CHECK(reopened.Value()->Read(new_three.delta.point.block_hash).Value());
    CHECK_EQ(reopened.Value()->StateAt(new_three.delta.point.height).Value(),
             std::optional<AccumulatorState>{StoreState(new_three.delta.point)});
    CHECK(reopened.Value()->Scrub());
    Cleanup(path);
}

TEST(proof_store_restart_finishes_forest_first_reorg_truncation)
{
    const auto path{StorePath("interrupted-reorg-truncation")};
    Cleanup(path);
    const ChainPoint base{40, StoreHash(40)};
    const StoreBlock one{MakeStoreBlock(41, base.block_hash)};
    const StoreBlock two{MakeStoreBlock(42, one.delta.point.block_hash)};
    const StoreBlock three{MakeStoreBlock(43, two.delta.point.block_hash)};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        auto store{opened.Take()};
        CHECK(store->Enqueue(one.delta, one.proof, StoreState(one.delta.point)));
        CHECK(store->Enqueue(two.delta, two.proof, StoreState(two.delta.point)));
        CHECK(store->Enqueue(three.delta, three.proof, StoreState(three.delta.point)));
        CHECK(store->Drain());
        CHECK_EQ(store->DurablePoint(), three.delta.point);
        // Simulate a crash after the online forest durably rolled back to block
        // 41, but before the proof archive could be truncated to match it.
    }
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        auto store{reopened.Take()};
        CHECK(store->DurablePoint().height > one.delta.point.height);
        CHECK_EQ(store->HashAt(one.delta.point.height).Value(),
                 std::optional<Hash256>{one.delta.point.block_hash});
        CHECK(store->Truncate(one.delta.point));
        CHECK_EQ(store->DurablePoint(), one.delta.point);
    }
    auto recovered{ProofStore::Open(StoreConfig(path, base))};
    CHECK(recovered);
    CHECK_EQ(recovered.Value()->DurablePoint(), one.delta.point);
    CHECK(recovered.Value()->Read(one.delta.point.block_hash).Value());
    CHECK(!recovered.Value()->Read(two.delta.point.block_hash).Value());
    CHECK(!recovered.Value()->Read(three.delta.point.block_hash).Value());
    Cleanup(path);
}

TEST(proof_store_archive_ahead_alignment_preserves_active_history_and_truncates_only_stale_suffix)
{
    const auto path{StorePath("archive-ahead-alignment")};
    Cleanup(path);
    const ChainPoint base{50, StoreHash(50)};
    std::array<StoreBlock, 5> blocks{};
    Hash256 previous{base.block_hash};
    auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(opened);
    auto store{opened.Take()};
    for (uint32_t index{0}; index < blocks.size(); ++index) {
        blocks[index] = MakeStoreBlock(base.height + index + 1, previous);
        previous = blocks[index].delta.point.block_hash;
        CHECK(store->Enqueue(blocks[index].delta, blocks[index].proof,
                             StoreState(blocks[index].delta.point)));
    }
    CHECK(store->Drain());
    const ChainPoint forest_point{blocks[0].delta.point};
    const ChainPoint original_tip{blocks.back().delta.point};

    uint32_t lookups{0};
    auto active_tip{FindHighestActiveArchivePoint(
        *store, forest_point, original_tip.height,
        [&](uint32_t height) -> Result<Hash256> {
            ++lookups;
            auto hash{store->HashAt(height)};
            return hash && hash.Value() ? Result<Hash256>::Ok(*hash.Value()) :
                                          Result<Hash256>::Err("missing active hash");
        })};
    CHECK(active_tip);
    CHECK_EQ(active_tip.Value(), original_tip);
    CHECK_EQ(store->DurablePoint(), original_tip);
    CHECK_EQ(lookups, 2U);

    lookups = 0;
    auto stale_suffix{FindHighestActiveArchivePoint(
        *store, forest_point, original_tip.height,
        [&](uint32_t height) -> Result<Hash256> {
            ++lookups;
            if (height <= blocks[2].delta.point.height) {
                auto hash{store->HashAt(height)};
                return hash && hash.Value() ?
                    Result<Hash256>::Ok(*hash.Value()) :
                    Result<Hash256>::Err("missing active hash");
            }
            return Result<Hash256>::Ok(StoreHash((9ULL << 32) | height));
        })};
    CHECK(stale_suffix);
    CHECK_EQ(stale_suffix.Value(), blocks[2].delta.point);
    CHECK_EQ(store->DurablePoint(), original_tip);
    CHECK(store->Truncate(stale_suffix.Value()));
    CHECK_EQ(store->DurablePoint(), blocks[2].delta.point);
    CHECK(store->Read(blocks[2].delta.point.block_hash).Value());
    CHECK(!store->Read(blocks[3].delta.point.block_hash).Value());
    CHECK(!store->Read(blocks[4].delta.point.block_hash).Value());
    Cleanup(path);
}

TEST(proof_store_archive_ahead_alignment_fails_closed_on_core_errors)
{
    const auto path{StorePath("archive-ahead-core-error")};
    Cleanup(path);
    const ChainPoint base{60, StoreHash(60)};
    const StoreBlock one{MakeStoreBlock(61, base.block_hash)};
    const StoreBlock two{MakeStoreBlock(62, one.delta.point.block_hash)};
    auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(one.delta, one.proof, StoreState(one.delta.point)));
    CHECK(store->Enqueue(two.delta, two.proof, StoreState(two.delta.point)));
    CHECK(store->Drain());
    const ChainPoint original_tip{store->DurablePoint()};

    uint32_t lookups{0};
    auto core_shorter{FindHighestActiveArchivePoint(
        *store, one.delta.point, original_tip.height - 1,
        [&](uint32_t) -> Result<Hash256> {
            ++lookups;
            return Result<Hash256>::Err("must not be called");
        })};
    CHECK(!core_shorter);
    CHECK(core_shorter.Error().find("shorter") != std::string::npos);
    CHECK_EQ(lookups, 0U);
    CHECK_EQ(store->DurablePoint(), original_tip);

    auto rpc_error{FindHighestActiveArchivePoint(
        *store, one.delta.point, original_tip.height,
        [&](uint32_t) -> Result<Hash256> {
            ++lookups;
            return Result<Hash256>::Err("temporary RPC failure");
        })};
    CHECK(!rpc_error);
    CHECK(rpc_error.Error().find("temporary RPC failure") != std::string::npos);
    CHECK_EQ(lookups, 1U);
    CHECK_EQ(store->DurablePoint(), original_tip);
    CHECK(store->Read(two.delta.point.block_hash).Value());

    lookups = 0;
    auto confirmation_error{FindHighestActiveArchivePoint(
        *store, one.delta.point, original_tip.height,
        [&](uint32_t height) -> Result<Hash256> {
            ++lookups;
            if (lookups == 2) {
                return Result<Hash256>::Err("RPC failed during confirmation");
            }
            auto hash{store->HashAt(height)};
            return hash && hash.Value() ? Result<Hash256>::Ok(*hash.Value()) :
                                          Result<Hash256>::Err("missing active hash");
        })};
    CHECK(!confirmation_error);
    CHECK(confirmation_error.Error().find("during confirmation") != std::string::npos);
    CHECK_EQ(lookups, 2U);
    CHECK_EQ(store->DurablePoint(), original_tip);
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
        CHECK(opened.Value()->Enqueue(block.delta, block.proof,
                                      StoreState(block.delta.point)));
        CHECK(opened.Value()->Drain());
    }
    const auto wal{path / "index.wal"};
    const auto data{path / "proofs.dat"};
    const auto wal_size{std::filesystem::file_size(wal)};
    const auto data_size{std::filesystem::file_size(data)};
    CHECK_EQ(ReadFile(path / "FORMAT"), PROOF_STORE_OWNER_CONTENT);
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
        CHECK(opened.Value()->Enqueue(block.delta, block.proof,
                                      StoreState(block.delta.point)));
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

TEST(proof_store_rejects_incomplete_markerless_base_without_mutating_it)
{
    const auto path{StorePath("base-tail")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    WriteFile(path / "proofs.dat", "");
    WriteFile(path / "index.wal", "partial-base");
    const std::string original_data{ReadFile(path / "proofs.dat")};
    const std::string original_wal{ReadFile(path / "index.wal")};
    const ChainPoint base{11, StoreHash(11)};
    auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!opened);
    CHECK(opened.Error().find("markerless") != std::string::npos);
    CHECK_EQ(ReadFile(path / "proofs.dat"), original_data);
    CHECK_EQ(ReadFile(path / "index.wal"), original_wal);
    CHECK(!std::filesystem::exists(path / "FORMAT"));
    CHECK(!std::filesystem::exists(path / "height.index"));
    Cleanup(path);
}

TEST(proof_store_recovers_base_state_data_without_committed_base_wal)
{
    const auto source_path{StorePath("base-crash-source")};
    Cleanup(source_path);
    const ChainPoint base{12, StoreHash(12)};
    {
        auto opened{ProofStore::Open(StoreConfig(source_path, base))};
        CHECK(opened);
    }
    const std::string base_data{ReadFile(source_path / "proofs.dat")};
    const std::string base_wal{ReadFile(source_path / "index.wal")};
    CHECK(!base_data.empty());
    CHECK_EQ(base_wal.size(), 176U);

    for (uint32_t scenario{0}; scenario < 4; ++scenario) {
        const auto path{StorePath("base-crash-" + std::to_string(scenario))};
        Cleanup(path);
        std::filesystem::create_directories(path);
        WriteFile(path / "proofs.dat", base_data);
        if (scenario == 0) {
            WriteFile(path / "index.wal", {});
        } else if (scenario == 1) {
            WriteFile(path / "index.wal", std::string_view{base_wal}.substr(0, 100));
        } else if (scenario == 2) {
            std::string no_marker{base_wal};
            std::fill(no_marker.end() - 8, no_marker.end(), '\0');
            WriteFile(path / "index.wal", no_marker);
        } else {
            // A complete BASE write that reached storage before the WAL fsync is
            // already self-authenticating and can be recovered as committed.
            WriteFile(path / "index.wal", base_wal);
        }
        // The first three cases model crashes after durable ownership was
        // established but before the base WAL commit completed. The fourth is
        // a complete pre-marker store and exercises one-time legacy adoption.
        if (scenario < 3) WriteOwnerMarker(path);
        auto recovered{ProofStore::Open(StoreConfig(path, base))};
        CHECK(recovered);
        CHECK_EQ(ReadFile(path / "FORMAT"), PROOF_STORE_OWNER_CONTENT);
        CHECK_EQ(recovered.Value()->BasePoint(), base);
        CHECK_EQ(recovered.Value()->StateAt(base.height).Value(),
                 StoreConfig(path, base).create_base_state);
        CHECK(recovered.Value()->Scrub());
        Cleanup(path);
    }
    Cleanup(source_path);
}

TEST(proof_store_rebuilds_mmap_index_and_detects_payload_corruption)
{
    const auto path{StorePath("corruption")};
    Cleanup(path);
    const ChainPoint base{30, StoreHash(30)};
    const StoreBlock block{MakeStoreBlock(31, base.block_hash)};
    uint64_t base_bytes{0};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        base_bytes = opened.Value()->Stats().data_bytes;
        CHECK(opened.Value()->Enqueue(block.delta, block.proof,
                                      StoreState(block.delta.point)));
        CHECK(opened.Value()->Drain());
    }
    FlipByte(path / "height.index", 0);
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        CHECK(reopened.Value()->Read(block.delta.point.block_hash).Value());
    }
    // Skip the v2 base record, block header, state body, and state digest so open
    // can validate the envelope while the full scrub catches payload corruption.
    FlipByte(path / "proofs.dat", static_cast<std::streamoff>(base_bytes + 172));
    {
        auto reopened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(reopened);
        auto scrubbed{reopened.Value()->Scrub()};
        CHECK(!scrubbed);
        CHECK(scrubbed.Error().find("checksum") != std::string::npos);
        auto corrupt{reopened.Value()->Read(block.delta.point.block_hash)};
        CHECK(!corrupt);
        CHECK(corrupt.Error().find("checksum") != std::string::npos);
    }
    Cleanup(path);
}

TEST(proof_store_reads_authenticated_state_without_reading_large_proof_payload)
{
    const auto path{StorePath("bounded-state-read")};
    Cleanup(path);
    const ChainPoint base{32, StoreHash(32)};
    auto block{MakeStoreBlock(33, base.block_hash)};
    block.proof.hashes.assign(20'000, StoreHash(33'000));
    const AccumulatorState expected_state{StoreState(block.delta.point)};
    uint64_t base_bytes{0};
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        base_bytes = opened.Value()->Stats().data_bytes;
        CHECK(opened.Value()->Enqueue(block.delta, block.proof, expected_state));
        CHECK(opened.Value()->Drain());
        CHECK(opened.Value()->Stats().largest_record_bytes > 600'000U);
    }

    // A proof-payload error is deliberately outside the independently authenticated
    // state prefix. StateAt remains a bounded read, while full proof reads and the
    // publication scrub still detect corruption of the complete record.
    FlipByte(path / "proofs.dat", static_cast<std::streamoff>(base_bytes + 172));
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(reopened);
    CHECK_EQ(reopened.Value()->StateAt(block.delta.point.height).Value(),
             std::optional<AccumulatorState>{expected_state});
    CHECK(!reopened.Value()->Read(block.delta.point.block_hash));
    CHECK(!reopened.Value()->Scrub());

    // Mutating the compact state itself is rejected without consulting the large
    // payload because the state has its own WAL-anchored checksum commitment.
    FlipByte(path / "proofs.dat", static_cast<std::streamoff>(base_bytes + 104));
    auto corrupt_state{reopened.Value()->StateAt(block.delta.point.height)};
    CHECK(!corrupt_state);
    CHECK(corrupt_state.Error().find("checksum") != std::string::npos);
    Cleanup(path);
}

TEST(proof_store_rejects_base_state_root_corruption_during_recovery)
{
    const auto path{StorePath("base-state-corruption")};
    Cleanup(path);
    const ChainPoint base{35, StoreHash(35)};
    auto config{StoreConfig(path, base)};
    config.create_base_state = StoreState(base);
    {
        auto opened{ProofStore::Open(config)};
        CHECK(opened);
        CHECK(opened.Value()->Coverage().state_start_height.has_value());
    }
    // v2 header (88 bytes), state prefix (16 bytes), then the first root.
    FlipByte(path / "proofs.dat", 104);
    auto reopened{ProofStore::Open(config)};
    CHECK(!reopened);
    CHECK(reopened.Error().find("checksum") != std::string::npos);
    Cleanup(path);
}

TEST(proof_store_rejects_overflowing_payload_size_without_allocating)
{
    const auto path{StorePath("payload-overflow")};
    Cleanup(path);
    const ChainPoint base{36, StoreHash(36)};
    const auto block{MakeStoreBlock(37, base.block_hash)};
    uint64_t base_bytes{0};
    std::shared_ptr<ProofStore> store;
    {
        auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(opened);
        store = opened.Take();
        base_bytes = store->Stats().data_bytes;
        CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
        CHECK(store->Drain());
    }
    const std::array<char, 8> huge_payload{
        static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0xff)};
    OverwriteFile(path / "proofs.dat", static_cast<std::streamoff>(base_bytes + 80),
                  std::string_view{huge_payload.data(), huge_payload.size()});
    auto corrupt_read{store->Read(block.delta.point.block_hash)};
    CHECK(!corrupt_read);
    CHECK(corrupt_read.Error().find("checksum") != std::string::npos ||
          corrupt_read.Error().find("truncated") != std::string::npos ||
          corrupt_read.Error().find("size") != std::string::npos ||
          corrupt_read.Error().find("inconsistent") != std::string::npos);
    store.reset();
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!reopened);
    CHECK(reopened.Error().find("truncated") != std::string::npos ||
          reopened.Error().find("size") != std::string::npos);
    Cleanup(path);
}

TEST(proof_store_bounds_mmap_record_size_before_state_or_scrub_allocation)
{
    const auto path{StorePath("index-size-overflow")};
    Cleanup(path);
    const ChainPoint base{38, StoreHash(38)};
    const auto block{MakeStoreBlock(39, base.block_hash)};
    auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
    CHECK(store->Drain());
    const std::array<char, 8> huge_size{
        static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0xff), static_cast<char>(0xff),
        static_cast<char>(0xff), static_cast<char>(0x7f)};
    // DiskIndexEntry::data_size follows its 8-byte data_offset.
    OverwriteFile(path / "height.index", 8,
                  std::string_view{huge_size.data(), huge_size.size()});
    auto state{store->StateAt(block.delta.point.height)};
    CHECK(!state);
    CHECK(state.Error().find("record size") != std::string::npos);
    auto scrubbed{store->Scrub()};
    CHECK(!scrubbed);
    CHECK(scrubbed.Error().find("record size") != std::string::npos);
    Cleanup(path);
}

TEST(proof_store_destructor_stops_workers_after_serializer_failure)
{
    const auto path{StorePath("failed-worker-destruction")};
    Cleanup(path);
    const ChainPoint base{39, StoreHash(39)};
    auto block{MakeStoreBlock(40, base.block_hash)};
    block.delta.proof_leaves.front().script_type = ScriptPubkeyType::OTHER;
    block.delta.proof_leaves.front().script.assign(10'001, std::byte{0x51});

    auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(block.delta, block.proof, StoreState(block.delta.point)));
    const auto failed{store->Drain()};
    CHECK(!failed);
    CHECK(failed.Error().find("serialization failed") != std::string::npos);

    // Destruction must abandon the failed queue and join every worker.  The
    // durable base remains reopenable because the rejected record was never
    // committed to either the data file or index WAL.
    store.reset();
    auto reopened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(reopened);
    CHECK_EQ(reopened.Value()->DurablePoint(), base);
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

TEST(proof_store_rejects_symlinked_owned_files_without_mutating_targets)
{
    const std::array<std::string_view, 3> owned_names{
        "proofs.dat", "index.wal", "height.index"};
    const ChainPoint base{50, StoreHash(50)};
    for (std::size_t index{0}; index < owned_names.size(); ++index) {
        const auto path{StorePath("owned-symlink-" + std::to_string(index))};
        const auto sentinel{StorePath("owned-symlink-sentinel-" +
                                      std::to_string(index))};
        Cleanup(path);
        std::error_code cleanup_error;
        std::filesystem::remove(sentinel, cleanup_error);
        WriteFile(sentinel, "proof-store external sentinel\n");
        std::filesystem::create_directories(path);
        WriteOwnerMarker(path);
        std::filesystem::create_symlink(
            sentinel, path / std::string{owned_names[index]});

        const auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(!opened);
        CHECK_EQ(ReadFile(sentinel), "proof-store external sentinel\n");

        Cleanup(path);
        std::filesystem::remove(sentinel, cleanup_error);
    }
}

TEST(proof_store_rejects_internal_hardlink_alias_before_writing)
{
    const auto path{StorePath("owned-internal-hardlink")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    WriteOwnerMarker(path);
    WriteFile(path / "proofs.dat", "internal alias sentinel\n");
    std::filesystem::create_hard_link(path / "proofs.dat", path / "index.wal");

    const ChainPoint base{51, StoreHash(51)};
    const auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!opened);
    CHECK_EQ(ReadFile(path / "proofs.dat"), "internal alias sentinel\n");
    CHECK_EQ(ReadFile(path / "index.wal"), "internal alias sentinel\n");
    Cleanup(path);
}

TEST(proof_store_rejects_external_hardlink_before_truncating_index)
{
    const auto path{StorePath("owned-external-hardlink")};
    const auto sentinel{StorePath("owned-external-hardlink-sentinel")};
    Cleanup(path);
    std::error_code cleanup_error;
    std::filesystem::remove(sentinel, cleanup_error);
    WriteFile(sentinel, "external index sentinel\n");
    std::filesystem::create_directories(path);
    WriteOwnerMarker(path);
    std::filesystem::create_hard_link(sentinel, path / "height.index");

    const ChainPoint base{52, StoreHash(52)};
    const auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!opened);
    CHECK_EQ(ReadFile(sentinel), "external index sentinel\n");

    Cleanup(path);
    std::filesystem::remove(sentinel, cleanup_error);
}

TEST(proof_store_rejects_unowned_same_name_files_without_mutating_them)
{
    const auto path{StorePath("unowned-same-name")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    WriteFile(path / "proofs.dat", "unrelated proof-data sentinel\n");
    WriteFile(path / "index.wal", "unrelated WAL sentinel\n");
    WriteFile(path / "height.index", "unrelated mmap-index sentinel\n");
    const std::string original_data{ReadFile(path / "proofs.dat")};
    const std::string original_wal{ReadFile(path / "index.wal")};
    const std::string original_index{ReadFile(path / "height.index")};

    const ChainPoint base{53, StoreHash(53)};
    const auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!opened);
    CHECK_EQ(ReadFile(path / "proofs.dat"), original_data);
    CHECK_EQ(ReadFile(path / "index.wal"), original_wal);
    CHECK_EQ(ReadFile(path / "height.index"), original_index);
    CHECK(!std::filesystem::exists(path / "FORMAT"));
    Cleanup(path);
}

TEST(proof_store_rejects_markerless_legacy_tails_without_recovery_mutation)
{
    const auto source_path{StorePath("markerless-tail-source")};
    Cleanup(source_path);
    const ChainPoint base{54, StoreHash(54)};
    const auto block{MakeStoreBlock(55, base.block_hash)};
    {
        auto opened{ProofStore::Open(StoreConfig(source_path, base))};
        CHECK(opened);
        CHECK(opened.Value()->Enqueue(block.delta, block.proof,
                                      StoreState(block.delta.point)));
        CHECK(opened.Value()->Drain());
    }
    const std::string committed_data{ReadFile(source_path / "proofs.dat")};
    const std::string committed_wal{ReadFile(source_path / "index.wal")};

    for (bool wal_tail : {false, true}) {
        const auto path{StorePath(wal_tail ? "markerless-wal-tail" :
                                            "markerless-data-tail")};
        Cleanup(path);
        std::filesystem::create_directories(path);
        WriteFile(path / "proofs.dat",
                  wal_tail ? committed_data : committed_data + "uncommitted-data");
        WriteFile(path / "index.wal",
                  wal_tail ? committed_wal + "torn-wal" : committed_wal);
        const std::string original_data{ReadFile(path / "proofs.dat")};
        const std::string original_wal{ReadFile(path / "index.wal")};

        const auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(!opened);
        CHECK(opened.Error().find("markerless") != std::string::npos);
        CHECK_EQ(ReadFile(path / "proofs.dat"), original_data);
        CHECK_EQ(ReadFile(path / "index.wal"), original_wal);
        CHECK(!std::filesystem::exists(path / "FORMAT"));
        CHECK(!std::filesystem::exists(path / "height.index"));
        Cleanup(path);
    }
    Cleanup(source_path);
}

TEST(proof_store_rejects_symlinked_or_hardlinked_owner_marker)
{
    const ChainPoint base{56, StoreHash(56)};
    for (bool hardlink : {false, true}) {
        const auto suffix{hardlink ? "hardlink" : "symlink"};
        const auto path{StorePath("owner-" + std::string{suffix})};
        const auto sentinel{StorePath("owner-sentinel-" + std::string{suffix})};
        Cleanup(path);
        std::error_code cleanup_error;
        std::filesystem::remove(sentinel, cleanup_error);
        WriteFile(sentinel, PROOF_STORE_OWNER_CONTENT);
        std::filesystem::create_directories(path);
        if (hardlink) {
            std::filesystem::create_hard_link(sentinel, path / "FORMAT");
        } else {
            std::filesystem::create_symlink(sentinel, path / "FORMAT");
        }

        const auto opened{ProofStore::Open(StoreConfig(path, base))};
        CHECK(!opened);
        CHECK_EQ(ReadFile(sentinel), PROOF_STORE_OWNER_CONTENT);
        CHECK(!std::filesystem::exists(path / "proofs.dat"));
        CHECK(!std::filesystem::exists(path / "index.wal"));
        CHECK(!std::filesystem::exists(path / "height.index"));

        Cleanup(path);
        std::filesystem::remove(sentinel, cleanup_error);
    }
}

TEST(proof_store_rejects_unrecognized_regular_owner_marker)
{
    const auto path{StorePath("owner-content")};
    Cleanup(path);
    std::filesystem::create_directories(path);
    WriteFile(path / "FORMAT", "utreexo-proof-store-v2\n");
    const std::string original_marker{ReadFile(path / "FORMAT")};

    const ChainPoint base{57, StoreHash(57)};
    const auto opened{ProofStore::Open(StoreConfig(path, base))};
    CHECK(!opened);
    CHECK(opened.Error().find("marker") != std::string::npos);
    CHECK_EQ(ReadFile(path / "FORMAT"), original_marker);
    CHECK(!std::filesystem::exists(path / "proofs.dat"));
    CHECK(!std::filesystem::exists(path / "index.wal"));
    CHECK(!std::filesystem::exists(path / "height.index"));
    Cleanup(path);
}
