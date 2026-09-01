#include <test_framework.h>
#include <utreexo/sync.h>

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>
#include <unistd.h>

using namespace utreexo;

namespace {
UniValue Json(std::string_view text)
{
    UniValue value;
    if (!value.read(text)) throw std::runtime_error{"invalid test JSON"};
    return value;
}

class FakeBlockSource final : public BlockSource
{
public:
    FakeBlockSource()
    {
        hashes = {
            Hash256::FromBitcoinHex(std::string(64, '0')).Value(),
            Hash256::FromBitcoinHex(std::string(64, '1')).Value(),
        };
        blocks.push_back(Json(
            "{\"hash\":\"" + hashes[0].ToBitcoinHex() + "\",\"height\":0,\"tx\":["
            "{\"txid\":\"" + std::string(64, '2') + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]}]}"));
        blocks.push_back(Json(
            "{\"hash\":\"" + hashes[1].ToBitcoinHex() + "\",\"height\":1,\"previousblockhash\":\"" + hashes[0].ToBitcoinHex() + "\",\"tx\":["
            "{\"txid\":\"" + std::string(64, '3') + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":["
            "{\"n\":0,\"value\":50.0,\"scriptPubKey\":{\"hex\":\"51\"}}]}]}"));
    }

    Result<uint32_t> TipHeight() override { return Result<uint32_t>::Ok(1); }
    Result<Hash256> BlockHash(uint32_t height) override
    {
        ++block_hash_calls;
        if (height >= hashes.size()) return Result<Hash256>::Err("height out of range");
        return Result<Hash256>::Ok(hashes[height]);
    }
    Result<FetchedBlock> FetchBlock(uint32_t height) override
    {
        ++fetch_calls;
        if (height >= hashes.size()) return Result<FetchedBlock>::Err("height out of range");
        std::string json{blocks[height].write()};
        const std::size_t json_size{json.size()};
        return Result<FetchedBlock>::Ok(FetchedBlock{
            .height = height,
            .hash = hashes[height],
            .json = RawJsonValue{.json = std::move(json), .value_offset = 0,
                                 .value_size = json_size},
        });
    }

    std::vector<Hash256> hashes;
    std::vector<UniValue> blocks;
    uint32_t block_hash_calls{0};
    uint32_t fetch_calls{0};
};

class CountingBlockSource final : public BlockSource
{
public:
    CountingBlockSource()
    {
        for (uint32_t height{0}; height < 4; ++height) {
            hashes.push_back(Hash256::FromBitcoinHex(std::string(64, static_cast<char>('1' + height))).Value());
        }
    }

    Result<uint32_t> TipHeight() override { return Result<uint32_t>::Ok(3); }
    Result<Hash256> BlockHash(uint32_t height) override
    {
        if (height >= hashes.size()) return Result<Hash256>::Err("height out of range");
        return Result<Hash256>::Ok(hashes[height]);
    }
    Result<FetchedBlock> FetchBlock(uint32_t height) override
    {
        if (height >= hashes.size()) return Result<FetchedBlock>::Err("height out of range");
        ++fetch_calls;
        std::string json{
            "{\"hash\":\"" + hashes[height].ToBitcoinHex() + "\",\"height\":" +
            std::to_string(height)};
        if (height != 0) {
            json += ",\"previousblockhash\":\"" + hashes[height - 1].ToBitcoinHex() + "\"";
        }
        json += ",\"tx\":[{\"txid\":\"" + std::string(64, 'a') +
                "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]}]}";
        const std::size_t size{json.size()};
        return Result<FetchedBlock>::Ok(FetchedBlock{
            .height = height,
            .hash = hashes[height],
            .json = RawJsonValue{.json = std::move(json), .value_offset = 0, .value_size = size},
        });
    }

    std::vector<Hash256> hashes;
    std::atomic<uint32_t> fetch_calls{0};
};
} // namespace

TEST(sequential_sync_builds_from_genesis_without_ibd)
{
    FakeBlockSource source;
    PackedForest forest;
    SequentialSync sync{source, forest};
    const auto first{sync.ProcessNext()};
    CHECK(first);
    CHECK_EQ(forest.NumLeaves(), 0U);
    const auto second{sync.ProcessNext()};
    CHECK(second);
    CHECK_EQ(forest.NumLeaves(), 1U);
    CHECK_EQ(sync.ChainHashes(), source.hashes);
    CHECK_EQ(sync.CurrentPoint()->height, 1U);
    CHECK(second.Value().metrics.total_us >= second.Value().metrics.modify_us);
    CHECK_EQ(source.fetch_calls, 2U);
    CHECK_EQ(source.block_hash_calls, 0U);
    CHECK(sync.ValidateCurrentPoint());
    CHECK_EQ(source.block_hash_calls, 1U);
}

TEST(sequential_sync_detects_reorg)
{
    FakeBlockSource source;
    PackedForest forest;
    SequentialSync sync{source, forest};
    CHECK(sync.ProcessNext());
    source.hashes[0] = Hash256::FromBitcoinHex(std::string(64, 'f')).Value();
    const auto active{sync.ValidateCurrentPoint()};
    CHECK(!active);
    CHECK(active.Error().find("reorganization") != std::string::npos);
}

TEST(sequential_sync_captures_proof_before_block_mutation)
{
    FakeBlockSource source;
    const Hash256 third_hash{Hash256::FromBitcoinHex(std::string(64, '4')).Value()};
    source.hashes.push_back(third_hash);
    source.blocks.push_back(Json(
        "{\"hash\":\"" + third_hash.ToBitcoinHex() + "\",\"height\":2,\"previousblockhash\":\"" +
        source.hashes[1].ToBitcoinHex() + "\",\"tx\":["
        "{\"txid\":\"" + std::string(64, '6') +
        "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]},"
        "{\"txid\":\"" + std::string(64, '5') +
        "\",\"vin\":[{\"txid\":\"" + std::string(64, '3') +
        "\",\"vout\":0,\"prevout\":{\"generated\":true,\"height\":1,"
        "\"value\":50.0,\"scriptPubKey\":{\"hex\":\"51\"}}}],\"vout\":[]}]}"));

    PackedForest forest;
    SequentialSync sync{source, forest};
    CHECK(sync.ProcessNext());
    CHECK(sync.ProcessNext());
    CHECK_EQ(forest.NumLeaves(), 1U);
    sync.SetProofGeneration(true);
    auto spent{sync.ProcessNext()};
    CHECK(spent);
    CHECK(spent.Value().proof.has_value());
    CHECK_EQ(spent.Value().delta.deletions.size(), 1U);
    CHECK_EQ(spent.Value().delta.proof_leaves.size(), 1U);
    CHECK_EQ(spent.Value().proof->targets, (std::vector<uint64_t>{0}));
    CHECK(spent.Value().proof->hashes.empty());
}

TEST(sequential_sync_prefetches_at_most_two_complete_blocks)
{
    using namespace std::chrono_literals;
    CountingBlockSource source;
    PackedForest forest;
    SequentialSync sync{source, forest};
    CHECK(sync.StartPrefetch(3));
    for (int i{0}; i < 100 && source.fetch_calls.load() < 2; ++i) std::this_thread::sleep_for(1ms);
    CHECK_EQ(source.fetch_calls.load(), 2U);
    std::this_thread::sleep_for(10ms);
    CHECK_EQ(source.fetch_calls.load(), 2U);
    CHECK(sync.ProcessNext());
    for (int i{0}; i < 100 && source.fetch_calls.load() < 3; ++i) std::this_thread::sleep_for(1ms);
    CHECK_EQ(source.fetch_calls.load(), 3U);
    CHECK(sync.ProcessNext());
    CHECK(sync.ProcessNext());
    CHECK(sync.ProcessNext());
    sync.StopPrefetch();
    CHECK(sync.ValidateCurrentPoint());
}

TEST(sequential_sync_reconciles_online_reorg_from_wal)
{
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-sync-reorg-" + std::to_string(::getpid()))};
    std::error_code cleanup_error;
    std::filesystem::remove_all(path, cleanup_error);
    {
        FakeBlockSource source;
        PackedForest forest;
        SequentialSync sync{source, forest};
        CHECK(sync.ProcessNext());
        CHECK(forest.EnableOnline(path, *sync.CurrentPoint(), sync.ChainHashes(),
            OnlineForestConfig{.max_dirty_bytes = 1024 * 1024,
                               .wal_segment_bytes = 1024 * 1024,
                               .undo_depth = 8,
                               .sync_wal = true}));
        CHECK(sync.ProcessNext());
        CHECK_EQ(sync.CurrentPoint()->height, 1U);
        CHECK_EQ(forest.NumLeaves(), 1U);

        source.hashes[1] = Hash256::FromBitcoinHex(std::string(64, 'f')).Value();
        const auto reconciled{sync.ReconcileCurrentPoint()};
        CHECK(reconciled);
        CHECK_EQ(reconciled.Value(), 1U);
        CHECK_EQ(sync.CurrentPoint()->height, 0U);
        CHECK_EQ(forest.NumLeaves(), 0U);
        CHECK(sync.ValidateCurrentPoint());
    }
    std::filesystem::remove_all(path, cleanup_error);
}
