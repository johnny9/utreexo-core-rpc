#include <test_framework.h>
#include <utreexo/sync.h>

#include <array>

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
        if (height >= hashes.size()) return Result<Hash256>::Err("height out of range");
        return Result<Hash256>::Ok(hashes[height]);
    }
    Result<UniValue> BlockWithPrevouts(const Hash256& hash) override
    {
        for (std::size_t i{0}; i < hashes.size(); ++i) if (hashes[i] == hash) return Result<UniValue>::Ok(blocks[i]);
        return Result<UniValue>::Err("block not found");
    }

    std::vector<Hash256> hashes;
    std::vector<UniValue> blocks;
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
}

TEST(sequential_sync_detects_reorg)
{
    FakeBlockSource source;
    PackedForest forest;
    SequentialSync sync{source, forest};
    CHECK(sync.ProcessNext());
    source.hashes[0] = Hash256::FromBitcoinHex(std::string(64, 'f')).Value();
    const auto next{sync.ProcessNext()};
    CHECK(!next);
    CHECK(next.Error().find("reorganization") != std::string::npos);
}
