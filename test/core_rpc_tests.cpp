#include <test_framework.h>
#include <utreexo/core_rpc.h>

#include <memory>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace utreexo;

namespace {
UniValue Json(std::string_view text)
{
    UniValue value;
    if (!value.read(text)) throw std::runtime_error{"invalid test JSON"};
    return value;
}

std::vector<std::byte> Bytes(std::string_view hex)
{
    std::vector<std::byte> bytes;
    const auto digit = [](char value) -> uint8_t {
        if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
        return static_cast<uint8_t>(value - 'A' + 10);
    };
    for (std::size_t i{0}; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<std::byte>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    }
    return bytes;
}

UniValue CoinbaseBlock(uint32_t height, std::string_view hash, std::string_view txid,
                       std::string_view extra_transactions = {})
{
    return Json("{\"hash\":\"" + std::string{hash} + "\",\"height\":" + std::to_string(height) +
                ",\"previousblockhash\":\"" + std::string(64, '0') + "\",\"tx\":["
                "{\"txid\":\"" + std::string{txid} +
                "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[{\"n\":0,\"value\":50.0,\"scriptPubKey\":{\"hex\":\"51\"}}]}" +
                std::string{extra_transactions} + "]}");
}

class FakeTransport final : public RpcTransport
{
public:
    explicit FakeTransport(std::string response) : m_response{std::move(response)} {}
    Result<std::string> Post(std::string body) override
    {
        request = std::move(body);
        return Result<std::string>::Ok(m_response);
    }
    std::string request;

private:
    std::string m_response;
};
} // namespace

TEST(rpc_amount_parsing_is_exact)
{
    CHECK_EQ(ParseBitcoinAmount(Json("50.00000000")).Value(), 5'000'000'000U);
    CHECK_EQ(ParseBitcoinAmount(Json("0.00000001")).Value(), 1U);
    CHECK_EQ(ParseBitcoinAmount(Json("1.2")).Value(), 120'000'000U);
    CHECK_EQ(ParseBitcoinAmount(Json("0")).Value(), 0U);
    CHECK_EQ(ParseBitcoinAmount(Json("21000000.00000000")).Value(), 2'100'000'000'000'000ULL);
    CHECK(!ParseBitcoinAmount(Json("0.000000001")));
    CHECK(!ParseBitcoinAmount(Json("-1.0")));
    CHECK(!ParseBitcoinAmount(Json("21000000.00000001")));
    CHECK(!ParseBitcoinAmount(Json("1e-8")));
}

TEST(rpc_client_validates_envelope)
{
    auto transport{std::make_unique<FakeTransport>("{\"result\":7,\"error\":null,\"id\":1}")};
    FakeTransport* observed{transport.get()};
    CoreRpcClient client{std::move(transport)};
    auto result{client.Call("getblockcount")};
    CHECK(result);
    CHECK_EQ(result.Value().getInt<int>(), 7);
    CHECK(observed->request.find("getblockcount") != std::string::npos);
    CHECK_EQ(client.LastCallMetrics().method, "getblockcount");
    CHECK(client.LastCallMetrics().success);
    CHECK(client.LastCallMetrics().response_bytes > 0U);
    CHECK_EQ(client.AggregateMetrics().calls, 1U);
    CHECK_EQ(client.AggregateMetrics().failures, 0U);
    CHECK_EQ(client.AggregateMetrics().response_bytes, client.LastCallMetrics().response_bytes);
    CHECK_EQ(client.AggregateMetrics().largest_response_method, "getblockcount");
}

TEST(rpc_client_counts_failed_calls)
{
    CoreRpcClient client{std::make_unique<FakeTransport>("not-json")};
    CHECK(!client.Call("getblockcount"));
    CHECK_EQ(client.AggregateMetrics().calls, 1U);
    CHECK_EQ(client.AggregateMetrics().failures, 1U);
    CHECK(client.AggregateMetrics().response_bytes > 0U);
}

TEST(verbose_block_cancels_same_block_spends)
{
    const std::string zero(64, '0');
    const std::string one(64, '1');
    const std::string two(64, '2');
    const std::string three(64, '3');
    const UniValue block{Json(
        "{\"hash\":\"" + three + "\",\"height\":10,\"previousblockhash\":\"" + two + "\",\"tx\":["
        "{\"txid\":\"" + zero + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[{\"n\":0,\"value\":1.0,\"scriptPubKey\":{\"hex\":\"51\"}}]},"
        "{\"txid\":\"" + one + "\",\"vin\":[],\"vout\":[{\"n\":0,\"value\":2.0,\"scriptPubKey\":{\"hex\":\"51\"}}]},"
        "{\"txid\":\"" + two + "\",\"vin\":[{\"txid\":\"" + one + "\",\"vout\":0}],\"vout\":[{\"n\":0,\"value\":2.0,\"scriptPubKey\":{\"hex\":\"6a\"}}]}]}" )};
    auto delta{ParseVerboseBlock(block, [](uint32_t) { return Result<Hash256>::Err("unused"); })};
    CHECK(delta);
    CHECK_EQ(delta.Value().additions.size(), 1U);
    CHECK(delta.Value().deletions.empty());
}

TEST(verbose_block_requires_undo_prevout)
{
    const std::string zero(64, '0');
    const std::string one(64, '1');
    const std::string two(64, '2');
    const UniValue block{Json(
        "{\"hash\":\"" + two + "\",\"height\":1,\"previousblockhash\":\"" + zero + "\",\"tx\":["
        "{\"txid\":\"" + zero + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]},"
        "{\"txid\":\"" + one + "\",\"vin\":[{\"txid\":\"" + zero + "\",\"vout\":0}],\"vout\":[]}]}" )};
    auto delta{ParseVerboseBlock(block, [](uint32_t) { return Result<Hash256>::Ok(Hash256{}); })};
    CHECK(!delta);
    CHECK(delta.Error().find("undo data") != std::string::npos);
}

TEST(verbose_block_derives_deletion_and_compact_leaf)
{
    const std::string zero(64, '0');
    const std::string one(64, '1');
    const std::string two(64, '2');
    const std::string three(64, '3');
    const std::string witness_script{"0014" + std::string(40, '0')};
    const UniValue block{Json(
        "{\"hash\":\"" + two + "\",\"height\":2,\"previousblockhash\":\"" + one + "\",\"tx\":["
        "{\"txid\":\"" + zero + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]},"
        "{\"txid\":\"" + one + "\",\"vin\":[{\"txid\":\"" + three + "\",\"vout\":4,\"prevout\":{"
        "\"generated\":true,\"height\":1,\"value\":1.25,\"scriptPubKey\":{\"hex\":\"" + witness_script + "\"}}}],\"vout\":[]}]}" )};
    auto delta{ParseVerboseBlock(block, [](uint32_t height) {
        if (height != 1) return Result<Hash256>::Err("wrong height");
        return Result<Hash256>::Ok(Hash256{});
    })};
    CHECK(delta);
    CHECK_EQ(delta.Value().deletions.size(), 1U);
    CHECK_EQ(delta.Value().proof_leaves.size(), 1U);
    CHECK_EQ(delta.Value().proof_leaves[0].header_code, 3U);
    CHECK_EQ(delta.Value().proof_leaves[0].amount, 125'000'000U);
    CHECK_EQ(delta.Value().proof_leaves[0].script_type, ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH);
}

TEST(verbose_block_skips_genesis_outputs_on_every_network)
{
    for (const char fill : {'0', 'a', 'f'}) {
        const std::string hash(64, fill);
        const auto delta{ParseVerboseBlock(CoinbaseBlock(0, hash, std::string(64, '1')),
                                           [](uint32_t) { return Result<Hash256>::Err("must not resolve"); })};
        CHECK(delta);
        CHECK(delta.Value().additions.empty());
    }
}

TEST(verbose_block_handles_the_complete_bip30_quartet)
{
    constexpr std::string_view original_91722{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"};
    constexpr std::string_view original_91812{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"};
    constexpr std::string_view repeat_91842{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"};
    constexpr std::string_view repeat_91880{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"};
    const std::string duplicate_txid(64, '1');
    const std::string ordinary_txid(64, '2');
    const std::string ordinary{
        ",{\"txid\":\"" + ordinary_txid +
        "\",\"vin\":[],\"vout\":[{\"n\":3,\"value\":1.0,\"scriptPubKey\":{\"hex\":\"51\"}}]}"};
    const auto resolver = [](uint32_t) { return Result<Hash256>::Err("unused"); };

    for (const auto [height, hash] : std::array{
             std::pair{91722U, original_91722}, std::pair{91812U, original_91812}}) {
        const auto delta{ParseVerboseBlock(CoinbaseBlock(height, hash, duplicate_txid, ordinary), resolver)};
        CHECK(delta);
        CHECK_EQ(delta.Value().additions.size(), 1U); // Non-coinbase transactions remain normal.
    }
    std::vector<Hash256> repeated;
    for (const auto [height, hash] : std::array{
             std::pair{91842U, repeat_91842}, std::pair{91880U, repeat_91880}}) {
        const auto delta{ParseVerboseBlock(CoinbaseBlock(height, hash, duplicate_txid), resolver)};
        CHECK(delta);
        CHECK_EQ(delta.Value().additions.size(), 1U);
        repeated.push_back(delta.Value().additions[0]);
    }
    CHECK(repeated[0] != repeated[1]); // Repeated txid, distinct creation block commitment.

    const std::string wrong_hash(64, '3');
    for (const uint32_t height : {91722U, 91812U}) {
        const auto delta{ParseVerboseBlock(CoinbaseBlock(height, wrong_hash, duplicate_txid), resolver)};
        CHECK(delta);
        CHECK_EQ(delta.Value().additions.size(), 1U); // Height alone must not activate the exception.
    }
}

TEST(verbose_block_matches_core_unspendable_boundaries_and_sparse_vouts)
{
    const std::string block_hash(64, '4');
    const std::string txid(64, '5');
    const std::string script_10000(20'000, '0');
    const std::string script_10001(20'002, '0');
    const UniValue block{Json(
        "{\"hash\":\"" + block_hash + "\",\"height\":7,\"previousblockhash\":\"" + std::string(64, '0') +
        "\",\"tx\":[{\"txid\":\"" + txid + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":["
        "{\"n\":0,\"value\":0,\"scriptPubKey\":{\"hex\":\"\"}},"
        "{\"n\":2,\"value\":0.00000001,\"scriptPubKey\":{\"hex\":\"" + script_10000 + "\"}},"
        "{\"n\":7,\"value\":1,\"scriptPubKey\":{\"hex\":\"" + script_10001 + "\"}},"
        "{\"n\":9,\"value\":1,\"scriptPubKey\":{\"hex\":\"6a\"}},"
        "{\"n\":10,\"value\":2,\"scriptPubKey\":{\"hex\":\"516a\"}}]}]}" )};
    const auto delta{ParseVerboseBlock(block, [](uint32_t) { return Result<Hash256>::Err("unused"); })};
    CHECK(delta);
    CHECK_EQ(delta.Value().additions.size(), 3U);

    const Hash256 parsed_block{Hash256::FromBitcoinHex(block_hash).Value()};
    const Hash256 parsed_txid{Hash256::FromBitcoinHex(txid).Value()};
    const std::array<LeafData, 3> expected{{
        {.block_hash = parsed_block, .outpoint = {parsed_txid, 0}, .block_height = 7, .coinbase = true,
         .output = {0, {}}},
        {.block_hash = parsed_block, .outpoint = {parsed_txid, 2}, .block_height = 7, .coinbase = true,
         .output = {1, std::vector<std::byte>(10'000)}},
        {.block_hash = parsed_block, .outpoint = {parsed_txid, 10}, .block_height = 7, .coinbase = true,
         .output = {200'000'000, Bytes("516a")}},
    }};
    for (std::size_t i{0}; i < expected.size(); ++i) CHECK_EQ(delta.Value().additions[i], LeafHash(expected[i]));
}

TEST(verbose_block_uses_txid_not_wtxid_and_preserves_max_vout)
{
    const std::string block_hash(64, '6');
    const std::string txid(64, '7');
    const std::string wtxid(64, '8');
    const UniValue block{Json(
        "{\"hash\":\"" + block_hash + "\",\"height\":8,\"previousblockhash\":\"" + std::string(64, '0') +
        "\",\"tx\":[{\"txid\":\"" + txid + "\",\"hash\":\"" + wtxid +
        "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[{\"n\":4294967295,\"value\":0,\"scriptPubKey\":{\"hex\":\"51\"}}]}]}" )};
    const auto delta{ParseVerboseBlock(block, [](uint32_t) { return Result<Hash256>::Err("unused"); })};
    CHECK(delta);
    const LeafData expected{
        .block_hash = Hash256::FromBitcoinHex(block_hash).Value(),
        .outpoint = {Hash256::FromBitcoinHex(txid).Value(), UINT32_MAX},
        .block_height = 8,
        .coinbase = true,
        .output = {0, Bytes("51")},
    };
    CHECK_EQ(delta.Value().additions, std::vector<Hash256>{LeafHash(expected)});
}

TEST(verbose_block_mixed_inputs_keep_proof_leaf_alignment)
{
    const std::string block_hash(64, '9');
    const std::string a(64, 'a');
    const std::string b(64, 'b');
    const std::string c(64, 'c');
    const std::string local(64, 'd');
    const UniValue block{Json(
        "{\"hash\":\"" + block_hash + "\",\"height\":20,\"previousblockhash\":\"" + std::string(64, '1') + "\",\"tx\":["
        "{\"txid\":\"" + std::string(64, '0') + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[{\"n\":0,\"value\":0,\"scriptPubKey\":{\"hex\":\"6a\"}}]},"
        "{\"txid\":\"" + local + "\",\"vin\":["
        "{\"txid\":\"" + a + "\",\"vout\":1,\"prevout\":{\"generated\":true,\"height\":2,\"value\":1,\"scriptPubKey\":{\"hex\":\"51\"}}},"
        "{\"txid\":\"" + b + "\",\"vout\":2,\"prevout\":{\"generated\":false,\"height\":3,\"value\":2,\"scriptPubKey\":{\"hex\":\"51\"}}}],"
        "\"vout\":[{\"n\":5,\"value\":3,\"scriptPubKey\":{\"hex\":\"51\"}}]},"
        "{\"txid\":\"" + std::string(64, 'e') + "\",\"vin\":["
        "{\"txid\":\"" + local + "\",\"vout\":5},"
        "{\"txid\":\"" + c + "\",\"vout\":3,\"prevout\":{\"generated\":false,\"height\":4,\"value\":3,\"scriptPubKey\":{\"hex\":\"51\"}}}],"
        "\"vout\":[{\"n\":0,\"value\":0,\"scriptPubKey\":{\"hex\":\"6a\"}}]}]}" )};
    const auto delta{ParseVerboseBlock(block, [](uint32_t height) {
        Hash256::Storage bytes{};
        bytes[0] = static_cast<std::byte>(height);
        return Result<Hash256>::Ok(Hash256{bytes});
    })};
    CHECK(delta);
    CHECK(delta.Value().additions.empty());
    CHECK_EQ(delta.Value().deletions.size(), 3U);
    CHECK_EQ(delta.Value().proof_leaves.size(), 3U);
    CHECK_EQ(delta.Value().proof_leaves[0].amount, 100'000'000U);
    CHECK_EQ(delta.Value().proof_leaves[0].header_code, 5U);
    CHECK_EQ(delta.Value().proof_leaves[1].amount, 200'000'000U);
    CHECK_EQ(delta.Value().proof_leaves[1].header_code, 6U);
    CHECK_EQ(delta.Value().proof_leaves[2].amount, 300'000'000U);
    CHECK_EQ(delta.Value().proof_leaves[2].header_code, 8U);
}

TEST(verbose_block_rejects_genesis_proof_leaf_before_hash_lookup)
{
    const std::string zero(64, '0');
    const std::string one(64, '1');
    const UniValue block{Json(
        "{\"hash\":\"" + one + "\",\"height\":1,\"previousblockhash\":\"" + zero + "\",\"tx\":["
        "{\"txid\":\"" + zero + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]},"
        "{\"txid\":\"" + one + "\",\"vin\":[{\"txid\":\"" + zero + "\",\"vout\":0,\"prevout\":{"
        "\"generated\":true,\"height\":0,\"value\":50,\"scriptPubKey\":{\"hex\":\"51\"}}}],\"vout\":[]}]}" )};
    bool resolved{false};
    const auto delta{ParseVerboseBlock(block, [&resolved](uint32_t) {
        resolved = true;
        return Result<Hash256>::Ok(Hash256{});
    })};
    CHECK(!delta);
    CHECK(!resolved);
    CHECK(delta.Error().find("genesis") != std::string::npos);
}
