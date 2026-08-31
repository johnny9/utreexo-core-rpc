#include <test_framework.h>
#include <utreexo/core_rpc.h>

#include <memory>
#include <atomic>
#include <array>
#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <cstddef>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
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
                       std::string_view extra_transactions = {}, std::string_view script = "51")
{
    return Json("{\"hash\":\"" + std::string{hash} + "\",\"height\":" + std::to_string(height) +
                ",\"previousblockhash\":\"" + std::string(64, '0') + "\",\"tx\":["
                "{\"txid\":\"" + std::string{txid} +
                "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[{\"n\":0,\"value\":50.0,\"scriptPubKey\":{\"hex\":\"" +
                std::string{script} + "\"}}]}" +
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

class FlakyTransport final : public RpcTransport
{
public:
    Result<std::string> Post(std::string) override
    {
        ++calls;
        if (calls == 1) return Result<std::string>::Err("reading RPC response failed: Resource temporarily unavailable");
        return Result<std::string>::Ok("{\"result\":7,\"error\":null,\"id\":1}");
    }
    uint32_t calls{0};
};

bool SendAll(int socket, std::string_view data)
{
    std::size_t sent{0};
    while (sent < data.size()) {
        const ssize_t result{::send(socket, data.data() + sent, data.size() - sent, MSG_NOSIGNAL)};
        if (result <= 0) return false;
        sent += static_cast<std::size_t>(result);
    }
    return true;
}

bool ReadHttpRequest(int socket, std::string& request)
{
    request.clear();
    std::array<char, 4096> buffer{};
    std::size_t required{0};
    while (true) {
        const auto header_end{request.find("\r\n\r\n")};
        if (header_end != std::string::npos && required == 0) {
            const auto length_header{request.find("Content-Length:")};
            if (length_header == std::string::npos || length_header > header_end) return false;
            std::size_t value_begin{length_header + std::string_view{"Content-Length:"}.size()};
            const std::size_t value_end{request.find("\r\n", value_begin)};
            while (value_begin < value_end && request[value_begin] == ' ') ++value_begin;
            std::size_t content_length{0};
            const auto [end, error]{std::from_chars(
                request.data() + value_begin, request.data() + value_end, content_length)};
            if (error != std::errc{} || end != request.data() + value_end) return false;
            required = header_end + 4 + content_length;
        }
        if (required != 0 && request.size() >= required) return true;
        const ssize_t received{::recv(socket, buffer.data(), buffer.size(), 0)};
        if (received <= 0) return false;
        request.append(buffer.data(), static_cast<std::size_t>(received));
    }
}
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

TEST(rpc_client_retries_transient_transport_failure)
{
    auto transport{std::make_unique<FlakyTransport>()};
    FlakyTransport* observed{transport.get()};
    CoreRpcClient client{std::move(transport)};
    const auto result{client.Call("getblockcount")};
    CHECK(result);
    CHECK_EQ(result.Value().getInt<int>(), 7);
    CHECK_EQ(observed->calls, 2U);
    CHECK_EQ(client.LastCallMetrics().attempts, 2U);
    CHECK_EQ(client.LastCallMetrics().retries, 1U);
    CHECK_EQ(client.AggregateMetrics().calls, 1U);
    CHECK_EQ(client.AggregateMetrics().failures, 0U);
    CHECK_EQ(client.AggregateMetrics().retries, 1U);
}

TEST(rpc_client_reuses_persistent_http_connection)
{
    const int listener{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (listener < 0 && (errno == EPERM || errno == EACCES)) return;
    if (listener < 0) throw std::runtime_error{"could not create loopback test socket"};
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener, 1) != 0) {
        ::close(listener);
        throw std::runtime_error{"could not bind loopback test socket"};
    }
    socklen_t address_size{sizeof(address)};
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ::close(listener);
        throw std::runtime_error{"could not inspect loopback test socket"};
    }

    std::atomic<bool> server_ok{true};
    std::string first_request;
    std::thread server{[&] {
        const int connection{::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC)};
        if (connection < 0) {
            server_ok = false;
            return;
        }
        std::string second_request;
        const std::string first_body{"{\"result\":7,\"error\":null,\"id\":1}"};
        std::ostringstream chunk_size;
        chunk_size << std::hex << first_body.size();
        const std::string first_response{
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" +
            chunk_size.str() + "\r\n" + first_body + "\r\n0\r\n\r\n"};
        const std::string second_body{"{\"result\":8,\"error\":null,\"id\":2}"};
        const std::string second_response{
            "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(second_body.size()) +
            "\r\nConnection: keep-alive\r\n\r\n" + second_body};
        if (!ReadHttpRequest(connection, first_request) || !SendAll(connection, first_response) ||
            !ReadHttpRequest(connection, second_request) || !SendAll(connection, second_response)) {
            server_ok = false;
        }
        ::close(connection);
    }};

    HttpRpcConfig config{
        .host = "127.0.0.1",
        .port = ntohs(address.sin_port),
        .path = "/",
        .authorization = "user:password",
        .timeout_seconds = 5,
        .max_response_bytes = 1024 * 1024,
    };
    CoreRpcClient client{std::make_unique<HttpRpcTransport>(std::move(config))};
    const auto first{client.Call("getblockcount")};
    const auto second{client.Call("getblockcount")};
    server.join();
    ::close(listener);

    CHECK(server_ok.load());
    CHECK(first);
    CHECK(second);
    CHECK_EQ(first.Value().getInt<int>(), 7);
    CHECK_EQ(second.Value().getInt<int>(), 8);
    CHECK(first_request.find("Connection: keep-alive") != std::string::npos);
    CHECK_EQ(client.AggregateMetrics().calls, 2U);
}

TEST(raw_rpc_envelope_exposes_result_without_copying_the_value)
{
    auto response{ExtractJsonRpcResult(
        " { \"id\" : 1, \"result\" : {\"height\":7}, \"error\" : null } ")};
    CHECK(response);
    CHECK_EQ(response.Value().Value(), "{\"height\":7}");
    CHECK(!ExtractJsonRpcResult("{\"result\":null,\"error\":{\"code\":-1}}"));
    CHECK(!ExtractJsonRpcResult("{\"error\":null}"));
    CHECK(!ExtractJsonRpcResult("not-json"));
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
    struct Bip30Case {
        uint32_t original_height;
        std::string_view original_block;
        uint32_t repeat_height;
        std::string_view repeat_block;
        std::string_view txid;
        std::string_view script;
        std::string_view original_leaf;
    };
    constexpr std::array cases{
        Bip30Case{
            91722,
            "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
            91880,
            "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721",
            "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468",
            "4104124b212f5416598a92ccec88819105179dcb2550d571842601492718273fe0f2179a9695096bff94cd99dcccdea7cd9bd943bfca8fea649cac963411979a33e9ac",
            "84b3af0783b410b4564c5d1f361868559f7cf77cfc65ce2be951210357022fe3",
        },
        Bip30Case{
            91812,
            "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
            91842,
            "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec",
            "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599",
            "41046896ecfc449cb8560594eb7f413f199deb9b4e5d947a142e7dc7d2de0b811b8e204833ea2a2fd9d4c7b153a8ca7661d0a0b7fc981df1f42f55d64b26b3da1e9cac",
            "bc6b4bf7cebbd33a18d6b0fe1f8ecc7aa5403083c39ee343b985d51fd0295ad8",
        },
    };
    const auto resolver = [](uint32_t) { return Result<Hash256>::Err("unused"); };

    for (const auto& test_case : cases) {
        const auto original{ParseVerboseBlock(
            CoinbaseBlock(test_case.original_height, test_case.original_block, test_case.txid,
                          {}, test_case.script), resolver)};
        CHECK(original);
        CHECK_EQ(original.Value().additions,
                 std::vector<Hash256>{Hash256::FromHex(test_case.original_leaf).Value()});

        const auto repeated{ParseVerboseBlock(
            CoinbaseBlock(test_case.repeat_height, test_case.repeat_block, test_case.txid,
                          {}, test_case.script), resolver)};
        CHECK(repeated);
        CHECK_EQ(repeated.Value().additions.size(), 1U);
        CHECK(repeated.Value().additions[0] != original.Value().additions[0]);
    }
}

TEST(verbose_block_rejects_spending_the_overwritten_bip30_originals)
{
    struct Bip30Original {
        uint32_t height;
        std::string_view block;
        std::string_view txid;
        std::string_view script;
    };
    constexpr std::array originals{
        Bip30Original{
            91722,
            "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e",
            "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468",
            "4104124b212f5416598a92ccec88819105179dcb2550d571842601492718273fe0f2179a9695096bff94cd99dcccdea7cd9bd943bfca8fea649cac963411979a33e9ac",
        },
        Bip30Original{
            91812,
            "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f",
            "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599",
            "41046896ecfc449cb8560594eb7f413f199deb9b4e5d947a142e7dc7d2de0b811b8e204833ea2a2fd9d4c7b153a8ca7661d0a0b7fc981df1f42f55d64b26b3da1e9cac",
        },
    };

    for (const auto& original : originals) {
        const UniValue block{Json(
            "{\"hash\":\"" + std::string(64, '4') + "\",\"height\":100000,\"previousblockhash\":\"" +
            std::string(64, '3') + "\",\"tx\":["
            "{\"txid\":\"" + std::string(64, '0') + "\",\"vin\":[{\"coinbase\":\"00\"}],\"vout\":[]},"
            "{\"txid\":\"" + std::string(64, '2') + "\",\"vin\":[{\"txid\":\"" + std::string{original.txid} +
            "\",\"vout\":0,\"prevout\":{\"generated\":true,\"height\":" + std::to_string(original.height) +
            ",\"value\":50.0,\"scriptPubKey\":{\"hex\":\"" + std::string{original.script} +
            "\"}}}],\"vout\":[]}]}" )};
        const auto delta{ParseVerboseBlock(block, [&original](uint32_t height) {
            if (height != original.height) return Result<Hash256>::Err("wrong height");
            return Hash256::FromBitcoinHex(original.block);
        })};
        CHECK(!delta);
        CHECK(delta.Error().find("unspendable BIP30 leaf") != std::string::npos);
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

TEST(streaming_verbose_block_projection_matches_dom_semantics)
{
    const std::string block_hash(64, '9');
    const std::string previous_hash(64, '1');
    const std::string coinbase_txid(64, 'a');
    const std::string external_txid(64, 'b');
    const std::string local_txid(64, 'c');
    const std::string spending_txid(64, 'd');
    const std::string json{
        "{\"ignored\":{\"deep\":[1,true,null,{\"escaped\":\"x\\\\y\"}]},"
        "\"hash\":\"" + block_hash + "\",\"height\":20,\"previousblockhash\":\"" +
        previous_hash + "\",\"tx\":["
        "{\"txid\":\"" + coinbase_txid +
        "\",\"hash\":\"" + std::string(64, 'e') +
        "\",\"vin\":[{\"coinbase\":\"00\",\"sequence\":4294967295}],"
        "\"vout\":[{\"n\":0,\"value\":1.0,\"scriptPubKey\":{\"asm\":\"1\",\"hex\":\"51\",\"type\":\"nonstandard\"}}]},"
        "{\"txid\":\"" + local_txid + "\",\"vin\":[{\"txid\":\"" + external_txid +
        "\",\"vout\":2,\"scriptSig\":{\"hex\":\"\"},\"prevout\":{\"generated\":false,"
        "\"height\":4,\"value\":2.5,\"scriptPubKey\":{\"hex\":\"51\",\"asm\":\"1\"}}}],"
        "\"vout\":[{\"n\":5,\"value\":3,\"scriptPubKey\":{\"hex\":\"51\"}}]},"
        "{\"txid\":\"" + spending_txid + "\",\"vin\":[{\"txid\":\"" + local_txid +
        "\",\"vout\":5}],\"vout\":[{\"n\":0,\"value\":0,\"scriptPubKey\":{\"hex\":\"6a\"}}]}]}"};
    const auto resolver = [](uint32_t height) {
        Hash256::Storage bytes{};
        bytes[0] = static_cast<std::byte>(height);
        return Result<Hash256>::Ok(Hash256{bytes});
    };
    const auto dom{ParseVerboseBlock(Json(json), resolver)};
    const auto streaming{ParseVerboseBlockJson(json, resolver)};
    CHECK(dom);
    CHECK(streaming);
    CHECK_EQ(streaming.Value().point, dom.Value().point);
    CHECK_EQ(streaming.Value().previous_block_hash, dom.Value().previous_block_hash);
    CHECK_EQ(streaming.Value().additions, dom.Value().additions);
    CHECK_EQ(streaming.Value().deletions, dom.Value().deletions);
    CHECK_EQ(streaming.Value().proof_leaves, dom.Value().proof_leaves);
    CHECK(!ParseVerboseBlockJson("{\"hash\":", resolver));
}
