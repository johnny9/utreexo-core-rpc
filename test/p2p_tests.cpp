#include <test_framework.h>
#include <utreexo/p2p.h>

#include <array>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace utreexo;

namespace {

std::string Hex(std::span<const std::byte> bytes)
{
    constexpr char map[]{"0123456789abcdef"};
    std::string output;
    output.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value{std::to_integer<uint8_t>(byte)};
        output.push_back(map[value >> 4]);
        output.push_back(map[value & 15U]);
    }
    return output;
}

void SendBytes(int socket, std::span<const std::byte> bytes, std::size_t fragment = 0)
{
    std::size_t sent{0};
    while (sent < bytes.size()) {
        const std::size_t count{fragment == 0 ? bytes.size() - sent :
            std::min(fragment, bytes.size() - sent)};
        const ssize_t result{::send(socket, bytes.data() + sent, count, MSG_NOSIGNAL)};
        if (result < 0 && errno == EINTR) continue;
        CHECK(result > 0);
        sent += static_cast<std::size_t>(result);
    }
}

void ReadBytes(int socket, std::span<std::byte> bytes)
{
    std::size_t received{0};
    while (received < bytes.size()) {
        const ssize_t result{::recv(socket, bytes.data() + received, bytes.size() - received, 0)};
        if (result < 0 && errno == EINTR) continue;
        CHECK(result > 0);
        received += static_cast<std::size_t>(result);
    }
}

P2PMessage ReadWireMessage(int socket, BitcoinNetwork network)
{
    std::array<std::byte, 24> header{};
    ReadBytes(socket, header);
    const uint32_t size{
        std::to_integer<uint8_t>(header[16]) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[17])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[18])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[19])) << 24)};
    std::vector<std::byte> message{header.begin(), header.end()};
    message.resize(header.size() + size);
    ReadBytes(socket, std::span<std::byte>{message}.subspan(header.size()));
    auto decoded{DecodeP2PMessage(network, message)};
    CHECK(decoded);
    return decoded.Take();
}

std::vector<std::byte> ClientVersion()
{
    std::vector<std::byte> payload(86, std::byte{0});
    payload[0] = std::byte{0x80};
    payload[1] = std::byte{0x11};
    payload[2] = std::byte{0x01};
    return payload;
}

int Connect(uint16_t port)
{
    const int socket{::socket(AF_INET, SOCK_STREAM, 0)};
    CHECK(socket >= 0);
    const timeval timeout{2, 0};
    CHECK(::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    CHECK(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    address.sin_port = htons(port);
    CHECK(::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
    return socket;
}

CachedBlockProof ExampleProof(uint8_t hash_byte = 0x11, uint32_t height = 42)
{
    Hash256::Storage block_bytes{};
    block_bytes.fill(static_cast<std::byte>(hash_byte));
    Hash256::Storage proof_bytes{};
    proof_bytes.fill(std::byte{0x22});
    return CachedBlockProof{
        .point = ChainPoint{height, Hash256{block_bytes}},
        .proof = Proof{{1, 300}, {Hash256{proof_bytes}}},
        .leaves = {
            CompactLeafData{.header_code = 3, .amount = 5,
                            .script_type = ScriptPubkeyType::OTHER,
                            .script = {std::byte{0x51}}},
            CompactLeafData{.header_code = 4, .amount = 6,
                            .script_type = ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH,
                            .script = {}},
        },
    };
}

GetUtreexoProofRequest EntireRequest(const Hash256& block_hash)
{
    return GetUtreexoProofRequest{.block_hash = block_hash, .request_bitmap = 0x07,
                                  .proof_indexes = {}, .leaf_indexes = {}};
}

} // namespace

TEST(p2p_v1_empty_envelope_matches_bitcoin_vector)
{
    auto message{EncodeP2PMessage(BitcoinNetwork::MAINNET, "verack", {})};
    CHECK(message);
    CHECK_EQ(Hex(message.Value()), "f9beb4d976657261636b000000000000000000005df6e0e2");
    auto decoded{DecodeP2PMessage(BitcoinNetwork::MAINNET, message.Value())};
    CHECK(decoded);
    CHECK_EQ(decoded.Value().command, "verack");
    CHECK(decoded.Value().payload.empty());

    auto corrupt{message.Value()};
    corrupt[20] ^= std::byte{1};
    CHECK(!DecodeP2PMessage(BitcoinNetwork::MAINNET, corrupt));
    CHECK(!DecodeP2PMessage(BitcoinNetwork::REGTEST, message.Value()));
}

TEST(getuproof_parser_enforces_canonical_bounded_layout)
{
    const auto proof{ExampleProof()};
    std::vector<std::byte> payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    payload.push_back(std::byte{0x05});
    payload.push_back(std::byte{0x02});
    payload.push_back(std::byte{0x01});
    payload.push_back(std::byte{0x80});
    payload.push_back(std::byte{0x01});
    payload.push_back(std::byte{0x04});
    auto parsed{ParseGetUtreexoProof(payload)};
    CHECK(parsed);
    CHECK_EQ(parsed.Value().block_hash, proof.point.block_hash);
    CHECK_EQ(parsed.Value().request_bitmap, 0x05U);
    CHECK_EQ(parsed.Value().proof_indexes,
             (std::vector<std::byte>{std::byte{0x01}, std::byte{0x80}}));
    CHECK_EQ(parsed.Value().leaf_indexes,
             (std::vector<std::byte>{std::byte{0x04}}));

    auto trailing{payload};
    trailing.push_back(std::byte{0});
    CHECK(!ParseGetUtreexoProof(trailing));
    payload[33] = std::byte{0xfd};
    payload.insert(payload.begin() + 34, {std::byte{0x02}, std::byte{0x00}});
    CHECK(!ParseGetUtreexoProof(payload));
}

TEST(uproof_serialization_matches_utreexod_field_order)
{
    const auto proof{ExampleProof()};
    auto serialized{SerializeUtreexoProof(proof, EntireRequest(proof.point.block_hash))};
    CHECK(serialized);
    CHECK_EQ(Hex(serialized.Value()),
        std::string(64, '1') +
        "01" + std::string(64, '2') +
        "0201fd2c01" +
        "02"
        "030000000500000000000000000151"
        "04000000060000000000000002");

    auto selective{EntireRequest(proof.point.block_hash)};
    selective.request_bitmap = 0x01;
    selective.proof_indexes = {std::byte{0x01}};
    selective.leaf_indexes = {std::byte{0x02}};
    serialized = SerializeUtreexoProof(proof, selective);
    CHECK(serialized);
    CHECK_EQ(Hex(serialized.Value()),
        std::string(64, '1') +
        "01" + std::string(64, '2') +
        "0201fd2c01"
        "0104000000060000000000000002");
}

TEST(recent_proof_cache_bounds_memory_and_discards_reorgs)
{
    RecentProofCache cache{2, 1024 * 1024};
    for (uint8_t value{1}; value <= 3; ++value) {
        auto proof{ExampleProof(value, value)};
        BlockDelta delta{.point = proof.point,
                         .previous_block_hash = {},
                         .additions = {},
                         .deletions = {Hash256{}, Hash256{}},
                         .proof_leaves = proof.leaves};
        CHECK(cache.Publish(delta, proof.proof));
    }
    CHECK_EQ(cache.Stats().entries, 2U);
    CHECK(!cache.Find(ExampleProof(1, 1).point.block_hash));
    CHECK(cache.Find(ExampleProof(2, 2).point.block_hash));
    cache.DiscardAfter(2);
    CHECK_EQ(cache.Stats().entries, 1U);
    CHECK(!cache.Find(ExampleProof(3, 3).point.block_hash));
    CHECK_EQ(cache.Stats().tip_height, 2U);

    RecentProofCache waiting_cache{1, 1024 * 1024};
    auto awaited_proof{ExampleProof(9, 9)};
    BlockDelta awaited_delta{.point = awaited_proof.point,
                             .previous_block_hash = {},
                             .additions = {},
                             .deletions = {Hash256{}, Hash256{}},
                             .proof_leaves = awaited_proof.leaves};
    std::atomic<bool> waiter_started{false};
    std::shared_ptr<const CachedBlockProof> waited;
    std::thread waiter{[&] {
        waiter_started.store(true);
        waited = waiting_cache.WaitFor(awaited_proof.point.block_hash,
                                       std::chrono::seconds(1));
    }};
    while (!waiter_started.load()) std::this_thread::yield();
    CHECK(waiting_cache.Publish(awaited_delta, awaited_proof.proof));
    waiter.join();
    CHECK(waited);
    CHECK_EQ(waited->point, awaited_proof.point);
}

TEST(p2p_server_handshakes_and_serves_floresta_proof_request)
{
    auto cache{std::make_shared<RecentProofCache>(8, 1024 * 1024)};
    auto proof{ExampleProof()};
    BlockDelta delta{.point = proof.point,
                     .previous_block_hash = {},
                     .additions = {},
                     .deletions = {Hash256{}, Hash256{}},
                     .proof_leaves = proof.leaves};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 2,
        .idle_timeout_seconds = 2,
        .user_agent = "/utreexo-test:1/",
    }, cache)};
    if (!started && (started.Error().find("Operation not permitted") != std::string::npos ||
                     started.Error().find("Permission denied") != std::string::npos)) {
        // Some local test sandboxes prohibit even loopback listeners. CI runs this path.
        return;
    }
    CHECK(started);
    auto server{started.Take()};

    // Current Floresta probes BIP324 before using its configured v1 fallback. A
    // v1-only listener must reject that non-magic prefix without waiting for a
    // payload whose apparent size came from random handshake bytes.
    const int probe_socket{Connect(server->BoundPort())};
    std::array<std::byte, 24> v2_probe{};
    v2_probe[16] = std::byte{64};
    SendBytes(probe_socket, v2_probe);
    std::byte rejected{};
    CHECK_EQ(::recv(probe_socket, &rejected, 1, 0), 0);
    ::close(probe_socket);

    const int socket{Connect(server->BoundPort())};

    auto version{EncodeP2PMessage(BitcoinNetwork::REGTEST, "version", ClientVersion())};
    CHECK(version);
    SendBytes(socket, version.Value(), 3);
    const auto server_version{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(server_version.command, "version");
    CHECK(server_version.payload.size() >= 86);
    uint64_t services{0};
    for (std::size_t i{0}; i < 8; ++i) {
        services |= static_cast<uint64_t>(std::to_integer<uint8_t>(server_version.payload[4 + i])) << (i * 8);
    }
    CHECK_EQ(services, 1ULL << 12);
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "verack");

    auto sendaddrv2{EncodeP2PMessage(BitcoinNetwork::REGTEST, "sendaddrv2", {})};
    auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
    CHECK(sendaddrv2);
    CHECK(verack);
    SendBytes(socket, sendaddrv2.Value());
    SendBytes(socket, verack.Value());

    auto getaddr{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getaddr", {})};
    CHECK(getaddr);
    SendBytes(socket, getaddr.Value());
    auto addresses{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(addresses.command, "addrv2");
    CHECK_EQ(addresses.payload, (std::vector<std::byte>{std::byte{0}}));

    const std::array<std::byte, 8> nonce{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    auto ping{EncodeP2PMessage(BitcoinNetwork::REGTEST, "ping", nonce)};
    CHECK(ping);
    SendBytes(socket, ping.Value());
    auto pong{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(pong.command, "pong");
    CHECK_EQ(pong.payload, (std::vector<std::byte>{nonce.begin(), nonce.end()}));

    std::vector<std::byte> request_payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(), {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(socket, request.Value(), 1);
    CHECK(cache->Publish(delta, proof.proof));
    auto response{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(response.command, "uproof");
    auto expected{SerializeUtreexoProof(proof, EntireRequest(proof.point.block_hash))};
    CHECK(expected);
    CHECK_EQ(response.payload, expected.Value());
    CHECK_EQ(cache->Stats().hits, 1U);

    ::shutdown(socket, SHUT_RDWR);
    ::close(socket);
}
