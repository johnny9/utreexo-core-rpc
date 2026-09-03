#include <test_framework.h>
#include <utreexo/p2p.h>
#include <utreexo/proof_store.h>

#include <array>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
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

#ifdef MSG_NOSIGNAL
constexpr int SEND_FLAGS{MSG_NOSIGNAL};
#else
constexpr int SEND_FLAGS{0};
#endif

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
#ifdef SO_NOSIGPIPE
    const int enabled{1};
    CHECK(::setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) == 0);
#endif
    std::size_t sent{0};
    while (sent < bytes.size()) {
        const std::size_t count{fragment == 0 ? bytes.size() - sent :
            std::min(fragment, bytes.size() - sent)};
        const ssize_t result{::send(socket, bytes.data() + sent, count, SEND_FLAGS)};
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

std::vector<std::byte> ClientVersion(uint64_t services = 0)
{
    std::vector<std::byte> payload(86, std::byte{0});
    payload[0] = std::byte{0x80};
    payload[1] = std::byte{0x11};
    payload[2] = std::byte{0x01};
    for (std::size_t i{0}; i < sizeof(services); ++i) {
        payload[4 + i] = static_cast<std::byte>((services >> (i * 8)) & 0xffU);
    }
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

Hash256 RepeatedHash(uint8_t value)
{
    Hash256::Storage bytes{};
    bytes.fill(static_cast<std::byte>(value));
    return Hash256{bytes};
}

std::vector<std::byte> GetUtreexoStatePayload(uint32_t height, const Hash256& stop_hash)
{
    std::vector<std::byte> payload{std::byte{1}};
    for (std::size_t i{0}; i < sizeof(height); ++i) {
        payload.push_back(static_cast<std::byte>(height & 0xffU));
        height >>= 8;
    }
    payload.insert(payload.end(), stop_hash.Bytes().begin(), stop_hash.Bytes().end());
    return payload;
}

std::vector<std::byte> UtreexoStateFilterPayload(const AccumulatorState& state)
{
    const std::size_t state_size{sizeof(state.num_leaves) +
                                 state.roots.size() * Hash256::SIZE};
    CHECK(state_size < 253);
    std::vector<std::byte> payload{std::byte{1}};
    payload.insert(payload.end(), state.point.block_hash.Bytes().begin(),
                   state.point.block_hash.Bytes().end());
    payload.push_back(static_cast<std::byte>(state_size));
    uint64_t leaves{state.num_leaves};
    for (std::size_t i{0}; i < sizeof(leaves); ++i) {
        payload.push_back(static_cast<std::byte>(leaves & 0xffU));
        leaves >>= 8;
    }
    for (const auto& root : state.roots) {
        payload.insert(payload.end(), root.Bytes().begin(), root.Bytes().end());
    }
    return payload;
}

void Handshake(int socket, BitcoinNetwork network)
{
    auto version{EncodeP2PMessage(network, "version", ClientVersion())};
    CHECK(version);
    SendBytes(socket, version.Value());
    CHECK_EQ(ReadWireMessage(socket, network).command, "version");
    CHECK_EQ(ReadWireMessage(socket, network).command, "verack");
    auto verack{EncodeP2PMessage(network, "verack", {})};
    CHECK(verack);
    SendBytes(socket, verack.Value());
}

bool WaitUntil(const std::function<bool()>& predicate,
               std::chrono::milliseconds timeout = std::chrono::seconds(2))
{
    const auto deadline{std::chrono::steady_clock::now() + timeout};
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return predicate();
}

bool ListenerUnavailable(const Result<std::unique_ptr<P2PServer>>& result)
{
    return !result && (result.Error().find("Operation not permitted") != std::string::npos ||
                       result.Error().find("Permission denied") != std::string::npos);
}

void CheckAddressPayload(const std::vector<std::byte>& payload,
                         std::string_view expected_suffix)
{
    CHECK(payload.size() >= 5);
    CHECK_EQ(payload.front(), std::byte{1});
    uint32_t timestamp{0};
    for (std::size_t i{0}; i < sizeof(timestamp); ++i) {
        timestamp |= static_cast<uint32_t>(std::to_integer<uint8_t>(payload[1 + i])) << (i * 8);
    }
    const auto now{std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
    CHECK(timestamp <= static_cast<uint64_t>(now) + 1);
    CHECK(timestamp + 5 >= static_cast<uint64_t>(now));
    CHECK_EQ(Hex(std::span<const std::byte>{payload}.subspan(5)), expected_suffix);
}

int ListenLoopback(uint16_t& port)
{
    const int listener{::socket(AF_INET, SOCK_STREAM, 0)};
    if (listener < 0) return -1;
    const int reuse{1};
    static_cast<void>(::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener, 1) != 0) {
        ::close(listener);
        return -1;
    }
    socklen_t address_size{sizeof(address)};
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ::close(listener);
        return -1;
    }
    port = ntohs(address.sin_port);
    return listener;
}

} // namespace

TEST(numeric_p2p_endpoint_parser_rejects_dns_and_ambiguous_ports)
{
    auto parsed{ParseP2PIPv4Endpoint("203.0.113.9:8333")};
    CHECK(parsed);
    CHECK_EQ(parsed.Value().address, "203.0.113.9");
    CHECK_EQ(parsed.Value().port, 8333U);
    CHECK(!ParseP2PIPv4Endpoint("seed.example:8333"));
    CHECK(!ParseP2PIPv4Endpoint("203.0.113.9"));
    CHECK(!ParseP2PIPv4Endpoint("203.0.113.9:0"));
    CHECK(!ParseP2PIPv4Endpoint("203.0.113.9:65536"));
    CHECK(!ParseP2PIPv4Endpoint("203.0.113.9:8333:1"));
}

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
    const auto entire_request{EntireRequest(proof.point.block_hash)};
    auto serialized{SerializeUtreexoProof(proof, entire_request)};
    CHECK(serialized);
    CHECK_EQ(Hex(serialized.Value()),
        std::string(64, '1') +
        "01" + std::string(64, '2') +
        "0201fd2c01" +
        "02"
        "030000000500000000000000000151"
        "04000000060000000000000002");

    auto exact_bound{SerializeUtreexoProof(proof, entire_request,
                                           serialized.Value().size())};
    CHECK(exact_bound);
    CHECK_EQ(exact_bound.Value(), serialized.Value());
    auto short_bound{SerializeUtreexoProof(proof, entire_request,
                                           serialized.Value().size() - 1)};
    CHECK(!short_bound);
    CHECK(short_bound.Error().find("exceeds configured maximum") != std::string::npos);

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

TEST(full_uproof_archive_roundtrip_is_strict)
{
    const auto proof{ExampleProof()};
    auto serialized{SerializeUtreexoProof(proof, EntireRequest(proof.point.block_hash))};
    CHECK(serialized);
    auto parsed{ParseFullUtreexoProof(proof.point.height, serialized.Value())};
    CHECK(parsed);
    CHECK_EQ(parsed.Value().point, proof.point);
    CHECK_EQ(parsed.Value().proof.targets, proof.proof.targets);
    CHECK_EQ(parsed.Value().proof.hashes, proof.proof.hashes);
    CHECK_EQ(parsed.Value().leaves, proof.leaves);
    auto trailing{serialized.Value()};
    trailing.push_back(std::byte{0});
    CHECK(!ParseFullUtreexoProof(proof.point.height, trailing));
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

TEST(recent_proof_cache_skips_one_oversized_proof_without_stopping)
{
    RecentProofCache cache{2, 1};
    auto proof{ExampleProof(10, 10)};
    BlockDelta delta{.point = proof.point,
                     .previous_block_hash = {},
                     .additions = {},
                     .deletions = {Hash256{}, Hash256{}},
                     .proof_leaves = proof.leaves};
    CHECK(cache.Publish(delta, std::move(proof.proof)));
    const auto stats{cache.Stats()};
    CHECK_EQ(stats.entries, 0U);
    CHECK_EQ(stats.bytes, 0U);
    CHECK_EQ(stats.oversized_skips, 1U);
    CHECK_EQ(stats.tip_height, delta.point.height);
    CHECK(!cache.Find(delta.point.block_hash));
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

TEST(p2p_server_returns_explicit_address_in_legacy_and_addrv2_wire_formats)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 4,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-address-test:1/",
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444},
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};

    const int legacy{Connect(server->BoundPort())};
    Handshake(legacy, BitcoinNetwork::REGTEST);
    auto getaddr{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getaddr", {})};
    CHECK(getaddr);
    SendBytes(legacy, getaddr.Value());
    auto addresses{ReadWireMessage(legacy, BitcoinNetwork::REGTEST)};
    CHECK_EQ(addresses.command, "addr");
    CheckAddressPayload(addresses.payload,
        "001000000000000000000000000000000000ffff7f000001480c");
    ::shutdown(legacy, SHUT_RDWR);
    ::close(legacy);

    const int v2{Connect(server->BoundPort())};
    auto version{EncodeP2PMessage(BitcoinNetwork::REGTEST, "version", ClientVersion())};
    CHECK(version);
    SendBytes(v2, version.Value());
    CHECK_EQ(ReadWireMessage(v2, BitcoinNetwork::REGTEST).command, "version");
    CHECK_EQ(ReadWireMessage(v2, BitcoinNetwork::REGTEST).command, "verack");
    auto sendaddrv2{EncodeP2PMessage(BitcoinNetwork::REGTEST, "sendaddrv2", {})};
    auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
    CHECK(sendaddrv2);
    CHECK(verack);
    SendBytes(v2, sendaddrv2.Value());
    SendBytes(v2, verack.Value());
    SendBytes(v2, getaddr.Value());
    addresses = ReadWireMessage(v2, BitcoinNetwork::REGTEST);
    CHECK_EQ(addresses.command, "addrv2");
    CheckAddressPayload(addresses.payload, "fd001001047f000001480c");
    ::shutdown(v2, SHUT_RDWR);
    ::close(v2);
}

TEST(p2p_discovery_requires_an_explicit_routable_address)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto private_mainnet{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::MAINNET,
        .bind_address = "127.0.0.1",
        .port = 0,
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 8333},
    }, cache)};
    CHECK(!private_mainnet);
    CHECK(private_mainnet.Error().find("globally routable") != std::string::npos);

    auto missing_address{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .gossip_seeds = {P2PIPv4Endpoint{"127.0.0.1", 18'444}},
    }, cache)};
    CHECK(!missing_address);
    CHECK(missing_address.Error().find("explicit advertised endpoint") != std::string::npos);
}

TEST(p2p_static_configuration_is_validated_without_opening_a_listener)
{
    CHECK_EQ(BitcoinNetworkGenesisHash(BitcoinNetwork::MAINNET).ToBitcoinHex(),
             "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    CHECK_EQ(BitcoinNetworkGenesisHash(BitcoinNetwork::REGTEST).ToBitcoinHex(),
             "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");
    P2PServerConfig config{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 18'444,
        .max_payload_bytes = 1024,
    };
    CHECK(ValidateP2PServerConfig(config));

    config.max_inbound_bytes_per_second = 128 * 1024;
    auto short_inbound_window{ValidateP2PServerConfig(config)};
    CHECK(!short_inbound_window);
    CHECK(short_inbound_window.Error().find("inbound byte") != std::string::npos);
    config.max_inbound_bytes_per_second = 4 * 1024 * 1024;

    config.idle_timeout_seconds = 0;
    auto zero_idle_timeout{ValidateP2PServerConfig(config)};
    CHECK(!zero_idle_timeout);
    CHECK(zero_idle_timeout.Error().find("idle timeout") != std::string::npos);
    config.idle_timeout_seconds = 120;

    config.egress_burst_bytes = 1024;
    auto short_burst{ValidateP2PServerConfig(config)};
    CHECK(!short_burst);
    CHECK(short_burst.Error().find("egress") != std::string::npos);

    config.egress_burst_bytes = 2048;
    config.bind_address = "192.0.2.1";
    auto unsupported_bind{ValidateP2PServerConfig(config)};
    CHECK(!unsupported_bind);
    CHECK(unsupported_bind.Error().find("bind address") != std::string::npos);

    config.bind_address = "127.0.0.1";
    config.advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444};
    config.gossip_seeds = {
        P2PIPv4Endpoint{"127.0.0.1", 18'445},
        P2PIPv4Endpoint{"127.0.0.1", 18'445},
    };
    auto duplicate_seed{ValidateP2PServerConfig(config)};
    CHECK(!duplicate_seed);
    CHECK(duplicate_seed.Error().find("duplicate") != std::string::npos);

    config.gossip_seeds = {*config.advertised_endpoint};
    auto self_seed{ValidateP2PServerConfig(config)};
    CHECK(!self_seed);
    CHECK(self_seed.Error().find("cannot equal") != std::string::npos);
}

TEST(p2p_server_handshakes_with_numeric_seed_and_announces_public_address)
{
    uint16_t seed_port{0};
    const int listener{ListenLoopback(seed_port)};
    if (listener < 0) return;
    const timeval accept_timeout{3, 0};
    static_cast<void>(::setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout,
                                  sizeof(accept_timeout)));

    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-gossip-test:1/",
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444},
        .gossip_seeds = {P2PIPv4Endpoint{"127.0.0.1", seed_port}},
        .gossip_retry_seconds = 1,
        .gossip_connect_timeout_seconds = 2,
    }, cache)};
    if (ListenerUnavailable(started)) {
        ::close(listener);
        return;
    }
    CHECK(started);
    auto server{started.Take()};
    std::exception_ptr seed_failure;
    std::thread seed{[&] {
        try {
            for (uint32_t attempt{0}; attempt < 2; ++attempt) {
                sockaddr_in peer_address{};
                socklen_t peer_size{sizeof(peer_address)};
                const int peer{::accept(listener, reinterpret_cast<sockaddr*>(&peer_address),
                                        &peer_size)};
                CHECK(peer >= 0);
                const timeval timeout{2, 0};
                CHECK(::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
                CHECK(::setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);

                const auto outbound_version{ReadWireMessage(peer, BitcoinNetwork::REGTEST)};
                CHECK_EQ(outbound_version.command, "version");
                uint64_t services{0};
                for (std::size_t i{0}; i < sizeof(services); ++i) {
                    services |= static_cast<uint64_t>(
                        std::to_integer<uint8_t>(outbound_version.payload[4 + i])) << (i * 8);
                }
                CHECK_EQ(services, 1ULL << 12);
                auto version{EncodeP2PMessage(
                    BitcoinNetwork::REGTEST, "version", ClientVersion(1ULL << 12))};
                auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
                CHECK(version);
                CHECK(verack);
                SendBytes(peer, version.Value());
                SendBytes(peer, verack.Value());
                CHECK_EQ(ReadWireMessage(peer, BitcoinNetwork::REGTEST).command, "verack");
                const auto announcement{ReadWireMessage(peer, BitcoinNetwork::REGTEST)};
                CHECK_EQ(announcement.command, "addr");
                CheckAddressPayload(announcement.payload,
                    "001000000000000000000000000000000000ffff7f000001480c");
                ::close(peer);
            }
        } catch (...) {
            seed_failure = std::current_exception();
        }
    }};

    CHECK(WaitUntil([&] { return server->Stats().gossip_announcements == 2; },
                        std::chrono::seconds(5)));
    seed.join();
    ::close(listener);
    if (seed_failure) std::rethrow_exception(seed_failure);
    const auto stats{server->Stats()};
    CHECK_EQ(stats.gossip_attempts, 2U);
    CHECK_EQ(stats.gossip_handshakes, 2U);
    CHECK_EQ(stats.gossip_announcements, 2U);
}

TEST(p2p_gossip_rejects_a_peer_without_utreexo_services)
{
    uint16_t seed_port{0};
    const int listener{ListenLoopback(seed_port)};
    if (listener < 0) return;
    const timeval accept_timeout{3, 0};
    static_cast<void>(::setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &accept_timeout,
                                  sizeof(accept_timeout)));

    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444},
        .gossip_seeds = {P2PIPv4Endpoint{"127.0.0.1", seed_port}},
        .gossip_retry_seconds = 60,
        .gossip_connect_timeout_seconds = 2,
    }, cache)};
    if (ListenerUnavailable(started)) {
        ::close(listener);
        return;
    }
    CHECK(started);
    auto server{started.Take()};
    std::exception_ptr seed_failure;
    std::thread seed{[&] {
        try {
            sockaddr_in peer_address{};
            socklen_t peer_size{sizeof(peer_address)};
            const int peer{::accept(listener, reinterpret_cast<sockaddr*>(&peer_address),
                                    &peer_size)};
            CHECK(peer >= 0);
            const timeval timeout{2, 0};
            CHECK(::setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                               sizeof(timeout)) == 0);
            CHECK_EQ(ReadWireMessage(peer, BitcoinNetwork::REGTEST).command, "version");
            auto version{EncodeP2PMessage(
                BitcoinNetwork::REGTEST, "version", ClientVersion())};
            auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
            CHECK(version);
            CHECK(verack);
            SendBytes(peer, version.Value());
            SendBytes(peer, verack.Value());
            CHECK_EQ(ReadWireMessage(peer, BitcoinNetwork::REGTEST).command, "verack");
            std::array<std::byte, 1> unexpected{};
            CHECK(::recv(peer, unexpected.data(), unexpected.size(), 0) <= 0);
            ::close(peer);
        } catch (...) {
            seed_failure = std::current_exception();
        }
    }};

    CHECK(WaitUntil([&] { return server->Stats().gossip_handshakes == 1; },
                    std::chrono::seconds(4)));
    seed.join();
    ::close(listener);
    if (seed_failure) std::rethrow_exception(seed_failure);
    CHECK_EQ(server->Stats().gossip_announcements, 0U);

    // The gossip loop is now in its long retry wait. Stopping must synchronize
    // with the wait predicate so notification cannot be lost.
    const auto stop_started{std::chrono::steady_clock::now()};
    server.reset();
    CHECK(std::chrono::steady_clock::now() - stop_started <
          std::chrono::milliseconds(1'500));
}

TEST(p2p_server_serves_archived_proof_when_ram_cache_is_empty)
{
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-p2p-proof-store-" + std::to_string(::getpid()))};
    std::error_code cleanup_error;
    std::filesystem::remove_all(path, cleanup_error);
    auto proof{ExampleProof(0x61, 42)};
    const ChainPoint base{41, Hash256::FromHex(
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").Value()};
    BlockDelta delta{
        .point = proof.point,
        .previous_block_hash = base.block_hash,
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = proof.leaves,
    };
    auto opened{ProofStore::Open(ProofStoreConfig{
        .directory = path,
        .create_base = base,
        .create_base_state = AccumulatorState{
            .point = base,
            .num_leaves = 1,
            .roots = {RepeatedHash(0x51)},
        },
        .serializer_threads = 2,
        .group_commit_blocks = 1,
        .group_commit_delay_ms = 0,
        .max_queued_blocks = 4,
        .max_queued_bytes = 1024 * 1024,
        .max_record_bytes = 1024 * 1024,
    })};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(delta, proof.proof, AccumulatorState{
        .point = proof.point,
        .num_leaves = 2,
        .roots = {RepeatedHash(0x52)},
    }));
    CHECK(store->Drain());

    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    cache->SetTip(proof.point.height);
    auto false_archive{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-partial-archive-test:1/",
        .advertise_archive = true,
    }, cache, store)};
    CHECK(!false_archive);
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_payload_bytes = 1024 * 1024,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-archive-test:1/",
    }, cache, store)};
    if (!started && (started.Error().find("Operation not permitted") != std::string::npos ||
                     started.Error().find("Permission denied") != std::string::npos)) {
        store.reset();
        std::filesystem::remove_all(path, cleanup_error);
        return;
    }
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    auto version{EncodeP2PMessage(BitcoinNetwork::REGTEST, "version", ClientVersion())};
    CHECK(version);
    SendBytes(socket, version.Value());
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "version");
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "verack");
    auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
    CHECK(verack);
    SendBytes(socket, verack.Value());

    std::vector<std::byte> request_payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(), {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(socket, request.Value());
    auto response{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(response.command, "uproof");
    auto expected{SerializeUtreexoProof(proof, EntireRequest(proof.point.block_hash))};
    CHECK(expected);
    CHECK_EQ(response.payload, expected.Value());
    CHECK_EQ(store->Stats().hits, 1U);

    ::shutdown(socket, SHUT_RDWR);
    ::close(socket);
    server.reset();
    store.reset();
    std::filesystem::remove_all(path, cleanup_error);
}

TEST(p2p_archive_service_requires_genesis_coverage_and_serves_utreexo_states)
{
    const auto path{std::filesystem::temp_directory_path() /
        ("utreexo-p2p-state-store-" + std::to_string(::getpid()))};
    std::error_code cleanup_error;
    std::filesystem::remove_all(path, cleanup_error);
    const auto regtest_genesis{Hash256::FromBitcoinHex(
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")};
    CHECK(regtest_genesis);
    const AccumulatorState base_state{
        .point = ChainPoint{0, regtest_genesis.Value()},
        .num_leaves = 0,
        .roots = {},
    };
    auto proof{ExampleProof(0x82, 1)};
    const AccumulatorState block_state{
        .point = proof.point,
        .num_leaves = 2,
        .roots = {RepeatedHash(0x92)},
    };
    BlockDelta delta{
        .point = proof.point,
        .previous_block_hash = base_state.point.block_hash,
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = proof.leaves,
    };
    auto opened{ProofStore::Open(ProofStoreConfig{
        .directory = path,
        .create_base = base_state.point,
        .create_base_state = base_state,
        .serializer_threads = 1,
        .group_commit_blocks = 1,
        .group_commit_delay_ms = 0,
        .max_queued_blocks = 2,
        .max_queued_bytes = 1024 * 1024,
        .max_record_bytes = 1024 * 1024,
    })};
    CHECK(opened);
    auto store{opened.Take()};
    CHECK(store->Enqueue(delta, proof.proof, block_state));
    CHECK(store->Drain());
    CHECK(store->Coverage().full_history);

    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    cache->SetTip(proof.point.height);
    auto without_store{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-state-test:1/",
        .advertise_archive = true,
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444},
    }, cache)};
    CHECK(!without_store);

    auto wrong_network{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::MAINNET,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-state-test:1/",
        .advertise_archive = true,
    }, cache, store)};
    CHECK(!wrong_network);
    CHECK(wrong_network.Error().find("canonical network genesis") != std::string::npos);

    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_payload_bytes = 1024 * 1024,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-state-test:1/",
        .advertise_archive = true,
        .advertised_endpoint = P2PIPv4Endpoint{"127.0.0.1", 18'444},
    }, cache, store)};
    if (ListenerUnavailable(started)) {
        store.reset();
        std::filesystem::remove_all(path, cleanup_error);
        return;
    }
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    auto version{EncodeP2PMessage(BitcoinNetwork::REGTEST, "version", ClientVersion())};
    CHECK(version);
    SendBytes(socket, version.Value());
    const auto server_version{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    uint64_t services{0};
    for (std::size_t i{0}; i < sizeof(services); ++i) {
        services |= static_cast<uint64_t>(
            std::to_integer<uint8_t>(server_version.payload[4 + i])) << (i * 8);
    }
    CHECK_EQ(services, (1ULL << 12) | (1ULL << 13));
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "verack");
    auto verack{EncodeP2PMessage(BitcoinNetwork::REGTEST, "verack", {})};
    CHECK(verack);
    SendBytes(socket, verack.Value());

    auto getaddr{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getaddr", {})};
    CHECK(getaddr);
    SendBytes(socket, getaddr.Value());
    auto response{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(response.command, "addr");
    CheckAddressPayload(response.payload,
        "003000000000000000000000000000000000ffff7f000001480c");

    auto get_states{EncodeP2PMessage(
        BitcoinNetwork::REGTEST, "getcfilters",
        GetUtreexoStatePayload(0, block_state.point.block_hash))};
    CHECK(get_states);
    SendBytes(socket, get_states.Value());
    response = ReadWireMessage(socket, BitcoinNetwork::REGTEST);
    CHECK_EQ(response.command, "cfilter");
    CHECK_EQ(response.payload, UtreexoStateFilterPayload(base_state));
    response = ReadWireMessage(socket, BitcoinNetwork::REGTEST);
    CHECK_EQ(response.command, "cfilter");
    CHECK_EQ(response.payload, UtreexoStateFilterPayload(block_state));
    const auto stats{server->Stats()};
    CHECK_EQ(stats.state_requests, 1U);
    CHECK_EQ(stats.state_misses, 0U);
    CHECK_EQ(stats.states_served, 2U);

    ::shutdown(socket, SHUT_RDWR);
    ::close(socket);
    server.reset();
    store.reset();
    std::filesystem::remove_all(path, cleanup_error);
}

TEST(p2p_server_limits_connections_from_one_ip)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 3,
        .max_peers_per_ip = 1,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-admission-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};

    const int first{Connect(server->BoundPort())};
    CHECK(WaitUntil([&] { return server->Stats().active_peers == 1; }));
    const int rejected{Connect(server->BoundPort())};
    CHECK(WaitUntil([&] { return server->Stats().rejected_per_ip == 1; }));
    std::byte byte{};
    CHECK_EQ(::recv(rejected, &byte, 1, 0), 0);
    CHECK_EQ(server->Stats().accepted_peers, 1U);
    CHECK_EQ(server->Stats().peak_active_peers, 1U);

    ::close(rejected);
    ::shutdown(first, SHUT_RDWR);
    ::close(first);
}

TEST(p2p_server_applies_one_deadline_to_a_dribbled_message)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_peers_per_ip = 1,
        .idle_timeout_seconds = 1,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-read-deadline-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    CHECK(WaitUntil([&] { return server->Stats().active_peers == 1; }));

    auto version{EncodeP2PMessage(BitcoinNetwork::REGTEST, "version", ClientVersion())};
    CHECK(version);
    for (std::size_t offset{0}; offset < 3; ++offset) {
        SendBytes(socket, std::span<const std::byte>{version.Value()}.subspan(offset, 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
    CHECK(WaitUntil([&] { return server->Stats().active_peers == 0; },
                    std::chrono::milliseconds(300)));
    ::close(socket);
}

TEST(p2p_server_bounds_inbound_wire_bytes_per_peer)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_peers_per_ip = 1,
        .max_inbound_bytes_per_second = 300 * 1024,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-inbound-limit-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    Handshake(socket, BitcoinNetwork::REGTEST);

    const std::vector<std::byte> payload(200 * 1024, std::byte{0x5a});
    auto message{EncodeP2PMessage(BitcoinNetwork::REGTEST, "unknown", payload)};
    CHECK(message);
    SendBytes(socket, message.Value());
    SendBytes(socket, std::span<const std::byte>{message.Value()}.first(24));
    CHECK(WaitUntil([&] { return server->Stats().inbound_limited == 1; }));
    std::byte rejected{};
    CHECK_EQ(::recv(socket, &rejected, 1, 0), 0);
    ::close(socket);
}

TEST(p2p_server_waits_for_proof_without_holding_work_or_egress_admission)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto waiting_proof{ExampleProof(0x71, 71)};
    auto available_proof{ExampleProof(0x70, 70)};
    BlockDelta available_delta{
        .point = available_proof.point,
        .previous_block_hash = {},
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = available_proof.leaves,
    };
    CHECK(cache->Publish(available_delta, available_proof.proof));
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 2,
        .max_peers_per_ip = 2,
        .max_concurrent_proof_requests = 1,
        .max_egress_bytes_per_second = 64ULL * 1024ULL * 1024ULL,
        .egress_burst_bytes = 4'120,
        .max_payload_bytes = 4'096,
        .idle_timeout_seconds = 3,
        .proof_wait_seconds = 2,
        .user_agent = "/utreexo-work-limit-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int first{Connect(server->BoundPort())};
    const int second{Connect(server->BoundPort())};
    Handshake(first, BitcoinNetwork::REGTEST);
    Handshake(second, BitcoinNetwork::REGTEST);

    std::vector<std::byte> waiting_payload{
        waiting_proof.point.block_hash.Bytes().begin(),
        waiting_proof.point.block_hash.Bytes().end()};
    waiting_payload.insert(waiting_payload.end(),
                           {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto waiting_request{
        EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", waiting_payload)};
    CHECK(waiting_request);
    SendBytes(first, waiting_request.Value());
    CHECK(WaitUntil([&] {
        return cache->Stats().misses >= 1 && server->Stats().active_proof_requests == 0;
    }));

    std::vector<std::byte> available_payload{
        available_proof.point.block_hash.Bytes().begin(),
        available_proof.point.block_hash.Bytes().end()};
    available_payload.insert(available_payload.end(),
                             {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto available_request{
        EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", available_payload)};
    CHECK(available_request);
    SendBytes(second, available_request.Value());
    CHECK_EQ(ReadWireMessage(second, BitcoinNetwork::REGTEST).command, "uproof");

    BlockDelta waiting_delta{
        .point = waiting_proof.point,
        .previous_block_hash = {},
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = waiting_proof.leaves,
    };
    CHECK(cache->Publish(waiting_delta, waiting_proof.proof));
    CHECK_EQ(ReadWireMessage(first, BitcoinNetwork::REGTEST).command, "uproof");
    CHECK(WaitUntil([&] { return server->Stats().active_proof_requests == 0; }));
    const auto stats{server->Stats()};
    CHECK_EQ(stats.proof_requests, 2U);
    CHECK_EQ(stats.proof_busy, 0U);
    CHECK_EQ(stats.proofs_served, 2U);
    CHECK_EQ(stats.peak_active_proof_requests, 1U);

    ::shutdown(first, SHUT_RDWR);
    ::close(first);
    ::shutdown(second, SHUT_RDWR);
    ::close(second);
}

TEST(p2p_server_releases_proof_work_when_a_peer_dribbles_response_reads)
{
    constexpr std::size_t MIB{1024 * 1024};
    auto cache{std::make_shared<RecentProofCache>(2, 16 * MIB)};
    auto proof{ExampleProof(0x75, 75)};
    proof.proof.hashes.assign(300'000, RepeatedHash(0x76));
    BlockDelta delta{
        .point = proof.point,
        .previous_block_hash = {},
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = proof.leaves,
    };
    CHECK(cache->Publish(delta, proof.proof));
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 2,
        .max_peers_per_ip = 2,
        .max_concurrent_proof_requests = 1,
        .max_egress_bytes_per_second = 1024ULL * MIB,
        .egress_burst_bytes = 12ULL * MIB + 24,
        .max_payload_bytes = 12U * MIB,
        .idle_timeout_seconds = 1,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-write-deadline-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int first{Connect(server->BoundPort())};
    const int small_receive_buffer{1024};
    CHECK(::setsockopt(first, SOL_SOCKET, SO_RCVBUF, &small_receive_buffer,
                       sizeof(small_receive_buffer)) == 0);
    const int second{Connect(server->BoundPort())};
    Handshake(first, BitcoinNetwork::REGTEST);
    Handshake(second, BitcoinNetwork::REGTEST);

    std::vector<std::byte> request_payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(),
                           {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(first, request.Value());
    CHECK(WaitUntil([&] { return server->Stats().active_proof_requests == 1; },
                    std::chrono::seconds(15)));

    std::jthread dribbling_reader{[&](const std::stop_token& stop) {
        std::array<std::byte, 64 * 1024> bytes{};
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            const ssize_t received{
                ::recv(first, bytes.data(), bytes.size(), MSG_DONTWAIT)};
            if (received == 0) return;
            if (received < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                return;
            }
        }
    }};

    SendBytes(second, request.Value());
    CHECK(WaitUntil([&] { return server->Stats().proof_busy == 1; }));
    std::byte rejected{};
    CHECK_EQ(::recv(second, &rejected, 1, 0), 0);
    // Serialization and checksumming of the deliberately large proof run under
    // heavy instrumentation in CI. This is test-harness grace; the server's
    // one-second socket write deadline above remains unchanged.
    CHECK(WaitUntil([&] { return server->Stats().active_proof_requests == 0; },
                    std::chrono::seconds(60)));
    CHECK_EQ(server->Stats().proofs_served, 0U);

    dribbling_reader.request_stop();
    dribbling_reader.join();
    ::close(first);
    ::close(second);
}

TEST(p2p_server_shutdown_cancels_a_long_proof_wait)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_peers_per_ip = 1,
        .idle_timeout_seconds = 120,
        .proof_wait_seconds = 120,
        .user_agent = "/utreexo-shutdown-wait-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    Handshake(socket, BitcoinNetwork::REGTEST);

    const auto missing{ExampleProof(0x77, 77)};
    std::vector<std::byte> request_payload{
        missing.point.block_hash.Bytes().begin(), missing.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(),
                           {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(socket, request.Value());
    CHECK(WaitUntil([&] { return cache->Stats().misses >= 1; }));

    const auto stop_started{std::chrono::steady_clock::now()};
    server.reset();
    const auto stop_elapsed{std::chrono::steady_clock::now() - stop_started};
    CHECK(stop_elapsed < std::chrono::milliseconds(1'500));
    ::close(socket);
}

TEST(p2p_server_reserves_exact_proof_wire_bytes_before_allocation)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto proof{ExampleProof(0x78, 78)};
    BlockDelta delta{
        .point = proof.point,
        .previous_block_hash = {},
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = proof.leaves,
    };
    CHECK(cache->Publish(delta, proof.proof));
    auto expected{SerializeUtreexoProof(proof, EntireRequest(proof.point.block_hash))};
    CHECK(expected);
    CHECK(2 * (expected.Value().size() + 24) < 4'120U);

    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 1,
        .max_peers_per_ip = 1,
        .max_concurrent_proof_requests = 1,
        .max_egress_bytes_per_second = 1,
        .egress_burst_bytes = 4'120,
        .max_payload_bytes = 4'096,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-exact-egress-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    Handshake(socket, BitcoinNetwork::REGTEST);

    std::vector<std::byte> request_payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(),
                           {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(socket, request.Value());
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "uproof");
    SendBytes(socket, request.Value());
    CHECK_EQ(ReadWireMessage(socket, BitcoinNetwork::REGTEST).command, "uproof");

    const auto stats{server->Stats()};
    CHECK_EQ(stats.proofs_served, 2U);
    CHECK_EQ(stats.egress_limited, 0U);
    CHECK_EQ(stats.response_bytes, 2 * (expected.Value().size() + 24));
    ::shutdown(socket, SHUT_RDWR);
    ::close(socket);
}

TEST(p2p_server_bounds_global_proof_egress_and_disconnects_misses)
{
    auto cache{std::make_shared<RecentProofCache>(2, 1024 * 1024)};
    auto proof{ExampleProof(0x72, 72)};
    proof.leaves[0].script.assign(1'500, std::byte{0x51});
    BlockDelta delta{
        .point = proof.point,
        .previous_block_hash = {},
        .additions = {},
        .deletions = {Hash256{}, Hash256{}},
        .proof_leaves = proof.leaves,
    };
    CHECK(cache->Publish(delta, proof.proof));
    auto started{P2PServer::Start(P2PServerConfig{
        .network = BitcoinNetwork::REGTEST,
        .bind_address = "127.0.0.1",
        .port = 0,
        .max_peers = 2,
        .max_peers_per_ip = 2,
        .max_concurrent_proof_requests = 1,
        .max_egress_bytes_per_second = 1,
        .egress_burst_bytes = 2'072,
        .max_payload_bytes = 2'048,
        .idle_timeout_seconds = 2,
        .proof_wait_seconds = 0,
        .user_agent = "/utreexo-egress-test:1/",
    }, cache)};
    if (ListenerUnavailable(started)) return;
    CHECK(started);
    auto server{started.Take()};
    const int socket{Connect(server->BoundPort())};
    Handshake(socket, BitcoinNetwork::REGTEST);

    std::vector<std::byte> request_payload{
        proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end()};
    request_payload.insert(request_payload.end(), {std::byte{0x07}, std::byte{0}, std::byte{0}});
    auto request{EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload)};
    CHECK(request);
    SendBytes(socket, request.Value());
    const auto response{ReadWireMessage(socket, BitcoinNetwork::REGTEST)};
    CHECK_EQ(response.command, "uproof");
    SendBytes(socket, request.Value());
    CHECK(WaitUntil([&] { return server->Stats().egress_limited == 1; }));
    std::byte rejected{};
    CHECK_EQ(::recv(socket, &rejected, 1, 0), 0);
    // Egress is reserved after lookup, but before serialization allocates a response.
    CHECK_EQ(cache->Stats().hits, 2U);
    CHECK_EQ(server->Stats().proofs_served, 1U);
    CHECK_EQ(server->Stats().response_bytes, response.payload.size() + 24U);
    ::close(socket);

    const int missing_socket{Connect(server->BoundPort())};
    Handshake(missing_socket, BitcoinNetwork::REGTEST);
    auto missing{ExampleProof(0x73, 73)};
    request_payload.assign(missing.point.block_hash.Bytes().begin(),
                           missing.point.block_hash.Bytes().end());
    request_payload.insert(request_payload.end(), {std::byte{0x07}, std::byte{0}, std::byte{0}});
    request = EncodeP2PMessage(BitcoinNetwork::REGTEST, "getuproof", request_payload);
    CHECK(request);
    SendBytes(missing_socket, request.Value());
    CHECK(WaitUntil([&] { return server->Stats().proof_misses == 1; }));
    CHECK_EQ(::recv(missing_socket, &rejected, 1, 0), 0);
    ::close(missing_socket);
}
