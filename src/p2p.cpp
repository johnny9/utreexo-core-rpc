// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/p2p.h>

#include <utreexo/hash.h>
#include <utreexo/log.h>
#include <utreexo/proof_store.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <mutex>
#include <netinet/in.h>
#include <new>
#include <optional>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unistd.h>
#include <utility>

namespace utreexo {
namespace {

constexpr std::size_t MESSAGE_HEADER_SIZE{24};
constexpr uint32_t PROTOCOL_VERSION{70016};
constexpr uint64_t NODE_UTREEXO{1ULL << 12};
constexpr uint64_t NODE_UTREEXO_ARCHIVE{1ULL << 13};
// The largest supported inbound request is getuproof's two bounded bitmaps.
// Responses may use the larger configured payload limit.
constexpr uint32_t MAX_INBOUND_MESSAGE_BYTES{256U * 1024U};
constexpr std::size_t MAX_PROOF_BITMAP_BYTES{128U * 1024U};
constexpr std::size_t MAX_LEAF_BITMAP_BYTES{4U * 1024U};
constexpr std::size_t MAX_INPUTS_PER_BLOCK{24'386};
constexpr std::size_t MAX_SCRIPT_BYTES{10'000};
constexpr uint64_t MAX_EGRESS_LIMIT{16ULL * 1024ULL * 1024ULL * 1024ULL};
constexpr uint32_t MAX_GETCFILTERS_RESULTS{1'000};
constexpr std::size_t MAX_GOSSIP_SEEDS{32};
constexpr uint64_t MAX_STATE_RESPONSE_BYTES{
    MESSAGE_HEADER_SIZE + 1 + Hash256::SIZE + 3 + sizeof(uint64_t) + 64 * Hash256::SIZE};

void EmergencyLog(std::string_view message) noexcept
{
    while (!message.empty()) {
        const ssize_t written{::write(STDERR_FILENO, message.data(), message.size())};
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return;
        message.remove_prefix(static_cast<std::size_t>(written));
    }
}

class SocketGuard
{
public:
    explicit SocketGuard(int socket) noexcept : m_socket{socket} {}
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    ~SocketGuard()
    {
        if (m_socket >= 0) ::close(m_socket);
    }

    void Release() noexcept { m_socket = -1; }

private:
    int m_socket;
};

bool SetCloseOnExec(int descriptor)
{
    int flags{-1};
    do {
        flags = ::fcntl(descriptor, F_GETFD);
    } while (flags < 0 && errno == EINTR);
    if (flags < 0) return false;
    int result{-1};
    do {
        result = ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC);
    } while (result < 0 && errno == EINTR);
    return result == 0;
}

bool ConfigureSocket(int descriptor)
{
    if (!SetCloseOnExec(descriptor)) return false;
#ifdef SO_NOSIGPIPE
    const int enabled{1};
    if (::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                     sizeof(enabled)) != 0) {
        return false;
    }
#endif
    return true;
}

#ifdef MSG_NOSIGNAL
constexpr int SEND_FLAGS{MSG_NOSIGNAL};
#else
constexpr int SEND_FLAGS{0};
#endif

std::array<std::byte, 4> NetworkMagic(BitcoinNetwork network)
{
    switch (network) {
    case BitcoinNetwork::MAINNET:
        return {std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4}, std::byte{0xd9}};
    case BitcoinNetwork::TESTNET3:
        return {std::byte{0x0b}, std::byte{0x11}, std::byte{0x09}, std::byte{0x07}};
    case BitcoinNetwork::SIGNET:
        return {std::byte{0x0a}, std::byte{0x03}, std::byte{0xcf}, std::byte{0x40}};
    case BitcoinNetwork::REGTEST:
        return {std::byte{0xfa}, std::byte{0xbf}, std::byte{0xb5}, std::byte{0xda}};
    }
    return {};
}

uint64_t AdvertisedServices(const P2PServerConfig& config)
{
    return NODE_UTREEXO | (config.advertise_archive ? NODE_UTREEXO_ARCHIVE : 0);
}

std::string EndpointText(const P2PIPv4Endpoint& endpoint)
{
    return endpoint.address + ":" + std::to_string(endpoint.port);
}

bool ParseIPv4(std::string_view text, in_addr& address)
{
    const std::string owned{text};
    return ::inet_pton(AF_INET, owned.c_str(), &address) == 1;
}

bool IsUnicastIPv4(const in_addr& address)
{
    const uint32_t host{ntohl(address.s_addr)};
    const uint8_t first{static_cast<uint8_t>(host >> 24)};
    return host != 0 && first < 224;
}

bool IsGloballyRoutableIPv4(const in_addr& address)
{
    const uint32_t host{ntohl(address.s_addr)};
    const auto in_range = [host](uint32_t network, uint32_t mask) {
        return (host & mask) == network;
    };
    if (!IsUnicastIPv4(address)) return false;
    return !in_range(0x00000000U, 0xff000000U) &&       // 0.0.0.0/8
           !in_range(0x0a000000U, 0xff000000U) &&       // RFC1918
           !in_range(0x64400000U, 0xffc00000U) &&       // RFC6598
           !in_range(0x7f000000U, 0xff000000U) &&       // loopback
           !in_range(0xa9fe0000U, 0xffff0000U) &&       // link local
           !in_range(0xac100000U, 0xfff00000U) &&       // RFC1918
           !in_range(0xc0000000U, 0xffffff00U) &&       // IETF protocol assignments
           !in_range(0xc0000200U, 0xffffff00U) &&       // TEST-NET-1
           !in_range(0xc0a80000U, 0xffff0000U) &&       // RFC1918
           !in_range(0xc6120000U, 0xfffe0000U) &&       // benchmark tests
           !in_range(0xc6336400U, 0xffffff00U) &&       // TEST-NET-2
           !in_range(0xcb007100U, 0xffffff00U) &&       // TEST-NET-3
           !in_range(0xe9fc0000U, 0xffff0000U);         // MCAST-TEST-NET
}

Hash256 NetworkGenesisHash(BitcoinNetwork network)
{
    // Bitcoin hashes are displayed with their internal/wire byte order reversed.
    // Parse the canonical display form so this compares directly with Core RPC hashes.
    switch (network) {
    case BitcoinNetwork::MAINNET:
        return Hash256::FromBitcoinHex(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").Value();
    case BitcoinNetwork::TESTNET3:
        return Hash256::FromBitcoinHex(
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943").Value();
    case BitcoinNetwork::SIGNET:
        return Hash256::FromBitcoinHex(
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6").Value();
    case BitcoinNetwork::REGTEST:
        return Hash256::FromBitcoinHex(
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206").Value();
    }
    return {};
}

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & static_cast<T>(0xffU)));
        value >>= 8;
    }
}

void AppendBE16(std::vector<std::byte>& output, uint16_t value)
{
    output.push_back(static_cast<std::byte>((value >> 8) & 0xffU));
    output.push_back(static_cast<std::byte>(value & 0xffU));
}

void AppendCompactSize(std::vector<std::byte>& output, uint64_t size)
{
    if (size < 253) {
        output.push_back(static_cast<std::byte>(size));
    } else if (size <= std::numeric_limits<uint16_t>::max()) {
        output.push_back(std::byte{253});
        AppendLE(output, static_cast<uint16_t>(size));
    } else if (size <= std::numeric_limits<uint32_t>::max()) {
        output.push_back(std::byte{254});
        AppendLE(output, static_cast<uint32_t>(size));
    } else {
        output.push_back(std::byte{255});
        AppendLE(output, size);
    }
}

uint64_t CompactSizeBytes(uint64_t value)
{
    if (value < 253) return 1;
    if (value <= std::numeric_limits<uint16_t>::max()) return 3;
    if (value <= std::numeric_limits<uint32_t>::max()) return 5;
    return 9;
}

class ByteReader
{
public:
    explicit ByteReader(std::span<const std::byte> input) : m_input{input} {}

    template <typename T>
    Result<T> ReadLE()
    {
        static_assert(std::is_unsigned_v<T>);
        if (Remaining() < sizeof(T)) return Result<T>::Err("truncated little-endian integer");
        uint64_t value{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            value |= static_cast<uint64_t>(std::to_integer<uint8_t>(m_input[m_cursor++])) << (i * 8);
        }
        return Result<T>::Ok(static_cast<T>(value));
    }

    Result<uint64_t> ReadCompactSize()
    {
        auto prefix{ReadLE<uint8_t>()};
        if (!prefix) return Result<uint64_t>::Err(prefix.Error());
        if (prefix.Value() < 253) return Result<uint64_t>::Ok(prefix.Value());
        if (prefix.Value() == 253) {
            auto value{ReadLE<uint16_t>()};
            if (!value) return Result<uint64_t>::Err(value.Error());
            if (value.Value() < 253) return Result<uint64_t>::Err("non-canonical CompactSize");
            return Result<uint64_t>::Ok(value.Value());
        }
        if (prefix.Value() == 254) {
            auto value{ReadLE<uint32_t>()};
            if (!value) return Result<uint64_t>::Err(value.Error());
            if (value.Value() <= std::numeric_limits<uint16_t>::max()) {
                return Result<uint64_t>::Err("non-canonical CompactSize");
            }
            return Result<uint64_t>::Ok(value.Value());
        }
        auto value{ReadLE<uint64_t>()};
        if (!value) return value;
        if (value.Value() <= std::numeric_limits<uint32_t>::max()) {
            return Result<uint64_t>::Err("non-canonical CompactSize");
        }
        return value;
    }

    Result<std::vector<std::byte>> ReadBytes(std::size_t size)
    {
        if (size > Remaining()) return Result<std::vector<std::byte>>::Err("truncated byte vector");
        std::vector<std::byte> output{
            m_input.begin() + static_cast<std::ptrdiff_t>(m_cursor),
            m_input.begin() + static_cast<std::ptrdiff_t>(m_cursor + size)};
        m_cursor += size;
        return Result<std::vector<std::byte>>::Ok(std::move(output));
    }

    std::size_t Remaining() const { return m_input.size() - m_cursor; }

private:
    std::span<const std::byte> m_input;
    std::size_t m_cursor{0};
};

Hash256 DoubleSha256(std::span<const std::byte> payload)
{
    const auto first{Sha256(payload)};
    return Sha256(first.Span());
}

Result<std::array<std::byte, MESSAGE_HEADER_SIZE>> EncodeP2PHeader(
    BitcoinNetwork network, std::string_view command,
    std::span<const std::byte> payload)
{
    if (command.empty() || command.size() > 12) {
        return Result<std::array<std::byte, MESSAGE_HEADER_SIZE>>::Err(
            "P2P command must contain 1 through 12 bytes");
    }
    for (const char raw_character : command) {
        const auto character{static_cast<unsigned char>(raw_character)};
        if (character < 0x20 || character > 0x7e) {
            return Result<std::array<std::byte, MESSAGE_HEADER_SIZE>>::Err(
                "P2P command contains a non-printable byte");
        }
    }
    if (payload.size() > std::numeric_limits<uint32_t>::max()) {
        return Result<std::array<std::byte, MESSAGE_HEADER_SIZE>>::Err(
            "P2P payload is too large");
    }

    std::array<std::byte, MESSAGE_HEADER_SIZE> header{};
    const auto magic{NetworkMagic(network)};
    std::copy(magic.begin(), magic.end(), header.begin());
    std::transform(command.begin(), command.end(), header.begin() + 4,
                   [](char character) {
                       return static_cast<std::byte>(static_cast<unsigned char>(character));
                   });
    const uint32_t size{static_cast<uint32_t>(payload.size())};
    for (std::size_t index{0}; index < sizeof(size); ++index) {
        header[16 + index] = static_cast<std::byte>((size >> (8 * index)) & 0xffU);
    }
    const auto checksum{DoubleSha256(payload)};
    std::copy_n(checksum.Bytes().begin(), 4, header.begin() + 20);
    return Result<std::array<std::byte, MESSAGE_HEADER_SIZE>>::Ok(header);
}

bool BitmapBit(std::span<const std::byte> bitmap, std::size_t index)
{
    const std::size_t byte_index{index / 8};
    if (byte_index >= bitmap.size()) return false;
    return (std::to_integer<uint8_t>(bitmap[byte_index]) & (1U << (index % 8))) != 0;
}

std::string Quoted(std::string_view value)
{
    std::ostringstream output;
    output << std::quoted(std::string{value});
    return output.str();
}

uint64_t ProofBytes(const Proof& proof, std::span<const CompactLeafData> leaves)
{
    uint64_t bytes{sizeof(CachedBlockProof)};
    const auto add = [&bytes](uint64_t amount) {
        bytes = amount > std::numeric_limits<uint64_t>::max() - bytes ?
                    std::numeric_limits<uint64_t>::max() : bytes + amount;
    };
    const auto add_product = [&add](std::size_t count, std::size_t item_size) {
        if (count > std::numeric_limits<uint64_t>::max() / item_size) {
            add(std::numeric_limits<uint64_t>::max());
        } else {
            add(static_cast<uint64_t>(count) * item_size);
        }
    };
    add_product(proof.targets.size(), sizeof(uint64_t));
    add_product(proof.hashes.size(), sizeof(Hash256));
    add_product(leaves.size(), sizeof(CompactLeafData));
    for (const auto& leaf : leaves) add(leaf.script.size());
    return bytes;
}

uint64_t ProofBytes(const CachedBlockProof& proof)
{
    return ProofBytes(proof.proof, proof.leaves);
}

Result<void> ReadExactUntil(int socket, std::span<std::byte> output,
                            std::chrono::steady_clock::time_point deadline)
{
    std::size_t received{0};
    while (received < output.size()) {
        const auto now{std::chrono::steady_clock::now()};
        if (now >= deadline) return Result<void>::Err("P2P message read timed out");
        const auto remaining{std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)};
        pollfd descriptor{.fd = socket, .events = POLLIN, .revents = 0};
        const int ready{::poll(
            &descriptor, 1, static_cast<int>(std::max<int64_t>(1, remaining.count())))};
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) return Result<void>::Err("P2P message read timed out");
        if (ready < 0) {
            return Result<void>::Err("P2P read poll failed: " +
                                     std::string{std::strerror(errno)});
        }
        const ssize_t result{::recv(socket, output.data() + received,
                                    output.size() - received, MSG_DONTWAIT)};
        if (result == 0) return Result<void>::Err("P2P peer closed connection");
        if (result < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return Result<void>::Err("P2P read failed: " +
                                     std::string{std::strerror(errno)});
        }
        received += static_cast<std::size_t>(result);
    }
    return Result<void>::Ok();
}

Result<void> SendAllUntil(int socket, std::span<const std::byte> data,
                          std::chrono::steady_clock::time_point deadline)
{
    std::size_t sent{0};
    while (sent < data.size()) {
        const auto now{std::chrono::steady_clock::now()};
        if (now >= deadline) return Result<void>::Err("P2P message write timed out");
        const auto remaining{
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)};
        pollfd descriptor{.fd = socket, .events = POLLOUT, .revents = 0};
        const int ready{::poll(
            &descriptor, 1, static_cast<int>(std::max<int64_t>(1, remaining.count())))};
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) return Result<void>::Err("P2P message write timed out");
        if (ready < 0) {
            return Result<void>::Err("P2P write poll failed: " +
                                     std::string{std::strerror(errno)});
        }
        const ssize_t result{::send(socket, data.data() + sent, data.size() - sent,
                                    SEND_FLAGS | MSG_DONTWAIT)};
        if (result < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return Result<void>::Err("socket write failed: " + std::string{std::strerror(errno)});
        }
        if (result == 0) return Result<void>::Err("socket write made no progress");
        sent += static_cast<std::size_t>(result);
    }
    return Result<void>::Ok();
}

Result<P2PMessage> ReadMessageUntil(int socket, BitcoinNetwork network, uint32_t max_payload,
                                    std::chrono::steady_clock::time_point deadline,
                                    uint64_t* inbound_bytes_remaining = nullptr)
{
    std::array<std::byte, MESSAGE_HEADER_SIZE> header{};
    auto read{ReadExactUntil(socket, header, deadline)};
    if (!read) return Result<P2PMessage>::Err(read.Error());
    const auto magic{NetworkMagic(network)};
    if (!std::equal(magic.begin(), magic.end(), header.begin())) {
        return Result<P2PMessage>::Err("wrong P2P network magic");
    }
    const uint32_t length{
        std::to_integer<uint8_t>(header[16]) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[17])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[18])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[19])) << 24)};
    if (length > max_payload) {
        return Result<P2PMessage>::Err("P2P payload exceeds configured maximum");
    }
    const uint64_t wire_bytes{MESSAGE_HEADER_SIZE + static_cast<uint64_t>(length)};
    if (inbound_bytes_remaining != nullptr) {
        if (wire_bytes > *inbound_bytes_remaining) {
            return Result<P2PMessage>::Err("P2P inbound byte rate limit exceeded");
        }
        *inbound_bytes_remaining -= wire_bytes;
    }
    std::vector<std::byte> wire{header.begin(), header.end()};
    wire.resize(MESSAGE_HEADER_SIZE + length);
    read = ReadExactUntil(socket, std::span<std::byte>{wire}.subspan(MESSAGE_HEADER_SIZE), deadline);
    if (!read) return Result<P2PMessage>::Err(read.Error());
    return DecodeP2PMessage(network, wire, max_payload);
}

Result<void> SendMessageUntil(int socket, BitcoinNetwork network, std::string_view command,
                              std::span<const std::byte> payload,
                              std::chrono::steady_clock::time_point deadline)
{
    auto header{EncodeP2PHeader(network, command, payload)};
    if (!header) return Result<void>::Err(header.Error());
    auto sent{SendAllUntil(socket, header.Value(), deadline)};
    if (!sent) return sent;
    return SendAllUntil(socket, payload, deadline);
}

std::array<std::byte, 4> IPv4Bytes(const in_addr& address)
{
    std::array<std::byte, 4> bytes{};
    static_assert(sizeof(address.s_addr) == bytes.size());
    std::memcpy(bytes.data(), &address.s_addr, bytes.size());
    return bytes;
}

std::vector<std::byte> AdvertisedAddressPayload(const P2PServerConfig& config,
                                                bool addrv2)
{
    if (!config.advertised_endpoint) return {std::byte{0}};
    in_addr address{};
    // Start() validates this before any peer thread can call this helper.
    static_cast<void>(ParseIPv4(config.advertised_endpoint->address, address));
    const auto address_bytes{IPv4Bytes(address)};
    const uint64_t services{AdvertisedServices(config)};
    const auto now{std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
    const uint32_t timestamp{now <= 0 ? 0U : static_cast<uint32_t>(
        std::min<uint64_t>(static_cast<uint64_t>(now),
                           std::numeric_limits<uint32_t>::max()))};

    std::vector<std::byte> output;
    output.reserve(32);
    AppendCompactSize(output, 1);
    AppendLE(output, timestamp);
    if (addrv2) {
        // BIP155: CompactSize services, IPv4 network ID, four address bytes, BE port.
        AppendCompactSize(output, services);
        output.push_back(std::byte{1});
        AppendCompactSize(output, address_bytes.size());
        output.insert(output.end(), address_bytes.begin(), address_bytes.end());
    } else {
        AppendLE(output, services);
        output.insert(output.end(), 10, std::byte{0});
        output.push_back(std::byte{0xff});
        output.push_back(std::byte{0xff});
        output.insert(output.end(), address_bytes.begin(), address_bytes.end());
    }
    AppendBE16(output, config.advertised_endpoint->port);
    return output;
}

std::vector<std::byte> VersionPayload(const P2PServerConfig& config, uint32_t height,
                                      uint16_t peer_port)
{
    const uint64_t services{AdvertisedServices(config)};
    std::vector<std::byte> output;
    output.reserve(128);
    AppendLE(output, PROTOCOL_VERSION);
    AppendLE(output, services);
    const auto now{std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
    AppendLE(output, static_cast<uint64_t>(now));

    const auto append_address = [&](uint64_t address_services, uint16_t port) {
        AppendLE(output, address_services);
        output.insert(output.end(), 10, std::byte{0});
        output.push_back(std::byte{0xff});
        output.push_back(std::byte{0xff});
        output.insert(output.end(), 4, std::byte{0});
        AppendBE16(output, port);
    };
    append_address(0, peer_port);
    append_address(services, config.advertised_endpoint ?
        config.advertised_endpoint->port : config.port);
    const uint64_t nonce{static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^
                         static_cast<uint64_t>(::getpid())};
    AppendLE(output, nonce);
    AppendCompactSize(output, config.user_agent.size());
    for (const char character : config.user_agent) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    AppendLE(output, height);
    output.push_back(std::byte{0}); // No transaction relay.
    return output;
}

bool ValidVersionPayload(std::span<const std::byte> payload)
{
    // version, services, timestamp, two net addresses, nonce, and user-agent length.
    if (payload.size() < 86) return false;
    ByteReader reader{payload.subspan(80)};
    auto user_agent_size{reader.ReadCompactSize()};
    return user_agent_size && user_agent_size.Value() <= 256 &&
           user_agent_size.Value() <= reader.Remaining() &&
           reader.Remaining() - user_agent_size.Value() >= sizeof(uint32_t);
}

std::optional<uint64_t> VersionServices(std::span<const std::byte> payload)
{
    if (!ValidVersionPayload(payload)) return std::nullopt;
    uint64_t services{0};
    for (std::size_t i{0}; i < sizeof(services); ++i) {
        services |= static_cast<uint64_t>(
            std::to_integer<uint8_t>(payload[sizeof(uint32_t) + i])) << (i * 8);
    }
    return services;
}

struct GetUtreexoStateRequest {
    uint32_t start_height{0};
    Hash256 stop_hash;
};

Result<GetUtreexoStateRequest> ParseGetUtreexoStateRequest(
    std::span<const std::byte> payload)
{
    ByteReader reader{payload};
    auto filter_type{reader.ReadLE<uint8_t>()};
    auto start_height{reader.ReadLE<uint32_t>()};
    auto stop_bytes{reader.ReadBytes(Hash256::SIZE)};
    if (!filter_type || !start_height || !stop_bytes || reader.Remaining() != 0) {
        return Result<GetUtreexoStateRequest>::Err("malformed getcfilters request");
    }
    if (filter_type.Value() != 1) {
        return Result<GetUtreexoStateRequest>::Err(
            "getcfilters request is not for a Utreexo state");
    }
    Hash256::Storage stop_hash{};
    std::copy(stop_bytes.Value().begin(), stop_bytes.Value().end(), stop_hash.begin());
    return Result<GetUtreexoStateRequest>::Ok(GetUtreexoStateRequest{
        .start_height = start_height.Value(),
        .stop_hash = Hash256{stop_hash},
    });
}

Result<std::vector<std::byte>> SerializeUtreexoStateFilter(
    const AccumulatorState& state)
{
    if (state.roots.size() > 64 ||
        state.roots.size() != static_cast<std::size_t>(std::popcount(state.num_leaves))) {
        return Result<std::vector<std::byte>>::Err("archived accumulator state is invalid");
    }
    const uint64_t state_bytes{sizeof(uint64_t) + state.roots.size() * Hash256::SIZE};
    std::vector<std::byte> output;
    output.reserve(1 + Hash256::SIZE + 3 + static_cast<std::size_t>(state_bytes));
    output.push_back(std::byte{1});
    output.insert(output.end(), state.point.block_hash.Bytes().begin(),
                  state.point.block_hash.Bytes().end());
    AppendCompactSize(output, state_bytes);
    AppendLE(output, state.num_leaves);
    for (const auto& root : state.roots) {
        output.insert(output.end(), root.Bytes().begin(), root.Bytes().end());
    }
    return Result<std::vector<std::byte>>::Ok(std::move(output));
}

uint16_t PeerPort(const sockaddr_in& address)
{
    return ntohs(address.sin_port);
}

std::string PeerAddress(const sockaddr_in& address)
{
    std::array<char, INET_ADDRSTRLEN> text{};
    if (::inet_ntop(AF_INET, &address.sin_addr, text.data(), text.size()) == nullptr) {
        return "unknown";
    }
    return text.data();
}

} // namespace

Result<BitcoinNetwork> ParseBitcoinNetwork(std::string_view value)
{
    if (value == "main" || value == "mainnet") return Result<BitcoinNetwork>::Ok(BitcoinNetwork::MAINNET);
    if (value == "test" || value == "testnet" || value == "testnet3") {
        return Result<BitcoinNetwork>::Ok(BitcoinNetwork::TESTNET3);
    }
    if (value == "signet") return Result<BitcoinNetwork>::Ok(BitcoinNetwork::SIGNET);
    if (value == "regtest") return Result<BitcoinNetwork>::Ok(BitcoinNetwork::REGTEST);
    return Result<BitcoinNetwork>::Err("invalid P2P network (expected mainnet, testnet3, signet, or regtest)");
}

Hash256 BitcoinNetworkGenesisHash(BitcoinNetwork network)
{
    return NetworkGenesisHash(network);
}

Result<P2PIPv4Endpoint> ParseP2PIPv4Endpoint(std::string_view value)
{
    const auto separator{value.find(':')};
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 == value.size() || value.find(':', separator + 1) != std::string_view::npos) {
        return Result<P2PIPv4Endpoint>::Err(
            "P2P endpoint must use numeric IPv4:port syntax");
    }
    const auto address_text{value.substr(0, separator)};
    in_addr address{};
    if (!ParseIPv4(address_text, address)) {
        return Result<P2PIPv4Endpoint>::Err("P2P endpoint address is not numeric IPv4");
    }
    uint32_t port{0};
    const auto port_text{value.substr(separator + 1)};
    const auto parsed{std::from_chars(port_text.data(), port_text.data() + port_text.size(), port)};
    if (parsed.ec != std::errc{} || parsed.ptr != port_text.data() + port_text.size() ||
        port == 0 || port > std::numeric_limits<uint16_t>::max()) {
        return Result<P2PIPv4Endpoint>::Err("P2P endpoint port must be between 1 and 65535");
    }
    std::array<char, INET_ADDRSTRLEN> canonical{};
    if (::inet_ntop(AF_INET, &address, canonical.data(), canonical.size()) == nullptr) {
        return Result<P2PIPv4Endpoint>::Err("could not format numeric P2P endpoint");
    }
    return Result<P2PIPv4Endpoint>::Ok(P2PIPv4Endpoint{
        .address = canonical.data(),
        .port = static_cast<uint16_t>(port),
    });
}

Result<std::vector<std::byte>> EncodeP2PMessage(BitcoinNetwork network,
                                                std::string_view command,
                                                std::span<const std::byte> payload)
{
    auto header{EncodeP2PHeader(network, command, payload)};
    if (!header) return Result<std::vector<std::byte>>::Err(header.Error());
    std::vector<std::byte> output;
    output.reserve(MESSAGE_HEADER_SIZE + payload.size());
    output.insert(output.end(), header.Value().begin(), header.Value().end());
    output.insert(output.end(), payload.begin(), payload.end());
    return Result<std::vector<std::byte>>::Ok(std::move(output));
}

Result<P2PMessage> DecodeP2PMessage(BitcoinNetwork network,
                                    std::span<const std::byte> message,
                                    uint32_t max_payload_bytes)
{
    if (message.size() < MESSAGE_HEADER_SIZE) return Result<P2PMessage>::Err("truncated P2P header");
    const auto magic{NetworkMagic(network)};
    if (!std::equal(magic.begin(), magic.end(), message.begin())) {
        return Result<P2PMessage>::Err("wrong P2P network magic");
    }
    std::string command;
    bool padded{false};
    for (std::size_t i{4}; i < 16; ++i) {
        const uint8_t character{std::to_integer<uint8_t>(message[i])};
        if (character == 0) {
            padded = true;
            continue;
        }
        if (padded || character < 0x20 || character > 0x7e) {
            return Result<P2PMessage>::Err("invalid P2P command padding");
        }
        command.push_back(static_cast<char>(character));
    }
    if (command.empty()) return Result<P2PMessage>::Err("empty P2P command");
    const uint32_t length{
        std::to_integer<uint8_t>(message[16]) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(message[17])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(message[18])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(message[19])) << 24)};
    if (length > max_payload_bytes) return Result<P2PMessage>::Err("P2P payload exceeds configured maximum");
    if (message.size() != MESSAGE_HEADER_SIZE + length) {
        return Result<P2PMessage>::Err("P2P message length does not match its header");
    }
    const auto payload{message.subspan(MESSAGE_HEADER_SIZE)};
    const auto checksum{DoubleSha256(payload)};
    if (!std::equal(checksum.Bytes().begin(), checksum.Bytes().begin() + 4, message.begin() + 20)) {
        return Result<P2PMessage>::Err("P2P payload checksum mismatch");
    }
    return Result<P2PMessage>::Ok(P2PMessage{
        .command = std::move(command),
        .payload = std::vector<std::byte>{payload.begin(), payload.end()},
    });
}

Result<GetUtreexoProofRequest> ParseGetUtreexoProof(std::span<const std::byte> payload)
{
    ByteReader reader{payload};
    auto hash_bytes{reader.ReadBytes(Hash256::SIZE)};
    if (!hash_bytes) return Result<GetUtreexoProofRequest>::Err("truncated getuproof block hash");
    Hash256::Storage hash{};
    std::copy(hash_bytes.Value().begin(), hash_bytes.Value().end(), hash.begin());
    auto request_bitmap{reader.ReadLE<uint8_t>()};
    if (!request_bitmap) return Result<GetUtreexoProofRequest>::Err("truncated getuproof request bitmap");
    if ((request_bitmap.Value() & 0xf8U) != 0) {
        return Result<GetUtreexoProofRequest>::Err("getuproof has unknown request bits");
    }
    auto proof_size{reader.ReadCompactSize()};
    if (!proof_size || proof_size.Value() > MAX_PROOF_BITMAP_BYTES) {
        return Result<GetUtreexoProofRequest>::Err("invalid getuproof proof bitmap size");
    }
    auto proof_indexes{reader.ReadBytes(static_cast<std::size_t>(proof_size.Value()))};
    if (!proof_indexes) return Result<GetUtreexoProofRequest>::Err(proof_indexes.Error());
    auto leaf_size{reader.ReadCompactSize()};
    if (!leaf_size || leaf_size.Value() > MAX_LEAF_BITMAP_BYTES) {
        return Result<GetUtreexoProofRequest>::Err("invalid getuproof leaf bitmap size");
    }
    auto leaf_indexes{reader.ReadBytes(static_cast<std::size_t>(leaf_size.Value()))};
    if (!leaf_indexes) return Result<GetUtreexoProofRequest>::Err(leaf_indexes.Error());
    if (reader.Remaining() != 0) return Result<GetUtreexoProofRequest>::Err("trailing getuproof bytes");
    return Result<GetUtreexoProofRequest>::Ok(GetUtreexoProofRequest{
        .block_hash = Hash256{hash},
        .request_bitmap = request_bitmap.Value(),
        .proof_indexes = proof_indexes.Take(),
        .leaf_indexes = leaf_indexes.Take(),
    });
}

namespace {

struct UtreexoProofLayout {
    uint64_t payload_bytes{0};
    uint64_t hash_count{0};
    uint64_t target_count{0};
    uint64_t leaf_count{0};
    bool all_hashes{false};
    bool targets_requested{false};
    bool all_leaves{false};
};

Result<UtreexoProofLayout> MeasureUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request,
    uint64_t max_payload_bytes)
{
    if (proof.point.block_hash != request.block_hash) {
        return Result<UtreexoProofLayout>::Err(
            "getuproof block hash does not match cached proof");
    }
    if (proof.proof.targets.size() != proof.leaves.size() ||
        proof.leaves.size() > MAX_INPUTS_PER_BLOCK) {
        return Result<UtreexoProofLayout>::Err(
            "cached proof target/leaf counts are invalid");
    }

    UtreexoProofLayout layout;
    layout.all_hashes = (request.request_bitmap & (1U << 1)) != 0;
    for (std::size_t i{0}; i < proof.proof.hashes.size(); ++i) {
        if (layout.all_hashes || BitmapBit(request.proof_indexes, i)) {
            ++layout.hash_count;
        }
    }

    layout.targets_requested = (request.request_bitmap & 1U) != 0;
    layout.target_count = layout.targets_requested ?
        static_cast<uint64_t>(proof.proof.targets.size()) : 0;
    layout.all_leaves = (request.request_bitmap & (1U << 2)) != 0;
    for (std::size_t i{0}; i < proof.leaves.size(); ++i) {
        if (layout.all_leaves || BitmapBit(request.leaf_indexes, i)) {
            ++layout.leaf_count;
        }
    }

    const auto add_bytes = [&](uint64_t bytes) {
        if (layout.payload_bytes > max_payload_bytes ||
            bytes > max_payload_bytes - layout.payload_bytes) {
            return false;
        }
        layout.payload_bytes += bytes;
        return true;
    };
    const auto fail_oversized = [] {
        return Result<UtreexoProofLayout>::Err(
            "uproof response exceeds configured maximum");
    };
    if (!add_bytes(Hash256::SIZE) ||
        !add_bytes(CompactSizeBytes(layout.hash_count)) ||
        layout.hash_count > std::numeric_limits<uint64_t>::max() / Hash256::SIZE ||
        !add_bytes(layout.hash_count * Hash256::SIZE) ||
        !add_bytes(CompactSizeBytes(layout.target_count))) {
        return fail_oversized();
    }
    if (layout.targets_requested) {
        for (const uint64_t target : proof.proof.targets) {
            if (!add_bytes(CompactSizeBytes(target))) return fail_oversized();
        }
    }
    if (!add_bytes(CompactSizeBytes(layout.leaf_count))) return fail_oversized();
    for (std::size_t index{0}; index < proof.leaves.size(); ++index) {
        if (!layout.all_leaves && !BitmapBit(request.leaf_indexes, index)) continue;
        const auto& leaf{proof.leaves[index]};
        if (static_cast<uint8_t>(leaf.script_type) >
            static_cast<uint8_t>(ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH)) {
            return Result<UtreexoProofLayout>::Err(
                "cached compact leaf has an unknown script type");
        }
        if (leaf.script_type == ScriptPubkeyType::OTHER &&
            leaf.script.size() > MAX_SCRIPT_BYTES) {
            return Result<UtreexoProofLayout>::Err(
                "cached compact leaf script is too large");
        }
        if (leaf.script_type != ScriptPubkeyType::OTHER && !leaf.script.empty()) {
            return Result<UtreexoProofLayout>::Err(
                "standard compact leaf unexpectedly contains a script");
        }
        if (!add_bytes(sizeof(leaf.header_code) + sizeof(leaf.amount) + sizeof(uint8_t))) {
            return fail_oversized();
        }
        if (leaf.script_type == ScriptPubkeyType::OTHER &&
            (!add_bytes(CompactSizeBytes(leaf.script.size())) ||
             !add_bytes(leaf.script.size()))) {
            return fail_oversized();
        }
    }
    if (layout.payload_bytes > std::numeric_limits<std::size_t>::max()) {
        return fail_oversized();
    }
    return Result<UtreexoProofLayout>::Ok(layout);
}

Result<std::vector<std::byte>> SerializeUtreexoProofWithLayout(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request,
    const UtreexoProofLayout& layout)
{
    std::vector<std::byte> output;
    output.reserve(static_cast<std::size_t>(layout.payload_bytes));
    output.insert(output.end(), proof.point.block_hash.Bytes().begin(),
                  proof.point.block_hash.Bytes().end());
    AppendCompactSize(output, layout.hash_count);
    for (std::size_t index{0}; index < proof.proof.hashes.size(); ++index) {
        if (!layout.all_hashes && !BitmapBit(request.proof_indexes, index)) continue;
        const auto& hash{proof.proof.hashes[index]};
        output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
    }
    AppendCompactSize(output, layout.target_count);
    if (layout.targets_requested) {
        for (const uint64_t target : proof.proof.targets) AppendCompactSize(output, target);
    }
    AppendCompactSize(output, layout.leaf_count);
    for (std::size_t index{0}; index < proof.leaves.size(); ++index) {
        if (!layout.all_leaves && !BitmapBit(request.leaf_indexes, index)) continue;
        const auto& leaf{proof.leaves[index]};
        AppendLE(output, leaf.header_code);
        AppendLE(output, leaf.amount);
        output.push_back(static_cast<std::byte>(leaf.script_type));
        if (leaf.script_type == ScriptPubkeyType::OTHER) {
            AppendCompactSize(output, leaf.script.size());
            output.insert(output.end(), leaf.script.begin(), leaf.script.end());
        }
    }
    if (output.size() != layout.payload_bytes) {
        return Result<std::vector<std::byte>>::Err(
            "internal uproof serialized-size mismatch");
    }
    return Result<std::vector<std::byte>>::Ok(std::move(output));
}

} // namespace

Result<std::vector<std::byte>> SerializeUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request,
    uint64_t max_payload_bytes)
{
    auto layout{MeasureUtreexoProof(proof, request, max_payload_bytes)};
    if (!layout) return Result<std::vector<std::byte>>::Err(layout.Error());
    return SerializeUtreexoProofWithLayout(proof, request, layout.Value());
}

Result<std::vector<std::byte>> SerializeUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request)
{
    return SerializeUtreexoProof(proof, request,
                                 std::numeric_limits<uint64_t>::max());
}

Result<CachedBlockProof> ParseFullUtreexoProof(uint32_t height,
                                              std::span<const std::byte> payload)
{
    ByteReader reader{payload};
    auto block_bytes{reader.ReadBytes(Hash256::SIZE)};
    if (!block_bytes) return Result<CachedBlockProof>::Err("truncated uproof block hash");
    Hash256::Storage block_hash{};
    std::copy(block_bytes.Value().begin(), block_bytes.Value().end(), block_hash.begin());

    auto hash_count{reader.ReadCompactSize()};
    if (!hash_count || hash_count.Value() > reader.Remaining() / Hash256::SIZE) {
        return Result<CachedBlockProof>::Err("invalid uproof hash count");
    }
    std::vector<Hash256> hashes;
    hashes.reserve(static_cast<std::size_t>(hash_count.Value()));
    for (uint64_t i{0}; i < hash_count.Value(); ++i) {
        auto bytes{reader.ReadBytes(Hash256::SIZE)};
        if (!bytes) return Result<CachedBlockProof>::Err("truncated uproof hash");
        Hash256::Storage hash{};
        std::copy(bytes.Value().begin(), bytes.Value().end(), hash.begin());
        hashes.emplace_back(hash);
    }

    auto target_count{reader.ReadCompactSize()};
    if (!target_count || target_count.Value() > MAX_INPUTS_PER_BLOCK) {
        return Result<CachedBlockProof>::Err("invalid uproof target count");
    }
    std::vector<uint64_t> targets;
    targets.reserve(static_cast<std::size_t>(target_count.Value()));
    for (uint64_t i{0}; i < target_count.Value(); ++i) {
        auto target{reader.ReadCompactSize()};
        if (!target) return Result<CachedBlockProof>::Err("invalid uproof target");
        targets.push_back(target.Value());
    }

    auto leaf_count{reader.ReadCompactSize()};
    if (!leaf_count || leaf_count.Value() != target_count.Value()) {
        return Result<CachedBlockProof>::Err("uproof leaf count does not match targets");
    }
    std::vector<CompactLeafData> leaves;
    leaves.reserve(static_cast<std::size_t>(leaf_count.Value()));
    for (uint64_t i{0}; i < leaf_count.Value(); ++i) {
        auto header_code{reader.ReadLE<uint32_t>()};
        auto amount{reader.ReadLE<uint64_t>()};
        auto type{reader.ReadLE<uint8_t>()};
        if (!header_code || !amount || !type ||
            type.Value() > static_cast<uint8_t>(ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH)) {
            return Result<CachedBlockProof>::Err("invalid compact leaf in uproof");
        }
        CompactLeafData leaf{
            .header_code = header_code.Value(),
            .amount = amount.Value(),
            .script_type = static_cast<ScriptPubkeyType>(type.Value()),
            .script = {},
        };
        if (leaf.script_type == ScriptPubkeyType::OTHER) {
            auto script_size{reader.ReadCompactSize()};
            if (!script_size || script_size.Value() > MAX_SCRIPT_BYTES) {
                return Result<CachedBlockProof>::Err("invalid compact leaf script size");
            }
            auto script{reader.ReadBytes(static_cast<std::size_t>(script_size.Value()))};
            if (!script) return Result<CachedBlockProof>::Err("truncated compact leaf script");
            leaf.script = script.Take();
        }
        leaves.push_back(std::move(leaf));
    }
    if (reader.Remaining() != 0) return Result<CachedBlockProof>::Err("trailing uproof bytes");
    return Result<CachedBlockProof>::Ok(CachedBlockProof{
        .point = ChainPoint{height, Hash256{block_hash}},
        .proof = Proof{std::move(targets), std::move(hashes)},
        .leaves = std::move(leaves),
    });
}

class RecentProofCache::Impl
{
public:
    Impl(uint32_t block_limit, uint64_t byte_limit)
        : max_blocks{block_limit}, max_bytes{byte_limit}
    {
    }

    uint32_t max_blocks;
    uint64_t max_bytes;
    mutable std::mutex mutex;
    mutable std::condition_variable published;
    std::deque<Hash256> order;
    std::unordered_map<Hash256, std::shared_ptr<const CachedBlockProof>, Hash256Hasher> entries;
    uint64_t bytes{0};
    mutable uint64_t hits{0};
    mutable uint64_t misses{0};
    uint64_t oversized_skips{0};
    uint32_t tip_height{0};
};

RecentProofCache::RecentProofCache(uint32_t max_blocks, uint64_t max_bytes)
    : m_impl{std::make_unique<Impl>(max_blocks, max_bytes)}
{
}

RecentProofCache::~RecentProofCache() = default;

Result<void> RecentProofCache::Publish(const BlockDelta& delta, Proof proof)
{
    try {
        if (proof.targets.size() != delta.deletions.size() ||
            delta.proof_leaves.size() != delta.deletions.size()) {
            return Result<void>::Err("block proof does not align with its deletion leaves");
        }
        const uint64_t record_bytes{ProofBytes(proof, delta.proof_leaves)};
        if (record_bytes > m_impl->max_bytes) {
            {
                std::lock_guard lock{m_impl->mutex};
                m_impl->tip_height = delta.point.height;
                ++m_impl->oversized_skips;
            }
            // The cache is deliberately disposable. An archive-backed server can
            // serve this proof from disk, and a cache-only server should remain
            // healthy even when one consensus-valid block exceeds its RAM budget.
            m_impl->published.notify_all();
            return Result<void>::Ok();
        }
        auto record{std::make_shared<CachedBlockProof>(CachedBlockProof{
            .point = delta.point,
            .proof = std::move(proof),
            .leaves = delta.proof_leaves,
        })};
        {
            std::lock_guard lock{m_impl->mutex};
            if (const auto existing{m_impl->entries.find(delta.point.block_hash)};
                existing != m_impl->entries.end()) {
                m_impl->order.push_back(delta.point.block_hash);
                auto newest{m_impl->order.end()};
                --newest;
                const auto old_order{std::find(m_impl->order.begin(), newest,
                                               delta.point.block_hash)};
                if (old_order != newest) m_impl->order.erase(old_order);
                m_impl->bytes -= ProofBytes(*existing->second);
                existing->second = std::move(record);
                m_impl->bytes += record_bytes;
            } else {
                const auto [inserted, was_inserted]{
                    m_impl->entries.emplace(delta.point.block_hash, record)};
                if (!was_inserted) return Result<void>::Err("proof-cache insertion conflict");
                try {
                    m_impl->order.push_back(delta.point.block_hash);
                } catch (...) {
                    m_impl->entries.erase(inserted);
                    throw;
                }
                m_impl->bytes += record_bytes;
            }
            m_impl->tip_height = delta.point.height;
            while (!m_impl->order.empty() &&
                   (m_impl->entries.size() > m_impl->max_blocks ||
                    m_impl->bytes > m_impl->max_bytes)) {
                const auto oldest{m_impl->order.front()};
                m_impl->order.pop_front();
                const auto entry{m_impl->entries.find(oldest)};
                if (entry == m_impl->entries.end()) continue;
                m_impl->bytes -= ProofBytes(*entry->second);
                m_impl->entries.erase(entry);
            }
        }
        m_impl->published.notify_all();
        return Result<void>::Ok();
    } catch (const std::bad_alloc&) {
        return Result<void>::Err("proof cache allocation failed");
    } catch (const std::exception& exception) {
        return Result<void>::Err("proof cache update failed: " + std::string{exception.what()});
    }
}

std::shared_ptr<const CachedBlockProof> RecentProofCache::Find(const Hash256& block_hash) const
{
    std::lock_guard lock{m_impl->mutex};
    const auto entry{m_impl->entries.find(block_hash)};
    if (entry == m_impl->entries.end()) {
        ++m_impl->misses;
        return {};
    }
    ++m_impl->hits;
    return entry->second;
}

std::shared_ptr<const CachedBlockProof> RecentProofCache::WaitFor(
    const Hash256& block_hash, std::chrono::milliseconds timeout,
    const std::atomic<bool>* cancelled) const
{
    std::unique_lock lock{m_impl->mutex};
    const auto available{[&] {
        return m_impl->entries.contains(block_hash) ||
               (cancelled != nullptr && cancelled->load());
    }};
    if (!m_impl->published.wait_for(lock, timeout, available)) {
        ++m_impl->misses;
        return {};
    }
    if (cancelled != nullptr && cancelled->load()) return {};
    ++m_impl->hits;
    return m_impl->entries.find(block_hash)->second;
}

void RecentProofCache::NotifyWaiters() const
{
    // Serialize with WaitFor's predicate-to-wait transition. Cancellation lives
    // outside this cache, so notifying without briefly taking the predicate mutex
    // could lose the wake and delay shutdown for the full proof wait timeout.
    {
        std::lock_guard lock{m_impl->mutex};
    }
    m_impl->published.notify_all();
}

void RecentProofCache::DiscardAfter(uint32_t height)
{
    std::lock_guard lock{m_impl->mutex};
    for (auto iterator{m_impl->order.begin()}; iterator != m_impl->order.end();) {
        const auto entry{m_impl->entries.find(*iterator)};
        if (entry != m_impl->entries.end() && entry->second->point.height > height) {
            m_impl->bytes -= ProofBytes(*entry->second);
            m_impl->entries.erase(entry);
            iterator = m_impl->order.erase(iterator);
        } else {
            ++iterator;
        }
    }
    m_impl->tip_height = height;
}

void RecentProofCache::SetTip(uint32_t height)
{
    std::lock_guard lock{m_impl->mutex};
    m_impl->tip_height = height;
}

ProofCacheStats RecentProofCache::Stats() const
{
    std::lock_guard lock{m_impl->mutex};
    return ProofCacheStats{
        .entries = m_impl->entries.size(),
        .bytes = m_impl->bytes,
        .hits = m_impl->hits,
        .misses = m_impl->misses,
        .oversized_skips = m_impl->oversized_skips,
        .tip_height = m_impl->tip_height,
    };
}

class P2PServer::Impl
{
public:
    struct ClientWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    Impl(P2PServerConfig server_config, std::shared_ptr<RecentProofCache> proof_cache,
         std::shared_ptr<ProofStore> proof_store, int listener_socket, uint16_t actual_port)
        : config{std::move(server_config)}, cache{std::move(proof_cache)},
          store{std::move(proof_store)}, listener{listener_socket}, bound_port{actual_port},
          egress_tokens{static_cast<long double>(config.egress_burst_bytes)},
          egress_updated{std::chrono::steady_clock::now()}
    {
        client_sockets.reserve(config.max_peers);
        client_workers.reserve(config.max_peers);
        active_peers_by_ip.reserve(config.max_peers);
    }

    void RequestStop()
    {
        // Publish cancellation while holding the same mutex used by GossipLoop's
        // predicate-to-wait transition. NotifyWaiters provides the equivalent
        // serialization for proof-cache waits.
        {
            std::lock_guard lock{gossip_wait_mutex};
            stopping.store(true);
        }
        cache->NotifyWaiters();
        gossip_wakeup.notify_all();
    }

    ~Impl() noexcept
    {
        RequestStop();
        InterruptCurrentGossipSocket();
        if (listener >= 0) {
            ::shutdown(listener, SHUT_RDWR);
            ::close(listener);
        }
        if (accept_thread.joinable()) accept_thread.join();
        if (gossip_thread.joinable()) gossip_thread.join();
        listener = -1;
        {
            std::lock_guard lock{clients_mutex};
            for (const int socket : client_sockets) ::shutdown(socket, SHUT_RDWR);
        }
        for (auto& worker : client_workers) {
            if (worker.thread.joinable()) worker.thread.join();
        }
        {
            std::lock_guard lock{clients_mutex};
            for (const int socket : client_sockets) ::close(socket);
            client_sockets.clear();
            active_peers_by_ip.clear();
            active_peers.store(0);
        }
        try {
            const auto stats{Stats()};
            Log(LogLevel::INFO, "p2p_server_stopped",
                "accepted_peers=" + std::to_string(stats.accepted_peers) +
                " rejected_max_peers=" + std::to_string(stats.rejected_max_peers) +
                " rejected_per_ip=" + std::to_string(stats.rejected_per_ip) +
                " inbound_limited=" + std::to_string(stats.inbound_limited) +
                " peak_active_peers=" + std::to_string(stats.peak_active_peers) +
                " proof_requests=" + std::to_string(stats.proof_requests) +
                " proof_busy=" + std::to_string(stats.proof_busy) +
                " proof_misses=" + std::to_string(stats.proof_misses) +
                " egress_limited=" + std::to_string(stats.egress_limited) +
                " proofs_served=" + std::to_string(stats.proofs_served) +
                " state_requests=" + std::to_string(stats.state_requests) +
                " state_misses=" + std::to_string(stats.state_misses) +
                " states_served=" + std::to_string(stats.states_served) +
                " gossip_attempts=" + std::to_string(stats.gossip_attempts) +
                " gossip_handshakes=" + std::to_string(stats.gossip_handshakes) +
                " gossip_announcements=" + std::to_string(stats.gossip_announcements) +
                " response_bytes=" + std::to_string(stats.response_bytes) +
                " peak_active_proof_requests=" +
                    std::to_string(stats.peak_active_proof_requests));
        } catch (...) {
            static constexpr char message[]{
                "level=error event=p2p_server_stop_log_failed reason=allocation_or_io_exception\n"};
            const ssize_t write_result{
                ::write(STDERR_FILENO, message, sizeof(message) - 1)};
            static_cast<void>(write_result);
        }
    }

    void Start()
    {
        accept_thread = std::thread{[this] {
            try {
                AcceptLoop();
            } catch (const std::bad_alloc&) {
                RequestStop();
                if (listener >= 0) ::shutdown(listener, SHUT_RDWR);
                EmergencyLog(
                    "level=error event=p2p_accept_loop_failed "
                    "reason=allocation_failed action=stop_accepting\n");
            } catch (const std::exception& exception) {
                RequestStop();
                if (listener >= 0) ::shutdown(listener, SHUT_RDWR);
                try {
                    Log(LogLevel::ERROR, "p2p_accept_loop_failed",
                        "error=" + Quoted(exception.what()) + " action=stop_accepting");
                } catch (...) {
                    EmergencyLog(
                        "level=error event=p2p_accept_loop_failed "
                        "error=log_allocation_failed action=stop_accepting\n");
                }
            }
        }};
        if (!config.gossip_seeds.empty()) {
            gossip_thread = std::thread{[this] {
                try {
                    GossipLoop();
                } catch (const std::bad_alloc&) {
                    CloseCurrentGossipSocket();
                    EmergencyLog(
                        "level=error event=p2p_gossip_failed "
                        "reason=allocation_failed action=stop_gossip\n");
                } catch (const std::exception& exception) {
                    CloseCurrentGossipSocket();
                    try {
                        Log(LogLevel::ERROR, "p2p_gossip_failed",
                            "error=" + Quoted(exception.what()) + " action=stop_gossip");
                    } catch (...) {
                        EmergencyLog(
                            "level=error event=p2p_gossip_failed "
                            "error=log_allocation_failed action=stop_gossip\n");
                    }
                }
            }};
        }
    }

    void CloseCurrentGossipSocket()
    {
        std::lock_guard lock{gossip_socket_mutex};
        const int socket{gossip_socket.exchange(-1)};
        if (socket >= 0) ::close(socket);
    }

    void InterruptCurrentGossipSocket()
    {
        std::lock_guard lock{gossip_socket_mutex};
        const int socket{gossip_socket.load()};
        if (socket >= 0) ::shutdown(socket, SHUT_RDWR);
    }

    void CloseGossipSocket(int socket)
    {
        std::lock_guard lock{gossip_socket_mutex};
        int expected{socket};
        if (gossip_socket.compare_exchange_strong(expected, -1)) ::close(socket);
    }

    class GossipSocketGuard
    {
    public:
        GossipSocketGuard(Impl& owner, int socket) : m_owner{owner}, m_socket{socket} {}
        ~GossipSocketGuard() { m_owner.CloseGossipSocket(m_socket); }
        GossipSocketGuard(const GossipSocketGuard&) = delete;
        GossipSocketGuard& operator=(const GossipSocketGuard&) = delete;

    private:
        Impl& m_owner;
        int m_socket;
    };

    Result<int> ConnectGossipSeed(const P2PIPv4Endpoint& seed)
    {
        const int socket{::socket(AF_INET, SOCK_STREAM, 0)};
        if (socket < 0) {
            return Result<int>::Err("could not create gossip socket: " +
                                    std::string{std::strerror(errno)});
        }
        if (!ConfigureSocket(socket)) {
            const std::string error{std::strerror(errno)};
            ::close(socket);
            return Result<int>::Err("could not configure gossip socket: " + error);
        }
        {
            std::lock_guard lock{gossip_socket_mutex};
            gossip_socket.store(socket);
        }
        if (stopping.load()) {
            CloseGossipSocket(socket);
            return Result<int>::Err("gossip shutdown requested");
        }
        const int flags{::fcntl(socket, F_GETFL, 0)};
        if (flags < 0 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) != 0) {
            const std::string error{std::strerror(errno)};
            CloseGossipSocket(socket);
            return Result<int>::Err("could not configure gossip socket: " + error);
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(seed.port);
        if (!ParseIPv4(seed.address, address.sin_addr)) {
            CloseGossipSocket(socket);
            return Result<int>::Err("gossip seed is not numeric IPv4");
        }
        if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 &&
            errno != EINPROGRESS) {
            const std::string error{std::strerror(errno)};
            CloseGossipSocket(socket);
            return Result<int>::Err("could not connect to gossip seed: " + error);
        }
        const auto connect_deadline{
            std::chrono::steady_clock::now() +
            std::chrono::seconds(config.gossip_connect_timeout_seconds)};
        int ready{0};
        while (!stopping.load()) {
            const auto now{std::chrono::steady_clock::now()};
            if (now >= connect_deadline) break;
            const auto remaining{std::chrono::duration_cast<std::chrono::milliseconds>(
                connect_deadline - now)};
            pollfd descriptor{.fd = socket, .events = POLLOUT, .revents = 0};
            ready = ::poll(&descriptor, 1,
                           static_cast<int>(std::max<int64_t>(1, remaining.count())));
            if (ready < 0 && errno == EINTR) continue;
            break;
        }
        if (ready <= 0 || stopping.load()) {
            const std::string error{ready == 0 ? "connect timed out" :
                (stopping.load() ? "shutdown requested" : std::strerror(errno))};
            CloseGossipSocket(socket);
            return Result<int>::Err("could not connect to gossip seed: " + error);
        }
        int socket_error{0};
        socklen_t error_size{sizeof(socket_error)};
        if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &socket_error, &error_size) != 0 ||
            socket_error != 0) {
            const int error{socket_error == 0 ? errno : socket_error};
            CloseGossipSocket(socket);
            return Result<int>::Err("could not connect to gossip seed: " +
                                    std::string{std::strerror(error)});
        }
        if (::fcntl(socket, F_SETFL, flags) != 0) {
            const std::string error{std::strerror(errno)};
            CloseGossipSocket(socket);
            return Result<int>::Err("could not restore gossip socket mode: " + error);
        }
        const timeval timeout{static_cast<time_t>(config.gossip_connect_timeout_seconds), 0};
        static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                                      sizeof(timeout)));
        return Result<int>::Ok(socket);
    }

    Result<void> AnnounceToSeed(const P2PIPv4Endpoint& seed)
    {
        auto connected{ConnectGossipSeed(seed)};
        if (!connected) return Result<void>::Err(connected.Error());
        const int socket{connected.Value()};
        GossipSocketGuard socket_guard{*this, socket};

        // One absolute deadline bounds the entire outbound handshake and address
        // announcement. A peer making incremental progress cannot extend it.
        const auto deadline{std::chrono::steady_clock::now() +
                            std::chrono::seconds(config.gossip_connect_timeout_seconds)};
        const auto version{VersionPayload(config, cache->Stats().tip_height, seed.port)};
        auto sent{SendMessageUntil(socket, config.network, "version", version, deadline)};
        if (!sent) return sent;
        bool received_version{false};
        bool received_verack{false};
        uint64_t peer_services{0};
        for (uint32_t messages{0}; messages < 32 && !(received_version && received_verack);
             ++messages) {
            auto message{ReadMessageUntil(socket, config.network, MAX_INBOUND_MESSAGE_BYTES,
                                          deadline)};
            if (!message) return Result<void>::Err(message.Error());
            if (message.Value().command == "version") {
                const auto services{VersionServices(message.Value().payload)};
                if (received_version || !services) {
                    return Result<void>::Err("gossip seed sent an invalid version message");
                }
                peer_services = *services;
                received_version = true;
                sent = SendMessageUntil(socket, config.network, "verack", {}, deadline);
                if (!sent) return sent;
            } else if (message.Value().command == "verack") {
                if (!received_version || !message.Value().payload.empty()) {
                    return Result<void>::Err("gossip seed sent an invalid verack");
                }
                received_verack = true;
            } else if (message.Value().command == "ping") {
                if (message.Value().payload.size() != sizeof(uint64_t)) {
                    return Result<void>::Err("gossip seed sent an invalid ping");
                }
                sent = SendMessageUntil(socket, config.network, "pong",
                                        message.Value().payload, deadline);
                if (!sent) return sent;
            }
        }
        if (!received_version || !received_verack) {
            return Result<void>::Err("gossip seed handshake message limit exceeded");
        }
        ++gossip_handshakes;
        if ((peer_services & (NODE_UTREEXO | NODE_UTREEXO_ARCHIVE)) == 0) {
            return Result<void>::Err(
                "gossip seed is not Utreexo-aware and may discard this address");
        }
        const auto address{AdvertisedAddressPayload(config, false)};
        sent = SendMessageUntil(socket, config.network, "addr", address, deadline);
        if (!sent) return sent;
        ++gossip_announcements;
        return Result<void>::Ok();
    }

    void GossipLoop()
    {
        while (!stopping.load()) {
            for (const auto& seed : config.gossip_seeds) {
                if (stopping.load()) return;
                ++gossip_attempts;
                auto announced{AnnounceToSeed(seed)};
                if (!announced) {
                    if (!stopping.load()) {
                        Log(LogLevel::DEBUG, "p2p_gossip_seed_failed",
                            "seed=" + Quoted(EndpointText(seed)) +
                            " error=" + Quoted(announced.Error()));
                    }
                    continue;
                }
                Log(LogLevel::INFO, "p2p_address_gossip_sent",
                    "seed=" + Quoted(EndpointText(seed)) +
                    " address=" + Quoted(EndpointText(*config.advertised_endpoint)) +
                    " services=" + std::to_string(AdvertisedServices(config)));
            }
            std::unique_lock lock{gossip_wait_mutex};
            gossip_wakeup.wait_for(lock, std::chrono::seconds(config.gossip_retry_seconds),
                                   [this] { return stopping.load(); });
        }
    }

    void AcceptLoop()
    {
        while (!stopping.load()) {
            sockaddr_in address{};
            socklen_t address_size{sizeof(address)};
            const int socket{::accept(listener, reinterpret_cast<sockaddr*>(&address), &address_size)};
            if (socket < 0) {
                if (stopping.load()) return;
                if (errno == EINTR) continue;
                Log(LogLevel::WARN, "p2p_accept_failed",
                    "error=" + Quoted(std::strerror(errno)));
                continue;
            }
            SocketGuard socket_guard{socket};
            if (!ConfigureSocket(socket)) {
                Log(LogLevel::WARN, "p2p_accept_failed",
                    "error=" + Quoted(std::strerror(errno)) +
                    " action=close_unconfigured_socket");
                continue;
            }
            const uint32_t address_key{address.sin_addr.s_addr};
            const std::string peer_address{PeerAddress(address)};
            {
                std::lock_guard lock{clients_mutex};
                ReapFinishedClients();
                if (active_peers.load() >= config.max_peers) {
                    ++rejected_max_peers;
                    Log(LogLevel::DEBUG, "p2p_peer_rejected",
                        "peer_address=" + Quoted(peer_address) + " reason=max_peers");
                    continue;
                }
                const auto existing_ip{active_peers_by_ip.find(address_key)};
                const uint32_t peers_from_ip{existing_ip == active_peers_by_ip.end() ?
                    0 : existing_ip->second};
                if (peers_from_ip >= config.max_peers_per_ip) {
                    ++rejected_per_ip;
                    Log(LogLevel::DEBUG, "p2p_peer_rejected",
                        "peer_address=" + Quoted(peer_address) + " reason=max_peers_per_ip" +
                        " active_from_ip=" + std::to_string(peers_from_ip));
                    continue;
                }
                auto done{std::make_shared<std::atomic<bool>>(false)};
                bool worker_slot_added{false};
                bool address_registered{false};
                bool socket_registered{false};
                bool active_registered{false};
                try {
                    // Allocate every container node before starting the thread, then
                    // make the registration transactional. A failed allocation or
                    // thread creation must neither leak the accepted fd nor leave
                    // peer accounting behind.
                    client_workers.emplace_back();
                    worker_slot_added = true;
                    auto [address_entry, inserted]{
                        active_peers_by_ip.try_emplace(address_key, 0)};
                    static_cast<void>(inserted);
                    ++address_entry->second;
                    address_registered = true;
                    client_sockets.push_back(socket);
                    socket_registered = true;
                    const uint32_t now_active{active_peers.fetch_add(1) + 1};
                    active_registered = true;
                    client_workers.back().done = done;
                    client_workers.back().thread =
                        std::thread{[this, socket, address, address_key, done] {
                            try {
                                ClientLoop(socket, address, address_key);
                            } catch (const std::bad_alloc&) {
                                RemoveClient(socket, address_key);
                                EmergencyLog(
                                    "level=error event=p2p_peer_allocation_failed "
                                    "action=disconnect\n");
                            } catch (const std::exception& exception) {
                                RemoveClient(socket, address_key);
                                try {
                                    Log(LogLevel::ERROR, "p2p_peer_exception",
                                        "peer_address=" + Quoted(PeerAddress(address)) +
                                        " error=" + Quoted(exception.what()) +
                                        " action=disconnect");
                                } catch (...) {
                                    EmergencyLog(
                                        "level=error event=p2p_peer_exception "
                                        "error=log_allocation_failed action=disconnect\n");
                                }
                            }
                            done->store(true);
                        }};
                    ++accepted_peers;
                    UpdatePeak(peak_active_peers, now_active);
                    socket_guard.Release();
                } catch (const std::bad_alloc&) {
                    if (worker_slot_added) client_workers.pop_back();
                    if (socket_registered) std::erase(client_sockets, socket);
                    if (address_registered) {
                        auto entry{active_peers_by_ip.find(address_key)};
                        if (entry != active_peers_by_ip.end() && --entry->second == 0) {
                            active_peers_by_ip.erase(entry);
                        }
                    }
                    if (active_registered) active_peers.fetch_sub(1);
                    EmergencyLog(
                        "level=error event=p2p_peer_worker_failed "
                        "reason=allocation_failed action=reject_peer\n");
                } catch (const std::exception& exception) {
                    if (worker_slot_added) client_workers.pop_back();
                    if (socket_registered) std::erase(client_sockets, socket);
                    if (address_registered) {
                        auto entry{active_peers_by_ip.find(address_key)};
                        if (entry != active_peers_by_ip.end() && --entry->second == 0) {
                            active_peers_by_ip.erase(entry);
                        }
                    }
                    if (active_registered) active_peers.fetch_sub(1);
                    try {
                        Log(LogLevel::ERROR, "p2p_peer_worker_failed",
                            "peer_address=" + Quoted(peer_address) +
                            " error=" + Quoted(exception.what()));
                    } catch (...) {
                        EmergencyLog(
                            "level=error event=p2p_peer_worker_failed "
                            "error=log_allocation_failed action=reject_peer\n");
                    }
                }
            }
        }
    }

    void ReapFinishedClients()
    {
        for (auto iterator{client_workers.begin()}; iterator != client_workers.end();) {
            if (!iterator->done->load()) {
                ++iterator;
                continue;
            }
            if (iterator->thread.joinable()) iterator->thread.join();
            iterator = client_workers.erase(iterator);
        }
    }

    void RemoveClient(int socket, uint32_t address_key)
    {
        {
            std::lock_guard lock{clients_mutex};
            std::erase(client_sockets, socket);
            auto entry{active_peers_by_ip.find(address_key)};
            if (entry != active_peers_by_ip.end() && --entry->second == 0) {
                active_peers_by_ip.erase(entry);
            }
        }
        ::close(socket);
        active_peers.fetch_sub(1);
    }

    void ClientLoop(int socket, sockaddr_in address, uint32_t address_key)
    {
        const timeval timeout{static_cast<time_t>(config.idle_timeout_seconds), 0};
        static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
        const uint16_t peer_port{PeerPort(address)};
        const std::string peer_address{PeerAddress(address)};
        bool sent_version{false};
        bool received_verack{false};
        bool wants_addrv2{false};
        uint64_t messages_in_window{0};
        uint64_t inbound_bytes_remaining{config.max_inbound_bytes_per_second};
        auto window_start{std::chrono::steady_clock::now()};
        std::string disconnect_reason{"shutdown"};
        while (!stopping.load()) {
            const auto read_started{std::chrono::steady_clock::now()};
            if (read_started - window_start >= std::chrono::seconds(1)) {
                messages_in_window = 0;
                inbound_bytes_remaining = config.max_inbound_bytes_per_second;
                window_start = read_started;
            }
            const auto message_deadline{
                read_started + std::chrono::seconds(config.idle_timeout_seconds)};
            auto message{ReadMessageUntil(socket, config.network,
                                          std::min(config.max_payload_bytes,
                                                   MAX_INBOUND_MESSAGE_BYTES),
                                          message_deadline, &inbound_bytes_remaining)};
            if (!message) {
                disconnect_reason = message.Error();
                if (disconnect_reason == "P2P inbound byte rate limit exceeded") {
                    ++inbound_limited;
                }
                break;
            }
            const auto now{std::chrono::steady_clock::now()};
            if (++messages_in_window > 256) {
                disconnect_reason = "message rate limit exceeded";
                break;
            }
            if (!sent_version) {
                if (message.Value().command != "version" ||
                    !ValidVersionPayload(message.Value().payload)) {
                    disconnect_reason = "expected a valid version message";
                    break;
                }
                const auto version{VersionPayload(config, cache->Stats().tip_height, peer_port)};
                const auto response_deadline{
                    now + std::chrono::seconds(config.idle_timeout_seconds)};
                auto sent{SendMessageUntil(socket, config.network, "version", version,
                                           response_deadline)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                sent = SendMessageUntil(socket, config.network, "verack", {},
                                        response_deadline);
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                sent_version = true;
                Log(LogLevel::DEBUG, "p2p_peer_version",
                    "peer_address=" + Quoted(peer_address) +
                    " peer_port=" + std::to_string(peer_port) +
                    " services=" + std::to_string(AdvertisedServices(config)));
                continue;
            }
            const auto& command{message.Value().command};
            if (command == "verack") {
                if (!message.Value().payload.empty()) {
                    disconnect_reason = "verack payload is not empty";
                    break;
                }
                received_verack = true;
                continue;
            }
            if (command == "sendaddrv2") {
                if (!message.Value().payload.empty() || received_verack) {
                    disconnect_reason = "sendaddrv2 outside handshake";
                    break;
                }
                wants_addrv2 = true;
                continue;
            }
            if (!received_verack) {
                disconnect_reason = "application message before verack";
                break;
            }
            if (command == "ping") {
                if (message.Value().payload.size() != sizeof(uint64_t)) {
                    disconnect_reason = "ping payload is not eight bytes";
                    break;
                }
                const auto response_deadline{
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(config.idle_timeout_seconds)};
                auto sent{SendMessageUntil(socket, config.network, "pong",
                                           message.Value().payload, response_deadline)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                continue;
            }
            if (command == "getaddr") {
                if (!message.Value().payload.empty()) {
                    disconnect_reason = "getaddr payload is not empty";
                    break;
                }
                const auto addresses{AdvertisedAddressPayload(config, wants_addrv2)};
                const auto response_deadline{
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(config.idle_timeout_seconds)};
                auto sent{SendMessageUntil(socket, config.network,
                                           wants_addrv2 ? "addrv2" : "addr", addresses,
                                           response_deadline)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                continue;
            }
            if (command == "getheaders") {
                const std::array<std::byte, 1> empty_count{std::byte{0}};
                const auto response_deadline{
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(config.idle_timeout_seconds)};
                auto sent{SendMessageUntil(socket, config.network, "headers", empty_count,
                                           response_deadline)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                continue;
            }
            if (command == "getcfilters") {
                if (message.Value().payload.size() != 1 + sizeof(uint32_t) + Hash256::SIZE) {
                    disconnect_reason = "malformed getcfilters request";
                    break;
                }
                if (std::to_integer<uint8_t>(message.Value().payload.front()) != 1) {
                    // This proof-only service does not advertise BIP157 compact filters.
                    continue;
                }
                ++state_requests;
                auto request{ParseGetUtreexoStateRequest(message.Value().payload)};
                if (!request) {
                    disconnect_reason = request.Error();
                    break;
                }
                if (!config.advertise_archive || !store) {
                    ++state_misses;
                    disconnect_reason = "historical accumulator state service is unavailable";
                    Log(LogLevel::DEBUG, "p2p_state_miss",
                        "peer_address=" + Quoted(peer_address) +
                        " height=" + std::to_string(request.Value().start_height) +
                        " stop_hash=" + request.Value().stop_hash.ToBitcoinHex() +
                        " reason=archive_not_advertised action=disconnect");
                    break;
                }
                ProofWorkGuard state_work{*this};
                if (!state_work.Acquired()) {
                    ++proof_busy;
                    disconnect_reason = "proof server busy";
                    Log(LogLevel::DEBUG, "p2p_state_rejected",
                        "peer_address=" + Quoted(peer_address) +
                        " height=" + std::to_string(request.Value().start_height) +
                        " reason=concurrency_limit active=" +
                            std::to_string(active_proof_requests.load()));
                    break;
                }

                // Resolve the stop hash using the mmap height index before touching proof
                // records. An absent or over-large range therefore cannot amplify into
                // hundreds of archive reads, and valid ranges reserve their worst-case
                // response budget before any state data is allocated or read.
                std::vector<Hash256> expected_hashes;
                expected_hashes.reserve(MAX_GETCFILTERS_RESULTS);
                bool found_stop{false};
                bool state_error{false};
                uint32_t height{request.Value().start_height};
                for (uint32_t count{0}; count < MAX_GETCFILTERS_RESULTS; ++count) {
                    auto hash{store->HashAt(height)};
                    if (!hash) {
                        disconnect_reason = "accumulator state archive index failed: " + hash.Error();
                        Log(LogLevel::ERROR, "p2p_state_store_index_failed",
                            "peer_address=" + Quoted(peer_address) +
                            " height=" + std::to_string(height) +
                            " error=" + Quoted(hash.Error()));
                        state_error = true;
                        break;
                    }
                    if (!hash.Value()) {
                        disconnect_reason = "requested accumulator state is unavailable";
                        state_error = true;
                        break;
                    }
                    found_stop = *hash.Value() == request.Value().stop_hash;
                    expected_hashes.push_back(*hash.Value());
                    if (found_stop || height == std::numeric_limits<uint32_t>::max()) break;
                    ++height;
                }
                if (state_error || !found_stop) {
                    ++state_misses;
                    if (!state_error) {
                        disconnect_reason =
                            "getcfilters stop hash is outside the 1000-state response range";
                    }
                    Log(LogLevel::DEBUG, "p2p_state_miss",
                        "peer_address=" + Quoted(peer_address) +
                        " start_height=" + std::to_string(request.Value().start_height) +
                        " stop_hash=" + request.Value().stop_hash.ToBitcoinHex() +
                        " action=disconnect");
                    break;
                }
                const uint64_t reserved_bytes{
                    expected_hashes.size() * MAX_STATE_RESPONSE_BYTES};
                EgressReservation state_egress{*this, reserved_bytes};
                if (!state_egress.Acquired()) {
                    ++egress_limited;
                    disconnect_reason = "proof egress limit exceeded";
                    Log(LogLevel::DEBUG, "p2p_state_rejected",
                        "peer_address=" + Quoted(peer_address) +
                        " start_height=" + std::to_string(request.Value().start_height) +
                        " states=" + std::to_string(expected_hashes.size()) +
                        " reason=egress_limit reserved_bytes=" +
                            std::to_string(reserved_bytes));
                    break;
                }

                std::vector<AccumulatorState> states;
                states.reserve(expected_hashes.size());
                height = request.Value().start_height;
                for (const auto& expected_hash : expected_hashes) {
                    auto state{store->StateAt(height)};
                    if (!state) {
                        disconnect_reason = "accumulator state archive read failed: " + state.Error();
                        Log(LogLevel::ERROR, "p2p_state_store_read_failed",
                            "peer_address=" + Quoted(peer_address) +
                            " height=" + std::to_string(height) +
                            " error=" + Quoted(state.Error()));
                        state_error = true;
                        break;
                    }
                    if (!state.Value() || state.Value()->point.height != height ||
                        state.Value()->point.block_hash != expected_hash) {
                        disconnect_reason =
                            "requested accumulator state changed during archive read";
                        state_error = true;
                        break;
                    }
                    states.push_back(std::move(*state.Value()));
                    ++height;
                }
                if (state_error) {
                    ++state_misses;
                    Log(LogLevel::DEBUG, "p2p_state_miss",
                        "peer_address=" + Quoted(peer_address) +
                        " start_height=" + std::to_string(request.Value().start_height) +
                        " stop_hash=" + request.Value().stop_hash.ToBitcoinHex() +
                        " action=disconnect");
                    break;
                }
                const auto response_deadline{
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(config.idle_timeout_seconds)};
                for (const auto& state : states) {
                    auto payload{SerializeUtreexoStateFilter(state)};
                    if (!payload) {
                        disconnect_reason = payload.Error();
                        state_error = true;
                        break;
                    }
                    if (payload.Value().size() > config.max_payload_bytes) {
                        disconnect_reason = "cfilter state response exceeds configured maximum";
                        state_error = true;
                        break;
                    }
                    const uint64_t wire_bytes{MESSAGE_HEADER_SIZE + payload.Value().size()};
                    auto sent{SendMessageUntil(socket, config.network, "cfilter",
                                               payload.Value(), response_deadline)};
                    if (!sent) {
                        disconnect_reason = sent.Error();
                        state_error = true;
                        break;
                    }
                    ++states_served;
                    response_bytes.fetch_add(wire_bytes);
                    Log(LogLevel::DEBUG, "p2p_state_served",
                        "peer_address=" + Quoted(peer_address) +
                        " height=" + std::to_string(state.point.height) +
                        " block_hash=" + state.point.block_hash.ToBitcoinHex() +
                        " leaves=" + std::to_string(state.num_leaves) +
                        " roots=" + std::to_string(state.roots.size()) +
                        " response_bytes=" + std::to_string(payload.Value().size()));
                }
                if (state_error) break;
                continue;
            }
            if (command != "getuproof") continue;
            ++proof_requests;
            auto request{ParseGetUtreexoProof(message.Value().payload)};
            if (!request) {
                disconnect_reason = request.Error();
                break;
            }
            std::optional<ProofWorkGuard> proof_work;
            const auto acquire_proof_work = [&]() {
                if (proof_work && proof_work->Acquired()) return true;
                proof_work.emplace(*this);
                if (proof_work->Acquired()) return true;
                ++proof_busy;
                disconnect_reason = "proof server busy";
                Log(LogLevel::DEBUG, "p2p_proof_rejected",
                    "peer_address=" + Quoted(peer_address) +
                    " block_hash=" + request.Value().block_hash.ToBitcoinHex() +
                    " reason=concurrency_limit active=" +
                        std::to_string(active_proof_requests.load()));
                return false;
            };
            auto proof{cache->Find(request.Value().block_hash)};
            if (proof && !acquire_proof_work()) break;
            if (!proof && store) {
                if (!acquire_proof_work()) break;
                auto archived{store->Read(request.Value().block_hash)};
                if (!archived) {
                    disconnect_reason = "proof archive read failed: " + archived.Error();
                    Log(LogLevel::ERROR, "p2p_proof_store_read_failed",
                        "peer_address=" + Quoted(peer_address) +
                        " block_hash=" + request.Value().block_hash.ToBitcoinHex() +
                        " error=" + Quoted(archived.Error()));
                    break;
                }
                proof = archived.Take();
                if (!proof) proof_work.reset();
            }
            if (!proof) {
                // A cache miss may wait for the sync pipeline, but cannot occupy an
                // archive/serialization slot or reserve worst-case egress while idle.
                proof = cache->WaitFor(request.Value().block_hash,
                                       std::chrono::seconds(config.proof_wait_seconds),
                                       &stopping);
                if (proof && !acquire_proof_work()) break;
            }
            if (!proof && stopping.load()) {
                disconnect_reason = "shutdown";
                break;
            }
            if (!proof && store) {
                if (!acquire_proof_work()) break;
                auto archived{store->Read(request.Value().block_hash)};
                if (!archived) {
                    disconnect_reason = "proof archive read failed: " + archived.Error();
                    Log(LogLevel::ERROR, "p2p_proof_store_read_failed",
                        "peer_address=" + Quoted(peer_address) +
                        " block_hash=" + request.Value().block_hash.ToBitcoinHex() +
                        " error=" + Quoted(archived.Error()));
                    break;
                }
                proof = archived.Take();
                if (!proof) proof_work.reset();
            }
            if (!proof) {
                ++proof_misses;
                disconnect_reason = "requested proof is unavailable";
                Log(LogLevel::DEBUG, "p2p_proof_miss",
                    "peer_address=" + Quoted(peer_address) +
                    " block_hash=" + request.Value().block_hash.ToBitcoinHex() +
                    " action=disconnect");
                // getuproof has no specified notfound payload. Closing the peer is an
                // immediate, unambiguous failure and lets Floresta retry another peer
                // instead of waiting for its request timeout.
                break;
            }
            // Measure without allocating the response, then reserve its exact wire size.
            // The work guard remains held through serialization and the bounded write.
            auto layout{MeasureUtreexoProof(*proof, request.Value(),
                                            config.max_payload_bytes)};
            if (!layout) {
                disconnect_reason = layout.Error();
                break;
            }
            const uint64_t reserved_bytes{MESSAGE_HEADER_SIZE + layout.Value().payload_bytes};
            EgressReservation proof_egress{*this, reserved_bytes};
            if (!proof_egress.Acquired()) {
                ++egress_limited;
                disconnect_reason = "proof egress limit exceeded";
                Log(LogLevel::DEBUG, "p2p_proof_rejected",
                    "peer_address=" + Quoted(peer_address) +
                    " block_hash=" + request.Value().block_hash.ToBitcoinHex() +
                    " reason=egress_limit reserved_bytes=" +
                        std::to_string(reserved_bytes));
                break;
            }
            const auto response_deadline{
                std::chrono::steady_clock::now() +
                std::chrono::seconds(config.idle_timeout_seconds)};
            auto payload{SerializeUtreexoProofWithLayout(*proof, request.Value(),
                                                         layout.Value())};
            if (!payload) {
                disconnect_reason = payload.Error();
                break;
            }
            if (payload.Value().size() > config.max_payload_bytes) {
                disconnect_reason = "uproof response exceeds configured maximum";
                break;
            }
            const uint64_t wire_bytes{MESSAGE_HEADER_SIZE + payload.Value().size()};
            auto sent{SendMessageUntil(socket, config.network, "uproof", payload.Value(),
                                       response_deadline)};
            if (!sent) {
                disconnect_reason = sent.Error();
                break;
            }
            ++proofs_served;
            response_bytes.fetch_add(wire_bytes);
            Log(LogLevel::DEBUG, "p2p_proof_served",
                "peer_address=" + Quoted(peer_address) +
                " height=" + std::to_string(proof->point.height) +
                " block_hash=" + proof->point.block_hash.ToBitcoinHex() +
                " request_bytes=" + std::to_string(message.Value().payload.size()) +
                " response_bytes=" + std::to_string(payload.Value().size()));
        }
        Log(LogLevel::DEBUG, "p2p_peer_disconnected",
            "peer_address=" + Quoted(peer_address) +
            " peer_port=" + std::to_string(peer_port) +
            " reason=" + Quoted(disconnect_reason));
        RemoveClient(socket, address_key);
    }

    bool TryAcquireProofWork()
    {
        uint32_t active{active_proof_requests.load()};
        while (active < config.max_concurrent_proof_requests) {
            if (active_proof_requests.compare_exchange_weak(active, active + 1)) {
                UpdatePeak(peak_active_proof_requests, active + 1);
                return true;
            }
        }
        return false;
    }

    void ReleaseProofWork() { active_proof_requests.fetch_sub(1); }

    class ProofWorkGuard
    {
    public:
        explicit ProofWorkGuard(Impl& owner) : m_owner{owner}, m_acquired{owner.TryAcquireProofWork()} {}
        ~ProofWorkGuard() { if (m_acquired) m_owner.ReleaseProofWork(); }
        ProofWorkGuard(const ProofWorkGuard&) = delete;
        ProofWorkGuard& operator=(const ProofWorkGuard&) = delete;
        bool Acquired() const { return m_acquired; }

    private:
        Impl& m_owner;
        bool m_acquired;
    };

    class EgressReservation
    {
    public:
        EgressReservation(Impl& owner, uint64_t bytes)
            : m_acquired{owner.ReserveEgress(bytes)}
        {
        }
        EgressReservation(const EgressReservation&) = delete;
        EgressReservation& operator=(const EgressReservation&) = delete;
        bool Acquired() const { return m_acquired; }

    private:
        bool m_acquired;
    };

    bool ReserveEgress(uint64_t bytes)
    {
        std::lock_guard lock{egress_mutex};
        const auto now{std::chrono::steady_clock::now()};
        const long double elapsed{
            std::chrono::duration<long double>(now - egress_updated).count()};
        egress_tokens = std::min(
            static_cast<long double>(config.egress_burst_bytes),
            egress_tokens + elapsed * static_cast<long double>(config.max_egress_bytes_per_second));
        egress_updated = now;
        if (static_cast<long double>(bytes) > egress_tokens) return false;
        egress_tokens -= static_cast<long double>(bytes);
        return true;
    }

    static void UpdatePeak(std::atomic<uint32_t>& peak, uint32_t value)
    {
        uint32_t prior{peak.load()};
        while (prior < value && !peak.compare_exchange_weak(prior, value)) {}
    }

    P2PServerStats Stats() const
    {
        return P2PServerStats{
            .active_peers = active_peers.load(),
            .peak_active_peers = peak_active_peers.load(),
            .active_proof_requests = active_proof_requests.load(),
            .peak_active_proof_requests = peak_active_proof_requests.load(),
            .accepted_peers = accepted_peers.load(),
            .rejected_max_peers = rejected_max_peers.load(),
            .rejected_per_ip = rejected_per_ip.load(),
            .inbound_limited = inbound_limited.load(),
            .proof_requests = proof_requests.load(),
            .proof_busy = proof_busy.load(),
            .proof_misses = proof_misses.load(),
            .egress_limited = egress_limited.load(),
            .proofs_served = proofs_served.load(),
            .response_bytes = response_bytes.load(),
            .state_requests = state_requests.load(),
            .state_misses = state_misses.load(),
            .states_served = states_served.load(),
            .gossip_attempts = gossip_attempts.load(),
            .gossip_handshakes = gossip_handshakes.load(),
            .gossip_announcements = gossip_announcements.load(),
        };
    }

    P2PServerConfig config;
    std::shared_ptr<RecentProofCache> cache;
    std::shared_ptr<ProofStore> store;
    int listener{-1};
    uint16_t bound_port{0};
    std::atomic<bool> stopping{false};
    std::atomic<uint32_t> active_peers{0};
    std::atomic<uint32_t> peak_active_peers{0};
    std::atomic<uint32_t> active_proof_requests{0};
    std::atomic<uint32_t> peak_active_proof_requests{0};
    std::atomic<uint64_t> accepted_peers{0};
    std::atomic<uint64_t> rejected_max_peers{0};
    std::atomic<uint64_t> rejected_per_ip{0};
    std::atomic<uint64_t> inbound_limited{0};
    std::atomic<uint64_t> proof_requests{0};
    std::atomic<uint64_t> proof_busy{0};
    std::atomic<uint64_t> proof_misses{0};
    std::atomic<uint64_t> egress_limited{0};
    std::atomic<uint64_t> proofs_served{0};
    std::atomic<uint64_t> response_bytes{0};
    std::atomic<uint64_t> state_requests{0};
    std::atomic<uint64_t> state_misses{0};
    std::atomic<uint64_t> states_served{0};
    std::atomic<uint64_t> gossip_attempts{0};
    std::atomic<uint64_t> gossip_handshakes{0};
    std::atomic<uint64_t> gossip_announcements{0};
    std::mutex gossip_socket_mutex;
    std::atomic<int> gossip_socket{-1};
    std::thread accept_thread;
    std::thread gossip_thread;
    std::mutex gossip_wait_mutex;
    std::condition_variable gossip_wakeup;
    std::mutex clients_mutex;
    std::unordered_map<uint32_t, uint32_t> active_peers_by_ip;
    std::vector<int> client_sockets;
    std::vector<ClientWorker> client_workers;
    std::mutex egress_mutex;
    long double egress_tokens{0};
    std::chrono::steady_clock::time_point egress_updated;
};

P2PServer::P2PServer(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}

P2PServer::~P2PServer() = default;

Result<void> ValidateP2PServerConfig(const P2PServerConfig& config)
{
    if (config.max_peers == 0 || config.max_peers > 1'024) {
        return Result<void>::Err("P2P max peers must be between 1 and 1024");
    }
    if (config.max_peers_per_ip == 0 || config.max_peers_per_ip > 1'024) {
        return Result<void>::Err(
            "P2P max peers per IP must be between 1 and 1024");
    }
    if (config.max_concurrent_proof_requests == 0 ||
        config.max_concurrent_proof_requests > 1'024) {
        return Result<void>::Err(
            "P2P concurrent proof requests must be between 1 and 1024");
    }
    if (config.max_inbound_bytes_per_second <
            MESSAGE_HEADER_SIZE + MAX_INBOUND_MESSAGE_BYTES ||
        config.max_inbound_bytes_per_second > MAX_EGRESS_LIMIT) {
        return Result<void>::Err(
            "P2P inbound byte limit must accommodate one maximum request and not exceed 16 GiB/s");
    }
    if (config.max_egress_bytes_per_second == 0 ||
        config.max_egress_bytes_per_second > MAX_EGRESS_LIMIT ||
        config.egress_burst_bytes < MESSAGE_HEADER_SIZE + config.max_payload_bytes ||
        config.egress_burst_bytes > MAX_EGRESS_LIMIT) {
        return Result<void>::Err("invalid P2P proof egress limits");
    }
    if (config.proof_wait_seconds > 120) {
        return Result<void>::Err("P2P proof wait cannot exceed 120 seconds");
    }
    if (config.idle_timeout_seconds == 0 || config.idle_timeout_seconds > 3'600) {
        return Result<void>::Err("P2P idle timeout must be between 1 and 3600 seconds");
    }
    if (config.gossip_seeds.size() > MAX_GOSSIP_SEEDS) {
        return Result<void>::Err(
            "P2P gossip supports at most 32 explicit seed endpoints");
    }
    if (!config.gossip_seeds.empty() && !config.advertised_endpoint) {
        return Result<void>::Err(
            "P2P gossip seeds require an explicit advertised endpoint");
    }
    if (!config.gossip_seeds.empty() &&
        (config.gossip_retry_seconds == 0 || config.gossip_retry_seconds > 86'400 ||
         config.gossip_connect_timeout_seconds == 0 ||
         config.gossip_connect_timeout_seconds > 30)) {
        return Result<void>::Err(
            "P2P gossip retry must be 1..86400 seconds and timeout 1..30 seconds");
    }
    if (config.advertised_endpoint) {
        in_addr advertised{};
        if (config.advertised_endpoint->port == 0 ||
            !ParseIPv4(config.advertised_endpoint->address, advertised)) {
            return Result<void>::Err(
                "P2P advertised endpoint must be numeric IPv4 with a nonzero port");
        }
        const bool acceptable{config.network == BitcoinNetwork::REGTEST ?
            IsUnicastIPv4(advertised) : IsGloballyRoutableIPv4(advertised)};
        if (!acceptable) {
            return Result<void>::Err(
                "P2P advertised IPv4 address is not globally routable");
        }
    }
    for (std::size_t index{0}; index < config.gossip_seeds.size(); ++index) {
        const auto& seed{config.gossip_seeds[index]};
        in_addr seed_address{};
        if (seed.port == 0 || !ParseIPv4(seed.address, seed_address) ||
            !IsUnicastIPv4(seed_address)) {
            return Result<void>::Err(
                "P2P gossip seed must be a numeric unicast IPv4 endpoint with a nonzero port");
        }
        if (config.advertised_endpoint &&
            seed.address == config.advertised_endpoint->address &&
            seed.port == config.advertised_endpoint->port) {
            return Result<void>::Err(
                "P2P gossip seed cannot equal the advertised endpoint");
        }
        for (std::size_t prior{0}; prior < index; ++prior) {
            if (seed.address == config.gossip_seeds[prior].address &&
                seed.port == config.gossip_seeds[prior].port) {
                return Result<void>::Err(
                    "duplicate P2P gossip seed endpoint");
            }
        }
    }
    if (config.bind_address != "127.0.0.1" && config.bind_address != "0.0.0.0") {
        return Result<void>::Err(
            "P2P bind address must be 127.0.0.1 or 0.0.0.0 in the v1 server");
    }
    return Result<void>::Ok();
}

Result<std::unique_ptr<P2PServer>> P2PServer::Start(
    P2PServerConfig config, std::shared_ptr<RecentProofCache> cache,
    std::shared_ptr<ProofStore> store)
{
    if (!cache) return Result<std::unique_ptr<P2PServer>>::Err("P2P proof cache is null");
    auto valid_config{ValidateP2PServerConfig(config)};
    if (!valid_config) {
        return Result<std::unique_ptr<P2PServer>>::Err(valid_config.Error());
    }
    if (config.advertise_archive) {
        if (!store) {
            return Result<std::unique_ptr<P2PServer>>::Err(
                "P2P archive service requires a proof store");
        }
        const auto coverage{store->Coverage()};
        const auto cache_tip{cache->Stats().tip_height};
        if (!coverage.full_history || coverage.base.height != 0 ||
            coverage.base.block_hash != NetworkGenesisHash(config.network) ||
            coverage.durable.height != cache_tip) {
            return Result<std::unique_ptr<P2PServer>>::Err(
                "P2P archive service requires canonical network genesis-to-tip "
                "proof/state coverage");
        }
    }
    const int listener{::socket(AF_INET, SOCK_STREAM, 0)};
    if (listener < 0) {
        return Result<std::unique_ptr<P2PServer>>::Err("could not create P2P listener: " +
                                                       std::string{std::strerror(errno)});
    }
    if (!ConfigureSocket(listener)) {
        const std::string error{std::strerror(errno)};
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err(
            "could not configure P2P listener: " + error);
    }
    const int reuse{1};
    static_cast<void>(::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.port);
    if (::inet_pton(AF_INET, config.bind_address.c_str(), &address.sin_addr) != 1) {
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err("invalid P2P IPv4 bind address");
    }
    if (::bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listener, static_cast<int>(config.max_peers)) != 0) {
        const std::string error{std::strerror(errno)};
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err("could not bind P2P listener: " + error);
    }
    socklen_t address_size{sizeof(address)};
    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        const std::string error{std::strerror(errno)};
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err("could not inspect P2P listener: " + error);
    }
    const uint16_t bound_port{PeerPort(address)};
    config.port = bound_port;
    std::unique_ptr<Impl> impl;
    try {
        impl = std::make_unique<Impl>(std::move(config), std::move(cache), std::move(store),
                                      listener, bound_port);
    } catch (const std::bad_alloc&) {
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err(
            "could not allocate P2P server admission state");
    } catch (const std::exception& exception) {
        ::close(listener);
        return Result<std::unique_ptr<P2PServer>>::Err(
            "could not initialize P2P server: " + std::string{exception.what()});
    }
    try {
        impl->Start();
    } catch (const std::exception& exception) {
        return Result<std::unique_ptr<P2PServer>>::Err(
            "could not start P2P accept thread: " + std::string{exception.what()});
    }
    auto server{std::unique_ptr<P2PServer>{new P2PServer{std::move(impl)}}};
    return Result<std::unique_ptr<P2PServer>>::Ok(std::move(server));
}

uint16_t P2PServer::BoundPort() const { return m_impl->bound_port; }

P2PServerStats P2PServer::Stats() const { return m_impl->Stats(); }

} // namespace utreexo
