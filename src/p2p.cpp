// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/p2p.h>

#include <utreexo/hash.h>
#include <utreexo/log.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <iomanip>
#include <limits>
#include <mutex>
#include <netinet/in.h>
#include <optional>
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
// The largest supported inbound request is getuproof's two bounded bitmaps.
// Responses may use the larger configured payload limit.
constexpr uint32_t MAX_INBOUND_MESSAGE_BYTES{256U * 1024U};
constexpr std::size_t MAX_PROOF_BITMAP_BYTES{128U * 1024U};
constexpr std::size_t MAX_LEAF_BITMAP_BYTES{4U * 1024U};
constexpr std::size_t MAX_INPUTS_PER_BLOCK{24'386};
constexpr std::size_t MAX_SCRIPT_BYTES{10'000};

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

uint64_t ProofBytes(const CachedBlockProof& proof)
{
    uint64_t bytes{sizeof(CachedBlockProof)};
    bytes += proof.proof.targets.size() * sizeof(uint64_t);
    bytes += proof.proof.hashes.size() * sizeof(Hash256);
    bytes += proof.leaves.size() * sizeof(CompactLeafData);
    for (const auto& leaf : proof.leaves) bytes += leaf.script.size();
    return bytes;
}

Result<void> ReadExact(int socket, std::span<std::byte> output)
{
    std::size_t received{0};
    while (received < output.size()) {
        const ssize_t result{::recv(socket, output.data() + received, output.size() - received, 0)};
        if (result == 0) return Result<void>::Err("peer closed connection");
        if (result < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err("socket read failed: " + std::string{std::strerror(errno)});
        }
        received += static_cast<std::size_t>(result);
    }
    return Result<void>::Ok();
}

Result<void> SendAll(int socket, std::span<const std::byte> data)
{
    std::size_t sent{0};
    while (sent < data.size()) {
        const ssize_t result{::send(socket, data.data() + sent, data.size() - sent, MSG_NOSIGNAL)};
        if (result < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err("socket write failed: " + std::string{std::strerror(errno)});
        }
        if (result == 0) return Result<void>::Err("socket write made no progress");
        sent += static_cast<std::size_t>(result);
    }
    return Result<void>::Ok();
}

Result<P2PMessage> ReadMessage(int socket, BitcoinNetwork network, uint32_t max_payload)
{
    std::array<std::byte, MESSAGE_HEADER_SIZE> header{};
    auto read{ReadExact(socket, header)};
    if (!read) return Result<P2PMessage>::Err(read.Error());
    const auto magic{NetworkMagic(network)};
    if (!std::equal(magic.begin(), magic.end(), header.begin())) {
        // In particular, let BIP324-first clients reconnect with v1 immediately.
        return Result<P2PMessage>::Err("wrong P2P network magic");
    }
    const uint32_t length{
        std::to_integer<uint8_t>(header[16]) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[17])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[18])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(header[19])) << 24)};
    if (length > max_payload) return Result<P2PMessage>::Err("P2P payload exceeds configured maximum");
    std::vector<std::byte> wire{header.begin(), header.end()};
    wire.resize(MESSAGE_HEADER_SIZE + length);
    read = ReadExact(socket, std::span<std::byte>{wire}.subspan(MESSAGE_HEADER_SIZE));
    if (!read) return Result<P2PMessage>::Err(read.Error());
    return DecodeP2PMessage(network, wire, max_payload);
}

Result<void> SendMessage(int socket, BitcoinNetwork network, std::string_view command,
                         std::span<const std::byte> payload)
{
    auto encoded{EncodeP2PMessage(network, command, payload)};
    if (!encoded) return Result<void>::Err(encoded.Error());
    return SendAll(socket, encoded.Value());
}

std::vector<std::byte> VersionPayload(const P2PServerConfig& config, uint32_t height,
                                      uint16_t peer_port)
{
    std::vector<std::byte> output;
    output.reserve(128);
    AppendLE(output, PROTOCOL_VERSION);
    AppendLE(output, NODE_UTREEXO);
    const auto now{std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};
    AppendLE(output, static_cast<uint64_t>(now));

    const auto append_address = [&](uint64_t services, uint16_t port) {
        AppendLE(output, services);
        output.insert(output.end(), 10, std::byte{0});
        output.push_back(std::byte{0xff});
        output.push_back(std::byte{0xff});
        output.insert(output.end(), 4, std::byte{0});
        AppendBE16(output, port);
    };
    append_address(0, peer_port);
    append_address(NODE_UTREEXO, config.port);
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

uint16_t PeerPort(const sockaddr_in& address)
{
    return ntohs(address.sin_port);
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

Result<std::vector<std::byte>> EncodeP2PMessage(BitcoinNetwork network,
                                                std::string_view command,
                                                std::span<const std::byte> payload)
{
    if (command.empty() || command.size() > 12) {
        return Result<std::vector<std::byte>>::Err("P2P command must contain 1 through 12 bytes");
    }
    for (const unsigned char character : command) {
        if (character < 0x20 || character > 0x7e) {
            return Result<std::vector<std::byte>>::Err("P2P command contains a non-printable byte");
        }
    }
    if (payload.size() > std::numeric_limits<uint32_t>::max()) {
        return Result<std::vector<std::byte>>::Err("P2P payload is too large");
    }
    std::vector<std::byte> output;
    output.reserve(MESSAGE_HEADER_SIZE + payload.size());
    const auto magic{NetworkMagic(network)};
    output.insert(output.end(), magic.begin(), magic.end());
    for (const char character : command) {
        output.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    output.insert(output.end(), 12 - command.size(), std::byte{0});
    AppendLE(output, static_cast<uint32_t>(payload.size()));
    const auto checksum{DoubleSha256(payload)};
    output.insert(output.end(), checksum.Bytes().begin(), checksum.Bytes().begin() + 4);
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

Result<std::vector<std::byte>> SerializeUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request)
{
    if (proof.point.block_hash != request.block_hash) {
        return Result<std::vector<std::byte>>::Err("getuproof block hash does not match cached proof");
    }
    if (proof.proof.targets.size() != proof.leaves.size() ||
        proof.leaves.size() > MAX_INPUTS_PER_BLOCK) {
        return Result<std::vector<std::byte>>::Err("cached proof target/leaf counts are invalid");
    }
    std::vector<std::byte> output;
    output.insert(output.end(), proof.point.block_hash.Bytes().begin(), proof.point.block_hash.Bytes().end());

    std::vector<const Hash256*> hashes;
    hashes.reserve(proof.proof.hashes.size());
    const bool all_hashes{(request.request_bitmap & (1U << 1)) != 0};
    for (std::size_t i{0}; i < proof.proof.hashes.size(); ++i) {
        if (all_hashes || BitmapBit(request.proof_indexes, i)) hashes.push_back(&proof.proof.hashes[i]);
    }
    AppendCompactSize(output, hashes.size());
    for (const auto* hash : hashes) {
        output.insert(output.end(), hash->Bytes().begin(), hash->Bytes().end());
    }

    const bool targets_requested{(request.request_bitmap & 1U) != 0};
    AppendCompactSize(output, targets_requested ? proof.proof.targets.size() : 0);
    if (targets_requested) {
        for (const uint64_t target : proof.proof.targets) AppendCompactSize(output, target);
    }

    std::vector<const CompactLeafData*> leaves;
    leaves.reserve(proof.leaves.size());
    const bool all_leaves{(request.request_bitmap & (1U << 2)) != 0};
    for (std::size_t i{0}; i < proof.leaves.size(); ++i) {
        if (all_leaves || BitmapBit(request.leaf_indexes, i)) leaves.push_back(&proof.leaves[i]);
    }
    AppendCompactSize(output, leaves.size());
    for (const auto* leaf : leaves) {
        if (static_cast<uint8_t>(leaf->script_type) >
            static_cast<uint8_t>(ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH)) {
            return Result<std::vector<std::byte>>::Err("cached compact leaf has an unknown script type");
        }
        if (leaf->script_type == ScriptPubkeyType::OTHER && leaf->script.size() > MAX_SCRIPT_BYTES) {
            return Result<std::vector<std::byte>>::Err("cached compact leaf script is too large");
        }
        AppendLE(output, leaf->header_code);
        AppendLE(output, leaf->amount);
        output.push_back(static_cast<std::byte>(leaf->script_type));
        if (leaf->script_type == ScriptPubkeyType::OTHER) {
            AppendCompactSize(output, leaf->script.size());
            output.insert(output.end(), leaf->script.begin(), leaf->script.end());
        } else if (!leaf->script.empty()) {
            return Result<std::vector<std::byte>>::Err("standard compact leaf unexpectedly contains a script");
        }
    }
    return Result<std::vector<std::byte>>::Ok(std::move(output));
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
    uint32_t tip_height{0};
};

RecentProofCache::RecentProofCache(uint32_t max_blocks, uint64_t max_bytes)
    : m_impl{std::make_unique<Impl>(max_blocks, max_bytes)}
{
}

RecentProofCache::~RecentProofCache() = default;

Result<void> RecentProofCache::Publish(const BlockDelta& delta, Proof proof)
{
    if (proof.targets.size() != delta.deletions.size() ||
        delta.proof_leaves.size() != delta.deletions.size()) {
        return Result<void>::Err("block proof does not align with its deletion leaves");
    }
    auto record{std::make_shared<CachedBlockProof>(CachedBlockProof{
        .point = delta.point,
        .proof = std::move(proof),
        .leaves = delta.proof_leaves,
    })};
    const uint64_t record_bytes{ProofBytes(*record)};
    {
        std::lock_guard lock{m_impl->mutex};
        if (record_bytes > m_impl->max_bytes) {
            return Result<void>::Err("one block proof exceeds the proof-cache byte limit");
        }
        if (const auto existing{m_impl->entries.find(delta.point.block_hash)};
            existing != m_impl->entries.end()) {
            m_impl->bytes -= ProofBytes(*existing->second);
            m_impl->entries.erase(existing);
            std::erase(m_impl->order, delta.point.block_hash);
        }
        m_impl->bytes += record_bytes;
        m_impl->entries.emplace(delta.point.block_hash, std::move(record));
        m_impl->order.push_back(delta.point.block_hash);
        m_impl->tip_height = delta.point.height;
        while (!m_impl->order.empty() &&
               (m_impl->entries.size() > m_impl->max_blocks || m_impl->bytes > m_impl->max_bytes)) {
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
    const Hash256& block_hash, std::chrono::milliseconds timeout) const
{
    std::unique_lock lock{m_impl->mutex};
    const auto available{[&] { return m_impl->entries.contains(block_hash); }};
    if (!m_impl->published.wait_for(lock, timeout, available)) {
        ++m_impl->misses;
        return {};
    }
    ++m_impl->hits;
    return m_impl->entries.find(block_hash)->second;
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
         int listener_socket, uint16_t actual_port)
        : config{std::move(server_config)}, cache{std::move(proof_cache)},
          listener{listener_socket}, bound_port{actual_port}
    {
    }

    ~Impl()
    {
        stopping.store(true);
        if (listener >= 0) {
            ::shutdown(listener, SHUT_RDWR);
            ::close(listener);
        }
        if (accept_thread.joinable()) accept_thread.join();
        listener = -1;
        {
            std::lock_guard lock{clients_mutex};
            for (const int socket : client_sockets) ::shutdown(socket, SHUT_RDWR);
        }
        for (auto& worker : client_workers) {
            if (worker.thread.joinable()) worker.thread.join();
        }
    }

    void Start() { accept_thread = std::thread{[this] { AcceptLoop(); }}; }

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
            uint32_t prior{active_peers.fetch_add(1)};
            if (prior >= config.max_peers) {
                active_peers.fetch_sub(1);
                ::close(socket);
                Log(LogLevel::DEBUG, "p2p_peer_rejected", "reason=max_peers");
                continue;
            }
            {
                std::lock_guard lock{clients_mutex};
                ReapFinishedClients();
                client_sockets.push_back(socket);
                auto done{std::make_shared<std::atomic<bool>>(false)};
                client_workers.push_back(ClientWorker{
                    .thread = std::thread{[this, socket, address, done] {
                        ClientLoop(socket, address);
                        done->store(true);
                    }},
                    .done = std::move(done),
                });
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

    void RemoveClient(int socket)
    {
        {
            std::lock_guard lock{clients_mutex};
            std::erase(client_sockets, socket);
        }
        ::close(socket);
        active_peers.fetch_sub(1);
    }

    void ClientLoop(int socket, sockaddr_in address)
    {
        const timeval timeout{static_cast<time_t>(config.idle_timeout_seconds), 0};
        static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        static_cast<void>(::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
        const uint16_t peer_port{PeerPort(address)};
        bool sent_version{false};
        bool received_verack{false};
        bool wants_addrv2{false};
        uint64_t messages_in_window{0};
        auto window_start{std::chrono::steady_clock::now()};
        std::string disconnect_reason{"shutdown"};
        while (!stopping.load()) {
            auto message{ReadMessage(socket, config.network,
                                     std::min(config.max_payload_bytes,
                                              MAX_INBOUND_MESSAGE_BYTES))};
            if (!message) {
                disconnect_reason = message.Error();
                break;
            }
            const auto now{std::chrono::steady_clock::now()};
            if (now - window_start >= std::chrono::seconds(1)) {
                messages_in_window = 0;
                window_start = now;
            }
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
                auto sent{SendMessage(socket, config.network, "version", version)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                sent = SendMessage(socket, config.network, "verack", {});
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                sent_version = true;
                Log(LogLevel::DEBUG, "p2p_peer_version",
                    "peer_port=" + std::to_string(peer_port) +
                    " services=" + std::to_string(NODE_UTREEXO));
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
                auto sent{SendMessage(socket, config.network, "pong", message.Value().payload)};
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
                const std::array<std::byte, 1> empty_count{std::byte{0}};
                auto sent{SendMessage(socket, config.network, wants_addrv2 ? "addrv2" : "addr",
                                      empty_count)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                continue;
            }
            if (command == "getheaders") {
                const std::array<std::byte, 1> empty_count{std::byte{0}};
                auto sent{SendMessage(socket, config.network, "headers", empty_count)};
                if (!sent) {
                    disconnect_reason = sent.Error();
                    break;
                }
                continue;
            }
            if (command != "getuproof") continue;
            auto request{ParseGetUtreexoProof(message.Value().payload)};
            if (!request) {
                disconnect_reason = request.Error();
                break;
            }
            const auto proof{cache->WaitFor(
                request.Value().block_hash,
                std::chrono::seconds(config.proof_wait_seconds))};
            if (!proof) {
                Log(LogLevel::DEBUG, "p2p_proof_miss",
                    "block_hash=" + request.Value().block_hash.ToBitcoinHex());
                continue;
            }
            auto payload{SerializeUtreexoProof(*proof, request.Value())};
            if (!payload) {
                disconnect_reason = payload.Error();
                break;
            }
            if (payload.Value().size() > config.max_payload_bytes) {
                disconnect_reason = "uproof response exceeds configured maximum";
                break;
            }
            auto sent{SendMessage(socket, config.network, "uproof", payload.Value())};
            if (!sent) {
                disconnect_reason = sent.Error();
                break;
            }
            Log(LogLevel::DEBUG, "p2p_proof_served",
                "height=" + std::to_string(proof->point.height) +
                " block_hash=" + proof->point.block_hash.ToBitcoinHex() +
                " request_bytes=" + std::to_string(message.Value().payload.size()) +
                " response_bytes=" + std::to_string(payload.Value().size()));
        }
        Log(LogLevel::DEBUG, "p2p_peer_disconnected",
            "peer_port=" + std::to_string(peer_port) +
            " reason=" + Quoted(disconnect_reason));
        RemoveClient(socket);
    }

    P2PServerConfig config;
    std::shared_ptr<RecentProofCache> cache;
    int listener{-1};
    uint16_t bound_port{0};
    std::atomic<bool> stopping{false};
    std::atomic<uint32_t> active_peers{0};
    std::thread accept_thread;
    std::mutex clients_mutex;
    std::vector<int> client_sockets;
    std::vector<ClientWorker> client_workers;
};

P2PServer::P2PServer(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}

P2PServer::~P2PServer() = default;

Result<std::unique_ptr<P2PServer>> P2PServer::Start(
    P2PServerConfig config, std::shared_ptr<RecentProofCache> cache)
{
    if (!cache) return Result<std::unique_ptr<P2PServer>>::Err("P2P proof cache is null");
    if (config.max_peers == 0 || config.max_peers > 1'024) {
        return Result<std::unique_ptr<P2PServer>>::Err("P2P max peers must be between 1 and 1024");
    }
    if (config.proof_wait_seconds > 120) {
        return Result<std::unique_ptr<P2PServer>>::Err("P2P proof wait cannot exceed 120 seconds");
    }
    if (config.bind_address != "127.0.0.1" && config.bind_address != "0.0.0.0") {
        return Result<std::unique_ptr<P2PServer>>::Err(
            "P2P bind address must be 127.0.0.1 or 0.0.0.0 in the v1 server");
    }
    const int listener{::socket(AF_INET, SOCK_STREAM, 0)};
    if (listener < 0) {
        return Result<std::unique_ptr<P2PServer>>::Err("could not create P2P listener: " +
                                                       std::string{std::strerror(errno)});
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
    auto impl{std::make_unique<Impl>(std::move(config), std::move(cache), listener, bound_port)};
    impl->Start();
    auto server{std::unique_ptr<P2PServer>{new P2PServer{std::move(impl)}}};
    return Result<std::unique_ptr<P2PServer>>::Ok(std::move(server));
}

uint16_t P2PServer::BoundPort() const { return m_impl->bound_port; }

} // namespace utreexo
