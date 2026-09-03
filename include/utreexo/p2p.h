// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_P2P_H
#define UTREEXO_P2P_H

#include <utreexo/block_delta.h>
#include <utreexo/forest.h>
#include <utreexo/result.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace utreexo {

class ProofStore;

enum class BitcoinNetwork : uint8_t { MAINNET, TESTNET3, SIGNET, REGTEST };

Result<BitcoinNetwork> ParseBitcoinNetwork(std::string_view value);
/** Canonical block-zero hash for the selected Bitcoin network. */
Hash256 BitcoinNetworkGenesisHash(BitcoinNetwork network);

/** A numeric IPv4 P2P endpoint. Hostname and DNS resolution are intentionally absent. */
struct P2PIPv4Endpoint {
    std::string address;
    uint16_t port{0};
};

/** Parse the unambiguous numeric form `IPv4:port`. */
Result<P2PIPv4Endpoint> ParseP2PIPv4Endpoint(std::string_view value);

struct P2PMessage {
    std::string command;
    std::vector<std::byte> payload;
};

struct GetUtreexoProofRequest {
    Hash256 block_hash;
    uint8_t request_bitmap{0};
    std::vector<std::byte> proof_indexes;
    std::vector<std::byte> leaf_indexes;
};

struct CachedBlockProof {
    ChainPoint point;
    Proof proof;
    std::vector<CompactLeafData> leaves;
};

/** Encode/decode the checksummed Bitcoin v1 transport envelope. */
Result<std::vector<std::byte>> EncodeP2PMessage(BitcoinNetwork network,
                                                std::string_view command,
                                                std::span<const std::byte> payload);
Result<P2PMessage> DecodeP2PMessage(BitcoinNetwork network,
                                    std::span<const std::byte> message,
                                    uint32_t max_payload_bytes = 32U * 1024U * 1024U);

/** Current utreexod/Floresta getuproof and uproof payload formats. */
Result<GetUtreexoProofRequest> ParseGetUtreexoProof(std::span<const std::byte> payload);
Result<std::vector<std::byte>> SerializeUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request);
/** Serialize only when the exact response fits max_payload_bytes. */
Result<std::vector<std::byte>> SerializeUtreexoProof(
    const CachedBlockProof& proof, const GetUtreexoProofRequest& request,
    uint64_t max_payload_bytes);
/** Decode the full (bitmap 0x07) uproof representation used by the proof archive. */
Result<CachedBlockProof> ParseFullUtreexoProof(uint32_t height,
                                              std::span<const std::byte> payload);

struct ProofCacheStats {
    uint64_t entries{0};
    uint64_t bytes{0};
    uint64_t hits{0};
    uint64_t misses{0};
    uint64_t oversized_skips{0};
    uint32_t tip_height{0};
};

/** Thread-safe, disposable cache of proofs captured before recent block mutations. */
class RecentProofCache
{
public:
    RecentProofCache(uint32_t max_blocks, uint64_t max_bytes);
    ~RecentProofCache();
    RecentProofCache(const RecentProofCache&) = delete;
    RecentProofCache& operator=(const RecentProofCache&) = delete;

    Result<void> Publish(const BlockDelta& delta, Proof proof);
    std::shared_ptr<const CachedBlockProof> Find(const Hash256& block_hash) const;
    std::shared_ptr<const CachedBlockProof> WaitFor(
        const Hash256& block_hash, std::chrono::milliseconds timeout,
        const std::atomic<bool>* cancelled = nullptr) const;
    /** Wake WaitFor callers so they can observe cancellation promptly. */
    void NotifyWaiters() const;
    void DiscardAfter(uint32_t height);
    void SetTip(uint32_t height);
    ProofCacheStats Stats() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

struct P2PServerConfig {
    BitcoinNetwork network{BitcoinNetwork::MAINNET};
    std::string bind_address{"127.0.0.1"};
    uint16_t port{0};
    uint32_t max_peers{16};
    /** Prevent one IPv4 source (including a large NAT) from consuming every peer slot. */
    uint32_t max_peers_per_ip{4};
    /** Bounds simultaneous archive reads, proof serialization, and response allocations. */
    uint32_t max_concurrent_proof_requests{4};
    /** Global proof-response token-bucket rate and burst limits. */
    uint64_t max_egress_bytes_per_second{64ULL * 1024ULL * 1024ULL};
    uint64_t egress_burst_bytes{384ULL * 1024ULL * 1024ULL};
    uint32_t max_payload_bytes{320U * 1024U * 1024U};
    /** Per-peer inbound wire-byte ceiling over each one-second window. */
    uint64_t max_inbound_bytes_per_second{4ULL * 1024ULL * 1024ULL};
    uint32_t idle_timeout_seconds{120};
    uint32_t proof_wait_seconds{15};
    std::string user_agent{"/utreexo-bridge:unknown/"};
    /** Advertise historical proof/state service only after complete genesis coverage. */
    bool advertise_archive{false};
    /**
     * Explicit address placed in addr/addrv2 gossip. It is never inferred from the bind
     * address or a peer, and must be globally routable outside regtest.
     */
    std::optional<P2PIPv4Endpoint> advertised_endpoint{};
    /** Numeric Utreexo-aware peers contacted only to announce advertised_endpoint. */
    std::vector<P2PIPv4Endpoint> gossip_seeds{};
    /** One bounded worker visits every seed, then sleeps before the next visit. */
    uint32_t gossip_retry_seconds{300};
    /** Bounds each seed's TCP connect plus Bitcoin handshake independently. */
    uint32_t gossip_connect_timeout_seconds{5};
};

/** Validate listener, resource, and discovery settings without opening a socket. */
Result<void> ValidateP2PServerConfig(const P2PServerConfig& config);

struct P2PServerStats {
    uint32_t active_peers{0};
    uint32_t peak_active_peers{0};
    uint32_t active_proof_requests{0};
    uint32_t peak_active_proof_requests{0};
    uint64_t accepted_peers{0};
    uint64_t rejected_max_peers{0};
    uint64_t rejected_per_ip{0};
    uint64_t inbound_limited{0};
    uint64_t proof_requests{0};
    uint64_t proof_busy{0};
    uint64_t proof_misses{0};
    uint64_t egress_limited{0};
    uint64_t proofs_served{0};
    uint64_t response_bytes{0};
    uint64_t state_requests{0};
    uint64_t state_misses{0};
    uint64_t states_served{0};
    uint64_t gossip_attempts{0};
    uint64_t gossip_handshakes{0};
    uint64_t gossip_announcements{0};
};

/** Bitcoin-v1 proof service with optional bounded address gossip. It never mutates the forest. */
class P2PServer
{
public:
    static Result<std::unique_ptr<P2PServer>> Start(
        P2PServerConfig config, std::shared_ptr<RecentProofCache> cache,
        std::shared_ptr<ProofStore> store = {});
    ~P2PServer();
    P2PServer(const P2PServer&) = delete;
    P2PServer& operator=(const P2PServer&) = delete;

    uint16_t BoundPort() const;
    P2PServerStats Stats() const;

private:
    class Impl;
    explicit P2PServer(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

} // namespace utreexo

#endif // UTREEXO_P2P_H
