// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_P2P_H
#define UTREEXO_P2P_H

#include <utreexo/block_delta.h>
#include <utreexo/forest.h>
#include <utreexo/result.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace utreexo {

class ProofStore;

enum class BitcoinNetwork : uint8_t { MAINNET, TESTNET3, SIGNET, REGTEST };

Result<BitcoinNetwork> ParseBitcoinNetwork(std::string_view value);

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
/** Decode the full (bitmap 0x07) uproof representation used by the proof archive. */
Result<CachedBlockProof> ParseFullUtreexoProof(uint32_t height,
                                              std::span<const std::byte> payload);

struct ProofCacheStats {
    uint64_t entries{0};
    uint64_t bytes{0};
    uint64_t hits{0};
    uint64_t misses{0};
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
        const Hash256& block_hash, std::chrono::milliseconds timeout) const;
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
    uint32_t max_payload_bytes{32U * 1024U * 1024U};
    uint32_t idle_timeout_seconds{120};
    uint32_t proof_wait_seconds{15};
    std::string user_agent{"/utreexo-bridge:unknown/"};
};

/** Inbound Bitcoin-v1 proof peer. It never reads or mutates the forest. */
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

private:
    class Impl;
    explicit P2PServer(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

} // namespace utreexo

#endif // UTREEXO_P2P_H
