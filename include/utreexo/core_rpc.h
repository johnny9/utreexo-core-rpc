// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_CORE_RPC_H
#define UTREEXO_CORE_RPC_H

#include <utreexo/block_delta.h>
#include <utreexo/result.h>

#include <univalue.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace utreexo {

struct HttpRpcConfig {
    std::string host{"127.0.0.1"};
    uint16_t port{8332};
    std::string path{"/"};
    std::string authorization;
    int timeout_seconds{30};
    std::size_t max_response_bytes{128U * 1024U * 1024U};
};

struct RpcCallMetrics {
    std::string method;
    uint64_t request_bytes{0};
    uint64_t response_bytes{0};
    uint64_t elapsed_us{0};
    bool success{false};
};

struct RpcAggregateMetrics {
    uint64_t calls{0};
    uint64_t failures{0};
    uint64_t request_bytes{0};
    uint64_t response_bytes{0};
    uint64_t elapsed_us{0};
    uint64_t largest_response_bytes{0};
    std::string largest_response_method;
    uint64_t slowest_call_us{0};
    std::string slowest_call_method;
};

Result<std::string> ReadCookieAuthorization(const std::filesystem::path& cookie_file);

class RpcTransport
{
public:
    virtual ~RpcTransport() = default;
    virtual Result<std::string> Post(std::string body) = 0;
};

class HttpRpcTransport final : public RpcTransport
{
public:
    explicit HttpRpcTransport(HttpRpcConfig config);
    Result<std::string> Post(std::string body) override;

private:
    HttpRpcConfig m_config;
};

class CoreRpcClient
{
public:
    explicit CoreRpcClient(std::unique_ptr<RpcTransport> transport);
    Result<UniValue> Call(const std::string& method, UniValue parameters = UniValue{UniValue::VARR});
    const RpcCallMetrics& LastCallMetrics() const { return m_last_call; }
    const RpcAggregateMetrics& AggregateMetrics() const { return m_aggregate; }

private:
    void RecordLastCall();

    std::unique_ptr<RpcTransport> m_transport;
    uint64_t m_request_id{0};
    RpcCallMetrics m_last_call;
    RpcAggregateMetrics m_aggregate;
};

class BlockSource
{
public:
    virtual ~BlockSource() = default;
    virtual Result<uint32_t> TipHeight() = 0;
    virtual Result<Hash256> BlockHash(uint32_t height) = 0;
    virtual Result<UniValue> BlockWithPrevouts(const Hash256& hash) = 0;
};

class CoreRpcBlockSource final : public BlockSource
{
public:
    explicit CoreRpcBlockSource(CoreRpcClient client);
    Result<uint32_t> TipHeight() override;
    Result<Hash256> BlockHash(uint32_t height) override;
    Result<UniValue> BlockWithPrevouts(const Hash256& hash) override;
    uint64_t LargestBlockResponseBytes() const { return m_largest_block_response_bytes; }
    uint64_t LargestBlockResponseElapsedUs() const { return m_largest_block_response_elapsed_us; }
    const Hash256& LargestBlockResponseHash() const { return m_largest_block_response_hash; }
    const RpcAggregateMetrics& RpcMetrics() const { return m_client.AggregateMetrics(); }

private:
    CoreRpcClient m_client;
    uint64_t m_largest_block_response_bytes{0};
    uint64_t m_largest_block_response_elapsed_us{0};
    Hash256 m_largest_block_response_hash;
};

using BlockHashResolver = std::function<Result<Hash256>(uint32_t)>;

/** Convert getblock(hash, 3) JSON into a metadata-free accumulator transition. */
Result<BlockDelta> ParseVerboseBlock(const UniValue& block,
                                     const BlockHashResolver& block_hash_at_height);
Result<uint64_t> ParseBitcoinAmount(const UniValue& value);

} // namespace utreexo

#endif // UTREEXO_CORE_RPC_H
