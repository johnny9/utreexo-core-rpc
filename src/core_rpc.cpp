// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/core_rpc.h>

#include <utreexo/leaf.h>
#include <utreexo/log.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <netdb.h>
#include <optional>
#include <sstream>
#include <string_view>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace utreexo {
namespace {

std::string Quoted(std::string_view value)
{
    std::ostringstream output;
    output << std::quoted(std::string{value});
    return output.str();
}

class FileDescriptor
{
public:
    explicit FileDescriptor(int value = -1) : m_value{value} {}
    ~FileDescriptor() { if (m_value >= 0) ::close(m_value); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : m_value{std::exchange(other.m_value, -1)} {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept
    {
        if (this != &other) {
            if (m_value >= 0) ::close(m_value);
            m_value = std::exchange(other.m_value, -1);
        }
        return *this;
    }
    int Get() const { return m_value; }
    explicit operator bool() const { return m_value >= 0; }

private:
    int m_value;
};

class AddressInfo
{
public:
    explicit AddressInfo(addrinfo* value = nullptr) : m_value{value} {}
    ~AddressInfo() { if (m_value) ::freeaddrinfo(m_value); }
    AddressInfo(const AddressInfo&) = delete;
    AddressInfo& operator=(const AddressInfo&) = delete;
    addrinfo* Get() const { return m_value; }

private:
    addrinfo* m_value;
};

std::string Base64Encode(std::string_view input)
{
    constexpr std::string_view alphabet{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t i{0}; i < input.size(); i += 3) {
        const uint32_t a{static_cast<unsigned char>(input[i])};
        const uint32_t b{i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0U};
        const uint32_t c{i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0U};
        const uint32_t bits{(a << 16) | (b << 8) | c};
        output.push_back(alphabet[(bits >> 18) & 63U]);
        output.push_back(alphabet[(bits >> 12) & 63U]);
        output.push_back(i + 1 < input.size() ? alphabet[(bits >> 6) & 63U] : '=');
        output.push_back(i + 2 < input.size() ? alphabet[bits & 63U] : '=');
    }
    return output;
}

std::string Lower(std::string_view input)
{
    std::string output{input};
    std::ranges::transform(output, output.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return output;
}

Result<std::string> DecodeChunked(std::string_view encoded)
{
    std::string output;
    std::size_t cursor{0};
    while (true) {
        const std::size_t line_end{encoded.find("\r\n", cursor)};
        if (line_end == std::string_view::npos) return Result<std::string>::Err("truncated chunk size");
        const auto extension{encoded.substr(cursor, line_end - cursor).find(';')};
        const auto size_text{encoded.substr(cursor, line_end - cursor).substr(0, extension)};
        std::size_t chunk_size{0};
        const auto [end, error]{std::from_chars(size_text.data(), size_text.data() + size_text.size(), chunk_size, 16)};
        if (error != std::errc{} || end != size_text.data() + size_text.size()) {
            return Result<std::string>::Err("invalid chunk size");
        }
        cursor = line_end + 2;
        if (chunk_size == 0) return Result<std::string>::Ok(std::move(output));
        if (chunk_size > encoded.size() - cursor || encoded.size() - cursor - chunk_size < 2) {
            return Result<std::string>::Err("truncated chunk body");
        }
        output.append(encoded.substr(cursor, chunk_size));
        cursor += chunk_size;
        if (encoded.substr(cursor, 2) != "\r\n") return Result<std::string>::Err("invalid chunk terminator");
        cursor += 2;
    }
}

Result<std::string> ParseHttpResponse(std::string response)
{
    const std::size_t header_end{response.find("\r\n\r\n")};
    if (header_end == std::string::npos) return Result<std::string>::Err("HTTP response has no header terminator");
    const std::size_t status_end{response.find("\r\n")};
    if (status_end == std::string::npos) return Result<std::string>::Err("HTTP response has no status line");
    const std::string_view status{response.data(), status_end};
    const std::size_t first_space{status.find(' ')};
    if (first_space == std::string_view::npos || status.size() < first_space + 4) {
        return Result<std::string>::Err("invalid HTTP status line");
    }
    int code{0};
    const auto code_text{status.substr(first_space + 1, 3)};
    const auto [end, error]{std::from_chars(code_text.data(), code_text.data() + code_text.size(), code)};
    if (error != std::errc{} || end != code_text.data() + code_text.size()) {
        return Result<std::string>::Err("invalid HTTP status code");
    }

    bool chunked{false};
    std::optional<std::size_t> content_length;
    std::size_t cursor{status_end + 2};
    while (cursor < header_end) {
        const std::size_t line_end{response.find("\r\n", cursor)};
        if (line_end == std::string::npos || line_end > header_end) break;
        const std::string_view line{response.data() + cursor, line_end - cursor};
        const std::size_t colon{line.find(':')};
        if (colon != std::string_view::npos) {
            const std::string name{Lower(line.substr(0, colon))};
            std::string_view value{line.substr(colon + 1)};
            while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
            if (name == "transfer-encoding" && Lower(value).find("chunked") != std::string::npos) chunked = true;
            if (name == "content-length") {
                std::size_t parsed{0};
                const auto [length_end, length_error]{std::from_chars(value.data(), value.data() + value.size(), parsed)};
                if (length_error != std::errc{} || length_end != value.data() + value.size()) {
                    return Result<std::string>::Err("invalid HTTP content length");
                }
                content_length = parsed;
            }
        }
        cursor = line_end + 2;
    }

    std::string body{response.substr(header_end + 4)};
    if (chunked) {
        auto decoded{DecodeChunked(body)};
        if (!decoded) return decoded;
        body = decoded.Take();
    } else if (content_length) {
        if (body.size() < *content_length) return Result<std::string>::Err("truncated HTTP body");
        body.resize(*content_length);
    }
    if (code != 200) {
        return Result<std::string>::Err("Bitcoin Core RPC returned HTTP " + std::to_string(code) + ": " + body);
    }
    return Result<std::string>::Ok(std::move(body));
}

Result<std::vector<std::byte>> ParseHexBytes(std::string_view hex)
{
    if ((hex.size() & 1U) != 0) return Result<std::vector<std::byte>>::Err("hex string has odd length");
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    std::vector<std::byte> output;
    output.reserve(hex.size() / 2);
    for (std::size_t i{0}; i < hex.size(); i += 2) {
        const int high{digit(hex[i])};
        const int low{digit(hex[i + 1])};
        if (high < 0 || low < 0) return Result<std::vector<std::byte>>::Err("invalid script hex");
        output.push_back(static_cast<std::byte>((high << 4) | low));
    }
    return Result<std::vector<std::byte>>::Ok(std::move(output));
}

Result<Hash256> JsonBitcoinHash(const UniValue& value, std::string_view field)
{
    if (!value.isStr()) return Result<Hash256>::Err(std::string{field} + " must be a hex string");
    auto hash{Hash256::FromBitcoinHex(value.get_str())};
    if (!hash) return Result<Hash256>::Err(std::string{field} + ": " + hash.Error());
    return hash;
}

bool IsBip30UnspendableCoinbase(uint32_t height, const Hash256& hash)
{
    if (height == 91722) {
        static const Hash256 expected{Hash256::FromBitcoinHex("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e").Value()};
        return hash == expected;
    }
    if (height == 91812) {
        static const Hash256 expected{Hash256::FromBitcoinHex("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f").Value()};
        return hash == expected;
    }
    return false;
}

Result<TxOut> JsonTxOut(const UniValue& object)
{
    if (!object.isObject()) return Result<TxOut>::Err("txout must be an object");
    const UniValue& script{object.find_value("scriptPubKey")};
    if (!script.isObject() || !script.exists("hex") || !script["hex"].isStr()) {
        return Result<TxOut>::Err("txout scriptPubKey.hex is missing");
    }
    auto amount{ParseBitcoinAmount(object.find_value("value"))};
    if (!amount) return Result<TxOut>::Err(amount.Error());
    auto bytes{ParseHexBytes(script["hex"].get_str())};
    if (!bytes) return Result<TxOut>::Err(bytes.Error());
    return Result<TxOut>::Ok(TxOut{amount.Value(), bytes.Take()});
}

} // namespace

Result<std::string> ReadCookieAuthorization(const std::filesystem::path& cookie_file)
{
    std::ifstream input{cookie_file};
    if (!input) return Result<std::string>::Err("could not open Bitcoin Core cookie file");
    std::string cookie;
    std::getline(input, cookie);
    if (cookie.empty() || cookie.find(':') == std::string::npos) {
        return Result<std::string>::Err("Bitcoin Core cookie is malformed");
    }
    return Result<std::string>::Ok(std::move(cookie));
}

HttpRpcTransport::HttpRpcTransport(HttpRpcConfig config) : m_config{std::move(config)} {}

Result<std::string> HttpRpcTransport::Post(std::string body)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw_addresses{nullptr};
    const std::string port{std::to_string(m_config.port)};
    const int lookup{::getaddrinfo(m_config.host.c_str(), port.c_str(), &hints, &raw_addresses)};
    if (lookup != 0) return Result<std::string>::Err("RPC address lookup failed: " + std::string{gai_strerror(lookup)});
    AddressInfo addresses{raw_addresses};

    FileDescriptor socket;
    for (addrinfo* address{addresses.Get()}; address; address = address->ai_next) {
        FileDescriptor candidate{::socket(address->ai_family, address->ai_socktype | SOCK_CLOEXEC, address->ai_protocol)};
        if (!candidate) continue;
        const timeval timeout{m_config.timeout_seconds, 0};
        static_cast<void>(::setsockopt(candidate.Get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        static_cast<void>(::setsockopt(candidate.Get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)));
        if (::connect(candidate.Get(), address->ai_addr, address->ai_addrlen) == 0) {
            socket = std::move(candidate);
            break;
        }
    }
    if (!socket) return Result<std::string>::Err("could not connect to Bitcoin Core RPC");

    std::ostringstream request;
    request << "POST " << m_config.path << " HTTP/1.1\r\n"
            << "Host: " << m_config.host << ':' << m_config.port << "\r\n"
            << "Authorization: Basic " << Base64Encode(m_config.authorization) << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n"
            << "Connection: close\r\n\r\n"
            << body;
    const std::string wire{request.str()};
    std::size_t sent{0};
    while (sent < wire.size()) {
        const ssize_t result{::send(socket.Get(), wire.data() + sent, wire.size() - sent, MSG_NOSIGNAL)};
        if (result <= 0) return Result<std::string>::Err("sending RPC request failed: " + std::string{std::strerror(errno)});
        sent += static_cast<std::size_t>(result);
    }

    std::string response;
    std::array<char, 64U * 1024U> buffer{};
    while (true) {
        const ssize_t received{::recv(socket.Get(), buffer.data(), buffer.size(), 0)};
        if (received == 0) break;
        if (received < 0) return Result<std::string>::Err("reading RPC response failed: " + std::string{std::strerror(errno)});
        if (response.size() + static_cast<std::size_t>(received) > m_config.max_response_bytes) {
            return Result<std::string>::Err("RPC response exceeds configured size limit");
        }
        response.append(buffer.data(), static_cast<std::size_t>(received));
    }
    return ParseHttpResponse(std::move(response));
}

CoreRpcClient::CoreRpcClient(std::unique_ptr<RpcTransport> transport) : m_transport{std::move(transport)} {}

void CoreRpcClient::RecordLastCall()
{
    ++m_aggregate.calls;
    if (!m_last_call.success) ++m_aggregate.failures;
    m_aggregate.request_bytes += m_last_call.request_bytes;
    m_aggregate.response_bytes += m_last_call.response_bytes;
    m_aggregate.elapsed_us += m_last_call.elapsed_us;
    if (m_last_call.response_bytes > m_aggregate.largest_response_bytes) {
        m_aggregate.largest_response_bytes = m_last_call.response_bytes;
        m_aggregate.largest_response_method = m_last_call.method;
    }
    if (m_last_call.elapsed_us > m_aggregate.slowest_call_us) {
        m_aggregate.slowest_call_us = m_last_call.elapsed_us;
        m_aggregate.slowest_call_method = m_last_call.method;
    }
}

Result<UniValue> CoreRpcClient::Call(const std::string& method, UniValue parameters)
{
    if (!m_transport) {
        m_last_call = RpcCallMetrics{.method = method};
        RecordLastCall();
        return Result<UniValue>::Err("RPC transport is not configured");
    }
    UniValue request{UniValue::VOBJ};
    request.pushKV("jsonrpc", "1.0");
    request.pushKV("id", ++m_request_id);
    request.pushKV("method", method);
    request.pushKV("params", std::move(parameters));
    const std::string request_body{request.write()};
    m_last_call = RpcCallMetrics{
        .method = method,
        .request_bytes = request_body.size(),
    };
    const auto start{std::chrono::steady_clock::now()};
    auto body{m_transport->Post(request_body)};
    m_last_call.elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start).count());
    if (!body) {
        if (LogEnabled(LogLevel::WARN)) {
            Log(LogLevel::WARN, "rpc_call_failed",
                "method=" + method +
                " request_bytes=" + std::to_string(m_last_call.request_bytes) +
                " response_bytes=0 elapsed_us=" + std::to_string(m_last_call.elapsed_us) +
                " attempts=1 retries=0 error=" + Quoted(body.Error()));
        }
        RecordLastCall();
        return Result<UniValue>::Err(body.Error());
    }
    m_last_call.response_bytes = body.Value().size();

    UniValue response;
    if (!response.read(body.Value()) || !response.isObject()) {
        Log(LogLevel::WARN, "rpc_response_invalid",
            "method=" + method + " response_bytes=" + std::to_string(m_last_call.response_bytes));
        RecordLastCall();
        return Result<UniValue>::Err("Bitcoin Core returned invalid JSON-RPC");
    }
    const UniValue& error{response.find_value("error")};
    if (!error.isNull()) {
        Log(LogLevel::WARN, "rpc_response_error",
            "method=" + method + " response_bytes=" + std::to_string(m_last_call.response_bytes) +
            " error=" + Quoted(error.write()));
        RecordLastCall();
        return Result<UniValue>::Err("Bitcoin Core RPC error: " + error.write());
    }
    if (!response.exists("result")) {
        Log(LogLevel::WARN, "rpc_response_invalid",
            "method=" + method + " reason=missing_result response_bytes=" +
            std::to_string(m_last_call.response_bytes));
        RecordLastCall();
        return Result<UniValue>::Err("Bitcoin Core RPC response has no result");
    }
    m_last_call.success = true;
    if (LogEnabled(LogLevel::TRACE)) {
        Log(LogLevel::TRACE, "rpc_call",
            "method=" + method +
            " request_bytes=" + std::to_string(m_last_call.request_bytes) +
            " response_bytes=" + std::to_string(m_last_call.response_bytes) +
            " elapsed_us=" + std::to_string(m_last_call.elapsed_us) +
            " attempts=1 retries=0 status=ok");
    }
    RecordLastCall();
    return Result<UniValue>::Ok(response.find_value("result"));
}

CoreRpcBlockSource::CoreRpcBlockSource(CoreRpcClient client) : m_client{std::move(client)} {}

Result<uint32_t> CoreRpcBlockSource::TipHeight()
{
    auto result{m_client.Call("getblockcount")};
    if (!result) return Result<uint32_t>::Err(result.Error());
    try {
        return Result<uint32_t>::Ok(result.Value().getInt<uint32_t>());
    } catch (const std::exception& error) {
        return Result<uint32_t>::Err("invalid getblockcount result: " + std::string{error.what()});
    }
}

Result<Hash256> CoreRpcBlockSource::BlockHash(uint32_t height)
{
    UniValue parameters{UniValue::VARR};
    parameters.push_back(height);
    auto result{m_client.Call("getblockhash", std::move(parameters))};
    if (!result) return Result<Hash256>::Err(result.Error());
    return JsonBitcoinHash(result.Value(), "getblockhash result");
}

Result<UniValue> CoreRpcBlockSource::BlockWithPrevouts(const Hash256& hash)
{
    UniValue parameters{UniValue::VARR};
    parameters.push_back(hash.ToBitcoinHex());
    parameters.push_back(3);
    auto result{m_client.Call("getblock", std::move(parameters))};
    const auto& metrics{m_client.LastCallMetrics()};
    if (result && metrics.response_bytes > m_largest_block_response_bytes) {
        m_largest_block_response_bytes = metrics.response_bytes;
        m_largest_block_response_elapsed_us = metrics.elapsed_us;
        m_largest_block_response_hash = hash;
        if (LogEnabled(LogLevel::DEBUG)) {
            Log(LogLevel::DEBUG, "rpc_largest_block_response",
                "block_hash=" + hash.ToBitcoinHex() +
                " response_bytes=" + std::to_string(metrics.response_bytes) +
                " elapsed_us=" + std::to_string(metrics.elapsed_us));
        }
    }
    return result;
}

Result<uint64_t> ParseBitcoinAmount(const UniValue& value)
{
    if (!value.isNum()) return Result<uint64_t>::Err("Bitcoin amount must be a JSON number");
    std::string_view text{value.getValStr()};
    if (text.empty() || text.front() == '-') return Result<uint64_t>::Err("Bitcoin amount must be non-negative");
    const std::size_t dot{text.find('.')};
    const std::string_view whole{text.substr(0, dot)};
    std::string_view fraction{dot == std::string_view::npos ? std::string_view{} : text.substr(dot + 1)};
    if (whole.empty() || fraction.size() > 8 || text.find_first_of("eE+") != std::string_view::npos) {
        return Result<uint64_t>::Err("Bitcoin amount has invalid precision or notation");
    }
    uint64_t coins{0};
    const auto [whole_end, whole_error]{std::from_chars(whole.data(), whole.data() + whole.size(), coins)};
    if (whole_error != std::errc{} || whole_end != whole.data() + whole.size() || coins > 21'000'000) {
        return Result<uint64_t>::Err("Bitcoin amount is out of range");
    }
    uint64_t fractional{0};
    if (!fraction.empty()) {
        const auto [fraction_end, fraction_error]{std::from_chars(fraction.data(), fraction.data() + fraction.size(), fractional)};
        if (fraction_error != std::errc{} || fraction_end != fraction.data() + fraction.size()) {
            return Result<uint64_t>::Err("Bitcoin amount has invalid fractional digits");
        }
    }
    for (std::size_t i{fraction.size()}; i < 8; ++i) fractional *= 10;
    const uint64_t satoshis{coins * 100'000'000 + fractional};
    if (satoshis > 21'000'000ULL * 100'000'000ULL) {
        return Result<uint64_t>::Err("Bitcoin amount is out of range");
    }
    return Result<uint64_t>::Ok(satoshis);
}

Result<BlockDelta> ParseVerboseBlock(const UniValue& block,
                                     const BlockHashResolver& block_hash_at_height)
{
    try {
        if (!block.isObject()) return Result<BlockDelta>::Err("getblock result must be an object");
        auto block_hash{JsonBitcoinHash(block.find_value("hash"), "block hash")};
        if (!block_hash) return Result<BlockDelta>::Err(block_hash.Error());
        const uint32_t height{block.find_value("height").getInt<uint32_t>()};
        Hash256 previous{};
        if (height > 0) {
            auto parsed{JsonBitcoinHash(block.find_value("previousblockhash"), "previous block hash")};
            if (!parsed) return Result<BlockDelta>::Err(parsed.Error());
            previous = parsed.Value();
        }
        const UniValue& transactions{block.find_value("tx")};
        if (!transactions.isArray() || transactions.empty()) return Result<BlockDelta>::Err("block has no transactions");

        std::vector<std::optional<Hash256>> additions;
        std::vector<Hash256> deletions;
        std::vector<CompactLeafData> proof_leaves;
        std::map<OutPoint, std::size_t> same_block_outputs;
        const bool skip_bip30_coinbase{IsBip30UnspendableCoinbase(height, block_hash.Value())};

        for (std::size_t tx_index{0}; tx_index < transactions.size(); ++tx_index) {
            const UniValue& transaction{transactions[tx_index]};
            auto txid{JsonBitcoinHash(transaction.find_value("txid"), "transaction id")};
            if (!txid) return Result<BlockDelta>::Err(txid.Error());
            const bool coinbase{tx_index == 0};
            const UniValue& inputs{transaction.find_value("vin")};
            const UniValue& outputs{transaction.find_value("vout")};
            if (!inputs.isArray() || !outputs.isArray()) return Result<BlockDelta>::Err("transaction vin/vout must be arrays");

            if (!coinbase) {
                for (const UniValue& input : inputs.getValues()) {
                    auto previous_txid{JsonBitcoinHash(input.find_value("txid"), "input txid")};
                    if (!previous_txid) return Result<BlockDelta>::Err(previous_txid.Error());
                    const OutPoint outpoint{previous_txid.Value(), input.find_value("vout").getInt<uint32_t>()};
                    if (const auto local{same_block_outputs.find(outpoint)}; local != same_block_outputs.end()) {
                        additions[local->second].reset();
                        same_block_outputs.erase(local);
                        continue;
                    }

                    const UniValue& prevout{input.find_value("prevout")};
                    if (!prevout.isObject()) {
                        return Result<BlockDelta>::Err("getblock verbosity 3 did not provide an input prevout; Core must be unpruned with undo data");
                    }
                    const uint32_t creation_height{prevout.find_value("height").getInt<uint32_t>()};
                    if (creation_height == 0) {
                        return Result<BlockDelta>::Err("input prevout claims genesis creation height");
                    }
                    auto creation_hash{block_hash_at_height(creation_height)};
                    if (!creation_hash) return Result<BlockDelta>::Err("creation block hash lookup failed: " + creation_hash.Error());
                    auto output{JsonTxOut(prevout)};
                    if (!output) return Result<BlockDelta>::Err(output.Error());
                    LeafData leaf{
                        .block_hash = creation_hash.Value(),
                        .outpoint = outpoint,
                        .block_height = creation_height,
                        .coinbase = prevout.find_value("generated").get_bool(),
                        .output = output.Take(),
                    };
                    deletions.push_back(LeafHash(leaf));
                    proof_leaves.push_back(CompactLeaf(leaf));
                }
            }

            if (height == 0 || (coinbase && skip_bip30_coinbase)) continue;
            for (const UniValue& output_json : outputs.getValues()) {
                const uint32_t index{output_json.find_value("n").getInt<uint32_t>()};
                auto output{JsonTxOut(output_json)};
                if (!output) return Result<BlockDelta>::Err(output.Error());
                if (IsProvablyUnspendable(output.Value())) continue;
                const OutPoint outpoint{txid.Value(), index};
                additions.emplace_back(LeafHash(LeafData{
                    .block_hash = block_hash.Value(),
                    .outpoint = outpoint,
                    .block_height = height,
                    .coinbase = coinbase,
                    .output = output.Take(),
                }));
                same_block_outputs.emplace(outpoint, additions.size() - 1);
            }
        }

        BlockDelta delta{
            .point = ChainPoint{height, block_hash.Value()},
            .previous_block_hash = previous,
            .additions = {},
            .deletions = std::move(deletions),
            .proof_leaves = std::move(proof_leaves),
        };
        delta.additions.reserve(additions.size());
        for (auto& hash : additions) if (hash) delta.additions.push_back(*hash);
        return Result<BlockDelta>::Ok(std::move(delta));
    } catch (const std::exception& error) {
        return Result<BlockDelta>::Err("invalid getblock verbosity-3 response: " + std::string{error.what()});
    }
}

} // namespace utreexo
