// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/core_rpc.h>

#include <charconv>
#include <cctype>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace utreexo {
namespace {

class JsonCursor
{
public:
    explicit JsonCursor(std::string_view input) : m_input{input} {}

    void Whitespace()
    {
        while (m_position < m_input.size() &&
               (m_input[m_position] == ' ' || m_input[m_position] == '\n' ||
                m_input[m_position] == '\r' || m_input[m_position] == '\t')) {
            ++m_position;
        }
    }

    bool Consume(char value)
    {
        Whitespace();
        if (m_position == m_input.size() || m_input[m_position] != value) return false;
        ++m_position;
        return true;
    }

    char Peek()
    {
        Whitespace();
        return m_position == m_input.size() ? '\0' : m_input[m_position];
    }

    std::size_t Position()
    {
        Whitespace();
        return m_position;
    }

    std::string_view Slice(std::size_t begin, std::size_t end) const
    {
        return m_input.substr(begin, end - begin);
    }

    bool Finished()
    {
        Whitespace();
        return m_position == m_input.size();
    }

    Result<std::string> String()
    {
        Whitespace();
        if (m_position == m_input.size() || m_input[m_position++] != '"') {
            return Result<std::string>::Err("expected JSON string");
        }
        std::string output;
        while (m_position < m_input.size()) {
            const unsigned char value{static_cast<unsigned char>(m_input[m_position++])};
            if (value == '"') return Result<std::string>::Ok(std::move(output));
            if (value < 0x20) return Result<std::string>::Err("unescaped control byte in JSON string");
            if (value != '\\') {
                output.push_back(static_cast<char>(value));
                continue;
            }
            if (m_position == m_input.size()) return Result<std::string>::Err("truncated JSON escape");
            const char escaped{m_input[m_position++]};
            switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u': {
                if (m_input.size() - m_position < 4) {
                    return Result<std::string>::Err("truncated JSON unicode escape");
                }
                unsigned codepoint{0};
                for (int i{0}; i < 4; ++i) {
                    const char digit{m_input[m_position++]};
                    codepoint <<= 4;
                    if (digit >= '0' && digit <= '9') codepoint |= static_cast<unsigned>(digit - '0');
                    else if (digit >= 'a' && digit <= 'f') codepoint |= static_cast<unsigned>(digit - 'a' + 10);
                    else if (digit >= 'A' && digit <= 'F') codepoint |= static_cast<unsigned>(digit - 'A' + 10);
                    else return Result<std::string>::Err("invalid JSON unicode escape");
                }
                // Bitcoin Core's field names are ASCII. Supporting their escaped
                // form keeps projection correct without needing surrogate handling.
                if (codepoint > 0x7f) {
                    return Result<std::string>::Err("non-ASCII escaped JSON object key");
                }
                output.push_back(static_cast<char>(codepoint));
                break;
            }
            default: return Result<std::string>::Err("invalid JSON string escape");
            }
        }
        return Result<std::string>::Err("unterminated JSON string");
    }

    Result<void> SkipValue(unsigned depth = 0)
    {
        if (depth > 64) return Result<void>::Err("JSON nesting exceeds limit");
        Whitespace();
        if (m_position == m_input.size()) return Result<void>::Err("missing JSON value");
        switch (m_input[m_position]) {
        case '"': return SkipString();
        case '{': {
            ++m_position;
            Whitespace();
            if (Consume('}')) return Result<void>::Ok();
            while (true) {
                auto key{String()};
                if (!key) return Result<void>::Err(key.Error());
                if (!Consume(':')) return Result<void>::Err("missing colon in JSON object");
                auto skipped{SkipValue(depth + 1)};
                if (!skipped) return skipped;
                if (Consume('}')) return Result<void>::Ok();
                if (!Consume(',')) return Result<void>::Err("missing comma in JSON object");
            }
        }
        case '[': {
            ++m_position;
            Whitespace();
            if (Consume(']')) return Result<void>::Ok();
            while (true) {
                auto skipped{SkipValue(depth + 1)};
                if (!skipped) return skipped;
                if (Consume(']')) return Result<void>::Ok();
                if (!Consume(',')) return Result<void>::Err("missing comma in JSON array");
            }
        }
        case 't': return Literal("true");
        case 'f': return Literal("false");
        case 'n': return Literal("null");
        default: return SkipNumber();
        }
    }

private:
    Result<void> SkipString()
    {
        if (m_input[m_position++] != '"') return Result<void>::Err("expected JSON string");
        while (m_position < m_input.size()) {
            const unsigned char value{static_cast<unsigned char>(m_input[m_position++])};
            if (value == '"') return Result<void>::Ok();
            if (value < 0x20) return Result<void>::Err("unescaped control byte in JSON string");
            if (value != '\\') continue;
            if (m_position == m_input.size()) return Result<void>::Err("truncated JSON escape");
            const char escaped{m_input[m_position++]};
            if (escaped == 'u') {
                if (m_input.size() - m_position < 4) {
                    return Result<void>::Err("truncated JSON unicode escape");
                }
                for (int i{0}; i < 4; ++i) {
                    if (!std::isxdigit(static_cast<unsigned char>(m_input[m_position++]))) {
                        return Result<void>::Err("invalid JSON unicode escape");
                    }
                }
            } else if (std::string_view{"\"\\/bfnrt"}.find(escaped) == std::string_view::npos) {
                return Result<void>::Err("invalid JSON string escape");
            }
        }
        return Result<void>::Err("unterminated JSON string");
    }

    Result<void> Literal(std::string_view literal)
    {
        if (m_input.substr(m_position, literal.size()) != literal) {
            return Result<void>::Err("invalid JSON literal");
        }
        m_position += literal.size();
        return Result<void>::Ok();
    }

    Result<void> SkipNumber()
    {
        const std::size_t begin{m_position};
        if (m_input[m_position] == '-') ++m_position;
        if (m_position == m_input.size()) return Result<void>::Err("truncated JSON number");
        if (m_input[m_position] == '0') {
            ++m_position;
        } else {
            if (m_input[m_position] < '1' || m_input[m_position] > '9') {
                return Result<void>::Err("invalid JSON number");
            }
            while (m_position < m_input.size() && std::isdigit(static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
        }
        if (m_position < m_input.size() && m_input[m_position] == '.') {
            ++m_position;
            const std::size_t fraction{m_position};
            while (m_position < m_input.size() && std::isdigit(static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
            if (fraction == m_position) return Result<void>::Err("invalid JSON fraction");
        }
        if (m_position < m_input.size() && (m_input[m_position] == 'e' || m_input[m_position] == 'E')) {
            ++m_position;
            if (m_position < m_input.size() && (m_input[m_position] == '+' || m_input[m_position] == '-')) {
                ++m_position;
            }
            const std::size_t exponent{m_position};
            while (m_position < m_input.size() && std::isdigit(static_cast<unsigned char>(m_input[m_position]))) {
                ++m_position;
            }
            if (exponent == m_position) return Result<void>::Err("invalid JSON exponent");
        }
        if (begin == m_position) return Result<void>::Err("invalid JSON value");
        return Result<void>::Ok();
    }

    std::string_view m_input;
    std::size_t m_position{0};
};

enum class Projection : uint8_t {
    BLOCK,
    TRANSACTION,
    INPUT,
    PREVOUT,
    OUTPUT,
    SCRIPT,
};

struct FieldProjection {
    enum class Kind : uint8_t { SCALAR, OBJECT, ARRAY } kind{Kind::SCALAR};
    Projection child{Projection::BLOCK};
};

std::optional<FieldProjection> ProjectedField(Projection projection, std::string_view key)
{
    using Kind = FieldProjection::Kind;
    switch (projection) {
    case Projection::BLOCK:
        if (key == "hash" || key == "height" || key == "previousblockhash") return FieldProjection{};
        if (key == "tx") return FieldProjection{Kind::ARRAY, Projection::TRANSACTION};
        break;
    case Projection::TRANSACTION:
        if (key == "txid") return FieldProjection{};
        if (key == "vin") return FieldProjection{Kind::ARRAY, Projection::INPUT};
        if (key == "vout") return FieldProjection{Kind::ARRAY, Projection::OUTPUT};
        break;
    case Projection::INPUT:
        if (key == "txid" || key == "vout") return FieldProjection{};
        if (key == "prevout") return FieldProjection{Kind::OBJECT, Projection::PREVOUT};
        break;
    case Projection::PREVOUT:
        if (key == "generated" || key == "height" || key == "value") return FieldProjection{};
        if (key == "scriptPubKey") return FieldProjection{Kind::OBJECT, Projection::SCRIPT};
        break;
    case Projection::OUTPUT:
        if (key == "n" || key == "value") return FieldProjection{};
        if (key == "scriptPubKey") return FieldProjection{Kind::OBJECT, Projection::SCRIPT};
        break;
    case Projection::SCRIPT:
        if (key == "hex") return FieldProjection{};
        break;
    }
    return std::nullopt;
}

Result<void> ProjectObject(JsonCursor& cursor, Projection projection, std::string& output);

Result<void> ProjectArray(JsonCursor& cursor, Projection element, std::string& output)
{
    if (!cursor.Consume('[')) return Result<void>::Err("projected JSON field must be an array");
    output.push_back('[');
    bool first{true};
    if (cursor.Consume(']')) {
        output.push_back(']');
        return Result<void>::Ok();
    }
    while (true) {
        if (!first) output.push_back(',');
        auto projected{ProjectObject(cursor, element, output)};
        if (!projected) return projected;
        first = false;
        if (cursor.Consume(']')) {
            output.push_back(']');
            return Result<void>::Ok();
        }
        if (!cursor.Consume(',')) return Result<void>::Err("missing comma in projected JSON array");
    }
}

Result<void> ProjectObject(JsonCursor& cursor, Projection projection, std::string& output)
{
    if (!cursor.Consume('{')) return Result<void>::Err("projected JSON field must be an object");
    output.push_back('{');
    bool first_output{true};
    if (cursor.Consume('}')) {
        output.push_back('}');
        return Result<void>::Ok();
    }
    while (true) {
        auto key{cursor.String()};
        if (!key) return Result<void>::Err(key.Error());
        if (!cursor.Consume(':')) return Result<void>::Err("missing colon in projected JSON object");
        const auto selected{ProjectedField(projection, key.Value())};
        if (!selected) {
            auto skipped{cursor.SkipValue()};
            if (!skipped) return skipped;
        } else {
            if (!first_output) output.push_back(',');
            output.push_back('"');
            output.append(key.Value());
            output.append("\":");
            if (selected->kind == FieldProjection::Kind::SCALAR) {
                const std::size_t begin{cursor.Position()};
                auto skipped{cursor.SkipValue()};
                if (!skipped) return skipped;
                output.append(cursor.Slice(begin, cursor.Position()));
            } else if (selected->kind == FieldProjection::Kind::OBJECT) {
                auto child{ProjectObject(cursor, selected->child, output)};
                if (!child) return child;
            } else {
                auto child{ProjectArray(cursor, selected->child, output)};
                if (!child) return child;
            }
            first_output = false;
        }
        if (cursor.Consume('}')) {
            output.push_back('}');
            return Result<void>::Ok();
        }
        if (!cursor.Consume(',')) return Result<void>::Err("missing comma in projected JSON object");
    }
}

Result<std::string> ProjectVerboseBlock(std::string_view block)
{
    JsonCursor cursor{block};
    std::string projected;
    projected.reserve(std::min<std::size_t>(block.size(), 8U * 1024U * 1024U));
    auto result{ProjectObject(cursor, Projection::BLOCK, projected)};
    if (!result) return Result<std::string>::Err(result.Error());
    if (!cursor.Finished()) return Result<std::string>::Err("trailing data after getblock result");
    return Result<std::string>::Ok(std::move(projected));
}

std::string_view Trim(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
    return value;
}

} // namespace

Result<RawJsonValue> ExtractJsonRpcResult(std::string response)
{
    JsonCursor cursor{response};
    if (!cursor.Consume('{')) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC");
    std::optional<std::pair<std::size_t, std::size_t>> result_span;
    std::optional<std::pair<std::size_t, std::size_t>> error_span;
    if (!cursor.Consume('}')) {
        while (true) {
            auto key{cursor.String()};
            if (!key) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC: " + key.Error());
            if (!cursor.Consume(':')) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC");
            const std::size_t begin{cursor.Position()};
            auto skipped{cursor.SkipValue()};
            if (!skipped) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC: " + skipped.Error());
            const std::size_t end{cursor.Position()};
            if (key.Value() == "result") result_span = std::pair{begin, end};
            if (key.Value() == "error") error_span = std::pair{begin, end};
            if (cursor.Consume('}')) break;
            if (!cursor.Consume(',')) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC");
        }
    }
    if (!cursor.Finished()) return Result<RawJsonValue>::Err("Bitcoin Core returned invalid JSON-RPC");
    if (error_span) {
        const auto error{Trim(std::string_view{response}.substr(
            error_span->first, error_span->second - error_span->first))};
        if (error != "null") {
            return Result<RawJsonValue>::Err("Bitcoin Core RPC error: " + std::string{error});
        }
    }
    if (!result_span) return Result<RawJsonValue>::Err("Bitcoin Core RPC response has no result");
    return Result<RawJsonValue>::Ok(RawJsonValue{
        .json = std::move(response),
        .value_offset = result_span->first,
        .value_size = result_span->second - result_span->first,
    });
}

Result<BlockDelta> ParseVerboseBlockJson(std::string_view block,
                                         const BlockHashResolver& block_hash_at_height)
{
    auto projected{ProjectVerboseBlock(block)};
    if (!projected) {
        return Result<BlockDelta>::Err("invalid streaming getblock response: " + projected.Error());
    }
    UniValue value;
    if (!value.read(projected.Value())) {
        return Result<BlockDelta>::Err("streaming getblock projection produced invalid JSON");
    }
    return ParseVerboseBlock(value, block_hash_at_height);
}

} // namespace utreexo
