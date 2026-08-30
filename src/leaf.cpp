// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/leaf.h>

#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace utreexo {
namespace {

constexpr std::array<std::byte, 64> UTREEXO_TAG_V1{
    std::byte{0x5b}, std::byte{0x83}, std::byte{0x2d}, std::byte{0xb8}, std::byte{0xca}, std::byte{0x26}, std::byte{0xc2}, std::byte{0x5b},
    std::byte{0xe1}, std::byte{0xc5}, std::byte{0x42}, std::byte{0xd6}, std::byte{0xcc}, std::byte{0xed}, std::byte{0xdd}, std::byte{0xa8},
    std::byte{0xc1}, std::byte{0x45}, std::byte{0x61}, std::byte{0x5c}, std::byte{0xff}, std::byte{0x5c}, std::byte{0x35}, std::byte{0x72},
    std::byte{0x7f}, std::byte{0xb3}, std::byte{0x46}, std::byte{0x26}, std::byte{0x10}, std::byte{0x80}, std::byte{0x7e}, std::byte{0x20},
    std::byte{0xae}, std::byte{0x53}, std::byte{0x4d}, std::byte{0xc3}, std::byte{0xf6}, std::byte{0x42}, std::byte{0x99}, std::byte{0x19},
    std::byte{0x99}, std::byte{0x31}, std::byte{0x77}, std::byte{0x2e}, std::byte{0x03}, std::byte{0x78}, std::byte{0x7d}, std::byte{0x18},
    std::byte{0x15}, std::byte{0x6e}, std::byte{0xb3}, std::byte{0x15}, std::byte{0x1e}, std::byte{0x0e}, std::byte{0xd1}, std::byte{0xb3},
    std::byte{0x09}, std::byte{0x8b}, std::byte{0xdc}, std::byte{0x84}, std::byte{0x45}, std::byte{0x86}, std::byte{0x18}, std::byte{0x85},
};

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & static_cast<T>(0xff)));
        value >>= 8;
    }
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

Result<std::vector<std::byte>> LastScriptPush(std::span<const std::byte> script)
{
    if (script.empty()) return Result<std::vector<std::byte>>::Err("empty scriptSig stack");
    std::size_t cursor{0};
    std::optional<std::vector<std::byte>> last_push;
    bool last_was_push{false};
    while (cursor < script.size()) {
        const uint8_t opcode{std::to_integer<uint8_t>(script[cursor++])};
        uint64_t length{0};
        if (opcode <= 75) {
            length = opcode;
        } else if (opcode == 76) {
            if (cursor == script.size()) return Result<std::vector<std::byte>>::Err("truncated OP_PUSHDATA1");
            length = std::to_integer<uint8_t>(script[cursor++]);
        } else if (opcode == 77) {
            if (script.size() - cursor < 2) return Result<std::vector<std::byte>>::Err("truncated OP_PUSHDATA2");
            length = std::to_integer<uint8_t>(script[cursor]) |
                     (static_cast<uint64_t>(std::to_integer<uint8_t>(script[cursor + 1])) << 8);
            cursor += 2;
        } else if (opcode == 78) {
            if (script.size() - cursor < 4) return Result<std::vector<std::byte>>::Err("truncated OP_PUSHDATA4");
            for (int i{0}; i < 4; ++i) {
                length |= static_cast<uint64_t>(std::to_integer<uint8_t>(script[cursor + static_cast<std::size_t>(i)])) << (i * 8);
            }
            cursor += 4;
        } else {
            last_push.reset();
            last_was_push = false;
            continue;
        }
        if (length > script.size() - cursor) return Result<std::vector<std::byte>>::Err("push extends past scriptSig");
        last_push.emplace(script.begin() + static_cast<std::ptrdiff_t>(cursor),
                          script.begin() + static_cast<std::ptrdiff_t>(cursor + static_cast<std::size_t>(length)));
        cursor += static_cast<std::size_t>(length);
        last_was_push = true;
    }
    if (!last_was_push || !last_push) return Result<std::vector<std::byte>>::Err("last scriptSig instruction is not a push");
    return Result<std::vector<std::byte>>::Ok(std::move(*last_push));
}

std::vector<std::byte> P2pkh(std::span<const std::byte, 20> hash)
{
    std::vector<std::byte> script{std::byte{0x76}, std::byte{0xa9}, std::byte{0x14}};
    script.insert(script.end(), hash.begin(), hash.end());
    script.push_back(std::byte{0x88});
    script.push_back(std::byte{0xac});
    return script;
}

std::vector<std::byte> P2sh(std::span<const std::byte, 20> hash)
{
    std::vector<std::byte> script{std::byte{0xa9}, std::byte{0x14}};
    script.insert(script.end(), hash.begin(), hash.end());
    script.push_back(std::byte{0x87});
    return script;
}

std::vector<std::byte> WitnessProgram(std::span<const std::byte> hash)
{
    std::vector<std::byte> script{std::byte{0x00}, static_cast<std::byte>(hash.size())};
    script.insert(script.end(), hash.begin(), hash.end());
    return script;
}

} // namespace

Hash256 LeafHash(const LeafData& leaf)
{
    const std::size_t size{UTREEXO_TAG_V1.size() * 2 + 32 + 32 + 4 + 4 + 8 + 9 +
                           leaf.output.script_pubkey.size()};
    std::vector<std::byte> serialized;
    serialized.reserve(size);
    serialized.insert(serialized.end(), UTREEXO_TAG_V1.begin(), UTREEXO_TAG_V1.end());
    serialized.insert(serialized.end(), UTREEXO_TAG_V1.begin(), UTREEXO_TAG_V1.end());
    serialized.insert(serialized.end(), leaf.block_hash.Bytes().begin(), leaf.block_hash.Bytes().end());
    serialized.insert(serialized.end(), leaf.outpoint.txid.Bytes().begin(), leaf.outpoint.txid.Bytes().end());
    AppendLE(serialized, leaf.outpoint.index);
    AppendLE(serialized, static_cast<uint32_t>((leaf.block_height << 1) | (leaf.coinbase ? 1U : 0U)));
    AppendLE(serialized, leaf.output.value);
    AppendCompactSize(serialized, leaf.output.script_pubkey.size());
    serialized.insert(serialized.end(), leaf.output.script_pubkey.begin(), leaf.output.script_pubkey.end());
    return Sha512_256(serialized);
}

CompactLeafData CompactLeaf(const LeafData& leaf)
{
    const auto& script{leaf.output.script_pubkey};
    ScriptPubkeyType type{ScriptPubkeyType::OTHER};
    if (script.size() == 25 && script[0] == std::byte{0x76} && script[1] == std::byte{0xa9} &&
        script[2] == std::byte{0x14} && script[23] == std::byte{0x88} && script[24] == std::byte{0xac}) {
        type = ScriptPubkeyType::PUBKEY_HASH;
    } else if (script.size() == 23 && script[0] == std::byte{0xa9} && script[1] == std::byte{0x14} &&
               script[22] == std::byte{0x87}) {
        type = ScriptPubkeyType::SCRIPT_HASH;
    } else if (script.size() == 22 && script[0] == std::byte{0x00} && script[1] == std::byte{0x14}) {
        type = ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH;
    } else if (script.size() == 34 && script[0] == std::byte{0x00} && script[1] == std::byte{0x20}) {
        type = ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH;
    }
    return CompactLeafData{
        .header_code = static_cast<uint32_t>((leaf.block_height << 1) | (leaf.coinbase ? 1U : 0U)),
        .amount = leaf.output.value,
        .script_type = type,
        .script = type == ScriptPubkeyType::OTHER ? script : std::vector<std::byte>{},
    };
}

Result<std::vector<std::byte>> ReconstructScriptPubkey(const CompactLeafData& leaf,
                                                       const SpendingInput& input)
{
    switch (leaf.script_type) {
    case ScriptPubkeyType::OTHER:
        return Result<std::vector<std::byte>>::Ok(leaf.script);
    case ScriptPubkeyType::PUBKEY_HASH: {
        auto pushed{LastScriptPush(input.script_sig)};
        if (!pushed) return Result<std::vector<std::byte>>::Err(pushed.Error());
        return Result<std::vector<std::byte>>::Ok(P2pkh(Hash160(pushed.Value())));
    }
    case ScriptPubkeyType::SCRIPT_HASH: {
        auto pushed{LastScriptPush(input.script_sig)};
        if (!pushed) return Result<std::vector<std::byte>>::Err(pushed.Error());
        return Result<std::vector<std::byte>>::Ok(P2sh(Hash160(pushed.Value())));
    }
    case ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH:
        if (input.witness.empty()) return Result<std::vector<std::byte>>::Err("empty witness stack");
        return Result<std::vector<std::byte>>::Ok(WitnessProgram(Hash160(input.witness.back())));
    case ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH:
        if (input.witness.empty()) return Result<std::vector<std::byte>>::Err("empty witness stack");
        return Result<std::vector<std::byte>>::Ok(WitnessProgram(Sha256(input.witness.back()).Span()));
    }
    return Result<std::vector<std::byte>>::Err("unknown compact script type");
}

bool IsProvablyUnspendable(const TxOut& output)
{
    constexpr std::size_t MAX_SCRIPT_SIZE{10'000};
    constexpr std::byte OP_RETURN{0x6a};
    return output.script_pubkey.size() > MAX_SCRIPT_SIZE ||
           (!output.script_pubkey.empty() && output.script_pubkey.front() == OP_RETURN);
}

} // namespace utreexo
