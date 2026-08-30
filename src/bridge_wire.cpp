// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/bridge_wire.h>

#include <cstdint>
#include <limits>
#include <type_traits>

namespace utreexo {
namespace {

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    uint64_t accumulator{value};
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(accumulator & 0xffU));
        accumulator >>= 8;
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

} // namespace

Result<std::vector<std::byte>> SerializeUData(const Proof& proof,
                                             std::span<const CompactLeafData> leaves)
{
    if (proof.targets.size() != leaves.size()) {
        return Result<std::vector<std::byte>>::Err("proof target and compact-leaf counts differ");
    }
    std::vector<std::byte> output;

    AppendCompactSize(output, 0); // remember_idx is not used by the bridge.
    AppendCompactSize(output, proof.targets.size());
    for (const uint64_t target : proof.targets) AppendCompactSize(output, target);
    AppendCompactSize(output, proof.hashes.size());
    for (const auto& hash : proof.hashes) {
        output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
    }
    AppendCompactSize(output, leaves.size());
    for (const auto& leaf : leaves) {
        AppendLE(output, leaf.header_code);
        AppendLE(output, leaf.amount);
        output.push_back(static_cast<std::byte>(leaf.script_type));
        if (leaf.script_type == ScriptPubkeyType::OTHER) {
            AppendCompactSize(output, leaf.script.size());
            output.insert(output.end(), leaf.script.begin(), leaf.script.end());
        } else if (!leaf.script.empty()) {
            return Result<std::vector<std::byte>>::Err("standard compact leaf unexpectedly contains a script");
        }
    }
    return Result<std::vector<std::byte>>::Ok(std::move(output));
}

} // namespace utreexo
