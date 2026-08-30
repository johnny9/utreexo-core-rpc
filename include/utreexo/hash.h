// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_HASH_H
#define UTREEXO_HASH_H

#include <utreexo/result.h>

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace utreexo {

class Hash256
{
public:
    static constexpr std::size_t SIZE{32};
    using Storage = std::array<std::byte, SIZE>;

    constexpr Hash256() = default;
    explicit constexpr Hash256(Storage bytes) : m_bytes{bytes} {}

    static Result<Hash256> FromHex(std::string_view hex);
    static Result<Hash256> FromBitcoinHex(std::string_view hex);

    std::string ToHex() const;
    std::string ToBitcoinHex() const;
    constexpr const Storage& Bytes() const { return m_bytes; }
    constexpr std::span<const std::byte, SIZE> Span() const { return m_bytes; }
    constexpr bool IsNull() const
    {
        for (const auto byte : m_bytes) if (byte != std::byte{0}) return false;
        return true;
    }

    auto operator<=>(const Hash256&) const = default;

private:
    Storage m_bytes{};
};

Hash256 Sha512_256(std::span<const std::byte> input);
Hash256 Sha256(std::span<const std::byte> input);
std::array<std::byte, 20> Hash160(std::span<const std::byte> input);
Hash256 ParentHash(const Hash256& left, const Hash256& right);

struct Hash256Hasher {
    std::size_t operator()(const Hash256& hash) const noexcept;
};

} // namespace utreexo

#endif // UTREEXO_HASH_H
