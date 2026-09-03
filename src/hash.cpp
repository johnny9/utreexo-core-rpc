// Copyright (c) 2014-2026 The Bitcoin Core and Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/hash.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <vector>

namespace utreexo {
namespace {

constexpr char HEXMAP[]{"0123456789abcdef"};

int HexDigit(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

constexpr std::array<uint64_t, 80> K{
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

constexpr std::array<uint32_t, 64> SHA256_K{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::array<uint8_t, 80> RIPEMD_R_LEFT{
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13,
};
constexpr std::array<uint8_t, 80> RIPEMD_R_RIGHT{
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11,
};
constexpr std::array<uint8_t, 80> RIPEMD_S_LEFT{
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6,
};
constexpr std::array<uint8_t, 80> RIPEMD_S_RIGHT{
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11,
};

uint64_t ReadBE64(const std::byte* input)
{
    uint64_t value{0};
    for (int i{0}; i < 8; ++i) value = (value << 8) | std::to_integer<uint8_t>(input[i]);
    return value;
}

void WriteBE64(std::byte* output, uint64_t value)
{
    for (int i{7}; i >= 0; --i) {
        output[i] = static_cast<std::byte>(value & 0xffU);
        value >>= 8;
    }
}

uint32_t ReadBE32(const std::byte* input)
{
    uint32_t value{0};
    for (int i{0}; i < 4; ++i) value = (value << 8) | std::to_integer<uint8_t>(input[i]);
    return value;
}

uint32_t ReadLE32(const std::byte* input)
{
    uint32_t value{0};
    for (int i{3}; i >= 0; --i) value = (value << 8) | std::to_integer<uint8_t>(input[i]);
    return value;
}

void WriteBE32(std::byte* output, uint32_t value)
{
    for (int i{3}; i >= 0; --i) {
        output[i] = static_cast<std::byte>(value & 0xffU);
        value >>= 8;
    }
}

void WriteLE32(std::byte* output, uint32_t value)
{
    for (int i{0}; i < 4; ++i) {
        output[i] = static_cast<std::byte>(value & 0xffU);
        value >>= 8;
    }
}

void Sha256Transform(std::array<uint32_t, 8>& state, const std::byte* chunk)
{
    std::array<uint32_t, 64> words{};
    for (std::size_t i{0}; i < 16; ++i) words[i] = ReadBE32(chunk + i * 4);
    for (std::size_t i{16}; i < words.size(); ++i) {
        const uint32_t s0{std::rotr(words[i - 15], 7) ^ std::rotr(words[i - 15], 18) ^ (words[i - 15] >> 3)};
        const uint32_t s1{std::rotr(words[i - 2], 17) ^ std::rotr(words[i - 2], 19) ^ (words[i - 2] >> 10)};
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state;
    for (std::size_t i{0}; i < SHA256_K.size(); ++i) {
        const uint32_t sum1{std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25)};
        const uint32_t choose{g ^ (e & (f ^ g))};
        const uint32_t t1{h + sum1 + choose + SHA256_K[i] + words[i]};
        const uint32_t sum0{std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22)};
        const uint32_t majority{(a & b) | (c & (a | b))};
        const uint32_t t2{sum0 + majority};
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

uint32_t RipemdFunction(std::size_t round, uint32_t x, uint32_t y, uint32_t z)
{
    if (round < 16) return x ^ y ^ z;
    if (round < 32) return (x & y) | (~x & z);
    if (round < 48) return (x | ~y) ^ z;
    if (round < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

uint32_t RipemdLeftConstant(std::size_t round)
{
    if (round < 16) return 0x00000000U;
    if (round < 32) return 0x5a827999U;
    if (round < 48) return 0x6ed9eba1U;
    if (round < 64) return 0x8f1bbcdcU;
    return 0xa953fd4eU;
}

uint32_t RipemdRightConstant(std::size_t round)
{
    if (round < 16) return 0x50a28be6U;
    if (round < 32) return 0x5c4dd124U;
    if (round < 48) return 0x6d703ef3U;
    if (round < 64) return 0x7a6d76e9U;
    return 0x00000000U;
}

void Ripemd160Transform(std::array<uint32_t, 5>& state, const std::byte* chunk)
{
    std::array<uint32_t, 16> words{};
    for (std::size_t i{0}; i < words.size(); ++i) words[i] = ReadLE32(chunk + i * 4);
    uint32_t al{state[0]}, bl{state[1]}, cl{state[2]}, dl{state[3]}, el{state[4]};
    uint32_t ar{al}, br{bl}, cr{cl}, dr{dl}, er{el};
    for (std::size_t i{0}; i < 80; ++i) {
        const uint32_t left{std::rotl(al + RipemdFunction(i, bl, cl, dl) +
                                         words[RIPEMD_R_LEFT[i]] + RipemdLeftConstant(i),
                                     RIPEMD_S_LEFT[i]) + el};
        al = el; el = dl; dl = std::rotl(cl, 10); cl = bl; bl = left;
        const uint32_t right{std::rotl(ar + RipemdFunction(79 - i, br, cr, dr) +
                                          words[RIPEMD_R_RIGHT[i]] + RipemdRightConstant(i),
                                      RIPEMD_S_RIGHT[i]) + er};
        ar = er; er = dr; dr = std::rotl(cr, 10); cr = br; br = right;
    }
    const uint32_t temporary{state[1] + cl + dr};
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = temporary;
}

void Transform(std::array<uint64_t, 8>& state, const std::byte* chunk)
{
    std::array<uint64_t, 80> words{};
    for (std::size_t i{0}; i < 16; ++i) words[i] = ReadBE64(chunk + i * 8);
    for (std::size_t i{16}; i < words.size(); ++i) {
        const uint64_t s0{std::rotr(words[i - 15], 1) ^ std::rotr(words[i - 15], 8) ^ (words[i - 15] >> 7)};
        const uint64_t s1{std::rotr(words[i - 2], 19) ^ std::rotr(words[i - 2], 61) ^ (words[i - 2] >> 6)};
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    auto [a, b, c, d, e, f, g, h] = state;
    for (std::size_t i{0}; i < K.size(); ++i) {
        const uint64_t big1{std::rotr(e, 14) ^ std::rotr(e, 18) ^ std::rotr(e, 41)};
        const uint64_t choose{g ^ (e & (f ^ g))};
        const uint64_t t1{h + big1 + choose + K[i] + words[i]};
        const uint64_t big0{std::rotr(a, 28) ^ std::rotr(a, 34) ^ std::rotr(a, 39)};
        const uint64_t majority{(a & b) | (c & (a | b))};
        const uint64_t t2{big0 + majority};
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

} // namespace

Result<Hash256> Hash256::FromHex(std::string_view hex)
{
    if (hex.size() != SIZE * 2) return Result<Hash256>::Err("hash must contain exactly 64 hex digits");
    Storage out{};
    for (std::size_t i{0}; i < SIZE; ++i) {
        const int high{HexDigit(hex[i * 2])};
        const int low{HexDigit(hex[i * 2 + 1])};
        if (high < 0 || low < 0) return Result<Hash256>::Err("hash contains a non-hex character");
        out[i] = static_cast<std::byte>((high << 4) | low);
    }
    return Result<Hash256>::Ok(Hash256{out});
}

Result<Hash256> Hash256::FromBitcoinHex(std::string_view hex)
{
    auto parsed{FromHex(hex)};
    if (!parsed) return parsed;
    auto bytes{parsed.Value().Bytes()};
    std::ranges::reverse(bytes);
    return Result<Hash256>::Ok(Hash256{bytes});
}

std::string Hash256::ToHex() const
{
    std::string out(SIZE * 2, '0');
    for (std::size_t i{0}; i < SIZE; ++i) {
        const auto value{std::to_integer<uint8_t>(m_bytes[i])};
        out[i * 2] = HEXMAP[value >> 4];
        out[i * 2 + 1] = HEXMAP[value & 15U];
    }
    return out;
}

std::string Hash256::ToBitcoinHex() const
{
    Hash256 reversed{m_bytes};
    std::ranges::reverse(reversed.m_bytes);
    return reversed.ToHex();
}

Hash256 Sha512_256(std::span<const std::byte> input)
{
    std::array<uint64_t, 8> state{
        0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL,
        0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
        0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL,
        0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL,
    };

    std::size_t offset{0};
    while (input.size() - offset >= 128) {
        Transform(state, input.data() + offset);
        offset += 128;
    }

    std::array<std::byte, 256> tail{};
    const std::size_t remaining{input.size() - offset};
    if (remaining != 0) std::memcpy(tail.data(), input.data() + offset, remaining);
    tail[remaining] = std::byte{0x80};
    const std::size_t padded_size{remaining < 112 ? 128U : 256U};
    const uint64_t bit_length_low{static_cast<uint64_t>(input.size()) * 8U};
    WriteBE64(tail.data() + padded_size - 16, 0);
    WriteBE64(tail.data() + padded_size - 8, bit_length_low);
    Transform(state, tail.data());
    if (padded_size == 256) Transform(state, tail.data() + 128);

    Hash256::Storage output{};
    for (std::size_t i{0}; i < 4; ++i) WriteBE64(output.data() + i * 8, state[i]);
    return Hash256{output};
}

Hash256 Sha256(std::span<const std::byte> input)
{
    std::array<uint32_t, 8> state{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    std::size_t offset{0};
    while (input.size() - offset >= 64) {
        Sha256Transform(state, input.data() + offset);
        offset += 64;
    }
    std::array<std::byte, 128> tail{};
    const std::size_t remaining{input.size() - offset};
    if (remaining != 0) std::memcpy(tail.data(), input.data() + offset, remaining);
    tail[remaining] = std::byte{0x80};
    const std::size_t padded_size{remaining < 56 ? 64U : 128U};
    WriteBE64(tail.data() + padded_size - 8, static_cast<uint64_t>(input.size()) * 8U);
    Sha256Transform(state, tail.data());
    if (padded_size == 128) Sha256Transform(state, tail.data() + 64);
    Hash256::Storage output{};
    for (std::size_t i{0}; i < state.size(); ++i) WriteBE32(output.data() + i * 4, state[i]);
    return Hash256{output};
}

std::array<std::byte, 20> Hash160(std::span<const std::byte> input)
{
    const Hash256 sha{Sha256(input)};
    std::array<uint32_t, 5> state{0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U};
    std::array<std::byte, 64> block{};
    std::ranges::copy(sha.Bytes(), block.begin());
    block[32] = std::byte{0x80};
    block[56] = std::byte{0x00};
    block[57] = std::byte{0x01}; // 32 bytes * 8, little endian.
    Ripemd160Transform(state, block.data());
    std::array<std::byte, 20> output{};
    for (std::size_t i{0}; i < state.size(); ++i) WriteLE32(output.data() + i * 4, state[i]);
    return output;
}

Hash256 ParentHash(const Hash256& left, const Hash256& right)
{
    std::array<std::byte, 64> input{};
    std::ranges::copy(left.Bytes(), input.begin());
    std::ranges::copy(right.Bytes(), input.begin() + 32);
    return Sha512_256(input);
}

std::size_t Hash256Hasher::operator()(const Hash256& hash) const noexcept
{
    uint64_t value{0};
    std::memcpy(&value, hash.Bytes().data(), sizeof(value));
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33;
    return static_cast<std::size_t>(value);
}

} // namespace utreexo
