#include <test_framework.h>
#include <utreexo/hash.h>

#include <array>
#include <cstddef>

using namespace utreexo;

TEST(hash_hex_roundtrip)
{
    const std::string hex{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
    const auto hash{Hash256::FromHex(hex)};
    CHECK(hash);
    CHECK_EQ(hash.Value().ToHex(), hex);
    CHECK_EQ(hash.Value().ToBitcoinHex(), "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    CHECK(!Hash256::FromHex("ff"));
}

TEST(sha512_256_vectors)
{
    const std::array<std::byte, 0> empty{};
    CHECK_EQ(Sha512_256(empty).ToHex(),
             "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");

    const Hash256 left{Hash256::Storage{}};
    Hash256::Storage right_bytes{};
    right_bytes.fill(std::byte{1});
    CHECK_EQ(ParentHash(left, Hash256{right_bytes}).ToHex(),
             "34e33ca0c40b7bd33d28932ca9e35170def7309a3bf91ecda5e1ceb067548a12");
}

TEST(bitcoin_script_hash_vectors)
{
    const std::array<std::byte, 0> empty{};
    CHECK_EQ(Sha256(empty).ToHex(),
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const auto hash160{Hash160(empty)};
    constexpr char map[]{"0123456789abcdef"};
    std::string hex;
    for (const auto byte : hash160) {
        const uint8_t value{std::to_integer<uint8_t>(byte)};
        hex.push_back(map[value >> 4]);
        hex.push_back(map[value & 15U]);
    }
    CHECK_EQ(hex, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
}
