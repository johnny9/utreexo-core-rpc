#include <test_framework.h>
#include <utreexo/bridge_wire.h>

#include <array>

using namespace utreexo;

namespace {
std::string Hex(std::span<const std::byte> bytes)
{
    constexpr char map[]{"0123456789abcdef"};
    std::string output;
    output.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value{std::to_integer<uint8_t>(byte)};
        output.push_back(map[value >> 4]);
        output.push_back(map[value & 15U]);
    }
    return output;
}
} // namespace

TEST(compact_leaf_classifies_standard_scripts)
{
    LeafData leaf;
    leaf.block_height = 100;
    leaf.coinbase = true;
    leaf.output.value = 42;
    leaf.output.script_pubkey = {
        std::byte{0x00}, std::byte{0x14}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    const auto compact{CompactLeaf(leaf)};
    CHECK_EQ(compact.header_code, 201U);
    CHECK_EQ(compact.amount, 42U);
    CHECK_EQ(compact.script_type, ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH);
    CHECK(compact.script.empty());
}

TEST(udata_serialization_matches_bridge_layout)
{
    const Proof proof{{1}, {Hash256::FromHex(std::string(64, '1')).Value()}};
    const std::array<CompactLeafData, 1> leaves{{
        CompactLeafData{.header_code = 3, .amount = 5, .script_type = ScriptPubkeyType::OTHER,
                        .script = {std::byte{0x51}}},
    }};
    const auto encoded{SerializeUData(proof, leaves)};
    CHECK(encoded);
    CHECK_EQ(Hex(encoded.Value()),
             "00010101" + std::string(64, '1') + "01030000000500000000000000000151");
}

TEST(udata_rejects_mismatched_leaf_count)
{
    const Proof proof{{1}, {}};
    CHECK(!SerializeUData(proof, {}));
}
