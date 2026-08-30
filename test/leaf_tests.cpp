#include <test_framework.h>
#include <utreexo/leaf.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace utreexo;

namespace {
std::vector<std::byte> ParseBytes(std::string_view hex)
{
    std::vector<std::byte> bytes;
    bytes.reserve(hex.size() / 2);
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        return static_cast<unsigned>(c - 'A' + 10);
    };
    for (std::size_t i{0}; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<std::byte>((digit(hex[i]) << 4) | digit(hex[i + 1])));
    }
    return bytes;
}
} // namespace

TEST(leaf_hash_bitcoin_serialization)
{
    LeafData leaf;
    leaf.block_hash = Hash256::FromBitcoinHex("00000000839a8e6886ab5951d76f4114754285bd7a81a48d0d722cb5b0c5e3a7").Value();
    leaf.outpoint.txid = Hash256::FromBitcoinHex("0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9").Value();
    leaf.outpoint.index = 0;
    leaf.block_height = 9;
    leaf.coinbase = true;
    leaf.output.value = 5'000'000'000;
    leaf.output.script_pubkey = ParseBytes("410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac");
    CHECK_EQ(LeafHash(leaf).ToHex(), "7348026012c0daa1f52c31951a0bb3da393e96645a8a0894e6907177ff88f3d3");
}

TEST(unspendable_outputs)
{
    CHECK(!IsProvablyUnspendable(TxOut{1, {std::byte{0x51}}}));
    CHECK(IsProvablyUnspendable(TxOut{0, {std::byte{0x6a}}}));
    CHECK(!IsProvablyUnspendable(TxOut{0, {}}));
    CHECK(!IsProvablyUnspendable(TxOut{0, {std::byte{0x51}, std::byte{0x6a}}}));
    CHECK(!IsProvablyUnspendable(TxOut{0, std::vector<std::byte>(10'000)}));
    CHECK(IsProvablyUnspendable(TxOut{0, std::vector<std::byte>(10'001)}));
}

TEST(floresta_compact_script_classification)
{
    struct Case { std::string_view script; ScriptPubkeyType type; bool retained; };
    const std::vector<Case> cases{
        {"76a914bf2646b8ba8b4a143220528bde9c306dac44a01c88ac", ScriptPubkeyType::PUBKEY_HASH, false},
        {"a914ed9371b30de550c0617cd0c4b2c0c0dc5e88c65487", ScriptPubkeyType::SCRIPT_HASH, false},
        {"001406a9852b7c9f4ff9993b5d2192ac42a5df54828e", ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH, false},
        {"0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d", ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH, false},
        {"51204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260", ScriptPubkeyType::OTHER, true},
        {"210395c223fbf96e49e5b9e06a236ca7ef95b10bf18c074bd91a5942fc40360d0b68ac", ScriptPubkeyType::OTHER, true},
        {"", ScriptPubkeyType::OTHER, true},
    };
    for (const auto& test_case : cases) {
        LeafData leaf;
        leaf.output.script_pubkey = ParseBytes(test_case.script);
        const auto compact{CompactLeaf(leaf)};
        CHECK_EQ(compact.script_type, test_case.type);
        CHECK_EQ(!compact.script.empty() || test_case.script.empty(), test_case.retained);
    }
}

TEST(floresta_compact_script_recovery_vectors)
{
    struct Case {
        ScriptPubkeyType type;
        std::string_view script_sig;
        std::vector<std::string_view> witness;
        std::string_view expected;
    };
    const std::vector<Case> cases{
        {ScriptPubkeyType::PUBKEY_HASH,
         "47304402202f89e2deb17f0c2c5732d6f7791a2731703cb128dc86ae0bf288e55a3d7ce9d6022051c2242ca0885a4a2054391385eda03132616fb0c2daa61d6823eff7a21b5d0c01210395c223fbf96e49e5b9e06a236ca7ef95b10bf18c074bd91a5942fc40360d0b68",
         {}, "76a914bf2646b8ba8b4a143220528bde9c306dac44a01c88ac"},
        {ScriptPubkeyType::SCRIPT_HASH,
         "00473044022001460e6d06dc44e163ef1f692d275a1e357d086d0361fbe5012dbf18cbf2617202207f9e8fb54e776d7e98a6425da2be15e2ffca2e623b7617234226eafe77c70eaa01473044022076d756a250ad4044e2b4a0049112d87367b2f0ce80253e400f3ba09d620cbbdd022020f67b65f7cb5e109b8ccbc852e30b4e84b0b682136a5e72f679bd581b271ea8014c695221021c04b91bffe90c3e4defd021a4b6da4983b97e13c772bf15009f1661480658832102be11f7f0d9696ef731c13ed8b6e955df43cd4238d694a1698b02fcb3c2d275322102e0ad7274a4e93b3b30793ff7a04a31d2792ed22a563fe5ea0095af844c10c9c453ae",
         {}, "a914ed9371b30de550c0617cd0c4b2c0c0dc5e88c65487"},
        {ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH, "",
         {"304402202936300c12249c8696bb90addcc9482995429d7be0418260178ddc0c630c10ed02206128cac337841b171d15d9aadc2af77d280da7cd85c049149c8134ddb5adc8a101",
          "038adb3497e025c0ff14521a789af4f10d526ec4c95348e708ebdc4d5ac58228e5"},
         "001406a9852b7c9f4ff9993b5d2192ac42a5df54828e"},
        {ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH, "",
         {"", "30440220289b2e0b6aec5a8f43d283edef0757206de77e3f3acdb322ade452a0468764db02201c332ec46a2ed3614fe392c4011063f39e77def57d89991ccbb99b6c7de2491901",
          "3044022044eaf71bdb4b3f0b0ba2f1eec82cad412729a1a4d5fc3b2fa251fecb73c56c0502201579c9e13b4d7595f9c6036a612828eac4796902c248131a7f25a117a0c68ca801",
          "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae"},
         "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"},
        {ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH, "", {"51"},
         "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"},
    };

    for (const auto& test_case : cases) {
        SpendingInput input{.script_sig = ParseBytes(test_case.script_sig), .witness = {}};
        for (const auto item : test_case.witness) input.witness.push_back(ParseBytes(item));
        const CompactLeafData leaf{.header_code = 0, .amount = 0, .script_type = test_case.type, .script = {}};
        const auto reconstructed{ReconstructScriptPubkey(leaf, input)};
        CHECK(reconstructed);
        CHECK_EQ(reconstructed.Value(), ParseBytes(test_case.expected));
    }
}

TEST(floresta_compact_script_recovery_rejects_bad_inputs)
{
    for (const auto type : {ScriptPubkeyType::PUBKEY_HASH, ScriptPubkeyType::SCRIPT_HASH}) {
        const CompactLeafData leaf{.header_code = 0, .amount = 0, .script_type = type, .script = {}};
        CHECK(!ReconstructScriptPubkey(leaf, SpendingInput{}));
        CHECK(!ReconstructScriptPubkey(leaf,
                                       SpendingInput{.script_sig = {std::byte{0x61}}, .witness = {}}));
        CHECK(!ReconstructScriptPubkey(leaf,
                                       SpendingInput{.script_sig = {std::byte{0x01}}, .witness = {}}));
    }
    for (const auto type : {ScriptPubkeyType::WITNESS_V0_PUBKEY_HASH,
                            ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH}) {
        const CompactLeafData leaf{.header_code = 0, .amount = 0, .script_type = type, .script = {}};
        CHECK(!ReconstructScriptPubkey(leaf, SpendingInput{}));
    }
    const CompactLeafData other{.header_code = 0, .amount = 0, .script_type = ScriptPubkeyType::OTHER,
                                .script = {std::byte{0x51}, std::byte{0x6a}}};
    CHECK_EQ(ReconstructScriptPubkey(other, SpendingInput{}).Value(), other.script);
}
