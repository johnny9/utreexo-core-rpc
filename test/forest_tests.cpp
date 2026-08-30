#include <test_framework.h>
#include <utreexo/forest.h>

#include <algorithm>
#include <array>
#include <random>
#include <set>
#include <string_view>
#include <vector>

using namespace utreexo;

namespace {
Hash256 H(std::string_view hex) { return Hash256::FromHex(hex).Value(); }

const std::array<std::string_view, 15> LEAVES{
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
    "dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986",
    "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5",
    "e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71",
    "e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db",
    "67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6",
    "ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879",
    "beead77994cf573341ec17b58bbf7eb34d2711c993c1d976b128b3188dc1829a",
    "2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9",
    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
    "e7cf46a078fed4fafd0b5e3aff144802b853f8ae459a4f0c14add3314b7cc3a6",
    "ef6cbd2161eaea7943ce8693b9824d23d1793ffb1c0fca05b600d3899b44c977",
    "9d1e0e2d9459d06523ad13e28a4093c2316baafe7aec5b25f30eba2e113599c4",
    "4d7b3ef7300acf70c892d8327db8272f54434adbc61a4e130a563cb59a0d0f47",
};

std::vector<Hash256> First(std::size_t count)
{
    std::vector<Hash256> hashes;
    for (std::size_t i{0}; i < count; ++i) hashes.push_back(H(LEAVES[i]));
    return hashes;
}
} // namespace

TEST(forest_matches_rustreexo_roots)
{
    PackedForest forest;
    const auto leaves{First(15)};
    CHECK(forest.Modify(leaves, {}));
    CHECK_EQ(forest.NumLeaves(), 15U);
    const auto roots{forest.Roots()};
    CHECK_EQ(roots.size(), 4U);
    CHECK_EQ(roots[0]->ToHex(), "b151a956139bb821d4effa34ea95c17560e0135d1e4661fc23cedc3af49dac42");
    CHECK_EQ(roots[1]->ToHex(), "9c053db406c1a077112189469a3aca0573d3481bef09fa3d2eda3304d7d44be8");
    CHECK_EQ(roots[2]->ToHex(), "55d0a0ef8f5c25a9da266b36c0c5f4b31008ece82df2512c8966bddcc27a66a0");
    CHECK_EQ(roots[3]->ToHex(), LEAVES[14]);
}

TEST(forest_proof_matches_rustreexo)
{
    PackedForest forest;
    const auto leaves{First(8)};
    CHECK(forest.Modify(leaves, {}));
    const std::array<Hash256, 1> target{leaves[0]};
    const auto proof{forest.Prove(target)};
    CHECK(proof);
    CHECK_EQ(proof.Value().targets, std::vector<uint64_t>{0});
    CHECK_EQ(proof.Value().hashes.size(), 3U);
    CHECK_EQ(proof.Value().hashes[0].ToHex(), LEAVES[1]);
    CHECK_EQ(proof.Value().hashes[1].ToHex(), "9576f4ade6e9bc3a6458b506ce3e4e890df29cb14cb5d3d887672aef55647a2b");
    CHECK_EQ(proof.Value().hashes[2].ToHex(), "29590a14c1b09384b94a2c0e94bf821ca75b62eacebc47893397ca88e3bbcbd7");
}

TEST(forest_batch_proof_matches_rustreexo)
{
    PackedForest forest;
    const auto leaves{First(8)};
    CHECK(forest.Modify(leaves, {}));
    const std::array<Hash256, 3> targets{leaves[5], leaves[3], leaves[1]};
    const auto proof{forest.Prove(targets)};
    CHECK(proof);
    const std::vector<uint64_t> expected_targets{5, 3, 1};
    CHECK_EQ(proof.Value().targets, expected_targets);
    const std::vector<Hash256> expected_hashes{
        H(LEAVES[0]), H(LEAVES[2]), H(LEAVES[4]),
        H("34028bbc87000c39476cdc60cf80ca32d579b3a0e2d3f80e0ad8c3739a01aa91"),
    };
    CHECK_EQ(proof.Value().hashes, expected_hashes);
}

TEST(forest_batch_deletion_matches_rustreexo)
{
    const auto leaves{First(8)};
    {
        PackedForest forest;
        CHECK(forest.Modify(leaves, {}));
        const std::array<Hash256, 2> deletions{leaves[1], leaves[7]};
        CHECK(forest.Modify({}, deletions));
        CHECK_EQ(forest.Roots()[0]->ToHex(),
                 "332c306188d35eb22ecb05d8c00446cd6a7a475f6615f46207cfaa713bb3e62c");
    }
    {
        PackedForest forest;
        CHECK(forest.Modify(leaves, {}));
        const std::array<Hash256, 3> deletions{leaves[1], leaves[5], leaves[7]};
        CHECK(forest.Modify({}, deletions));
        CHECK_EQ(forest.Roots()[0]->ToHex(),
                 "3b8b6eb231437092f6d9fbf8a0696b7cb446e40f1bf81ddb23d3eabb3080b0dd");
    }
}

TEST(forest_delete_promotes_sibling_and_reuses_slots)
{
    PackedForest forest;
    const auto leaves{First(8)};
    CHECK(forest.Modify(leaves, {}));
    const auto before{forest.Usage()};
    CHECK(forest.Delete(leaves[0]));
    CHECK(!forest.Contains(leaves[0]));
    CHECK(forest.Contains(leaves[1]));
    const std::array<Hash256, 1> target{leaves[1]};
    const auto proof{forest.Prove(target)};
    CHECK(proof);
    CHECK_EQ(proof.Value().targets, std::vector<uint64_t>{8});
    CHECK(forest.Add(H(LEAVES[8])));
    CHECK(forest.Usage().allocated_slots <= before.allocated_slots + 1);
}

TEST(forest_modify_prevalidation_is_atomic)
{
    PackedForest forest;
    const auto leaves{First(2)};
    CHECK(forest.Modify(leaves, {}));
    const Hash256 missing{H(LEAVES[3])};
    const std::array<Hash256, 1> additions{H(LEAVES[2])};
    const std::array<Hash256, 1> deletions{missing};
    CHECK(!forest.Modify(additions, deletions));
    CHECK_EQ(forest.NumLeaves(), 2U);
    CHECK(!forest.Contains(additions[0]));
}

TEST(forest_randomized_index_and_checkpoint_stress)
{
    PackedForest forest;
    std::vector<Hash256> live;
    for (uint64_t value{0}; value < 512; ++value) {
        std::array<std::byte, 8> preimage{};
        for (std::size_t i{0}; i < preimage.size(); ++i) {
            preimage[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
        }
        const Hash256 hash{Sha512_256(preimage)};
        CHECK(forest.Add(hash));
        live.push_back(hash);
    }

    std::mt19937 random{0x5eedU};
    for (int round{0}; round < 12; ++round) {
        std::shuffle(live.begin(), live.end(), random);
        const std::size_t delete_count{std::min<std::size_t>(17, live.size() / 3)};
        std::vector<Hash256> deletions{live.begin(), live.begin() + static_cast<std::ptrdiff_t>(delete_count)};
        CHECK(forest.Modify({}, deletions));
        live.erase(live.begin(), live.begin() + static_cast<std::ptrdiff_t>(delete_count));
        for (const auto& hash : live) CHECK(forest.Contains(hash));
        if (!live.empty()) {
            const std::array<Hash256, 1> target{live.front()};
            CHECK(forest.Prove(target));
        }
    }
    CHECK_EQ(forest.Usage().index_entries, live.size());
    CHECK_EQ(forest.Usage().estimated_bytes,
             forest.Usage().arena_estimated_bytes + forest.Usage().index_estimated_bytes);
}
