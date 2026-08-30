#include <test_framework.h>
#include <utreexo/position.h>

#include <vector>

using namespace utreexo::position;

TEST(position_tree_rows)
{
    CHECK_EQ(TreeRows(0), 0);
    CHECK_EQ(TreeRows(8), 3);
    CHECK_EQ(TreeRows(9), 4);
    CHECK_EQ(TreeRows(255), 8);
}

TEST(position_roots)
{
    CHECK_EQ(RootPosition(5, 2, 3), 12U);
    CHECK_EQ(RootPosition(5, 0, 3), 4U);
    CHECK(IsRootPosition(12, 5, 3));
    CHECK(IsRootPosition(4, 5, 3));
}

TEST(position_proof_set)
{
    const auto positions{ProofPositions({0}, 8, TreeRows(8))};
    CHECK_EQ(positions, std::vector<uint64_t>({1, 9, 13}));
}
