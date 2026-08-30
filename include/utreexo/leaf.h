// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_LEAF_H
#define UTREEXO_LEAF_H

#include <utreexo/hash.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace utreexo {

struct OutPoint {
    Hash256 txid;
    uint32_t index{0};
    auto operator<=>(const OutPoint&) const = default;
};

struct TxOut {
    uint64_t value{0};
    std::vector<std::byte> script_pubkey;
    auto operator<=>(const TxOut&) const = default;
};

struct LeafData {
    Hash256 block_hash;
    OutPoint outpoint;
    uint32_t block_height{0};
    bool coinbase{false};
    TxOut output;
};

enum class ScriptPubkeyType : uint8_t {
    OTHER = 0,
    PUBKEY_HASH = 1,
    WITNESS_V0_PUBKEY_HASH = 2,
    SCRIPT_HASH = 3,
    WITNESS_V0_SCRIPT_HASH = 4,
};

/** Validation metadata sent beside a proof; standard scripts are reconstructed by the client. */
struct CompactLeafData {
    uint32_t header_code{0};
    uint64_t amount{0};
    ScriptPubkeyType script_type{ScriptPubkeyType::OTHER};
    std::vector<std::byte> script;
    auto operator<=>(const CompactLeafData&) const = default;
};

struct SpendingInput {
    std::vector<std::byte> script_sig;
    std::vector<std::vector<std::byte>> witness;
};

Hash256 LeafHash(const LeafData& leaf);
CompactLeafData CompactLeaf(const LeafData& leaf);
/** Reconstruct the script committed by a compact leaf as Floresta does. */
Result<std::vector<std::byte>> ReconstructScriptPubkey(const CompactLeafData& leaf,
                                                       const SpendingInput& input);
bool IsProvablyUnspendable(const TxOut& output);

} // namespace utreexo

#endif // UTREEXO_LEAF_H
