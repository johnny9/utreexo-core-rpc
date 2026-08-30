// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_BRIDGE_WIRE_H
#define UTREEXO_BRIDGE_WIRE_H

#include <utreexo/forest.h>
#include <utreexo/leaf.h>
#include <utreexo/result.h>

#include <cstddef>
#include <span>
#include <vector>

namespace utreexo {

/** Serialize bridge-compatible UData to append after a consensus-encoded Bitcoin block. */
Result<std::vector<std::byte>> SerializeUData(const Proof& proof,
                                             std::span<const CompactLeafData> leaves);

} // namespace utreexo

#endif // UTREEXO_BRIDGE_WIRE_H
