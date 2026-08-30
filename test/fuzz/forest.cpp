// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/forest.h>

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    constexpr std::size_t MAX_INPUT_SIZE{4U * 1024U * 1024U};
    if (size > MAX_INPUT_SIZE) return 0;

    const std::string bytes{reinterpret_cast<const char*>(data), size};
    std::istringstream input{bytes, std::ios::binary};
    auto forest{utreexo::ReadForest(input)};
    if (forest) {
        (void)forest.Value().Roots();
        (void)forest.Value().Usage();
    }
    return 0;
}
