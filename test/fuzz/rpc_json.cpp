// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/core_rpc.h>

#include <univalue.h>

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    constexpr std::size_t MAX_INPUT_SIZE{2U * 1024U * 1024U};
    if (size > MAX_INPUT_SIZE) return 0;

    UniValue value;
    const std::string json{reinterpret_cast<const char*>(data), size};
    if (!value.read(json)) return 0;

    (void)utreexo::ParseBitcoinAmount(value);
    if (value.isObject()) {
        (void)utreexo::ParseVerboseBlock(value, [](uint32_t) {
            return utreexo::Result<utreexo::Hash256>::Ok(utreexo::Hash256{});
        });
    }
    return 0;
}
