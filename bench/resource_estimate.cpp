// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <bit>
#include <charconv>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>

int main(int argc, char** argv)
{
    uint64_t leaves{180'000'000};
    if (argc == 2) {
        const std::string_view text{argv[1]};
        const auto [end, error]{std::from_chars(text.data(), text.data() + text.size(), leaves)};
        if (error != std::errc{} || end != text.data() + text.size() || leaves == 0) {
            std::cerr << "usage: utreexo-resource-estimate [live-utxos]\n";
            return 1;
        }
    } else if (argc != 1) {
        std::cerr << "usage: utreexo-resource-estimate [live-utxos]\n";
        return 1;
    }

    constexpr uint64_t chunk_slots{uint64_t{1} << 20};
    constexpr uint64_t node_bytes{45};
    constexpr uint64_t bucket_bytes{5};
    const uint64_t roots{static_cast<uint64_t>(std::popcount(leaves))};
    const uint64_t nodes{leaves * 2 - roots};
    const uint64_t arena_slots{((nodes + chunk_slots - 1) / chunk_slots) * chunk_slots};
    const uint64_t requested_buckets{(leaves * 5 + 3) / 4};
    const uint64_t buckets{std::bit_ceil(requested_buckets)};
    const uint64_t arena_bytes{arena_slots * node_bytes};
    const uint64_t index_bytes{buckets * bucket_bytes};
    const uint64_t chain_hash_bytes{1'000'000ULL * 32};
    const uint64_t total{arena_bytes + index_bytes + chain_hash_bytes};
    constexpr double gib{1024.0 * 1024.0 * 1024.0};

    std::cout << "live_utxos=" << leaves << '\n'
              << "live_nodes=" << nodes << '\n'
              << "arena_slots=" << arena_slots << '\n'
              << "arena_gib=" << static_cast<double>(arena_bytes) / gib << '\n'
              << "index_buckets=" << buckets << '\n'
              << "index_gib=" << static_cast<double>(index_bytes) / gib << '\n'
              << "one_million_chain_hashes_gib=" << static_cast<double>(chain_hash_bytes) / gib << '\n'
              << "estimated_total_gib=" << static_cast<double>(total) / gib << '\n';
    return total <= 20ULL * 1024ULL * 1024ULL * 1024ULL ? 0 : 2;
}
