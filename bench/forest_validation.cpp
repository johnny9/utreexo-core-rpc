// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/forest.h>

#include <chrono>
#include <exception>
#include <iostream>
#include <sys/resource.h>
#include <vector>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "Usage: utreexo-forest-validation-benchmark ONLINE_STATE_COPY\n"
                     "Opens an isolated offline copy and may refresh its validation cache.\n";
        return 1;
    }
    try {
        const auto start{std::chrono::steady_clock::now()};
        std::vector<utreexo::Hash256> chain;
        utreexo::ChainPoint point;
        auto opened{utreexo::PackedForest::OpenOnline(argv[1], chain, point)};
        if (!opened) {
            std::cerr << opened.Error() << '\n';
            return 1;
        }
        const auto& forest{opened.Value()};
        const auto usage{forest.OnlineUsage()};
        const auto elapsed{std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count()};
        rusage resources{};
        if (::getrusage(RUSAGE_SELF, &resources) != 0) return 1;
        std::cout << "{\n  \"height\": " << point.height
                  << ",\n  \"block_hash\": \"" << point.block_hash.ToBitcoinHex()
                  << "\",\n  \"num_leaves\": " << forest.NumLeaves()
                  << ",\n  \"live_nodes\": " << forest.Usage().live_nodes
                  << ",\n  \"index_bytes\": " << forest.Usage().index_estimated_bytes
                  << ",\n  \"elapsed_ms\": " << elapsed
                  << ",\n  \"validation_us\": " << usage.startup_validation_us
                  << ",\n  \"cache_hit\": " << (usage.startup_cache_hit ? "true" : "false")
                  << ",\n  \"full_scan\": " << (usage.startup_full_scan ? "true" : "false")
#if defined(__linux__)
                  << ",\n  \"peak_rss_kib\": " << resources.ru_maxrss
                  << ",\n  \"filesystem_read_bytes\": " << resources.ru_inblock * 512LL
                  << ",\n  \"filesystem_write_bytes\": " << resources.ru_oublock * 512LL
#endif
                  << ",\n  \"roots\": [";
        bool first{true};
        for (const auto& root : forest.Roots()) {
            if (!first) std::cout << ',';
            first = false;
            if (root) std::cout << '"' << root->ToHex() << '"';
            else std::cout << "null";
        }
        std::cout << "]\n}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
