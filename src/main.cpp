// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/checkpoint.h>
#include <utreexo/core_rpc.h>
#include <utreexo/log.h>
#include <utreexo/p2p.h>
#include <utreexo/sync.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

namespace {

#ifndef UTREEXO_BRIDGE_VERSION
#define UTREEXO_BRIDGE_VERSION "unknown"
#endif

using Clock = std::chrono::steady_clock;

struct Options {
    std::string host{"127.0.0.1"};
    uint16_t port{8332};
    std::string authorization;
    std::filesystem::path cookie;
    std::optional<std::filesystem::path> checkpoint;
    std::optional<std::filesystem::path> online_state;
    std::optional<std::filesystem::path> state_json;
    std::optional<uint32_t> stop_height;
    uint32_t checkpoint_interval{0};
    uint64_t online_cache_mib{0};
    uint64_t online_wal_segment_mib{256};
    uint32_t online_undo_depth{1'008};
    uint32_t poll_interval_ms{5'000};
    std::string p2p_bind{"127.0.0.1"};
    std::optional<uint16_t> p2p_port;
    utreexo::BitcoinNetwork p2p_network{utreexo::BitcoinNetwork::MAINNET};
    uint32_t p2p_max_peers{16};
    uint32_t p2p_proof_cache_blocks{288};
    uint64_t p2p_proof_cache_mib{256};
    utreexo::LogLevel log_level{utreexo::LogLevel::INFO};
    bool follow{false};
    bool show_version{false};
};

struct IntervalMetrics {
    uint64_t blocks{0};
    uint64_t chain_check_us{0};
    uint64_t block_hash_us{0};
    uint64_t block_fetch_us{0};
    uint64_t parse_us{0};
    uint64_t modify_us{0};
    uint64_t total_us{0};
    uint64_t slowest_us{0};
    uint32_t slowest_height{0};

    void Add(uint32_t height, const utreexo::BlockProcessingMetrics& metrics)
    {
        ++blocks;
        chain_check_us += metrics.chain_check_us;
        block_hash_us += metrics.block_hash_us;
        block_fetch_us += metrics.block_fetch_us;
        parse_us += metrics.parse_us;
        modify_us += metrics.modify_us;
        total_us += metrics.total_us;
        if (metrics.total_us > slowest_us) {
            slowest_us = metrics.total_us;
            slowest_height = height;
        }
    }
};

template <typename T>
bool ParseInteger(std::string_view text, T& output)
{
    const auto [end, error]{std::from_chars(text.data(), text.data() + text.size(), output)};
    return error == std::errc{} && end == text.data() + text.size();
}

void Usage()
{
    std::cout
        << "Usage: utreexo-bridge (--rpc-cookie=PATH | --rpc-auth=USER:PASS) [options]\n"
        << "  --rpc-host=HOST             Bitcoin Core RPC host (default 127.0.0.1)\n"
        << "  --rpc-port=PORT             Bitcoin Core RPC port (default 8332)\n"
        << "  --checkpoint=PATH           Load/save a sparse atomic checkpoint\n"
        << "  --checkpoint-interval=N     Full checkpoint every N blocks (default 0: final only)\n"
        << "                              Allocation failures save the last completed checkpoint\n"
        << "  --online-state=DIR          Native mmap/WAL state; create after reaching Core tip\n"
        << "  --online-cache-mib=N        Dirty-node cache (default: 128 on <=20GiB, else 512)\n"
        << "  --online-wal-segment-mib=N  WAL segment size (default 256)\n"
        << "  --online-undo-depth=N       Retained WAL before-image window (default 1008)\n"
        << "  --follow                    Poll Core and remain online after the initial sync\n"
        << "  --poll-interval-ms=N        Follow-mode Core tip poll interval (default 5000)\n"
        << "  --p2p-port=N                Serve recent getuproof requests over Bitcoin v1 P2P\n"
        << "  --p2p-bind=IP               P2P IPv4 bind address: 127.0.0.1 or 0.0.0.0\n"
        << "  --p2p-network=NETWORK       mainnet, testnet3, signet, or regtest\n"
        << "  --p2p-max-peers=N           Maximum inbound proof peers (default 16)\n"
        << "  --p2p-proof-cache-blocks=N  Recent in-memory proof window (default 288)\n"
        << "  --p2p-proof-cache-mib=N     Proof-cache memory ceiling (default 256)\n"
        << "  --state-json=PATH           Write final height, leaf count, and roots as JSON\n"
        << "  --stop-height=N             Stop before the current Core tip\n"
        << "  --log-level=LEVEL           error, warn, info, debug, or trace (default info)\n"
        << "  --version                   Show the sidecar version\n"
        << "  --help                      Show this help\n";
}

utreexo::Result<Options> ParseOptions(int argc, char** argv)
{
    Options options;
    for (int i{1}; i < argc; ++i) {
        const std::string_view argument{argv[i]};
        const auto value = [argument](std::string_view name) -> std::optional<std::string_view> {
            const std::string prefix{std::string{name} + '='};
            if (argument.starts_with(prefix)) return argument.substr(prefix.size());
            return std::nullopt;
        };
        if (argument == "--help") {
            Usage();
            std::exit(0);
        } else if (argument == "--version") {
            options.show_version = true;
        } else if (auto host{value("--rpc-host")}) {
            options.host = *host;
        } else if (auto port{value("--rpc-port")}) {
            if (!ParseInteger(*port, options.port)) return utreexo::Result<Options>::Err("invalid --rpc-port");
        } else if (auto auth{value("--rpc-auth")}) {
            options.authorization = *auth;
        } else if (auto cookie{value("--rpc-cookie")}) {
            options.cookie = *cookie;
        } else if (auto checkpoint{value("--checkpoint")}) {
            options.checkpoint = std::filesystem::path{*checkpoint};
        } else if (auto online_state{value("--online-state")}) {
            options.online_state = std::filesystem::path{*online_state};
        } else if (auto interval{value("--checkpoint-interval")}) {
            if (!ParseInteger(*interval, options.checkpoint_interval)) {
                return utreexo::Result<Options>::Err("invalid --checkpoint-interval");
            }
        } else if (auto state_json{value("--state-json")}) {
            options.state_json = std::filesystem::path{*state_json};
        } else if (auto cache{value("--online-cache-mib")}) {
            if (!ParseInteger(*cache, options.online_cache_mib) || options.online_cache_mib == 0) {
                return utreexo::Result<Options>::Err("invalid --online-cache-mib");
            }
        } else if (auto segment{value("--online-wal-segment-mib")}) {
            if (!ParseInteger(*segment, options.online_wal_segment_mib) || options.online_wal_segment_mib == 0) {
                return utreexo::Result<Options>::Err("invalid --online-wal-segment-mib");
            }
        } else if (auto depth{value("--online-undo-depth")}) {
            if (!ParseInteger(*depth, options.online_undo_depth) || options.online_undo_depth == 0) {
                return utreexo::Result<Options>::Err("invalid --online-undo-depth");
            }
        } else if (auto poll{value("--poll-interval-ms")}) {
            if (!ParseInteger(*poll, options.poll_interval_ms) || options.poll_interval_ms == 0) {
                return utreexo::Result<Options>::Err("invalid --poll-interval-ms");
            }
        } else if (auto bind{value("--p2p-bind")}) {
            options.p2p_bind = *bind;
        } else if (auto p2p_port{value("--p2p-port")}) {
            uint16_t parsed_port{0};
            if (!ParseInteger(*p2p_port, parsed_port) || parsed_port == 0) {
                return utreexo::Result<Options>::Err("invalid --p2p-port");
            }
            options.p2p_port = parsed_port;
        } else if (auto network{value("--p2p-network")}) {
            auto parsed_network{utreexo::ParseBitcoinNetwork(*network)};
            if (!parsed_network) return utreexo::Result<Options>::Err(parsed_network.Error());
            options.p2p_network = parsed_network.Value();
        } else if (auto peers{value("--p2p-max-peers")}) {
            if (!ParseInteger(*peers, options.p2p_max_peers) || options.p2p_max_peers == 0 ||
                options.p2p_max_peers > 1'024) {
                return utreexo::Result<Options>::Err("invalid --p2p-max-peers");
            }
        } else if (auto blocks{value("--p2p-proof-cache-blocks")}) {
            if (!ParseInteger(*blocks, options.p2p_proof_cache_blocks) ||
                options.p2p_proof_cache_blocks == 0) {
                return utreexo::Result<Options>::Err("invalid --p2p-proof-cache-blocks");
            }
        } else if (auto proof_cache{value("--p2p-proof-cache-mib")}) {
            if (!ParseInteger(*proof_cache, options.p2p_proof_cache_mib) ||
                options.p2p_proof_cache_mib == 0 ||
                options.p2p_proof_cache_mib > std::numeric_limits<uint64_t>::max() / (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --p2p-proof-cache-mib");
            }
        } else if (argument == "--follow") {
            options.follow = true;
        } else if (auto stop_height{value("--stop-height")}) {
            uint32_t height{0};
            if (!ParseInteger(*stop_height, height)) return utreexo::Result<Options>::Err("invalid --stop-height");
            options.stop_height = height;
        } else if (auto log_level{value("--log-level")}) {
            auto level{utreexo::ParseLogLevel(*log_level)};
            if (!level) return utreexo::Result<Options>::Err(level.Error());
            options.log_level = level.Value();
        } else {
            return utreexo::Result<Options>::Err("unknown argument: " + std::string{argument});
        }
    }
    if (!options.show_version && options.authorization.empty() && options.cookie.empty()) {
        return utreexo::Result<Options>::Err("provide --rpc-cookie or --rpc-auth");
    }
    if (options.follow && !options.online_state) {
        return utreexo::Result<Options>::Err("--follow requires --online-state");
    }
    if (options.follow && options.stop_height) {
        return utreexo::Result<Options>::Err("--follow cannot be combined with --stop-height");
    }
    if (options.p2p_port && !options.follow) {
        return utreexo::Result<Options>::Err("--p2p-port requires --follow");
    }
    return utreexo::Result<Options>::Ok(std::move(options));
}

uint64_t PhysicalMemoryBytes()
{
    const long pages{::sysconf(_SC_PHYS_PAGES)};
    const long page_size{::sysconf(_SC_PAGESIZE)};
    if (pages <= 0 || page_size <= 0) return 0;
    return static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_size);
}

utreexo::OnlineForestConfig OnlineConfig(const Options& options)
{
    constexpr uint64_t MIB{1024ULL * 1024};
    const uint64_t physical{PhysicalMemoryBytes()};
    const uint64_t automatic_mib{
        physical != 0 && physical <= 20ULL * 1024 * MIB ? 128ULL : 512ULL};
    return utreexo::OnlineForestConfig{
        .max_dirty_bytes = (options.online_cache_mib == 0 ? automatic_mib : options.online_cache_mib) * MIB,
        .wal_segment_bytes = options.online_wal_segment_mib * MIB,
        .undo_depth = options.online_undo_depth,
        .sync_wal = true,
    };
}

std::string RootsField(const utreexo::PackedForest& forest)
{
    std::ostringstream output;
    const auto roots{forest.Roots()};
    for (std::size_t i{0}; i < roots.size(); ++i) {
        if (i != 0) output << ',';
        output << (roots[i] ? roots[i]->ToHex() : std::string(64, '0'));
    }
    return output.str();
}

std::string PathField(const std::filesystem::path& path)
{
    std::ostringstream output;
    output << std::quoted(path.string());
    return output.str();
}

std::string StringField(std::string_view value)
{
    std::ostringstream output;
    output << std::quoted(std::string{value});
    return output.str();
}

void LogMemoryBreakdown(std::string_view phase, uint32_t height,
                        const utreexo::PackedForest& forest)
{
    if (!utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) return;
    const auto usage{forest.Usage()};
    const uint64_t index_load_ppm{usage.index_capacity == 0 ? 0 :
        usage.index_entries * 1'000'000 / usage.index_capacity};
    utreexo::Log(utreexo::LogLevel::DEBUG, "forest_memory",
        "phase=" + std::string{phase} +
        " height=" + std::to_string(height) +
        " live_nodes=" + std::to_string(usage.live_nodes) +
        " allocated_slots=" + std::to_string(usage.allocated_slots) +
        " arena_capacity_slots=" + std::to_string(usage.arena_capacity_slots) +
        " free_slots=" + std::to_string(usage.free_slots) +
        " index_entries=" + std::to_string(usage.index_entries) +
        " index_capacity=" + std::to_string(usage.index_capacity) +
        " index_tombstones=" + std::to_string(usage.index_tombstones) +
        " index_load_ppm=" + std::to_string(index_load_ppm) +
        " arena_bytes=" + std::to_string(usage.arena_estimated_bytes) +
        " index_bytes=" + std::to_string(usage.index_estimated_bytes) +
        " estimated_bytes=" + std::to_string(usage.estimated_bytes));
}

void LogOnlineBreakdown(std::string_view phase, uint32_t height,
                        const utreexo::PackedForest& forest)
{
    if (!forest.IsOnline()) return;
    const auto usage{forest.OnlineUsage()};
    utreexo::Log(utreexo::LogLevel::DEBUG, "online_storage",
        "phase=" + std::string{phase} +
        " height=" + std::to_string(height) +
        " base_bytes=" + std::to_string(usage.base_bytes) +
        " dirty_nodes=" + std::to_string(usage.dirty_nodes) +
        " dirty_bytes=" + std::to_string(usage.dirty_bytes) +
        " wal_bytes=" + std::to_string(usage.wal_bytes) +
        " redo_wal_bytes=" + std::to_string(usage.redo_wal_bytes) +
        " base_lsn=" + std::to_string(usage.base_lsn) +
        " current_lsn=" + std::to_string(usage.current_lsn) +
        " last_transaction_nodes=" + std::to_string(usage.last_transaction_nodes) +
        " last_transaction_wal_bytes=" + std::to_string(usage.last_transaction_wal_bytes));
}

utreexo::Result<void> WriteStateJson(const std::filesystem::path& path,
                                     const utreexo::ChainPoint& point,
                                     const utreexo::PackedForest& forest)
{
    std::ofstream output{path, std::ios::trunc};
    if (!output) return utreexo::Result<void>::Err("could not open state JSON output");
    output << "{\"format\":1,\"height\":" << point.height
           << ",\"block_hash\":\"" << point.block_hash.ToBitcoinHex()
           << "\",\"num_leaves\":" << forest.NumLeaves() << ",\"roots\":[";
    const auto roots{forest.Roots()};
    for (std::size_t i{0}; i < roots.size(); ++i) {
        if (i != 0) output << ',';
        output << '\"' << (roots[i] ? roots[i]->ToHex() : std::string(64, '0')) << '\"';
    }
    output << "]}\n";
    if (!output) return utreexo::Result<void>::Err("writing state JSON failed");
    return utreexo::Result<void>::Ok();
}

} // namespace

int main(int argc, char** argv)
{
    auto parsed{ParseOptions(argc, argv)};
    if (!parsed) {
        std::cerr << "Error: " << parsed.Error() << "\n\n";
        Usage();
        return 1;
    }
    Options options{parsed.Take()};
    if (options.show_version) {
        std::cout << "utreexo-bridge " << UTREEXO_BRIDGE_VERSION
                  << " checkpoint_format=" << utreexo::CHECKPOINT_FORMAT_VERSION
                  << " forest_format="
                  << utreexo::PackedForest::FORMAT_VERSION << '\n';
        return 0;
    }
    utreexo::SetLogLevel(options.log_level);
    utreexo::Log(utreexo::LogLevel::INFO, "sidecar_start",
        "version=" UTREEXO_BRIDGE_VERSION
        " checkpoint_format=" + std::to_string(utreexo::CHECKPOINT_FORMAT_VERSION) +
        " forest_format=" +
        std::to_string(utreexo::PackedForest::FORMAT_VERSION) +
        " log_level=" + std::string{utreexo::LogLevelName(options.log_level)});
    if (options.authorization.empty()) {
        auto cookie{utreexo::ReadCookieAuthorization(options.cookie)};
        if (!cookie) {
            utreexo::Log(utreexo::LogLevel::ERROR, "cookie_read_failed",
                         "error=" + StringField(cookie.Error()));
            return 1;
        }
        options.authorization = cookie.Take();
    }

    const auto online_config{OnlineConfig(options)};
    utreexo::PackedForest forest;
    std::vector<utreexo::Hash256> chain_hashes;
    bool loaded_online{false};
    if (options.online_state && std::filesystem::exists(*options.online_state)) {
        utreexo::Log(utreexo::LogLevel::INFO, "online_state_load_started",
            "path=" + PathField(*options.online_state) +
            " cache_bytes=" + std::to_string(online_config.max_dirty_bytes) +
            " wal_segment_bytes=" + std::to_string(online_config.wal_segment_bytes) +
            " undo_depth=" + std::to_string(online_config.undo_depth));
        utreexo::ChainPoint recovered_point;
        auto opened{utreexo::PackedForest::OpenOnline(*options.online_state, chain_hashes,
                                                       recovered_point, online_config)};
        if (!opened) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_state_load_failed",
                "path=" + PathField(*options.online_state) +
                " error=" + StringField(opened.Error()) +
                " action=fail_closed");
            return 1;
        }
        forest = opened.Take();
        loaded_online = true;
        utreexo::Log(utreexo::LogLevel::INFO, "online_state_loaded",
            "height=" + std::to_string(recovered_point.height) +
            " block_hash=" + recovered_point.block_hash.ToBitcoinHex() +
            " path=" + PathField(*options.online_state));
        LogMemoryBreakdown("online_state_loaded", recovered_point.height, forest);
        LogOnlineBreakdown("online_state_loaded", recovered_point.height, forest);
    } else if (options.checkpoint && std::filesystem::exists(*options.checkpoint)) {
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_load_started",
                     "path=" + PathField(*options.checkpoint));
        utreexo::CheckpointMetrics checkpoint_metrics;
        auto loaded{utreexo::LoadCheckpoint(*options.checkpoint, &checkpoint_metrics)};
        if (!loaded) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                         "path=" + PathField(*options.checkpoint) +
                         " error=" + StringField(loaded.Error()));
            return 1;
        }
        if (loaded.Value().chain_hashes.empty()) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                         "reason=missing_chain_hash_index");
            return 1;
        }
        const uint32_t loaded_height{loaded.Value().point.height};
        forest = std::move(loaded.Value().forest);
        chain_hashes = std::move(loaded.Value().chain_hashes);
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_loaded",
            "height=" + std::to_string(loaded_height) +
            " path=" + PathField(*options.checkpoint) +
            " bytes=" + std::to_string(checkpoint_metrics.final_bytes) +
            " total_us=" + std::to_string(checkpoint_metrics.total_us));
        if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) {
            utreexo::Log(utreexo::LogLevel::DEBUG, "checkpoint_load_metrics",
                "height=" + std::to_string(loaded_height) +
                " bytes=" + std::to_string(checkpoint_metrics.final_bytes) +
                " checksum_us=" + std::to_string(checkpoint_metrics.checksum_us) +
                " deserialize_us=" + std::to_string(checkpoint_metrics.deserialize_us) +
                " total_us=" + std::to_string(checkpoint_metrics.total_us));
        }
        LogMemoryBreakdown("checkpoint_loaded", loaded_height, forest);
    }

    utreexo::HttpRpcConfig rpc_config{
        .host = options.host,
        .port = options.port,
        .path = "/",
        .authorization = options.authorization,
    };
    utreexo::CoreRpcBlockSource source{utreexo::CoreRpcClient{
        std::make_unique<utreexo::HttpRpcTransport>(std::move(rpc_config))}};
    utreexo::SequentialSync sync{source, forest, std::move(chain_hashes)};
    if (forest.IsOnline()) {
        const auto reconciled{sync.ReconcileCurrentPoint()};
        if (!reconciled) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_reconcile_failed",
                "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
                " error=" + StringField(reconciled.Error()) +
                " action=fail_closed_restore_validated_checkpoint");
            return 1;
        }
        if (reconciled.Value() != 0) {
            utreexo::Log(utreexo::LogLevel::WARN, "online_reorg_rolled_back",
                "disconnected_blocks=" + std::to_string(reconciled.Value()) +
                " recovered_height=" + std::to_string(sync.CurrentPoint()->height));
        }
    }
    auto tip{sync.TipHeight()};
    if (!tip) {
        utreexo::Log(utreexo::LogLevel::ERROR, "core_tip_failed",
                     "error=" + StringField(tip.Error()));
        return 1;
    }
    const uint32_t target{options.stop_height ? std::min(*options.stop_height, tip.Value()) : tip.Value()};
    utreexo::Log(utreexo::LogLevel::INFO, "sync_started",
        "start_height=" + std::to_string(sync.ChainHashes().empty() ? 0 : sync.ChainHashes().size() - 1) +
        " target_height=" + std::to_string(target) +
        " core_tip_height=" + std::to_string(tip.Value()) +
        " storage_mode=" + std::string{loaded_online ? "mmap_wal" : "ram_bootstrap"} +
        " prefetch_blocks=2 rpc_transport=persistent json_parser=streaming_projection");
    const auto prefetch_started{sync.StartPrefetch(target)};
    if (!prefetch_started) {
        utreexo::Log(utreexo::LogLevel::ERROR, "prefetch_start_failed",
                     "error=" + StringField(prefetch_started.Error()));
        return 1;
    }

    const auto save_checkpoint = [&](const utreexo::ChainPoint& point,
                                     std::string_view reason) -> utreexo::Result<void> {
        if (!options.checkpoint) return utreexo::Result<void>::Ok();
        std::error_code space_error;
        const auto space{std::filesystem::space(options.checkpoint->parent_path().empty() ?
                                                    std::filesystem::path{"."} :
                                                    options.checkpoint->parent_path(),
                                                space_error)};
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_save_started",
            "height=" + std::to_string(point.height) +
            " reason=" + std::string{reason} +
            " path=" + PathField(*options.checkpoint) +
            " free_bytes_before=" + std::to_string(space_error ? 0 : space.available));
        LogMemoryBreakdown("checkpoint_save_started", point.height, forest);
        utreexo::CheckpointMetrics metrics;
        auto saved{utreexo::SaveCheckpoint(*options.checkpoint, point, forest,
                                            sync.ChainHashes(), &metrics)};
        if (!saved) return saved;
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_saved",
            "height=" + std::to_string(point.height) +
            " reason=" + std::string{reason} +
            " path=" + PathField(*options.checkpoint) +
            " bytes=" + std::to_string(metrics.final_bytes) +
            " total_us=" + std::to_string(metrics.total_us));
        if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) {
            std::error_code after_error;
            const auto after{std::filesystem::space(options.checkpoint->parent_path().empty() ?
                                                         std::filesystem::path{"."} :
                                                         options.checkpoint->parent_path(),
                                                     after_error)};
            utreexo::Log(utreexo::LogLevel::DEBUG, "checkpoint_save_metrics",
                "height=" + std::to_string(point.height) +
                " payload_bytes=" + std::to_string(metrics.payload_bytes) +
                " write_us=" + std::to_string(metrics.write_us) +
                " checksum_us=" + std::to_string(metrics.checksum_us) +
                " checksum_append_us=" + std::to_string(metrics.checksum_append_us) +
                " file_sync_us=" + std::to_string(metrics.file_sync_us) +
                " rename_us=" + std::to_string(metrics.rename_us) +
                " directory_sync_us=" + std::to_string(metrics.directory_sync_us) +
                " total_us=" + std::to_string(metrics.total_us) +
                " free_bytes_after=" + std::to_string(after_error ? 0 : after.available));
        }
        return utreexo::Result<void>::Ok();
    };

    IntervalMetrics interval;
    IntervalMetrics overall;
    auto interval_start{Clock::now()};
    const auto sync_wall_start{Clock::now()};

    while (sync.ChainHashes().size() <= target) {
        utreexo::Result<utreexo::ProcessedBlock> block{utreexo::Result<utreexo::ProcessedBlock>::Err("uninitialized")};
        try {
            block = sync.ProcessNext();
        } catch (const std::bad_alloc&) {
            sync.StopPrefetch();
            const auto point{sync.CurrentPoint()};
            const uint32_t safe_height{point ? point->height : 0};
            if (forest.IsOnline()) {
                const auto usage{forest.OnlineUsage()};
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=online_block_transition safe_height=" + std::to_string(safe_height) +
                    " durable_lsn=" + std::to_string(usage.current_lsn) +
                    " action=stop_without_full_checkpoint recovery=reopen_mmap_and_replay_wal");
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                "phase=block_transition safe_height=" + std::to_string(safe_height) +
                " target_height=" + std::to_string(target) +
                " action=emergency_checkpoint");
            if (!options.checkpoint || !point) {
                utreexo::Log(utreexo::LogLevel::ERROR, "emergency_checkpoint_unavailable",
                    "reason=" + std::string{!options.checkpoint ? "no_checkpoint_path" : "no_completed_block"} +
                    " recovery=restart_from_last_checkpoint");
                return 2;
            }
            const auto saved{save_checkpoint(*point, "memory_allocation_failure")};
            if (!saved) {
                utreexo::Log(utreexo::LogLevel::ERROR, "emergency_checkpoint_failed",
                    "height=" + std::to_string(safe_height) +
                    " error=" + StringField(saved.Error()) +
                    " recovery=restart_from_last_checkpoint");
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "sync_aborted_memory_limit",
                "safe_height=" + std::to_string(safe_height) +
                " checkpoint_status=saved exit_code=2"
                " recovery=restart_from_saved_checkpoint_after_freeing_memory");
            return 2;
        }
        if (!block) {
            sync.StopPrefetch();
            utreexo::Log(utreexo::LogLevel::ERROR, "sync_failed",
                "height=" + std::to_string(sync.ChainHashes().size()) +
                " error=" + StringField(block.Error()));
            return 1;
        }
        const uint32_t height{block.Value().delta.point.height};
        interval.Add(height, block.Value().metrics);
        overall.Add(height, block.Value().metrics);
        if (utreexo::LogEnabled(utreexo::LogLevel::TRACE)) {
            utreexo::Log(utreexo::LogLevel::TRACE, "block_processed",
                "height=" + std::to_string(height) +
                " block_hash=" + block.Value().delta.point.block_hash.ToBitcoinHex() +
                " additions=" + std::to_string(block.Value().delta.additions.size()) +
                " deletions=" + std::to_string(block.Value().delta.deletions.size()) +
                " chain_check_us=" + std::to_string(block.Value().metrics.chain_check_us) +
                " block_hash_us=" + std::to_string(block.Value().metrics.block_hash_us) +
                " block_fetch_us=" + std::to_string(block.Value().metrics.block_fetch_us) +
                " parse_us=" + std::to_string(block.Value().metrics.parse_us) +
                " modify_us=" + std::to_string(block.Value().metrics.modify_us) +
                " total_us=" + std::to_string(block.Value().metrics.total_us));
        }
        if (height % 1'000 == 0 || height == target) {
            const auto usage{forest.Usage()};
            const uint64_t interval_us{static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - interval_start).count())};
            const uint64_t blocks_per_second_milli{interval_us == 0 ? 0 :
                interval.blocks * 1'000'000'000ULL / interval_us};
            utreexo::Log(utreexo::LogLevel::INFO, "sync_progress",
                "height=" + std::to_string(height) +
                " target_height=" + std::to_string(target) +
                " leaves=" + std::to_string(forest.NumLeaves()) +
                " live_nodes=" + std::to_string(usage.live_nodes) +
                " estimated_ram_mib=" + std::to_string(usage.estimated_bytes / (1024 * 1024)) +
                " blocks_per_second_milli=" + std::to_string(blocks_per_second_milli));
            LogMemoryBreakdown("sync_progress", height, forest);
            LogOnlineBreakdown("sync_progress", height, forest);
            if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG) && interval.blocks != 0) {
                utreexo::Log(utreexo::LogLevel::DEBUG, "block_timing_window",
                    "height=" + std::to_string(height) +
                    " blocks=" + std::to_string(interval.blocks) +
                    " wall_us=" + std::to_string(interval_us) +
                    " avg_chain_check_us=" + std::to_string(interval.chain_check_us / interval.blocks) +
                    " avg_block_hash_us=" + std::to_string(interval.block_hash_us / interval.blocks) +
                    " avg_block_fetch_us=" + std::to_string(interval.block_fetch_us / interval.blocks) +
                    " avg_parse_us=" + std::to_string(interval.parse_us / interval.blocks) +
                    " avg_modify_us=" + std::to_string(interval.modify_us / interval.blocks) +
                    " avg_total_us=" + std::to_string(interval.total_us / interval.blocks) +
                    " slowest_height=" + std::to_string(interval.slowest_height) +
                    " slowest_total_us=" + std::to_string(interval.slowest_us));
            }
            interval = {};
            interval_start = Clock::now();
        }
        if (options.checkpoint && !forest.IsOnline() && options.checkpoint_interval != 0 &&
            height != 0 && height % options.checkpoint_interval == 0) {
            const auto point{sync.CurrentPoint()};
            const auto saved{save_checkpoint(*point, "interval")};
            if (!saved) {
                utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_save_failed",
                    "height=" + std::to_string(height) +
                    " error=" + StringField(saved.Error()));
                return 1;
            }
        }
    }

    sync.StopPrefetch();
    const auto active_point{sync.ValidateCurrentPoint()};
    if (!active_point) {
        utreexo::Log(utreexo::LogLevel::ERROR, "sync_failed",
            "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " error=" + StringField(active_point.Error()));
        return 1;
    }

    if (options.online_state && !forest.IsOnline()) {
        if (target != tip.Value()) {
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_deferred",
                "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
                " core_tip_height=" + std::to_string(tip.Value()) +
                " reason=stop_height_before_core_tip");
        } else if (!sync.CurrentPoint()) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_switch_failed",
                         "reason=no_completed_chain_point");
            return 1;
        } else {
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_started",
                "height=" + std::to_string(sync.CurrentPoint()->height) +
                " path=" + PathField(*options.online_state) +
                " cache_bytes=" + std::to_string(online_config.max_dirty_bytes) +
                " wal_segment_bytes=" + std::to_string(online_config.wal_segment_bytes) +
                " undo_depth=" + std::to_string(online_config.undo_depth));
            const auto switched{forest.EnableOnline(*options.online_state, *sync.CurrentPoint(),
                                                    sync.ChainHashes(), online_config)};
            if (!switched) {
                utreexo::Log(utreexo::LogLevel::ERROR, "online_switch_failed",
                    "height=" + std::to_string(sync.CurrentPoint()->height) +
                    " path=" + PathField(*options.online_state) +
                    " error=" + StringField(switched.Error()));
                return 1;
            }
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_complete",
                "height=" + std::to_string(sync.CurrentPoint()->height) +
                " path=" + PathField(*options.online_state) +
                " storage_mode=mmap_wal");
            LogMemoryBreakdown("online_switch_complete", sync.CurrentPoint()->height, forest);
            LogOnlineBreakdown("online_switch_complete", sync.CurrentPoint()->height, forest);
        }
    }

    const uint64_t sync_wall_us{static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - sync_wall_start).count())};
    if (overall.blocks != 0) {
        utreexo::Log(utreexo::LogLevel::INFO, "sync_timing_summary",
            "blocks=" + std::to_string(overall.blocks) +
            " wall_us=" + std::to_string(sync_wall_us) +
            " avg_total_us=" + std::to_string(overall.total_us / overall.blocks) +
            " slowest_height=" + std::to_string(overall.slowest_height) +
            " slowest_total_us=" + std::to_string(overall.slowest_us));
    }

    std::shared_ptr<utreexo::RecentProofCache> proof_cache;
    std::unique_ptr<utreexo::P2PServer> p2p_server;
    if (options.p2p_port) {
        constexpr uint64_t MIB{1024ULL * 1024};
        proof_cache = std::make_shared<utreexo::RecentProofCache>(
            options.p2p_proof_cache_blocks, options.p2p_proof_cache_mib * MIB);
        proof_cache->SetTip(sync.CurrentPoint()->height);
        sync.SetProofGeneration(true);
        auto started{utreexo::P2PServer::Start(utreexo::P2PServerConfig{
            .network = options.p2p_network,
            .bind_address = options.p2p_bind,
            .port = *options.p2p_port,
            .max_peers = options.p2p_max_peers,
            .max_payload_bytes = 32U * 1024U * 1024U,
            .idle_timeout_seconds = 120,
            .user_agent = "/utreexo-bridge:" UTREEXO_BRIDGE_VERSION "/",
        }, proof_cache)};
        if (!started) {
            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_listen_failed",
                "bind=" + StringField(options.p2p_bind) +
                " port=" + std::to_string(*options.p2p_port) +
                " error=" + StringField(started.Error()));
            return 1;
        }
        p2p_server = started.Take();
        utreexo::Log(utreexo::LogLevel::INFO, "p2p_listening",
            "bind=" + StringField(options.p2p_bind) +
            " port=" + std::to_string(p2p_server->BoundPort()) +
            " services=NODE_UTREEXO transport=v1 archive=false"
            " cache_blocks=" + std::to_string(options.p2p_proof_cache_blocks) +
            " cache_bytes=" + std::to_string(options.p2p_proof_cache_mib * MIB) +
            " cached_proofs=0 cache_persistence=disposable"
            " note=proofs_become_available_as_new_blocks_are_followed");
    }

    if (options.follow) {
        if (!forest.IsOnline()) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_follow_failed",
                         "reason=online_switch_was_not_completed");
            return 1;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "online_follow_started",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " poll_interval_ms=" + std::to_string(options.poll_interval_ms) +
            " wal_sync=per_block");
        auto last_base_flush{Clock::now()};
        while (true) {
            const auto reconciled{sync.ReconcileCurrentPoint()};
            if (!reconciled) {
                utreexo::Log(utreexo::LogLevel::ERROR, "online_reconcile_failed",
                    "height=" + std::to_string(sync.CurrentPoint()->height) +
                    " error=" + StringField(reconciled.Error()) +
                    " action=fail_closed_restore_validated_checkpoint retained_undo_depth=" +
                    std::to_string(online_config.undo_depth));
                return 1;
            }
            if (reconciled.Value() != 0) {
                if (proof_cache) proof_cache->DiscardAfter(sync.CurrentPoint()->height);
                utreexo::Log(utreexo::LogLevel::WARN, "online_reorg_rolled_back",
                    "disconnected_blocks=" + std::to_string(reconciled.Value()) +
                    " recovered_height=" + std::to_string(sync.CurrentPoint()->height));
            }
            auto current_tip{sync.TipHeight()};
            if (!current_tip) {
                utreexo::Log(utreexo::LogLevel::WARN, "online_tip_poll_failed",
                             "error=" + StringField(current_tip.Error()) + " action=retry");
                std::this_thread::sleep_for(std::chrono::milliseconds(options.poll_interval_ms));
                continue;
            }
            if (sync.ChainHashes().size() <= current_tip.Value()) {
                auto started{sync.StartPrefetch(current_tip.Value())};
                if (!started) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "online_prefetch_failed",
                                 "error=" + StringField(started.Error()));
                    return 1;
                }
                while (sync.ChainHashes().size() <= current_tip.Value()) {
                    utreexo::Result<utreexo::ProcessedBlock> block{
                        utreexo::Result<utreexo::ProcessedBlock>::Err("uninitialized online block")};
                    try {
                        block = sync.ProcessNext();
                    } catch (const std::bad_alloc&) {
                        sync.StopPrefetch();
                        const auto storage{forest.OnlineUsage()};
                        utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                            "phase=online_follow_block safe_height=" +
                            std::to_string(sync.CurrentPoint()->height) +
                            " durable_lsn=" + std::to_string(storage.current_lsn) +
                            " dirty_bytes=" + std::to_string(storage.dirty_bytes) +
                            " redo_wal_bytes=" + std::to_string(storage.redo_wal_bytes) +
                            " action=stop_without_full_checkpoint"
                            " recovery=reopen_mmap_and_replay_wal");
                        return 2;
                    }
                    if (!block) {
                        sync.StopPrefetch();
                        utreexo::Log(utreexo::LogLevel::ERROR, "online_block_failed",
                            "height=" + std::to_string(sync.ChainHashes().size()) +
                            " error=" + StringField(block.Error()));
                        return 1;
                    }
                    if (proof_cache) {
                        if (!block.Value().proof) {
                            sync.StopPrefetch();
                            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_proof_capture_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " reason=missing_generated_proof action=stop");
                            return 1;
                        }
                        auto published{proof_cache->Publish(block.Value().delta,
                                                           std::move(*block.Value().proof))};
                        if (!published) {
                            sync.StopPrefetch();
                            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_proof_capture_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " error=" + StringField(published.Error()) + " action=stop");
                            return 1;
                        }
                    }
                    const auto storage{forest.OnlineUsage()};
                    const auto cache_stats{proof_cache ? proof_cache->Stats() :
                        utreexo::ProofCacheStats{}};
                    utreexo::Log(utreexo::LogLevel::INFO, "online_block_committed",
                        "height=" + std::to_string(block.Value().delta.point.height) +
                        " block_hash=" + block.Value().delta.point.block_hash.ToBitcoinHex() +
                        " additions=" + std::to_string(block.Value().delta.additions.size()) +
                        " deletions=" + std::to_string(block.Value().delta.deletions.size()) +
                        " modify_us=" + std::to_string(block.Value().metrics.modify_us) +
                        " total_us=" + std::to_string(block.Value().metrics.total_us) +
                        " dirty_nodes=" + std::to_string(storage.dirty_nodes) +
                        " dirty_bytes=" + std::to_string(storage.dirty_bytes) +
                        " wal_bytes=" + std::to_string(storage.wal_bytes) +
                        " redo_wal_bytes=" + std::to_string(storage.redo_wal_bytes) +
                        " transaction_nodes=" + std::to_string(storage.last_transaction_nodes) +
                        " transaction_wal_bytes=" + std::to_string(storage.last_transaction_wal_bytes) +
                        " lsn=" + std::to_string(storage.current_lsn) +
                        (proof_cache ? " proof_cache_entries=" + std::to_string(cache_stats.entries) +
                                       " proof_cache_bytes=" + std::to_string(cache_stats.bytes) : ""));
                }
                sync.StopPrefetch();
                const auto validated{sync.ValidateCurrentPoint()};
                if (!validated) {
                    utreexo::Log(utreexo::LogLevel::WARN, "online_batch_reorg_detected",
                                 "error=" + StringField(validated.Error()) +
                                 " action=reconcile");
                    continue;
                }
            }
            if (Clock::now() - last_base_flush >= std::chrono::hours(24)) {
                const auto before{forest.OnlineUsage()};
                auto flushed{forest.FlushOnline()};
                if (!flushed) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "online_base_flush_failed",
                                 "error=" + StringField(flushed.Error()) + " action=stop");
                    return 1;
                }
                const auto after{forest.OnlineUsage()};
                utreexo::Log(utreexo::LogLevel::INFO, "online_base_flushed",
                    "height=" + std::to_string(sync.CurrentPoint()->height) +
                    " dirty_nodes=" + std::to_string(before.dirty_nodes) +
                    " base_lsn_before=" + std::to_string(before.base_lsn) +
                    " base_lsn_after=" + std::to_string(after.base_lsn));
                last_base_flush = Clock::now();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(options.poll_interval_ms));
        }
    }

    const auto& rpc_metrics{source.RpcMetrics()};
    utreexo::Log(utreexo::LogLevel::INFO, "rpc_summary",
        "calls=" + std::to_string(rpc_metrics.calls) +
        " failures=" + std::to_string(rpc_metrics.failures) +
        " retries=" + std::to_string(rpc_metrics.retries) +
        " request_bytes=" + std::to_string(rpc_metrics.request_bytes) +
        " response_bytes=" + std::to_string(rpc_metrics.response_bytes) +
        " elapsed_us=" + std::to_string(rpc_metrics.elapsed_us) +
        " largest_response_bytes=" + std::to_string(rpc_metrics.largest_response_bytes) +
        " largest_response_method=" + rpc_metrics.largest_response_method +
        " slowest_call_us=" + std::to_string(rpc_metrics.slowest_call_us) +
        " slowest_call_method=" + rpc_metrics.slowest_call_method +
        " largest_block_response_bytes=" + std::to_string(source.LargestBlockResponseBytes()) +
        " largest_block_response_hash=" + source.LargestBlockResponseHash().ToBitcoinHex() +
        " largest_block_response_elapsed_us=" +
        std::to_string(source.LargestBlockResponseElapsedUs()));

    if (forest.IsOnline()) {
        const auto before{forest.OnlineUsage()};
        const auto flushed{forest.FlushOnline()};
        if (!flushed) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_base_flush_failed",
                         "reason=clean_shutdown error=" + StringField(flushed.Error()));
            return 1;
        }
        const auto after{forest.OnlineUsage()};
        utreexo::Log(utreexo::LogLevel::INFO, "online_base_flushed",
            "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " reason=clean_shutdown dirty_nodes=" + std::to_string(before.dirty_nodes) +
            " base_lsn_before=" + std::to_string(before.base_lsn) +
            " base_lsn_after=" + std::to_string(after.base_lsn));
    }
    if (options.checkpoint && sync.CurrentPoint() && !forest.IsOnline()) {
        const auto saved{save_checkpoint(*sync.CurrentPoint(), "final")};
        if (!saved) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_save_failed",
                         "reason=final error=" + StringField(saved.Error()));
            return 1;
        }
    } else if (options.checkpoint && sync.CurrentPoint() && forest.IsOnline()) {
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_save_skipped",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " reason=online_native_state_is_durable fallback_checkpoint_preserved=true");
    }
    if (options.state_json && sync.CurrentPoint()) {
        const auto written{WriteStateJson(*options.state_json, *sync.CurrentPoint(), forest)};
        if (!written) {
            utreexo::Log(utreexo::LogLevel::ERROR, "state_json_failed",
                         "error=" + StringField(written.Error()));
            return 1;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "state_json_written",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " path=" + PathField(*options.state_json));
    }
    if (sync.CurrentPoint()) {
        uint64_t checkpoint_bytes{0};
        if (options.checkpoint) {
            std::error_code size_error;
            checkpoint_bytes = std::filesystem::file_size(*options.checkpoint, size_error);
            if (size_error) checkpoint_bytes = 0;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "milestone_manifest",
            "version=" UTREEXO_BRIDGE_VERSION
            " checkpoint_format=" + std::to_string(utreexo::CHECKPOINT_FORMAT_VERSION) +
            " forest_format=" +
            std::to_string(utreexo::PackedForest::FORMAT_VERSION) +
            " height=" + std::to_string(sync.CurrentPoint()->height) +
            " block_hash=" + sync.CurrentPoint()->block_hash.ToBitcoinHex() +
            " num_leaves=" + std::to_string(forest.NumLeaves()) +
            " roots=" + RootsField(forest) +
            " checkpoint_bytes=" + std::to_string(checkpoint_bytes) +
            " storage_mode=" + std::string{forest.IsOnline() ? "mmap_wal" : "ram_checkpoint"} +
            " online_base_bytes=" + std::to_string(forest.OnlineUsage().base_bytes) +
            " online_wal_bytes=" + std::to_string(forest.OnlineUsage().wal_bytes) +
            " online_base_lsn=" + std::to_string(forest.OnlineUsage().base_lsn));
    }
    utreexo::Log(utreexo::LogLevel::INFO, "sync_complete",
                 "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0));
    return 0;
}
