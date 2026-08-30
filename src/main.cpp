// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/checkpoint.h>
#include <utreexo/core_rpc.h>
#include <utreexo/log.h>
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
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

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
    std::optional<std::filesystem::path> state_json;
    std::optional<uint32_t> stop_height;
    uint32_t checkpoint_interval{0};
    utreexo::LogLevel log_level{utreexo::LogLevel::INFO};
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
        } else if (auto parsed{value("--rpc-host")}) {
            options.host = *parsed;
        } else if (auto parsed{value("--rpc-port")}) {
            if (!ParseInteger(*parsed, options.port)) return utreexo::Result<Options>::Err("invalid --rpc-port");
        } else if (auto parsed{value("--rpc-auth")}) {
            options.authorization = *parsed;
        } else if (auto parsed{value("--rpc-cookie")}) {
            options.cookie = *parsed;
        } else if (auto parsed{value("--checkpoint")}) {
            options.checkpoint = std::filesystem::path{*parsed};
        } else if (auto parsed{value("--checkpoint-interval")}) {
            if (!ParseInteger(*parsed, options.checkpoint_interval)) {
                return utreexo::Result<Options>::Err("invalid --checkpoint-interval");
            }
        } else if (auto parsed{value("--state-json")}) {
            options.state_json = std::filesystem::path{*parsed};
        } else if (auto parsed{value("--stop-height")}) {
            uint32_t height{0};
            if (!ParseInteger(*parsed, height)) return utreexo::Result<Options>::Err("invalid --stop-height");
            options.stop_height = height;
        } else if (auto parsed{value("--log-level")}) {
            auto level{utreexo::ParseLogLevel(*parsed)};
            if (!level) return utreexo::Result<Options>::Err(level.Error());
            options.log_level = level.Value();
        } else {
            return utreexo::Result<Options>::Err("unknown argument: " + std::string{argument});
        }
    }
    if (!options.show_version && options.authorization.empty() && options.cookie.empty()) {
        return utreexo::Result<Options>::Err("provide --rpc-cookie or --rpc-auth");
    }
    return utreexo::Result<Options>::Ok(std::move(options));
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
                  << " checkpoint_format=2 forest_format="
                  << utreexo::PackedForest::FORMAT_VERSION << '\n';
        return 0;
    }
    utreexo::SetLogLevel(options.log_level);
    utreexo::Log(utreexo::LogLevel::INFO, "sidecar_start",
        "version=" UTREEXO_BRIDGE_VERSION
        " checkpoint_format=2 forest_format=" +
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

    utreexo::PackedForest forest;
    std::vector<utreexo::Hash256> chain_hashes;
    if (options.checkpoint && std::filesystem::exists(*options.checkpoint)) {
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
        " core_tip_height=" + std::to_string(tip.Value()));

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
        auto block{sync.ProcessNext()};
        if (!block) {
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
        if (options.checkpoint && options.checkpoint_interval != 0 &&
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
    const auto& rpc_metrics{source.RpcMetrics()};
    utreexo::Log(utreexo::LogLevel::INFO, "rpc_summary",
        "calls=" + std::to_string(rpc_metrics.calls) +
        " failures=" + std::to_string(rpc_metrics.failures) +
        " retries=0" +
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

    if (options.checkpoint && sync.CurrentPoint()) {
        const auto saved{save_checkpoint(*sync.CurrentPoint(), "final")};
        if (!saved) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_save_failed",
                         "reason=final error=" + StringField(saved.Error()));
            return 1;
        }
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
            " checkpoint_format=2 forest_format=" +
            std::to_string(utreexo::PackedForest::FORMAT_VERSION) +
            " height=" + std::to_string(sync.CurrentPoint()->height) +
            " block_hash=" + sync.CurrentPoint()->block_hash.ToBitcoinHex() +
            " num_leaves=" + std::to_string(forest.NumLeaves()) +
            " roots=" + RootsField(forest) +
            " checkpoint_bytes=" + std::to_string(checkpoint_bytes));
    }
    utreexo::Log(utreexo::LogLevel::INFO, "sync_complete",
                 "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0));
    return 0;
}
