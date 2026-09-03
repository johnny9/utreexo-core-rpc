// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/checkpoint.h>
#include <utreexo/core_rpc.h>
#include <utreexo/log.h>
#include <utreexo/memory.h>
#include <utreexo/p2p.h>
#include <utreexo/proof_store.h>
#include <utreexo/sync.h>
#include <utreexo/trusted_checkpoint.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>
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
#include <sys/resource.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace {

#ifndef UTREEXO_BRIDGE_VERSION
#define UTREEXO_BRIDGE_VERSION "unknown"
#endif

using Clock = std::chrono::steady_clock;

volatile std::sig_atomic_t g_shutdown_signal{0};

extern "C" void HandleShutdownSignal(int signal_number)
{
    if (g_shutdown_signal == 0) g_shutdown_signal = signal_number;
}

utreexo::Result<void> InstallShutdownSignalHandlers()
{
    struct sigaction action {};
    action.sa_handler = HandleShutdownSignal;
    action.sa_flags = SA_RESTART;
    if (::sigemptyset(&action.sa_mask) != 0 ||
        ::sigaction(SIGINT, &action, nullptr) != 0 ||
        ::sigaction(SIGTERM, &action, nullptr) != 0) {
        return utreexo::Result<void>::Err(
            "could not install shutdown signal handlers: " + std::string{std::strerror(errno)});
    }
    return utreexo::Result<void>::Ok();
}

int RequestedShutdownSignal()
{
    return static_cast<int>(g_shutdown_signal);
}

std::string_view ShutdownSignalName(int signal_number)
{
    if (signal_number == SIGINT) return "SIGINT";
    if (signal_number == SIGTERM) return "SIGTERM";
    return "unknown";
}

struct Options {
    std::string host{"127.0.0.1"};
    uint16_t port{8332};
    std::string authorization;
    std::filesystem::path cookie;
    std::optional<std::filesystem::path> checkpoint;
    std::optional<std::filesystem::path> recovery_checkpoint;
    std::optional<std::filesystem::path> online_state;
    std::optional<std::filesystem::path> proof_store;
    std::optional<std::filesystem::path> state_json;
    std::optional<uint32_t> stop_height;
    uint32_t checkpoint_interval{0};
    uint64_t online_cache_mib{0};
    uint64_t online_wal_segment_mib{256};
    uint32_t online_undo_depth{1'008};
    uint32_t proof_store_threads{2};
    uint32_t proof_store_group_blocks{32};
    uint32_t proof_store_group_delay_ms{0};
    uint32_t proof_store_queue_blocks{1'008};
    uint64_t proof_store_queue_mib{256};
    uint64_t proof_store_max_record_mib{320};
    uint64_t memory_reserve_mib{2'048};
    uint32_t poll_interval_ms{5'000};
    std::string p2p_bind{"127.0.0.1"};
    std::optional<uint16_t> p2p_port;
    std::optional<utreexo::P2PIPv4Endpoint> p2p_advertise;
    std::vector<utreexo::P2PIPv4Endpoint> p2p_gossip_seeds;
    utreexo::BitcoinNetwork p2p_network{utreexo::BitcoinNetwork::MAINNET};
    uint32_t p2p_max_peers{16};
    uint32_t p2p_max_peers_per_ip{4};
    uint32_t p2p_max_proof_requests{4};
    uint64_t p2p_egress_mib_per_second{64};
    uint64_t p2p_egress_burst_mib{384};
    uint64_t p2p_max_payload_mib{320};
    uint32_t p2p_gossip_retry_seconds{300};
    uint32_t p2p_gossip_timeout_seconds{5};
    uint32_t p2p_proof_cache_blocks{288};
    uint64_t p2p_proof_cache_mib{256};
    utreexo::LogLevel log_level{utreexo::LogLevel::INFO};
    bool allow_untrusted_checkpoint{false};
    bool proof_store_scrub{false};
    bool fast_sync{false};
    bool follow{false};
    bool show_version{false};
};

struct IntervalMetrics {
    uint64_t blocks{0};
    uint64_t generated_proofs{0};
    uint64_t fetch_wait_us{0};
    uint64_t chain_check_us{0};
    uint64_t block_hash_us{0};
    uint64_t block_fetch_us{0};
    uint64_t parse_us{0};
    uint64_t proof_policy_us{0};
    uint64_t prove_us{0};
    uint64_t verify_us{0};
    uint64_t modify_us{0};
    uint64_t proof_enqueue_us{0};
    uint64_t proof_durable_wait_us{0};
    uint64_t total_us{0};
    uint64_t end_to_end_us{0};
    uint64_t slowest_total_us{0};
    uint32_t slowest_total_height{0};
    uint64_t slowest_end_to_end_us{0};
    uint32_t slowest_end_to_end_height{0};

    void Add(uint32_t height, const utreexo::BlockProcessingMetrics& metrics,
             bool generated_proof)
    {
        ++blocks;
        if (generated_proof) ++generated_proofs;
        fetch_wait_us += metrics.fetch_wait_us;
        chain_check_us += metrics.chain_check_us;
        block_hash_us += metrics.block_hash_us;
        block_fetch_us += metrics.block_fetch_us;
        parse_us += metrics.parse_us;
        proof_policy_us += metrics.proof_policy_us;
        prove_us += metrics.prove_us;
        verify_us += metrics.verify_us;
        modify_us += metrics.modify_us;
        proof_enqueue_us += metrics.proof_enqueue_us;
        proof_durable_wait_us += metrics.proof_durable_wait_us;
        total_us += metrics.total_us;
        end_to_end_us += metrics.end_to_end_us;
        if (metrics.total_us > slowest_total_us) {
            slowest_total_us = metrics.total_us;
            slowest_total_height = height;
        }
        if (metrics.end_to_end_us > slowest_end_to_end_us) {
            slowest_end_to_end_us = metrics.end_to_end_us;
            slowest_end_to_end_height = height;
        }
    }
};

struct ProcessResources {
    bool rusage_available{false};
    bool proc_status_available{false};
    bool proc_io_available{false};
    uint64_t rss_bytes{0};
    uint64_t peak_rss_bytes{0};
    uint64_t rss_anon_bytes{0};
    uint64_t rss_file_bytes{0};
    uint64_t rss_shmem_bytes{0};
    uint64_t minor_faults{0};
    uint64_t major_faults{0};
    uint64_t user_cpu_us{0};
    uint64_t system_cpu_us{0};
    uint64_t voluntary_context_switches{0};
    uint64_t involuntary_context_switches{0};
    uint64_t io_read_chars{0};
    uint64_t io_write_chars{0};
    uint64_t io_read_syscalls{0};
    uint64_t io_write_syscalls{0};
    uint64_t io_read_bytes{0};
    uint64_t io_write_bytes{0};
    uint64_t io_cancelled_write_bytes{0};
};

template <typename T>
uint64_t NonNegative(T value)
{
    if constexpr (std::is_signed_v<T>) {
        if (value <= 0) return 0;
    }
    return static_cast<uint64_t>(value);
}

uint64_t SaturatingMultiply(uint64_t value, uint64_t factor)
{
    return factor != 0 && value > std::numeric_limits<uint64_t>::max() / factor ?
        std::numeric_limits<uint64_t>::max() : value * factor;
}

uint64_t TimevalMicros(const timeval& value)
{
    const uint64_t seconds{NonNegative(value.tv_sec)};
    const uint64_t micros{NonNegative(value.tv_usec)};
    const uint64_t scaled{SaturatingMultiply(seconds, 1'000'000)};
    return micros > std::numeric_limits<uint64_t>::max() - scaled ?
        std::numeric_limits<uint64_t>::max() : scaled + micros;
}

ProcessResources ReadProcessResources()
{
    ProcessResources result;
    rusage usage{};
    if (::getrusage(RUSAGE_SELF, &usage) == 0) {
        result.rusage_available = true;
        result.minor_faults = NonNegative(usage.ru_minflt);
        result.major_faults = NonNegative(usage.ru_majflt);
        result.user_cpu_us = TimevalMicros(usage.ru_utime);
        result.system_cpu_us = TimevalMicros(usage.ru_stime);
        result.voluntary_context_switches = NonNegative(usage.ru_nvcsw);
        result.involuntary_context_switches = NonNegative(usage.ru_nivcsw);
#if defined(__APPLE__)
        result.peak_rss_bytes = NonNegative(usage.ru_maxrss);
#else
        result.peak_rss_bytes = SaturatingMultiply(NonNegative(usage.ru_maxrss), 1'024);
#endif
    }
#if defined(__linux__)
    {
        std::ifstream status{"/proc/self/status"};
        std::string line;
        while (std::getline(status, line)) {
            std::istringstream fields{line};
            std::string name;
            uint64_t value{0};
            std::string unit;
            if (!(fields >> name >> value >> unit) || unit != "kB") continue;
            const uint64_t bytes{SaturatingMultiply(value, 1'024)};
            if (name == "VmRSS:") result.rss_bytes = bytes;
            else if (name == "VmHWM:") result.peak_rss_bytes = std::max(result.peak_rss_bytes, bytes);
            else if (name == "RssAnon:") result.rss_anon_bytes = bytes;
            else if (name == "RssFile:") result.rss_file_bytes = bytes;
            else if (name == "RssShmem:") result.rss_shmem_bytes = bytes;
        }
        result.proc_status_available = static_cast<bool>(status) || status.eof();
    }
    {
        std::ifstream io{"/proc/self/io"};
        std::string name;
        uint64_t value{0};
        while (io >> name >> value) {
            if (name == "rchar:") result.io_read_chars = value;
            else if (name == "wchar:") result.io_write_chars = value;
            else if (name == "syscr:") result.io_read_syscalls = value;
            else if (name == "syscw:") result.io_write_syscalls = value;
            else if (name == "read_bytes:") result.io_read_bytes = value;
            else if (name == "write_bytes:") result.io_write_bytes = value;
            else if (name == "cancelled_write_bytes:") result.io_cancelled_write_bytes = value;
        }
        result.proc_io_available = io.eof();
    }
#endif
    return result;
}

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
        << "  --checkpoint=PATH           Load a bootstrap or local checkpoint\n"
        << "  --recovery-checkpoint=PATH  Load/save a local RAM-sync recovery point\n"
        << "                              (trusted bootstrap default: PATH.resume)\n"
        << "  --allow-untrusted-checkpoint\n"
        << "                              Skip compiled validation or create a local checkpoint\n"
        << "  --fast-sync                 Keep the forest in RAM until Core tip (opt-in)\n"
        << "                              WARNING: requires at least 32 GiB system RAM\n"
        << "  --checkpoint-interval=N     Full checkpoint every N blocks (default 0: final only)\n"
        << "                              RAM guard saves at safe completed sync boundaries\n"
        << "  --online-state=DIR          Native mmap/WAL state (default for checkpoint catch-up)\n"
        << "  --online-cache-mib=N        Dirty-node cache (default: 128 on <=20GiB, else 512)\n"
        << "  --online-wal-segment-mib=N  WAL segment size (default 256)\n"
        << "  --online-undo-depth=N       Retained WAL before-image window (default 1008)\n"
        << "  --proof-store=DIR           Durable checkpoint-to-tip AssumeUtreexo proofs\n"
        << "  --proof-store-scrub         Verify every durable proof/state record before serving\n"
        << "  --proof-store-threads=N     Parallel proof serializers (default 2)\n"
        << "  --proof-store-group-blocks=N  Maximum proofs per fsync group (default 32)\n"
        << "  --proof-store-group-delay-ms=N  Timed partial-group flush (default 0: disabled)\n"
        << "  --proof-store-queue-blocks=N  Pipeline/recovery window (default 1008)\n"
        << "  --proof-store-queue-mib=N   Pipeline memory ceiling (default 256)\n"
        << "  --proof-store-max-record-mib=N  Largest archived proof (default 320)\n"
        << "  --memory-reserve-mib=N      Stop/checkpoint RAM sync below this availability\n"
        << "                              (default 2048; 0 disables the proactive guard)\n"
        << "  --follow                    Poll Core and remain online after the initial sync\n"
        << "  --poll-interval-ms=N        Follow-mode Core tip poll interval (default 5000)\n"
        << "  --p2p-port=N                Serve cached/archived getuproof over Bitcoin v1 P2P\n"
        << "  --p2p-bind=IP               P2P IPv4 bind address: 127.0.0.1 or 0.0.0.0\n"
        << "  --p2p-advertise=IPv4:PORT   Public address returned and announced to seeds\n"
        << "  --p2p-gossip-seed=IPv4:PORT Utreexo-aware peer for address announcement\n"
        << "                              (repeatable; numeric IPv4 only; default none)\n"
        << "  --p2p-gossip-retry-seconds=N  Reannounce interval (default 300)\n"
        << "  --p2p-gossip-timeout-seconds=N Seed connect/handshake timeout (default 5)\n"
        << "  --p2p-network=NETWORK       mainnet, testnet3, signet, or regtest\n"
        << "  --p2p-max-peers=N           Maximum inbound proof peers (default 16)\n"
        << "  --p2p-max-peers-per-ip=N    Per-IPv4 inbound limit (default 4)\n"
        << "  --p2p-max-proof-requests=N  Concurrent proof/state work limit (default 4)\n"
        << "  --p2p-egress-mib-per-sec=N  Global proof-response rate (default 64)\n"
        << "  --p2p-egress-burst-mib=N    Global proof-response burst (default 384)\n"
        << "  --p2p-max-payload-mib=N     Largest proof response (default 320)\n"
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
            if (!ParseInteger(*port, options.port) || options.port == 0) {
                return utreexo::Result<Options>::Err("invalid --rpc-port");
            }
        } else if (auto auth{value("--rpc-auth")}) {
            options.authorization = *auth;
        } else if (auto cookie{value("--rpc-cookie")}) {
            options.cookie = *cookie;
        } else if (auto checkpoint{value("--checkpoint")}) {
            options.checkpoint = std::filesystem::path{*checkpoint};
        } else if (auto recovery{value("--recovery-checkpoint")}) {
            options.recovery_checkpoint = std::filesystem::path{*recovery};
        } else if (auto online_state{value("--online-state")}) {
            options.online_state = std::filesystem::path{*online_state};
        } else if (auto proof_store{value("--proof-store")}) {
            options.proof_store = std::filesystem::path{*proof_store};
        } else if (auto interval{value("--checkpoint-interval")}) {
            if (!ParseInteger(*interval, options.checkpoint_interval)) {
                return utreexo::Result<Options>::Err("invalid --checkpoint-interval");
            }
        } else if (auto state_json{value("--state-json")}) {
            options.state_json = std::filesystem::path{*state_json};
        } else if (auto cache{value("--online-cache-mib")}) {
            if (!ParseInteger(*cache, options.online_cache_mib) ||
                options.online_cache_mib == 0 ||
                options.online_cache_mib > std::numeric_limits<uint64_t>::max() /
                                                   (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --online-cache-mib");
            }
        } else if (auto segment{value("--online-wal-segment-mib")}) {
            if (!ParseInteger(*segment, options.online_wal_segment_mib) ||
                options.online_wal_segment_mib == 0 ||
                options.online_wal_segment_mib > std::numeric_limits<uint64_t>::max() /
                                                         (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --online-wal-segment-mib");
            }
        } else if (auto depth{value("--online-undo-depth")}) {
            if (!ParseInteger(*depth, options.online_undo_depth) || options.online_undo_depth == 0) {
                return utreexo::Result<Options>::Err("invalid --online-undo-depth");
            }
        } else if (auto threads{value("--proof-store-threads")}) {
            if (!ParseInteger(*threads, options.proof_store_threads) ||
                options.proof_store_threads == 0 || options.proof_store_threads > 64) {
                return utreexo::Result<Options>::Err("invalid --proof-store-threads");
            }
        } else if (auto group_blocks{value("--proof-store-group-blocks")}) {
            if (!ParseInteger(*group_blocks, options.proof_store_group_blocks) ||
                options.proof_store_group_blocks == 0 || options.proof_store_group_blocks > 4'096) {
                return utreexo::Result<Options>::Err("invalid --proof-store-group-blocks");
            }
        } else if (auto delay{value("--proof-store-group-delay-ms")}) {
            if (!ParseInteger(*delay, options.proof_store_group_delay_ms) ||
                options.proof_store_group_delay_ms > 10'000) {
                return utreexo::Result<Options>::Err("invalid --proof-store-group-delay-ms");
            }
        } else if (auto queue_blocks{value("--proof-store-queue-blocks")}) {
            if (!ParseInteger(*queue_blocks, options.proof_store_queue_blocks) ||
                options.proof_store_queue_blocks == 0) {
                return utreexo::Result<Options>::Err("invalid --proof-store-queue-blocks");
            }
        } else if (auto queue{value("--proof-store-queue-mib")}) {
            if (!ParseInteger(*queue, options.proof_store_queue_mib) ||
                options.proof_store_queue_mib == 0 ||
                options.proof_store_queue_mib > std::numeric_limits<uint64_t>::max() /
                                                     (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --proof-store-queue-mib");
            }
        } else if (auto record{value("--proof-store-max-record-mib")}) {
            if (!ParseInteger(*record, options.proof_store_max_record_mib) ||
                options.proof_store_max_record_mib == 0 ||
                options.proof_store_max_record_mib > 4'095) {
                return utreexo::Result<Options>::Err(
                    "invalid --proof-store-max-record-mib");
            }
        } else if (auto reserve{value("--memory-reserve-mib")}) {
            if (!ParseInteger(*reserve, options.memory_reserve_mib) ||
                options.memory_reserve_mib > std::numeric_limits<uint64_t>::max() /
                                                     (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --memory-reserve-mib");
            }
        } else if (auto poll{value("--poll-interval-ms")}) {
            if (!ParseInteger(*poll, options.poll_interval_ms) ||
                options.poll_interval_ms == 0 || options.poll_interval_ms > 60'000) {
                return utreexo::Result<Options>::Err("invalid --poll-interval-ms");
            }
        } else if (auto bind{value("--p2p-bind")}) {
            options.p2p_bind = *bind;
        } else if (auto advertised{value("--p2p-advertise")}) {
            auto endpoint{utreexo::ParseP2PIPv4Endpoint(*advertised)};
            if (!endpoint) {
                return utreexo::Result<Options>::Err(
                    "invalid --p2p-advertise: " + endpoint.Error());
            }
            options.p2p_advertise = endpoint.Take();
        } else if (auto seed{value("--p2p-gossip-seed")}) {
            auto endpoint{utreexo::ParseP2PIPv4Endpoint(*seed)};
            if (!endpoint) {
                return utreexo::Result<Options>::Err(
                    "invalid --p2p-gossip-seed: " + endpoint.Error());
            }
            options.p2p_gossip_seeds.push_back(endpoint.Take());
        } else if (auto retry{value("--p2p-gossip-retry-seconds")}) {
            if (!ParseInteger(*retry, options.p2p_gossip_retry_seconds) ||
                options.p2p_gossip_retry_seconds == 0 ||
                options.p2p_gossip_retry_seconds > 86'400) {
                return utreexo::Result<Options>::Err(
                    "invalid --p2p-gossip-retry-seconds");
            }
        } else if (auto timeout{value("--p2p-gossip-timeout-seconds")}) {
            if (!ParseInteger(*timeout, options.p2p_gossip_timeout_seconds) ||
                options.p2p_gossip_timeout_seconds == 0 ||
                options.p2p_gossip_timeout_seconds > 30) {
                return utreexo::Result<Options>::Err(
                    "invalid --p2p-gossip-timeout-seconds");
            }
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
        } else if (auto peers_per_ip{value("--p2p-max-peers-per-ip")}) {
            if (!ParseInteger(*peers_per_ip, options.p2p_max_peers_per_ip) ||
                options.p2p_max_peers_per_ip == 0 ||
                options.p2p_max_peers_per_ip > 1'024) {
                return utreexo::Result<Options>::Err("invalid --p2p-max-peers-per-ip");
            }
        } else if (auto requests{value("--p2p-max-proof-requests")}) {
            if (!ParseInteger(*requests, options.p2p_max_proof_requests) ||
                options.p2p_max_proof_requests == 0 ||
                options.p2p_max_proof_requests > 1'024) {
                return utreexo::Result<Options>::Err("invalid --p2p-max-proof-requests");
            }
        } else if (auto rate{value("--p2p-egress-mib-per-sec")}) {
            if (!ParseInteger(*rate, options.p2p_egress_mib_per_second) ||
                options.p2p_egress_mib_per_second == 0 ||
                options.p2p_egress_mib_per_second >
                    std::numeric_limits<uint64_t>::max() / (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --p2p-egress-mib-per-sec");
            }
        } else if (auto burst{value("--p2p-egress-burst-mib")}) {
            if (!ParseInteger(*burst, options.p2p_egress_burst_mib) ||
                options.p2p_egress_burst_mib == 0 ||
                options.p2p_egress_burst_mib >
                    std::numeric_limits<uint64_t>::max() / (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --p2p-egress-burst-mib");
            }
        } else if (auto payload{value("--p2p-max-payload-mib")}) {
            if (!ParseInteger(*payload, options.p2p_max_payload_mib) ||
                options.p2p_max_payload_mib == 0 || options.p2p_max_payload_mib > 4'095) {
                return utreexo::Result<Options>::Err("invalid --p2p-max-payload-mib");
            }
        } else if (auto cache_blocks{value("--p2p-proof-cache-blocks")}) {
            if (!ParseInteger(*cache_blocks, options.p2p_proof_cache_blocks) ||
                options.p2p_proof_cache_blocks == 0) {
                return utreexo::Result<Options>::Err("invalid --p2p-proof-cache-blocks");
            }
        } else if (auto proof_cache{value("--p2p-proof-cache-mib")}) {
            if (!ParseInteger(*proof_cache, options.p2p_proof_cache_mib) ||
                options.p2p_proof_cache_mib == 0 ||
                options.p2p_proof_cache_mib > std::numeric_limits<uint64_t>::max() / (1024ULL * 1024)) {
                return utreexo::Result<Options>::Err("invalid --p2p-proof-cache-mib");
            }
        } else if (argument == "--allow-untrusted-checkpoint") {
            options.allow_untrusted_checkpoint = true;
        } else if (argument == "--proof-store-scrub") {
            options.proof_store_scrub = true;
        } else if (argument == "--fast-sync") {
            options.fast_sync = true;
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
    if (options.checkpoint && options.checkpoint->empty()) {
        return utreexo::Result<Options>::Err("--checkpoint path cannot be empty");
    }
    if (options.recovery_checkpoint && options.recovery_checkpoint->empty()) {
        return utreexo::Result<Options>::Err(
            "--recovery-checkpoint path cannot be empty");
    }
    if (options.checkpoint && options.recovery_checkpoint &&
        *options.checkpoint == *options.recovery_checkpoint) {
        return utreexo::Result<Options>::Err(
            "--recovery-checkpoint must differ from --checkpoint");
    }
    if (options.online_state && options.online_state->empty()) {
        return utreexo::Result<Options>::Err("--online-state path cannot be empty");
    }
    if (options.proof_store && options.proof_store->empty()) {
        return utreexo::Result<Options>::Err("--proof-store path cannot be empty");
    }
    if (options.state_json && options.state_json->empty()) {
        return utreexo::Result<Options>::Err("--state-json path cannot be empty");
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
    if ((options.p2p_advertise || !options.p2p_gossip_seeds.empty()) &&
        !options.p2p_port) {
        return utreexo::Result<Options>::Err(
            "--p2p-advertise and --p2p-gossip-seed require --p2p-port");
    }
    if (!options.p2p_gossip_seeds.empty() && !options.p2p_advertise) {
        return utreexo::Result<Options>::Err(
            "--p2p-gossip-seed requires --p2p-advertise");
    }
    if (options.allow_untrusted_checkpoint && !options.checkpoint) {
        return utreexo::Result<Options>::Err(
            "--allow-untrusted-checkpoint requires --checkpoint");
    }
    if (options.proof_store_scrub && !options.proof_store) {
        return utreexo::Result<Options>::Err("--proof-store-scrub requires --proof-store");
    }
    if (options.p2p_max_peers_per_ip > options.p2p_max_peers) {
        return utreexo::Result<Options>::Err(
            "--p2p-max-peers-per-ip cannot exceed --p2p-max-peers");
    }
    if (options.p2p_max_proof_requests > options.p2p_max_peers) {
        return utreexo::Result<Options>::Err(
            "--p2p-max-proof-requests cannot exceed --p2p-max-peers");
    }
    return utreexo::Result<Options>::Ok(std::move(options));
}

struct ConfiguredPath {
    std::string option;
    std::filesystem::path original;
    std::filesystem::path lexical;
    std::filesystem::path resolved;
    bool exists{false};
};

utreexo::Result<ConfiguredPath> InspectConfiguredPath(
    std::string option, const std::filesystem::path& path)
{
    std::error_code error;
    auto absolute{std::filesystem::absolute(path, error)};
    if (error) {
        return utreexo::Result<ConfiguredPath>::Err(
            "could not resolve " + option + ": " + error.message());
    }
    absolute = absolute.lexically_normal();

    auto resolved{std::filesystem::weakly_canonical(absolute, error)};
    if (error) {
        return utreexo::Result<ConfiguredPath>::Err(
            "could not resolve " + option + ": " + error.message());
    }

    const bool exists{std::filesystem::exists(absolute, error)};
    if (error) {
        return utreexo::Result<ConfiguredPath>::Err(
            "could not inspect " + option + ": " + error.message());
    }
    return utreexo::Result<ConfiguredPath>::Ok(ConfiguredPath{
        .option = std::move(option),
        .original = path,
        .lexical = std::move(absolute),
        .resolved = resolved.lexically_normal(),
        .exists = exists,
    });
}

bool SameOrDescendant(const std::filesystem::path& candidate,
                      const std::filesystem::path& directory)
{
    auto candidate_component{candidate.begin()};
    for (const auto& directory_component : directory) {
        if (candidate_component == candidate.end() ||
            *candidate_component != directory_component) {
            return false;
        }
        ++candidate_component;
    }
    return true;
}

utreexo::Result<bool> SameConfiguredPath(const ConfiguredPath& first,
                                         const ConfiguredPath& second)
{
    if (first.lexical == second.lexical || first.resolved == second.resolved) {
        return utreexo::Result<bool>::Ok(true);
    }
    if (!first.exists || !second.exists) return utreexo::Result<bool>::Ok(false);

    std::error_code error;
    const bool equivalent{
        std::filesystem::equivalent(first.original, second.original, error)};
    if (error) {
        return utreexo::Result<bool>::Err(
            "could not compare " + first.option + " and " + second.option +
            ": " + error.message());
    }
    return utreexo::Result<bool>::Ok(equivalent);
}

utreexo::Result<void> ValidatePathLayout(
    const Options& options,
    const std::optional<std::filesystem::path>& recovery_checkpoint)
{
    std::vector<ConfiguredPath> files;
    std::vector<ConfiguredPath> directories;
    const auto add_path = [](std::vector<ConfiguredPath>& paths,
                             std::string option,
                             const std::optional<std::filesystem::path>& path)
        -> utreexo::Result<void> {
        if (!path) return utreexo::Result<void>::Ok();
        auto inspected{InspectConfiguredPath(std::move(option), *path)};
        if (!inspected) return utreexo::Result<void>::Err(inspected.Error());
        paths.push_back(inspected.Take());
        return utreexo::Result<void>::Ok();
    };

    auto added{add_path(files, "--checkpoint", options.checkpoint)};
    if (!added) return added;
    added = add_path(files, "--recovery-checkpoint", recovery_checkpoint);
    if (!added) return added;
    added = add_path(files, "--state-json", options.state_json);
    if (!added) return added;
    added = add_path(directories, "--online-state", options.online_state);
    if (!added) return added;
    added = add_path(directories, "--proof-store", options.proof_store);
    if (!added) return added;

    for (std::size_t first{0}; first < files.size(); ++first) {
        for (std::size_t second{first + 1}; second < files.size(); ++second) {
            auto same{SameConfiguredPath(files[first], files[second])};
            if (!same) return utreexo::Result<void>::Err(same.Error());
            if (same.Value()) {
                return utreexo::Result<void>::Err(
                    files[first].option + " and " + files[second].option +
                    " must refer to different files");
            }
        }
    }

    for (const auto& file : files) {
        for (const auto& directory : directories) {
            if (SameOrDescendant(file.lexical, directory.lexical) ||
                SameOrDescendant(file.resolved, directory.resolved)) {
                return utreexo::Result<void>::Err(
                    file.option + " must not be the same as or inside " +
                    directory.option);
            }
        }
    }

    if (directories.size() == 2) {
        auto same{SameConfiguredPath(directories[0], directories[1])};
        if (!same) return utreexo::Result<void>::Err(same.Error());
        const bool nested{
            same.Value() ||
            SameOrDescendant(directories[0].lexical, directories[1].lexical) ||
            SameOrDescendant(directories[1].lexical, directories[0].lexical) ||
            SameOrDescendant(directories[0].resolved, directories[1].resolved) ||
            SameOrDescendant(directories[1].resolved, directories[0].resolved)};
        if (nested) {
            return utreexo::Result<void>::Err(
                directories[0].option + " and " + directories[1].option +
                " must be separate, non-nested directories");
        }
    }
    return utreexo::Result<void>::Ok();
}

uint64_t PhysicalMemoryBytes()
{
    const long pages{::sysconf(_SC_PHYS_PAGES)};
    const long page_size{::sysconf(_SC_PAGESIZE)};
    if (pages <= 0 || page_size <= 0) return 0;
    return static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_size);
}

uint64_t DetectedMemoryBudgetBytes()
{
    const uint64_t physical{PhysicalMemoryBytes()};
    const auto available{utreexo::ReadMemoryAvailability().EffectiveAvailableBytes()};
    if (!available) return physical;
    return physical == 0 ? *available : std::min(physical, *available);
}

utreexo::OnlineForestConfig OnlineConfig(const Options& options)
{
    constexpr uint64_t MIB{1024ULL * 1024};
    const uint64_t detected_budget{DetectedMemoryBudgetBytes()};
    const uint64_t automatic_mib{
        detected_budget != 0 && detected_budget <= 20ULL * 1024 * MIB ? 128ULL : 512ULL};
    return utreexo::OnlineForestConfig{
        .max_dirty_bytes = (options.online_cache_mib == 0 ? automatic_mib : options.online_cache_mib) * MIB,
        .wal_segment_bytes = options.online_wal_segment_mib * MIB,
        .undo_depth = options.online_undo_depth,
        .sync_wal = true,
    };
}

utreexo::P2PServerConfig P2PConfig(const Options& options, bool advertise_archive)
{
    constexpr uint64_t MIB{1024ULL * 1024};
    return utreexo::P2PServerConfig{
        .network = options.p2p_network,
        .bind_address = options.p2p_bind,
        .port = options.p2p_port.value_or(0),
        .max_peers = options.p2p_max_peers,
        .max_peers_per_ip = options.p2p_max_peers_per_ip,
        .max_concurrent_proof_requests = options.p2p_max_proof_requests,
        .max_egress_bytes_per_second = options.p2p_egress_mib_per_second * MIB,
        .egress_burst_bytes = options.p2p_egress_burst_mib * MIB,
        .max_payload_bytes = static_cast<uint32_t>(options.p2p_max_payload_mib * MIB),
        .idle_timeout_seconds = 120,
        .user_agent = "/utreexo-bridge:" UTREEXO_BRIDGE_VERSION "/",
        .advertise_archive = advertise_archive,
        .advertised_endpoint = options.p2p_advertise,
        .gossip_seeds = options.p2p_gossip_seeds,
        .gossip_retry_seconds = options.p2p_gossip_retry_seconds,
        .gossip_connect_timeout_seconds = options.p2p_gossip_timeout_seconds,
    };
}

utreexo::Result<utreexo::AccumulatorState> CaptureAccumulatorState(
    const utreexo::ChainPoint& point, const utreexo::PackedForest& forest)
{
    try {
        utreexo::AccumulatorState state{
            .point = point,
            .num_leaves = forest.NumLeaves(),
            .roots = {},
        };
        const auto roots{forest.Roots()};
        state.roots.reserve(roots.size());
        for (const auto& root : roots) {
            if (!root) {
                return utreexo::Result<utreexo::AccumulatorState>::Err(
                    "forest contains a missing accumulator root");
            }
            state.roots.push_back(*root);
        }
        return utreexo::Result<utreexo::AccumulatorState>::Ok(std::move(state));
    } catch (const std::bad_alloc&) {
        return utreexo::Result<utreexo::AccumulatorState>::Err(
            "allocation failed while capturing accumulator state");
    }
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

bool IsAllocationFailure(std::string_view error)
{
    return (error.find("allocation") != std::string_view::npos &&
            error.find("failed") != std::string_view::npos) ||
           error.find("could not allocate") != std::string_view::npos;
}

template <std::size_t N>
void EmergencyStderr(const char (&message)[N]) noexcept
{
    std::size_t written{0};
    while (written + 1 < N) {
        const ssize_t result{::write(STDERR_FILENO, message + written, N - 1 - written)};
        if (result > 0) {
            written += static_cast<std::size_t>(result);
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
}

void LogProcessResources(std::string_view phase, uint32_t height)
{
    if (!utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) return;
    const auto usage{ReadProcessResources()};
    const auto memory{utreexo::ReadMemoryAvailability()};
    const auto available_field = [](const std::optional<uint64_t>& bytes) {
        return bytes ? std::to_string(*bytes) : std::string{"unavailable"};
    };
    utreexo::Log(utreexo::LogLevel::DEBUG, "process_resources",
        "phase=" + std::string{phase} +
        " height=" + std::to_string(height) +
        " rusage_available=" + std::string{usage.rusage_available ? "true" : "false"} +
        " proc_status_available=" +
            std::string{usage.proc_status_available ? "true" : "false"} +
        " proc_io_available=" + std::string{usage.proc_io_available ? "true" : "false"} +
        " rss_bytes=" + std::to_string(usage.rss_bytes) +
        " peak_rss_bytes=" + std::to_string(usage.peak_rss_bytes) +
        " rss_anon_bytes=" + std::to_string(usage.rss_anon_bytes) +
        " rss_file_bytes=" + std::to_string(usage.rss_file_bytes) +
        " rss_shmem_bytes=" + std::to_string(usage.rss_shmem_bytes) +
        " minor_faults=" + std::to_string(usage.minor_faults) +
        " major_faults=" + std::to_string(usage.major_faults) +
        " user_cpu_us=" + std::to_string(usage.user_cpu_us) +
        " system_cpu_us=" + std::to_string(usage.system_cpu_us) +
        " voluntary_context_switches=" +
            std::to_string(usage.voluntary_context_switches) +
        " involuntary_context_switches=" +
            std::to_string(usage.involuntary_context_switches) +
        " io_read_chars=" + std::to_string(usage.io_read_chars) +
        " io_write_chars=" + std::to_string(usage.io_write_chars) +
        " io_read_syscalls=" + std::to_string(usage.io_read_syscalls) +
        " io_write_syscalls=" + std::to_string(usage.io_write_syscalls) +
        " io_read_bytes=" + std::to_string(usage.io_read_bytes) +
        " io_write_bytes=" + std::to_string(usage.io_write_bytes) +
        " io_cancelled_write_bytes=" + std::to_string(usage.io_cancelled_write_bytes) +
        " system_available_bytes=" + available_field(memory.system_available_bytes) +
        " cgroup_available_bytes=" + available_field(memory.cgroup_available_bytes) +
        " effective_available_bytes=" + available_field(memory.EffectiveAvailableBytes()));
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
        " wal_segment_directory_syncs=" +
            std::to_string(usage.wal_segment_directory_syncs) +
        " last_transaction_nodes=" + std::to_string(usage.last_transaction_nodes) +
        " last_transaction_wal_bytes=" + std::to_string(usage.last_transaction_wal_bytes) +
        " last_transaction_serialize_us=" +
            std::to_string(usage.last_transaction_serialize_us) +
        " last_transaction_segment_us=" +
            std::to_string(usage.last_transaction_segment_us) +
        " last_transaction_write_us=" + std::to_string(usage.last_transaction_write_us) +
        " last_transaction_sync_us=" + std::to_string(usage.last_transaction_sync_us) +
        " last_transaction_publish_us=" +
            std::to_string(usage.last_transaction_publish_us) +
        " last_transaction_total_us=" + std::to_string(usage.last_transaction_total_us));
}

void LogProofStoreBreakdown(std::string_view phase, const utreexo::ProofStore& store)
{
    if (!utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) return;
    const auto stats{store.Stats()};
    const uint64_t average_batch_milli{stats.committed_batches == 0 ? 0 :
        stats.committed_proofs * 1'000 / stats.committed_batches};
    utreexo::Log(utreexo::LogLevel::DEBUG, "proof_store",
        "phase=" + std::string{phase} +
        " base_height=" + std::to_string(stats.base_height) +
        " durable_height=" + std::to_string(stats.durable_height) +
        " enqueued_height=" + std::to_string(stats.enqueued_height) +
        " active_proofs=" + std::to_string(stats.active_proofs) +
        " queued_blocks=" + std::to_string(stats.queued_blocks) +
        " queued_bytes=" + std::to_string(stats.queued_bytes) +
        " input_blocks=" + std::to_string(stats.input_blocks) +
        " ready_blocks=" + std::to_string(stats.ready_blocks) +
        " peak_queued_blocks=" + std::to_string(stats.peak_queued_blocks) +
        " peak_queued_bytes=" + std::to_string(stats.peak_queued_bytes) +
        " peak_input_blocks=" + std::to_string(stats.peak_input_blocks) +
        " peak_ready_blocks=" + std::to_string(stats.peak_ready_blocks) +
        " enqueue_blocked=" + std::to_string(stats.enqueue_blocked) +
        " backpressure_flushes=" + std::to_string(stats.backpressure_flushes) +
        " durability_waits=" + std::to_string(stats.durability_waits) +
        " data_bytes=" + std::to_string(stats.data_bytes) +
        " wal_bytes=" + std::to_string(stats.wal_bytes) +
        " mmap_index_bytes=" + std::to_string(stats.index_bytes) +
        " serialized_proofs=" + std::to_string(stats.serialized_proofs) +
        " serialized_bytes=" + std::to_string(stats.serialized_bytes) +
        " largest_record_bytes=" + std::to_string(stats.largest_record_bytes) +
        " enqueue_wait_us=" + std::to_string(stats.enqueue_wait_us) +
        " serialization_us=" + std::to_string(stats.serialization_us) +
        " committed_proofs=" + std::to_string(stats.committed_proofs) +
        " committed_batches=" + std::to_string(stats.committed_batches) +
        " full_batches=" + std::to_string(stats.full_batches) +
        " partial_batches=" + std::to_string(stats.partial_batches) +
        " largest_batch_proofs=" + std::to_string(stats.largest_batch_proofs) +
        " average_batch_milli=" + std::to_string(average_batch_milli) +
        " commit_us=" + std::to_string(stats.commit_us) +
        " data_write_us=" + std::to_string(stats.data_write_us) +
        " data_syncs=" + std::to_string(stats.data_syncs) +
        " data_sync_us=" + std::to_string(stats.data_sync_us) +
        " wal_write_us=" + std::to_string(stats.wal_write_us) +
        " wal_syncs=" + std::to_string(stats.wal_syncs) +
        " wal_sync_us=" + std::to_string(stats.wal_sync_us) +
        " index_publish_us=" + std::to_string(stats.index_publish_us) +
        " hits=" + std::to_string(stats.hits) +
        " misses=" + std::to_string(stats.misses));
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

int BridgeMain(int argc, char** argv)
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
                  << utreexo::PackedForest::FORMAT_VERSION
                  << " proof_store_format=" << utreexo::ProofStore::FORMAT_VERSION << '\n';
        return 0;
    }
    utreexo::SetLogLevel(options.log_level);
    // A published checkpoint is immutable input. RAM-sync progress is written to
    // a separate local resume file and preferred on the next start. Retain the
    // historical load/save behavior only for an explicit untrusted local path.
    bool automatic_recovery_path{false};
    std::optional<std::filesystem::path> recovery_checkpoint{
        options.recovery_checkpoint};
    if (!recovery_checkpoint && options.checkpoint &&
        !options.allow_untrusted_checkpoint) {
        recovery_checkpoint = *options.checkpoint;
        *recovery_checkpoint += ".resume";
        automatic_recovery_path = true;
    }
    const std::optional<std::filesystem::path> checkpoint_output_path{
        recovery_checkpoint ? recovery_checkpoint :
        (options.allow_untrusted_checkpoint ? options.checkpoint : std::nullopt)};
    const auto path_layout{ValidatePathLayout(options, recovery_checkpoint)};
    if (!path_layout) {
        utreexo::Log(utreexo::LogLevel::ERROR, "path_configuration_invalid",
            "error=" + StringField(path_layout.Error()) +
            " action=fail_before_rpc_or_storage");
        return 1;
    }
    const auto signal_handlers{InstallShutdownSignalHandlers()};
    if (!signal_handlers) {
        utreexo::Log(utreexo::LogLevel::ERROR, "signal_handler_install_failed",
                     "error=" + StringField(signal_handlers.Error()));
        return 1;
    }
    utreexo::Log(utreexo::LogLevel::INFO, "sidecar_start",
        "version=" UTREEXO_BRIDGE_VERSION
        " checkpoint_format=" + std::to_string(utreexo::CHECKPOINT_FORMAT_VERSION) +
        " forest_format=" +
        std::to_string(utreexo::PackedForest::FORMAT_VERSION) +
        " proof_store_format=" + std::to_string(utreexo::ProofStore::FORMAT_VERSION) +
        " log_level=" + std::string{utreexo::LogLevelName(options.log_level)});
    if (recovery_checkpoint && options.checkpoint) {
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_paths_configured",
            "bootstrap_path=" + PathField(*options.checkpoint) +
            " recovery_path=" + PathField(*recovery_checkpoint) +
            " recovery_path_source=" +
                std::string{automatic_recovery_path ? "automatic" : "explicit"} +
            " bootstrap_immutable=true");
    }
    if (options.p2p_port) {
        auto valid_p2p{utreexo::ValidateP2PServerConfig(P2PConfig(options, false))};
        if (!valid_p2p) {
            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_config_invalid",
                "error=" + StringField(valid_p2p.Error()) +
                " action=fail_before_state_load_or_sync");
            return 1;
        }
    }
    {
        constexpr uint64_t MIB{1024ULL * 1024};
        const auto memory{utreexo::ReadMemoryAvailability()};
        const auto available_field = [](const std::optional<uint64_t>& bytes) {
            return bytes ? std::to_string(*bytes) : std::string{"unavailable"};
        };
        utreexo::Log(utreexo::LogLevel::INFO, "memory_guard_configured",
            "enabled=" + std::string{options.memory_reserve_mib != 0 ? "true" : "false"} +
            " reserve_bytes=" + std::to_string(options.memory_reserve_mib * MIB) +
            " applies_to=ram_bootstrap sample_interval_ms=1000" +
            " system_available_bytes=" + available_field(memory.system_available_bytes) +
            " cgroup_available_bytes=" + available_field(memory.cgroup_available_bytes) +
            " effective_available_bytes=" + available_field(memory.EffectiveAvailableBytes()));
        if (options.memory_reserve_mib != 0 && !memory.EffectiveAvailableBytes()) {
            utreexo::Log(utreexo::LogLevel::WARN, "memory_guard_unavailable",
                "reason=host_and_cgroup_availability_not_reported"
                " action=continue_with_allocation_failure_checkpoint_fallback");
        }
    }
    LogProcessResources("sidecar_start", 0);
    if (options.fast_sync) {
        constexpr uint64_t GIB{1024ULL * 1024 * 1024};
        const uint64_t physical_bytes{PhysicalMemoryBytes()};
        const auto availability{utreexo::ReadMemoryAvailability()};
        const auto effective_available{availability.EffectiveAvailableBytes()};
        const bool existing_online{options.online_state &&
                                   std::filesystem::exists(*options.online_state)};
        if (existing_online) {
            utreexo::Log(utreexo::LogLevel::INFO, "fast_sync_not_used",
                "reason=online_state_already_exists storage_mode=mmap_wal");
        } else {
            utreexo::Log(utreexo::LogLevel::WARN, "fast_sync_memory_warning",
                "message=fast_sync_requires_at_least_32_GiB_of_system_RAM"
                " minimum_system_ram_gib=32 physical_system_ram_gib=" +
                std::to_string(physical_bytes / GIB) +
                " physical_below_minimum=" +
                std::string{physical_bytes != 0 && physical_bytes < 32 * GIB ?
                    "true" : "false"} +
                " effective_available_gib=" +
                std::string{effective_available ?
                    std::to_string(*effective_available / GIB) : "unavailable"} +
                " effective_available_below_minimum=" +
                std::string{effective_available && *effective_available < 32 * GIB ?
                    "true" : "false"} +
                " storage_mode=ram_bootstrap risk=memory_exhaustion");
        }
    }
    if (options.authorization.empty()) {
        auto cookie{utreexo::ReadCookieAuthorization(options.cookie)};
        if (!cookie) {
            utreexo::Log(utreexo::LogLevel::ERROR, "cookie_read_failed",
                         "error=" + StringField(cookie.Error()));
            return 1;
        }
        options.authorization = cookie.Take();
    }

    utreexo::HttpRpcConfig rpc_config{
        .host = options.host,
        .port = options.port,
        .path = "/",
        .authorization = options.authorization,
    };
    utreexo::CoreRpcBlockSource source{utreexo::CoreRpcClient{
        std::make_unique<utreexo::HttpRpcTransport>(std::move(rpc_config))}};
    if (options.p2p_port) {
        auto core_genesis{source.BlockHash(0)};
        if (!core_genesis) {
            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_network_validation_failed",
                "reason=core_genesis_unavailable error=" + StringField(core_genesis.Error()) +
                " action=fail_before_state_load_or_sync");
            return 1;
        }
        const auto expected{utreexo::BitcoinNetworkGenesisHash(options.p2p_network)};
        if (core_genesis.Value() != expected) {
            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_network_validation_failed",
                "reason=selected_network_does_not_match_core"
                " core_genesis=" + core_genesis.Value().ToBitcoinHex() +
                " expected_genesis=" + expected.ToBitcoinHex() +
                " action=fail_before_state_load_or_sync");
            return 1;
        }
    }

    const auto online_config{OnlineConfig(options)};
    std::optional<std::filesystem::path> checkpoint_load_path;
    bool loading_recovery_checkpoint{false};
    if (recovery_checkpoint && std::filesystem::exists(*recovery_checkpoint)) {
        checkpoint_load_path = recovery_checkpoint;
        loading_recovery_checkpoint = true;
    } else if (options.checkpoint && std::filesystem::exists(*options.checkpoint)) {
        checkpoint_load_path = options.checkpoint;
    }
    if (recovery_checkpoint && options.checkpoint &&
        std::filesystem::exists(*options.checkpoint)) {
        const std::array recovery_files{
            *recovery_checkpoint,
            std::filesystem::path{recovery_checkpoint->string() + ".tmp"},
        };
        for (const auto& candidate : recovery_files) {
            if (!std::filesystem::exists(candidate)) continue;
            std::error_code equivalent_error;
            const bool same_file{std::filesystem::equivalent(
                candidate, *options.checkpoint, equivalent_error)};
            if (equivalent_error) {
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "checkpoint_path_validation_failed",
                    "path=" + PathField(candidate) +
                    " error=" + StringField(equivalent_error.message()) +
                    " action=fail_closed");
                return 1;
            }
            if (same_file) {
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "checkpoint_path_validation_failed",
                    "path=" + PathField(candidate) +
                    " reason=bootstrap_aliases_recovery_write_target action=fail_closed");
                return 1;
            }
        }
    }
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
        LogProcessResources("online_state_loaded", recovered_point.height);
    } else if (checkpoint_load_path) {
        if (!options.fast_sync && !options.online_state) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                "reason=mmap_wal_is_default_for_checkpoint_catchup"
                " action=provide_online_state_or_use_fast_sync");
            return 1;
        }
        const auto use_automatic_bootstrap_fallback =
            [&](std::string_view reason) -> bool {
                if (!automatic_recovery_path || !loading_recovery_checkpoint ||
                    !options.checkpoint || !std::filesystem::exists(*options.checkpoint)) {
                    return false;
                }
                utreexo::Log(utreexo::LogLevel::WARN,
                    "recovery_checkpoint_fallback",
                    "recovery_path=" + PathField(*checkpoint_load_path) +
                    " bootstrap_path=" + PathField(*options.checkpoint) +
                    " reason=" + StringField(reason) +
                    " action=retry_exact_trusted_bootstrap");
                checkpoint_load_path = options.checkpoint;
                loading_recovery_checkpoint = false;
                return true;
            };
        while (true) {
        const utreexo::TrustedCheckpoint* trusted{
            utreexo::FindTrustedCheckpoint("mainnet-943013")};
        const bool exact_trusted_input{
            !loading_recovery_checkpoint && !options.allow_untrusted_checkpoint};
        const bool trusted_resume{
            loading_recovery_checkpoint && options.checkpoint &&
            !options.allow_untrusted_checkpoint};
        if ((exact_trusted_input || trusted_resume) && !trusted) {
            utreexo::Log(utreexo::LogLevel::ERROR,
                "trusted_checkpoint_validation_failed",
                "reason=compiled_anchor_missing action=fail_closed");
            return 1;
        }
        if (loading_recovery_checkpoint) {
            utreexo::Log(utreexo::LogLevel::WARN,
                "recovery_checkpoint_validation_started",
                "path=" + PathField(*checkpoint_load_path) +
                " trust=local_filesystem checksum=required active_chain_check=required" +
                std::string{trusted_resume ? " trusted_base_lineage=required" : ""});
        } else if (options.allow_untrusted_checkpoint) {
            utreexo::Log(utreexo::LogLevel::WARN,
                "trusted_checkpoint_validation_skipped",
                "path=" + PathField(*checkpoint_load_path) +
                " reason=operator_override risk=checkpoint_state_not_authenticated");
        } else {
            utreexo::Log(utreexo::LogLevel::INFO,
                "trusted_checkpoint_file_validation_started",
                "anchor=" + StringField(trusted->name) +
                " path=" + PathField(*checkpoint_load_path) +
                " expected_bytes=" + std::to_string(trusted->file_size) +
                " expected_sha256=" + trusted->file_sha256.ToHex());
            auto identity{utreexo::ReadCheckpointFileIdentity(*checkpoint_load_path)};
            if (!identity) {
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "trusted_checkpoint_validation_failed",
                    "anchor=" + StringField(trusted->name) +
                    " error=" + StringField(identity.Error()) + " action=fail_closed");
                return 1;
            }
            auto validated_file{
                utreexo::ValidateTrustedCheckpointFile(*trusted, identity.Value())};
            if (!validated_file) {
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "trusted_checkpoint_validation_failed",
                    "anchor=" + StringField(trusted->name) +
                    " error=" + StringField(validated_file.Error()) +
                    " action=fail_closed override=--allow-untrusted-checkpoint");
                return 1;
            }
            utreexo::Log(utreexo::LogLevel::INFO, "trusted_checkpoint_file_validated",
                "anchor=" + StringField(trusted->name) +
                " bytes=" + std::to_string(identity.Value().size) +
                " sha256=" + identity.Value().sha256.ToHex());
        }
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_load_started",
            "path=" + PathField(*checkpoint_load_path) +
            " role=" + std::string{loading_recovery_checkpoint ? "local_recovery" :
                                                               "bootstrap"} +
            " storage_mode=" + std::string{options.fast_sync ? "ram_bootstrap" : "mmap_wal"} +
            " import_mode=" + std::string{options.fast_sync ? "deserialize_ram" : "stream_to_native"});
        utreexo::CheckpointMetrics checkpoint_metrics;
        auto checkpoint_online_config{online_config};
        checkpoint_online_config.defer_publish = true;
        auto loaded{options.fast_sync ?
            utreexo::LoadCheckpoint(*checkpoint_load_path, &checkpoint_metrics) :
            utreexo::LoadCheckpointOnline(*checkpoint_load_path, *options.online_state,
                                          checkpoint_online_config, &checkpoint_metrics)};
        if (!loaded) {
            if (use_automatic_bootstrap_fallback(loaded.Error())) continue;
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                         "path=" + PathField(*checkpoint_load_path) +
                         " error=" + StringField(loaded.Error()));
            return 1;
        }
        if (loaded.Value().chain_hashes.empty()) {
            if (use_automatic_bootstrap_fallback("missing chain-hash index")) continue;
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                         "reason=missing_chain_hash_index");
            return 1;
        }
        if (exact_trusted_input) {
            auto validated_state{
                utreexo::ValidateTrustedCheckpointState(*trusted, loaded.Value())};
            if (!validated_state) {
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "trusted_checkpoint_validation_failed",
                    "anchor=" + StringField(trusted->name) +
                    " error=" + StringField(validated_state.Error()) +
                    " action=fail_closed");
                return 1;
            }
            utreexo::Log(utreexo::LogLevel::INFO, "trusted_checkpoint_state_validated",
                "anchor=" + StringField(trusted->name) +
                " height=" + std::to_string(loaded.Value().point.height) +
                " block_hash=" + loaded.Value().point.block_hash.ToBitcoinHex() +
                " num_leaves=" + std::to_string(loaded.Value().forest.NumLeaves()) +
                " roots=" + RootsField(loaded.Value().forest) +
                " exact_file=true");
        }
        if (trusted_resume) {
            if (loaded.Value().point.height < trusted->point.height ||
                loaded.Value().chain_hashes.size() <= trusted->point.height ||
                loaded.Value().chain_hashes[trusted->point.height] != trusted->point.block_hash) {
                if (use_automatic_bootstrap_fallback(
                        "recovery checkpoint is not a descendant of the trusted base")) {
                    continue;
                }
                utreexo::Log(utreexo::LogLevel::ERROR,
                    "recovery_checkpoint_validation_failed",
                    "reason=missing_trusted_base_lineage anchor=" + StringField(trusted->name) +
                    " action=fail_closed_remove_or_relocate_recovery_to_use_bootstrap");
                return 1;
            }
            utreexo::Log(utreexo::LogLevel::INFO,
                "recovery_checkpoint_lineage_validated",
                "anchor=" + StringField(trusted->name) +
                " recovery_height=" + std::to_string(loaded.Value().point.height));
        }
        auto active_checkpoint_hash{source.BlockHash(loaded.Value().point.height)};
        if (!active_checkpoint_hash ||
            active_checkpoint_hash.Value() != loaded.Value().point.block_hash) {
            if (use_automatic_bootstrap_fallback(
                    active_checkpoint_hash ? "recovery point is not on Core's active chain" :
                                             "could not validate recovery point with Core")) {
                continue;
            }
            utreexo::Log(utreexo::LogLevel::ERROR,
                "checkpoint_active_chain_validation_failed",
                "height=" + std::to_string(loaded.Value().point.height) +
                " checkpoint_hash=" + loaded.Value().point.block_hash.ToBitcoinHex() +
                (active_checkpoint_hash ?
                    " active_hash=" + active_checkpoint_hash.Value().ToBitcoinHex() :
                    " error=" + StringField(active_checkpoint_hash.Error())) +
                " action=fail_closed");
            return 1;
        }
        if (!options.fast_sync) {
            auto published{loaded.Value().forest.PublishOnline()};
            if (!published) {
                utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
                    "reason=online_publish_failed error=" + StringField(published.Error()) +
                    " action=fail_closed");
                return 1;
            }
        }
        const uint32_t loaded_height{loaded.Value().point.height};
        forest = std::move(loaded.Value().forest);
        chain_hashes = std::move(loaded.Value().chain_hashes);
        loaded_online = forest.IsOnline();
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_loaded",
            "height=" + std::to_string(loaded_height) +
            " path=" + PathField(*checkpoint_load_path) +
            " role=" + std::string{loading_recovery_checkpoint ? "local_recovery" :
                                                               "bootstrap"} +
            " bytes=" + std::to_string(checkpoint_metrics.final_bytes) +
            " total_us=" + std::to_string(checkpoint_metrics.total_us) +
            " storage_mode=" + std::string{loaded_online ? "mmap_wal" : "ram_bootstrap"});
        if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) {
            utreexo::Log(utreexo::LogLevel::DEBUG, "checkpoint_load_metrics",
                "height=" + std::to_string(loaded_height) +
                " bytes=" + std::to_string(checkpoint_metrics.final_bytes) +
                " checksum_us=" + std::to_string(checkpoint_metrics.checksum_us) +
                " deserialize_us=" + std::to_string(checkpoint_metrics.deserialize_us) +
                " total_us=" + std::to_string(checkpoint_metrics.total_us));
        }
        LogMemoryBreakdown("checkpoint_loaded", loaded_height, forest);
        if (loaded_online) LogOnlineBreakdown("checkpoint_loaded", loaded_height, forest);
        LogProcessResources("checkpoint_loaded", loaded_height);
        break;
        }
    } else if (options.checkpoint && !options.allow_untrusted_checkpoint) {
        utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_load_failed",
            "path=" + PathField(*options.checkpoint) +
            " reason=required_checkpoint_missing action=fail_closed"
            " hint=use_allow_untrusted_checkpoint_only_for_an_intentional_genesis_rebuild");
        return 1;
    } else if (checkpoint_output_path) {
        utreexo::Log(utreexo::LogLevel::WARN, "local_checkpoint_output_armed",
            "path=" + PathField(*checkpoint_output_path) +
            " reason=operator_requested_local_genesis_recovery_output"
            " existing_input=false");
    }

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

    std::shared_ptr<utreexo::ProofStore> proof_store;
    if (options.proof_store) {
        constexpr uint64_t MIB{1024ULL * 1024};
        std::optional<utreexo::ChainPoint> create_base{sync.CurrentPoint()};
        utreexo::Result<utreexo::AccumulatorState> create_base_state{
            utreexo::Result<utreexo::AccumulatorState>::Err("uninitialized proof-store base")};
        if (create_base) {
            create_base_state = CaptureAccumulatorState(*create_base, forest);
        } else {
            auto genesis_hash{source.BlockHash(0)};
            if (!genesis_hash) {
                utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_open_failed",
                    "reason=genesis_hash_unavailable error=" + StringField(genesis_hash.Error()) +
                    " action=require_unpruned_genesis_chain_data");
                return 1;
            }
            create_base = utreexo::ChainPoint{0, genesis_hash.Value()};
            // Bitcoin's genesis coinbase is never inserted into the accumulator,
            // so its post-block state is the empty pre-genesis forest.
            create_base_state = utreexo::Result<utreexo::AccumulatorState>::Ok(
                utreexo::AccumulatorState{
                    .point = *create_base,
                    .num_leaves = 0,
                    .roots = {},
                });
        }
        if (!create_base_state) {
            const bool allocation_failure{IsAllocationFailure(create_base_state.Error())};
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_open_failed",
                "reason=base_state_capture_failed error=" +
                    StringField(create_base_state.Error()) +
                " exit_code=" + std::to_string(allocation_failure ? 2 : 1));
            return allocation_failure ? 2 : 1;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "proof_store_open_started",
            "path=" + PathField(*options.proof_store) +
            " serializer_threads=" + std::to_string(options.proof_store_threads) +
            " queue_blocks=" + std::to_string(options.proof_store_queue_blocks) +
            " queue_bytes=" + std::to_string(options.proof_store_queue_mib * MIB) +
            " group_commit_blocks=" + std::to_string(options.proof_store_group_blocks) +
            " group_commit_delay_ms=" + std::to_string(options.proof_store_group_delay_ms));
        auto opened{utreexo::ProofStore::Open(utreexo::ProofStoreConfig{
            .directory = *options.proof_store,
            .create_base = create_base,
            .create_base_state = create_base_state.Value(),
            .serializer_threads = options.proof_store_threads,
            .group_commit_blocks = options.proof_store_group_blocks,
            .group_commit_delay_ms = options.proof_store_group_delay_ms,
            .max_queued_blocks = options.proof_store_queue_blocks,
            .max_queued_bytes = options.proof_store_queue_mib * MIB,
            .max_record_bytes = options.proof_store_max_record_mib * MIB,
        })};
        if (!opened) {
            const bool allocation_failure{IsAllocationFailure(opened.Error())};
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_open_failed",
                "path=" + PathField(*options.proof_store) +
                " error=" + StringField(opened.Error()) + " action=fail_closed" +
                " exit_code=" + std::to_string(allocation_failure ? 2 : 1));
            return allocation_failure ? 2 : 1;
        }
        proof_store = opened.Take();
        const auto base{proof_store->BasePoint()};
        auto archive_tip{proof_store->DurablePoint()};
        auto forest_point{sync.CurrentPoint()};
        if (!forest_point) {
            utreexo::Log(utreexo::LogLevel::INFO, "proof_store_genesis_rebuild",
                "base_height=" + std::to_string(base.height) +
                " durable_height=" + std::to_string(archive_tip.height) +
                " start_height=0 proof_generation_start_height=" +
                    std::to_string(base.height + (base.height != std::numeric_limits<uint32_t>::max())));
        } else if (forest_point->height >= base.height) {
            const uint32_t overlap_height{std::min(forest_point->height, archive_tip.height)};
            auto overlap_hash{proof_store->HashAt(overlap_height)};
            if (!overlap_hash || !overlap_hash.Value()) {
                utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                    "height=" + std::to_string(overlap_height) +
                    " reason=missing_archive_height error=" +
                    StringField(overlap_hash ? std::string{"none"} : overlap_hash.Error()));
                return 1;
            }
            const bool overlap_matches{
                sync.ChainHashes()[overlap_height] == *overlap_hash.Value()};
            utreexo::ChainPoint common{overlap_height, sync.ChainHashes()[overlap_height]};
            if (!overlap_matches) {
                bool found_common{false};
                uint32_t candidate{overlap_height};
                while (true) {
                    auto stored{proof_store->HashAt(candidate)};
                    if (!stored || !stored.Value()) {
                        utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                            "height=" + std::to_string(candidate) +
                            " reason=archive_index_gap");
                        return 1;
                    }
                    if (sync.ChainHashes()[candidate] == *stored.Value()) {
                        common = utreexo::ChainPoint{candidate, *stored.Value()};
                        found_common = true;
                        break;
                    }
                    if (candidate == base.height) break;
                    --candidate;
                }
                if (!found_common) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                        "base_height=" + std::to_string(base.height) +
                        " reason=archive_base_not_in_forest_chain action=use_matching_checkpoint");
                    return 1;
                }
                if (!forest.IsOnline() && forest_point->height != common.height) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                        "forest_height=" + std::to_string(forest_point->height) +
                        " common_height=" + std::to_string(common.height) +
                        " reason=ram_checkpoint_cannot_rollback action=use_matching_checkpoint");
                    return 1;
                }
                if (forest_point->height > common.height) {
                    auto rolled_back{sync.RollbackTo(common)};
                    if (!rolled_back) {
                        utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                            "height=" + std::to_string(common.height) +
                            " error=" + StringField(rolled_back.Error()) +
                            " action=restore_checkpoint_within_online_undo_window");
                        return 1;
                    }
                    utreexo::Log(utreexo::LogLevel::WARN, "proof_store_forest_rolled_back",
                        "disconnected_blocks=" + std::to_string(rolled_back.Value()) +
                        " recovered_height=" + std::to_string(common.height) +
                        " reason=archive_chain_mismatch");
                }
                // Roll the forest back first. If the process stops between these two
                // durable operations, the longer proof archive remains recoverable;
                // truncating the only proofs first could leave neither side usable.
                auto truncated{proof_store->Truncate(common)};
                if (!truncated) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_truncate_failed",
                        "height=" + std::to_string(common.height) +
                        " error=" + StringField(truncated.Error()) +
                        " action=retry_archive_truncation_on_restart");
                    return 1;
                }
                archive_tip = common;
                forest_point = sync.CurrentPoint();
            } else if (forest_point->height > archive_tip.height) {
                if (!forest.IsOnline()) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                        "forest_height=" + std::to_string(forest_point->height) +
                        " archive_height=" + std::to_string(archive_tip.height) +
                        " reason=checkpoint_ahead_of_durable_proofs action=use_earlier_checkpoint");
                    return 1;
                }
                auto rolled_back{sync.RollbackTo(archive_tip)};
                if (!rolled_back) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                        "archive_height=" + std::to_string(archive_tip.height) +
                        " error=" + StringField(rolled_back.Error()) +
                        " action=restore_checkpoint_within_online_undo_window");
                    return 1;
                }
                forest_point = sync.CurrentPoint();
                utreexo::Log(utreexo::LogLevel::WARN, "proof_store_forest_rolled_back",
                    "disconnected_blocks=" + std::to_string(rolled_back.Value()) +
                    " recovered_height=" + std::to_string(forest_point->height) +
                    " reason=forest_ahead_of_durable_proof_wal");
            } else if (forest_point->height < archive_tip.height && forest.IsOnline()) {
                const auto previous_archive_tip{archive_tip};
                // The archive can legitimately be ahead when an older online
                // forest is reopened. Preserve every archived block that Core
                // still considers active, and only discard a stale suffix.
                auto current_core_tip{sync.TipHeight()};
                if (!current_core_tip) {
                    utreexo::Log(utreexo::LogLevel::ERROR,
                        "proof_store_alignment_failed",
                        "forest_height=" + std::to_string(forest_point->height) +
                        " archive_height=" + std::to_string(archive_tip.height) +
                        " reason=core_tip_query_failed error=" +
                            StringField(current_core_tip.Error()) +
                        " action=fail_closed_archive_unchanged");
                    return 1;
                }
                auto active_common{utreexo::FindHighestActiveArchivePoint(
                    *proof_store, *forest_point, current_core_tip.Value(),
                    [&source](uint32_t height) { return source.BlockHash(height); })};
                if (!active_common) {
                    utreexo::Log(utreexo::LogLevel::ERROR,
                        "proof_store_alignment_failed",
                        "forest_height=" + std::to_string(forest_point->height) +
                        " archive_height=" + std::to_string(archive_tip.height) +
                        " core_tip_height=" + std::to_string(current_core_tip.Value()) +
                        " reason=archive_active_chain_scan_failed error=" +
                            StringField(active_common.Error()) +
                        " action=fail_closed_archive_unchanged");
                    return 1;
                }
                if (active_common.Value() == archive_tip) {
                    utreexo::Log(utreexo::LogLevel::INFO,
                        "proof_store_archive_preserved",
                        "forest_height=" + std::to_string(forest_point->height) +
                        " archive_height=" + std::to_string(archive_tip.height) +
                        " reason=archive_tip_is_on_core_active_chain"
                        " action=reuse_archived_prefix_while_forest_catches_up");
                } else {
                    auto truncated{proof_store->Truncate(active_common.Value())};
                    if (!truncated) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "proof_store_truncate_failed",
                            "height=" + std::to_string(active_common.Value().height) +
                            " error=" + StringField(truncated.Error()) +
                            " reason=stale_archive_suffix"
                            " action=retry_archive_truncation_on_restart");
                        return 1;
                    }
                    archive_tip = active_common.Value();
                    if (archive_tip == *forest_point) {
                        // A reorg commits the authoritative online forest rollback
                        // before truncating the proof archive. This is the distinct
                        // interrupted forest-first recovery case.
                        utreexo::Log(utreexo::LogLevel::WARN,
                            "proof_store_archive_recovered",
                            "previous_archive_height=" +
                                std::to_string(previous_archive_tip.height) +
                            " recovered_height=" + std::to_string(archive_tip.height) +
                            " reason=forest_rollback_committed_before_archive_truncation"
                            " recovery=completed");
                    } else {
                        utreexo::Log(utreexo::LogLevel::WARN,
                            "proof_store_archive_suffix_truncated",
                            "forest_height=" + std::to_string(forest_point->height) +
                            " previous_archive_height=" +
                                std::to_string(previous_archive_tip.height) +
                            " retained_archive_height=" +
                                std::to_string(archive_tip.height) +
                            " reason=archive_suffix_not_on_core_active_chain"
                            " action=reuse_retained_prefix_then_regenerate");
                    }
                }
            }
        }
        forest_point = sync.CurrentPoint();
        if (forest_point && forest_point->height >= base.height &&
            forest_point->height <= proof_store->DurablePoint().height) {
            auto archived_state{proof_store->StateAt(forest_point->height)};
            if (!archived_state) {
                utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                    "height=" + std::to_string(forest_point->height) +
                    " reason=state_read_failed error=" + StringField(archived_state.Error()));
                return 1;
            }
            if (archived_state.Value()) {
                auto forest_state{CaptureAccumulatorState(*forest_point, forest)};
                if (!forest_state || forest_state.Value() != *archived_state.Value()) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                        "height=" + std::to_string(forest_point->height) +
                        " reason=post_block_accumulator_state_mismatch action=fail_closed");
                    return 1;
                }
            }
        }
        const auto coverage{proof_store->Coverage()};
        utreexo::Log(utreexo::LogLevel::INFO, "proof_store_opened",
            "path=" + PathField(*options.proof_store) +
            " base_height=" + std::to_string(base.height) +
            " durable_height=" + std::to_string(proof_store->DurablePoint().height) +
            " forest_height=" +
                std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " state_start_height=" +
                std::string{coverage.state_start_height ?
                    std::to_string(*coverage.state_start_height) : "none"} +
            " full_history=" + std::string{coverage.full_history ? "true" : "false"} +
            " data_wal_order=proofs_dat_then_index_wal"
            " mmap_index=rebuildable wal_sync=group_commit");
        LogProofStoreBreakdown("open", *proof_store);
        LogProcessResources("proof_store_opened",
                            sync.CurrentPoint() ? sync.CurrentPoint()->height : 0);

        sync.SetProofGenerationPolicy([proof_store, &forest](const utreexo::BlockDelta& delta)
            -> utreexo::Result<bool> {
            const auto base_point{proof_store->BasePoint()};
            if (delta.point.height < base_point.height) {
                return utreexo::Result<bool>::Ok(false);
            }
            if (delta.point.height == base_point.height) {
                if (delta.point != base_point) {
                    return utreexo::Result<bool>::Err(
                        "active block does not match the proof-store AssumeUtreexo base");
                }
                return utreexo::Result<bool>::Ok(false);
            }
            const auto durable{proof_store->DurablePoint()};
            if (delta.point.height <= durable.height) {
                auto archived{proof_store->HashAt(delta.point.height)};
                if (!archived || !archived.Value()) {
                    return utreexo::Result<bool>::Err(
                        archived ? "proof archive has a height gap" : archived.Error());
                }
                if (*archived.Value() == delta.point.block_hash) {
                    auto record{proof_store->Read(delta.point.block_hash)};
                    if (!record || !record.Value()) {
                        return utreexo::Result<bool>::Err(record ?
                            "proof archive hash index has no corresponding record" : record.Error());
                    }
                    std::vector<utreexo::Hash256> roots;
                    roots.reserve(forest.Roots().size());
                    for (const auto& root : forest.Roots()) {
                        if (!root) {
                            return utreexo::Result<bool>::Err(
                                "pre-block forest contains a missing root");
                        }
                        roots.push_back(*root);
                    }
                    auto verified{utreexo::VerifyProof(record.Value()->proof, delta.deletions,
                                                       roots, forest.NumLeaves())};
                    const bool leaves_match{record.Value()->leaves == delta.proof_leaves};
                    if (verified && verified.Value() && leaves_match) {
                        return utreexo::Result<bool>::Ok(false);
                    }
                    const utreexo::ChainPoint previous{
                        delta.point.height - 1, delta.previous_block_hash};
                    auto truncated{proof_store->Truncate(previous)};
                    if (!truncated) return utreexo::Result<bool>::Err(truncated.Error());
                    utreexo::Log(utreexo::LogLevel::WARN, "proof_store_proof_rejected",
                        "height=" + std::to_string(delta.point.height) +
                        " proof_valid=" + std::string{verified && verified.Value() ? "true" : "false"} +
                        " leaves_match=" + std::string{leaves_match ? "true" : "false"} +
                        " action=truncate_and_regenerate");
                    return utreexo::Result<bool>::Ok(true);
                }
                const utreexo::ChainPoint previous{
                    delta.point.height - 1, delta.previous_block_hash};
                auto truncated{proof_store->Truncate(previous)};
                if (!truncated) return utreexo::Result<bool>::Err(truncated.Error());
                utreexo::Log(utreexo::LogLevel::WARN, "proof_store_branch_truncated",
                    "new_tip_height=" + std::to_string(previous.height) +
                    " conflicting_height=" + std::to_string(delta.point.height) +
                    " action=regenerate_active_branch");
            }
            return utreexo::Result<bool>::Ok(true);
        });
    }
    auto tip{sync.TipHeight()};
    if (!tip) {
        utreexo::Log(utreexo::LogLevel::ERROR, "core_tip_failed",
                     "error=" + StringField(tip.Error()));
        return 1;
    }
    if (proof_store) {
        const auto base{proof_store->BasePoint()};
        if (base.height > tip.Value() || proof_store->DurablePoint().height > tip.Value()) {
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                "core_tip_height=" + std::to_string(tip.Value()) +
                " proof_base_height=" + std::to_string(base.height) +
                " proof_tip_height=" + std::to_string(proof_store->DurablePoint().height) +
                " reason=proof_store_ahead_of_core");
            return 1;
        }
        auto active_base{source.BlockHash(base.height)};
        if (!active_base || active_base.Value() != base.block_hash) {
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_alignment_failed",
                "base_height=" + std::to_string(base.height) +
                " base_hash=" + base.block_hash.ToBitcoinHex() +
                " reason=assumeutreexo_base_not_on_core_active_chain" +
                (active_base ? " active_hash=" + active_base.Value().ToBitcoinHex() :
                               " error=" + StringField(active_base.Error())));
            return 1;
        }
    }
    const uint32_t target{options.stop_height ? std::min(*options.stop_height, tip.Value()) : tip.Value()};
    const bool fresh_genesis_online{
        options.online_state && !options.fast_sync && !forest.IsOnline() &&
        !sync.CurrentPoint()};
    utreexo::Log(utreexo::LogLevel::INFO, "sync_started",
        "start_height=" + std::to_string(sync.ChainHashes().empty() ? 0 : sync.ChainHashes().size() - 1) +
        " target_height=" + std::to_string(target) +
        " core_tip_height=" + std::to_string(tip.Value()) +
        " storage_mode=" + std::string{loaded_online ? "mmap_wal" :
            (fresh_genesis_online ? "mmap_wal_after_genesis" : "ram_bootstrap")} +
        " prefetch_blocks=2 rpc_transport=persistent json_parser=streaming_projection" +
        std::string{proof_store ? " proof_pipeline=ordered_parallel proof_wal=group_commit" :
                                  " proof_pipeline=disabled"});
    const auto save_checkpoint = [&](const utreexo::ChainPoint& point,
                                     std::string_view reason) -> utreexo::Result<void> {
        if (!checkpoint_output_path) return utreexo::Result<void>::Ok();
        if (proof_store) {
            auto drained{proof_store->Drain()};
            if (!drained) {
                return utreexo::Result<void>::Err(
                    "proof store could not reach the checkpoint height: " + drained.Error());
            }
            if (proof_store->DurablePoint().height < point.height &&
                point.height > proof_store->BasePoint().height) {
                return utreexo::Result<void>::Err(
                    "proof store is behind the requested checkpoint height");
            }
        }
        std::error_code space_error;
        const auto space{std::filesystem::space(checkpoint_output_path->parent_path().empty() ?
                                                    std::filesystem::path{"."} :
                                                    checkpoint_output_path->parent_path(),
                                                space_error)};
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_save_started",
            "height=" + std::to_string(point.height) +
            " reason=" + std::string{reason} +
            " path=" + PathField(*checkpoint_output_path) +
            " free_bytes_before=" + std::to_string(space_error ? 0 : space.available));
        LogMemoryBreakdown("checkpoint_save_started", point.height, forest);
        utreexo::CheckpointMetrics metrics;
        auto saved{utreexo::SaveCheckpoint(*checkpoint_output_path, point, forest,
                                            sync.ChainHashes(), &metrics)};
        if (!saved) return saved;
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_saved",
            "height=" + std::to_string(point.height) +
            " reason=" + std::string{reason} +
            " path=" + PathField(*checkpoint_output_path) +
            " bytes=" + std::to_string(metrics.final_bytes) +
            " total_us=" + std::to_string(metrics.total_us));
        LogProcessResources("checkpoint_saved", point.height);
        if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG)) {
            std::error_code after_error;
            const auto after{std::filesystem::space(checkpoint_output_path->parent_path().empty() ?
                                                         std::filesystem::path{"."} :
                                                         checkpoint_output_path->parent_path(),
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
    const auto start_prefetch = [&](uint32_t prefetch_target)
        -> utreexo::Result<void> {
        try {
            return sync.StartPrefetch(prefetch_target);
        } catch (const std::bad_alloc&) {
            sync.StopPrefetch();
            return utreexo::Result<void>::Err(
                "allocation failed while starting block prefetch");
        } catch (const std::exception& error) {
            sync.StopPrefetch();
            return utreexo::Result<void>::Err(
                "could not start block prefetch: " + std::string{error.what()});
        }
    };

    int shutdown_signal_number{RequestedShutdownSignal()};
    bool shutdown_noted{false};
    const auto note_shutdown = [&](std::string_view phase) {
        if (shutdown_signal_number == 0) {
            shutdown_signal_number = RequestedShutdownSignal();
        }
        if (shutdown_signal_number == 0 || shutdown_noted) return;
        shutdown_noted = true;
        utreexo::Log(utreexo::LogLevel::INFO, "shutdown_requested",
            "signal=" + std::string{ShutdownSignalName(shutdown_signal_number)} +
            " signal_number=" + std::to_string(shutdown_signal_number) +
            " phase=" + std::string{phase} +
            " safe_height=" +
                std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " action=stop_at_block_boundary_and_persist");
    };

    if (shutdown_signal_number == 0) {
        const auto prefetch_started{start_prefetch(target)};
        if (!prefetch_started) {
            if (IsAllocationFailure(prefetch_started.Error())) {
                const auto point{sync.CurrentPoint()};
                bool checkpoint_saved{false};
                if (!forest.IsOnline() && checkpoint_output_path && point) {
                    const auto saved{save_checkpoint(*point, "prefetch_allocation_failure")};
                    checkpoint_saved = static_cast<bool>(saved);
                    if (!saved) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "emergency_checkpoint_failed",
                            "height=" + std::to_string(point->height) +
                            " phase=prefetch_start error=" + StringField(saved.Error()) +
                            " recovery=restart_from_previous_checkpoint_or_genesis");
                    }
                }
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=prefetch_start safe_height=" +
                        std::to_string(point ? point->height : 0) +
                    " checkpoint_status=" + std::string{checkpoint_saved ?
                        "saved" : "previous_only"} +
                    " action=stop exit_code=2 recovery=" + std::string{forest.IsOnline() ?
                        "reopen_mmap_and_replay_wal" :
                        "restart_from_previous_checkpoint_or_genesis"});
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "prefetch_start_failed",
                         "error=" + StringField(prefetch_started.Error()));
            return 1;
        }
    } else {
        note_shutdown("before_initial_prefetch");
    }

    IntervalMetrics interval;
    IntervalMetrics overall;
    auto interval_start{Clock::now()};
    const auto sync_wall_start{Clock::now()};

    auto next_memory_check{Clock::now()};
    while (sync.ChainHashes().size() <= target && RequestedShutdownSignal() == 0) {
        const auto now{Clock::now()};
        const bool ram_bootstrap{
            !forest.IsOnline() && (!options.online_state || options.fast_sync)};
        if (ram_bootstrap && options.memory_reserve_mib != 0 &&
            now >= next_memory_check) {
            constexpr uint64_t MIB{1024ULL * 1024};
            next_memory_check = now + std::chrono::seconds(1);
            const auto memory{utreexo::ReadMemoryAvailability()};
            const auto effective{memory.EffectiveAvailableBytes()};
            const uint64_t reserve_bytes{options.memory_reserve_mib * MIB};
            if (effective && *effective < reserve_bytes) {
                sync.StopPrefetch();
                const auto point{sync.CurrentPoint()};
                const auto available_field = [](const std::optional<uint64_t>& bytes) {
                    return bytes ? std::to_string(*bytes) : std::string{"unavailable"};
                };
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_guard_triggered",
                    "safe_height=" + std::to_string(point ? point->height : 0) +
                    " target_height=" + std::to_string(target) +
                    " reserve_bytes=" + std::to_string(reserve_bytes) +
                    " system_available_bytes=" +
                        available_field(memory.system_available_bytes) +
                    " cgroup_available_bytes=" +
                        available_field(memory.cgroup_available_bytes) +
                    " effective_available_bytes=" + std::to_string(*effective) +
                    " action=stop_before_next_block_and_save_checkpoint");
                if (!checkpoint_output_path || !point) {
                    utreexo::Log(utreexo::LogLevel::ERROR,
                        "memory_guard_checkpoint_unavailable",
                        "reason=" + std::string{!checkpoint_output_path ?
                            "no_checkpoint_path" : "no_completed_block"} +
                        " exit_code=2 recovery=restart_from_last_checkpoint");
                    return 2;
                }
                const auto saved{save_checkpoint(*point, "memory_reserve")};
                if (!saved) {
                    utreexo::Log(utreexo::LogLevel::ERROR,
                        "memory_guard_checkpoint_failed",
                        "height=" + std::to_string(point->height) +
                        " error=" + StringField(saved.Error()) +
                        " exit_code=2 recovery=restart_from_last_checkpoint");
                    return 2;
                }
                utreexo::Log(utreexo::LogLevel::ERROR, "sync_aborted_memory_reserve",
                    "safe_height=" + std::to_string(point->height) +
                    " checkpoint_status=saved exit_code=2"
                    " recovery=restart_from_saved_checkpoint_after_freeing_memory");
                return 2;
            }
        }
        const auto block_iteration_start{Clock::now()};
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
            if (!checkpoint_output_path || !point) {
                utreexo::Log(utreexo::LogLevel::ERROR, "emergency_checkpoint_unavailable",
                    "reason=" + std::string{!checkpoint_output_path ? "no_checkpoint_path" : "no_completed_block"} +
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
            if (IsAllocationFailure(block.Error())) {
                const auto point{sync.CurrentPoint()};
                const uint32_t safe_height{point ? point->height : 0};
                if (forest.IsOnline()) {
                    const auto usage{forest.OnlineUsage()};
                    utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                        "phase=block_result safe_height=" + std::to_string(safe_height) +
                        " durable_lsn=" + std::to_string(usage.current_lsn) +
                        " checkpoint_status=online_wal_durable action=stop exit_code=2"
                        " recovery=reopen_mmap_and_replay_wal error=" +
                            StringField(block.Error()));
                    return 2;
                }
                bool checkpoint_saved{false};
                if (checkpoint_output_path && point) {
                    checkpoint_saved = static_cast<bool>(
                        save_checkpoint(*point, "block_result_allocation_failure"));
                }
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=block_result safe_height=" + std::to_string(safe_height) +
                    " checkpoint_status=" + std::string{checkpoint_saved ?
                        "saved" : "previous_only"} +
                    " action=stop exit_code=2 recovery=" + std::string{checkpoint_saved ?
                        "restart_from_saved_checkpoint_after_freeing_memory" :
                        "restart_from_previous_checkpoint_or_genesis"} +
                    " error=" + StringField(block.Error()));
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "sync_failed",
                "height=" + std::to_string(sync.ChainHashes().size()) +
                " error=" + StringField(block.Error()));
            return 1;
        }
        const uint32_t height{block.Value().delta.point.height};
        const bool generated_proof{block.Value().proof.has_value()};
        if (proof_store) {
            auto post_state{CaptureAccumulatorState(block.Value().delta.point, forest)};
            if (!post_state) {
                sync.StopPrefetch();
                if (IsAllocationFailure(post_state.Error())) {
                    utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                        "phase=proof_state_capture safe_forest_height=" +
                            std::to_string(block.Value().delta.point.height) +
                        " durable_proof_height=" +
                            std::to_string(proof_store->DurablePoint().height) +
                        " checkpoint_status=previous_only action=stop_without_new_checkpoint"
                        " exit_code=2 recovery=" + std::string{forest.IsOnline() ?
                            "rollback_forest_wal_to_proof_tip" :
                            "restart_from_previous_checkpoint_or_genesis"});
                    return 2;
                }
                utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_state_capture_failed",
                    "height=" + std::to_string(block.Value().delta.point.height) +
                    " error=" + StringField(post_state.Error()) + " action=stop");
                return 1;
            }
            if (block.Value().proof) {
                utreexo::Result<void> queued{
                    utreexo::Result<void>::Err("uninitialized proof enqueue")};
                const auto enqueue_start{Clock::now()};
                try {
                    queued = proof_store->Enqueue(block.Value().delta,
                                                  std::move(*block.Value().proof),
                                                  post_state.Take());
                } catch (const std::bad_alloc&) {
                    sync.StopPrefetch();
                    utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                        "phase=proof_pipeline_enqueue safe_forest_height=" +
                        std::to_string(block.Value().delta.point.height) +
                        " durable_proof_height=" +
                        std::to_string(proof_store->DurablePoint().height) +
                        " action=stop recovery=restart_from_checkpoint_and_reuse_proof_store");
                    return 2;
                }
                block.Value().metrics.proof_enqueue_us = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        Clock::now() - enqueue_start).count());
                if (!queued) {
                    sync.StopPrefetch();
                    if (IsAllocationFailure(queued.Error())) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "memory_allocation_failed",
                            "phase=proof_pipeline_enqueue safe_forest_height=" +
                                std::to_string(block.Value().delta.point.height) +
                            " durable_proof_height=" +
                                std::to_string(proof_store->DurablePoint().height) +
                            " checkpoint_status=previous_only"
                            " action=stop_without_new_checkpoint exit_code=2 recovery=" +
                                std::string{forest.IsOnline() ?
                                    "rollback_forest_wal_to_proof_tip" :
                                    "restart_from_previous_checkpoint_or_genesis"} +
                            " error=" + StringField(queued.Error()));
                        return 2;
                    }
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_enqueue_failed",
                        "height=" + std::to_string(block.Value().delta.point.height) +
                        " error=" + StringField(queued.Error()) + " action=stop");
                    return 1;
                }
                if (forest.IsOnline()) {
                    const auto durable_wait_start{Clock::now()};
                    auto bounded{proof_store->EnforceRecoveryWindow(
                        block.Value().delta.point.height, online_config.undo_depth)};
                    block.Value().metrics.proof_durable_wait_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            Clock::now() - durable_wait_start).count());
                    if (!bounded) {
                        sync.StopPrefetch();
                        if (IsAllocationFailure(bounded.Error())) {
                            utreexo::Log(utreexo::LogLevel::ERROR,
                                "memory_allocation_failed",
                                "phase=proof_pipeline_commit safe_forest_height=" +
                                    std::to_string(block.Value().delta.point.height) +
                                " durable_proof_height=" +
                                    std::to_string(proof_store->DurablePoint().height) +
                                " checkpoint_status=online_wal_durable"
                                " action=stop exit_code=2"
                                " recovery=rollback_forest_wal_to_proof_tip error=" +
                                    StringField(bounded.Error()));
                            return 2;
                        }
                        utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_commit_failed",
                            "height=" + std::to_string(block.Value().delta.point.height) +
                            " error=" + StringField(bounded.Error()) +
                            " action=stop_recover_by_online_wal_rollback");
                        return 1;
                    }
                    if (bounded.Value()) {
                        utreexo::Log(utreexo::LogLevel::DEBUG,
                            "proof_store_recovery_window_flush",
                            "height=" + std::to_string(block.Value().delta.point.height) +
                            " undo_depth=" + std::to_string(online_config.undo_depth) +
                            " durable_height=" +
                                std::to_string(proof_store->DurablePoint().height));
                    }
                }
            } else {
                auto archived_state{proof_store->StateAt(block.Value().delta.point.height)};
                if (!archived_state) {
                    sync.StopPrefetch();
                    if (IsAllocationFailure(archived_state.Error())) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "memory_allocation_failed",
                            "phase=proof_state_read safe_forest_height=" +
                                std::to_string(block.Value().delta.point.height) +
                            " checkpoint_status=previous_only action=stop"
                            " exit_code=2 recovery=" + std::string{forest.IsOnline() ?
                                "rollback_forest_wal_to_proof_tip" :
                                "restart_from_previous_checkpoint_or_genesis"} +
                            " error=" + StringField(archived_state.Error()));
                        return 2;
                    }
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_state_read_failed",
                        "height=" + std::to_string(block.Value().delta.point.height) +
                        " error=" + StringField(archived_state.Error()) + " action=stop");
                    return 1;
                }
                if (archived_state.Value() &&
                    *archived_state.Value() != post_state.Value()) {
                    sync.StopPrefetch();
                    const utreexo::ChainPoint previous{
                        block.Value().delta.point.height - 1,
                        block.Value().delta.previous_block_hash};
                    if (forest.IsOnline()) {
                        auto rolled_back{sync.RollbackTo(previous)};
                        if (!rolled_back) {
                            utreexo::Log(utreexo::LogLevel::ERROR,
                                "proof_store_state_mismatch",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " rollback_error=" + StringField(rolled_back.Error()) +
                                " action=fail_closed_restore_checkpoint");
                            return 1;
                        }
                    }
                    auto truncated{proof_store->Truncate(previous)};
                    if (!truncated) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "proof_store_state_mismatch",
                            "height=" + std::to_string(block.Value().delta.point.height) +
                            " truncate_error=" + StringField(truncated.Error()) +
                            " action=fail_closed_retry_on_restart");
                        return 1;
                    }
                    utreexo::Log(utreexo::LogLevel::ERROR,
                        "proof_store_state_mismatch",
                        "height=" + std::to_string(block.Value().delta.point.height) +
                        " recovered_height=" + std::to_string(previous.height) +
                        " archive_status=truncated_before_invalid_state"
                        " action=restart_and_regenerate_from_last_valid_proof");
                    return 1;
                }
            }
        }
        if (fresh_genesis_online && height == 0 && !forest.IsOnline()) {
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_started",
                "height=0 path=" + PathField(*options.online_state) +
                " reason=default_genesis_mmap" +
                " cache_bytes=" + std::to_string(online_config.max_dirty_bytes) +
                " wal_segment_bytes=" + std::to_string(online_config.wal_segment_bytes) +
                " undo_depth=" + std::to_string(online_config.undo_depth));
            const auto switched{forest.EnableOnline(*options.online_state,
                                                    *sync.CurrentPoint(),
                                                    sync.ChainHashes(), online_config)};
            if (!switched) {
                sync.StopPrefetch();
                utreexo::Log(utreexo::LogLevel::ERROR, "online_switch_failed",
                    "height=0 path=" + PathField(*options.online_state) +
                    " reason=default_genesis_mmap error=" +
                        StringField(switched.Error()));
                return 1;
            }
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_complete",
                "height=0 path=" + PathField(*options.online_state) +
                " reason=default_genesis_mmap storage_mode=mmap_wal");
            LogMemoryBreakdown("online_switch_complete", height, forest);
            LogOnlineBreakdown("online_switch_complete", height, forest);
            LogProcessResources("online_switch_complete", height);
        }
        block.Value().metrics.end_to_end_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - block_iteration_start).count());
        interval.Add(height, block.Value().metrics, generated_proof);
        overall.Add(height, block.Value().metrics, generated_proof);
        if (utreexo::LogEnabled(utreexo::LogLevel::TRACE)) {
            utreexo::Log(utreexo::LogLevel::TRACE, "block_processed",
                "height=" + std::to_string(height) +
                " block_hash=" + block.Value().delta.point.block_hash.ToBitcoinHex() +
                " additions=" + std::to_string(block.Value().delta.additions.size()) +
                " deletions=" + std::to_string(block.Value().delta.deletions.size()) +
                " generated_proof=" + std::string{generated_proof ? "true" : "false"} +
                " fetch_wait_us=" + std::to_string(block.Value().metrics.fetch_wait_us) +
                " chain_check_us=" + std::to_string(block.Value().metrics.chain_check_us) +
                " block_hash_us=" + std::to_string(block.Value().metrics.block_hash_us) +
                " block_fetch_us=" + std::to_string(block.Value().metrics.block_fetch_us) +
                " parse_us=" + std::to_string(block.Value().metrics.parse_us) +
                " proof_policy_us=" + std::to_string(block.Value().metrics.proof_policy_us) +
                " prove_us=" + std::to_string(block.Value().metrics.prove_us) +
                " verify_us=" + std::to_string(block.Value().metrics.verify_us) +
                " modify_us=" + std::to_string(block.Value().metrics.modify_us) +
                " proof_enqueue_us=" + std::to_string(block.Value().metrics.proof_enqueue_us) +
                " proof_durable_wait_us=" +
                    std::to_string(block.Value().metrics.proof_durable_wait_us) +
                " total_us=" + std::to_string(block.Value().metrics.total_us) +
                " end_to_end_us=" + std::to_string(block.Value().metrics.end_to_end_us));
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
            if (proof_store) LogProofStoreBreakdown("sync_progress", *proof_store);
            LogProcessResources("sync_progress", height);
            if (utreexo::LogEnabled(utreexo::LogLevel::DEBUG) && interval.blocks != 0) {
                utreexo::Log(utreexo::LogLevel::DEBUG, "block_timing_window",
                    "height=" + std::to_string(height) +
                    " blocks=" + std::to_string(interval.blocks) +
                    " generated_proofs=" + std::to_string(interval.generated_proofs) +
                    " wall_us=" + std::to_string(interval_us) +
                    " avg_fetch_wait_us=" + std::to_string(interval.fetch_wait_us / interval.blocks) +
                    " avg_chain_check_us=" + std::to_string(interval.chain_check_us / interval.blocks) +
                    " avg_block_hash_us=" + std::to_string(interval.block_hash_us / interval.blocks) +
                    " avg_block_fetch_us=" + std::to_string(interval.block_fetch_us / interval.blocks) +
                    " avg_parse_us=" + std::to_string(interval.parse_us / interval.blocks) +
                    " avg_proof_policy_us=" +
                        std::to_string(interval.proof_policy_us / interval.blocks) +
                    " avg_prove_us=" + std::to_string(interval.prove_us / interval.blocks) +
                    " avg_verify_us=" + std::to_string(interval.verify_us / interval.blocks) +
                    " avg_modify_us=" + std::to_string(interval.modify_us / interval.blocks) +
                    " avg_proof_enqueue_us=" +
                        std::to_string(interval.proof_enqueue_us / interval.blocks) +
                    " avg_proof_durable_wait_us=" +
                        std::to_string(interval.proof_durable_wait_us / interval.blocks) +
                    " avg_total_us=" + std::to_string(interval.total_us / interval.blocks) +
                    " avg_end_to_end_us=" +
                        std::to_string(interval.end_to_end_us / interval.blocks) +
                    " slowest_total_height=" +
                        std::to_string(interval.slowest_total_height) +
                    " slowest_total_us=" + std::to_string(interval.slowest_total_us) +
                    " slowest_end_to_end_height=" +
                        std::to_string(interval.slowest_end_to_end_height) +
                    " slowest_end_to_end_us=" +
                        std::to_string(interval.slowest_end_to_end_us));
            }
            interval = {};
            interval_start = Clock::now();
        }
        if (checkpoint_output_path && !forest.IsOnline() && options.checkpoint_interval != 0 &&
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
    if (RequestedShutdownSignal() != 0) note_shutdown("initial_sync");
    if (proof_store) {
        auto drained{proof_store->Drain()};
        if (!drained) {
            if (IsAllocationFailure(drained.Error())) {
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=proof_pipeline_drain safe_forest_height=" +
                        std::to_string(sync.CurrentPoint() ?
                            sync.CurrentPoint()->height : 0) +
                    " durable_proof_height=" +
                        std::to_string(proof_store->DurablePoint().height) +
                    " checkpoint_status=previous_only action=stop exit_code=2 recovery=" +
                        std::string{forest.IsOnline() ?
                            "rollback_forest_wal_to_proof_tip" :
                            "restart_from_previous_checkpoint_or_genesis"} +
                    " error=" + StringField(drained.Error()));
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_drain_failed",
                "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
                " error=" + StringField(drained.Error()) + " action=stop");
            return 1;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "proof_store_durable",
            "height=" + std::to_string(proof_store->DurablePoint().height) +
            " forest_height=" +
                std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " reason=before_validation_and_online_switch");
        LogProofStoreBreakdown("initial_sync_drain", *proof_store);
        LogProcessResources("initial_sync_drain",
                            sync.CurrentPoint() ? sync.CurrentPoint()->height : 0);
        if (RequestedShutdownSignal() != 0) note_shutdown("proof_store_drain");
        if (options.proof_store_scrub && shutdown_signal_number == 0) {
            const auto scrub_start{Clock::now()};
            utreexo::Log(utreexo::LogLevel::INFO, "proof_store_scrub_started",
                "base_height=" + std::to_string(proof_store->BasePoint().height) +
                " durable_height=" + std::to_string(proof_store->DurablePoint().height));
            auto scrubbed{proof_store->Scrub([] { return RequestedShutdownSignal() != 0; })};
            if (!scrubbed) {
                if (RequestedShutdownSignal() != 0) {
                    note_shutdown("proof_store_scrub");
                    utreexo::Log(utreexo::LogLevel::INFO,
                        "proof_store_scrub_interrupted",
                        "reason=shutdown_requested action=continue_clean_shutdown");
                } else {
                    if (IsAllocationFailure(scrubbed.Error())) {
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "memory_allocation_failed",
                            "phase=proof_store_scrub checkpoint_status=unchanged"
                            " action=stop exit_code=2 recovery=restart_without_scrub_or_free_memory"
                            " error=" + StringField(scrubbed.Error()));
                        return 2;
                    }
                    utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_scrub_failed",
                        "error=" + StringField(scrubbed.Error()) + " action=fail_closed");
                    return 1;
                }
            } else {
                const auto scrub_us{static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        Clock::now() - scrub_start).count())};
                utreexo::Log(utreexo::LogLevel::INFO, "proof_store_scrub_completed",
                    "durable_height=" + std::to_string(scrubbed.Value().durable.height) +
                    " proofs_verified=" + std::to_string(scrubbed.Value().proofs_verified) +
                    " states_verified=" + std::to_string(scrubbed.Value().states_verified) +
                    " bytes_verified=" + std::to_string(scrubbed.Value().bytes_verified) +
                    " full_history=" +
                        std::string{scrubbed.Value().full_history ? "true" : "false"} +
                    " total_us=" + std::to_string(scrub_us));
            }
        } else if (options.proof_store_scrub) {
            utreexo::Log(utreexo::LogLevel::INFO, "proof_store_scrub_skipped",
                "reason=shutdown_requested");
        }
    }
    // Refresh the cached signal immediately before the final active-chain RPC.
    // A signal can arrive while the proof pipeline is draining or being scrubbed,
    // after the prior signal checks have already completed.
    if (RequestedShutdownSignal() != 0) note_shutdown("before_initial_validation");
    bool active_point_revalidated{false};
    utreexo::Result<void> active_point{utreexo::Result<void>::Ok()};
    if (sync.CurrentPoint() && shutdown_signal_number == 0) {
        active_point = sync.ValidateCurrentPoint();
        if (!active_point && RequestedShutdownSignal() != 0) {
            // If shutdown interrupted the RPC, preserve the last completed block
            // as a recovery-only checkpoint. Reload still validates it against
            // Core before it can become authoritative.
            note_shutdown("initial_validation");
            utreexo::Log(utreexo::LogLevel::WARN,
                "active_chain_revalidation_skipped",
                "height=" + std::to_string(sync.CurrentPoint()->height) +
                " reason=shutdown_during_rpc checkpoint_role=recovery_only");
            active_point = utreexo::Result<void>::Ok();
        } else {
            active_point_revalidated = static_cast<bool>(active_point);
        }
    } else if (!sync.CurrentPoint() && shutdown_signal_number == 0) {
        active_point = utreexo::Result<void>::Err("cannot validate an empty chain point");
    } else if (sync.CurrentPoint()) {
        // Do not make a graceful RAM checkpoint depend on another RPC after the
        // operator has requested shutdown. It is explicitly a recovery point;
        // normal reload validation still rejects it if a reorg won the race.
        utreexo::Log(utreexo::LogLevel::WARN,
            "active_chain_revalidation_skipped",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " reason=shutdown_requested checkpoint_role=recovery_only");
    }
    if (!active_point) {
        utreexo::Log(utreexo::LogLevel::ERROR, "sync_failed",
            "height=" + std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0) +
            " error=" + StringField(active_point.Error()));
        return 1;
    }
    if (RequestedShutdownSignal() != 0) note_shutdown("initial_validation");

    if (options.online_state && !forest.IsOnline()) {
        if (shutdown_signal_number != 0) {
            utreexo::Log(utreexo::LogLevel::INFO, "online_switch_deferred",
                "height=" + std::to_string(sync.CurrentPoint() ?
                    sync.CurrentPoint()->height : 0) +
                " core_tip_height=" + std::to_string(tip.Value()) +
                " reason=shutdown_requested");
        } else if (target != tip.Value()) {
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
            LogProcessResources("online_switch_complete", sync.CurrentPoint()->height);
        }
    }

    const uint64_t sync_wall_us{static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - sync_wall_start).count())};
    if (overall.blocks != 0) {
        utreexo::Log(utreexo::LogLevel::INFO, "sync_timing_summary",
            "blocks=" + std::to_string(overall.blocks) +
            " generated_proofs=" + std::to_string(overall.generated_proofs) +
            " wall_us=" + std::to_string(sync_wall_us) +
            " avg_fetch_wait_us=" + std::to_string(overall.fetch_wait_us / overall.blocks) +
            " avg_chain_check_us=" + std::to_string(overall.chain_check_us / overall.blocks) +
            " avg_block_hash_us=" + std::to_string(overall.block_hash_us / overall.blocks) +
            " avg_block_fetch_us=" + std::to_string(overall.block_fetch_us / overall.blocks) +
            " avg_parse_us=" + std::to_string(overall.parse_us / overall.blocks) +
            " avg_proof_policy_us=" + std::to_string(overall.proof_policy_us / overall.blocks) +
            " avg_prove_us=" + std::to_string(overall.prove_us / overall.blocks) +
            " avg_verify_us=" + std::to_string(overall.verify_us / overall.blocks) +
            " avg_modify_us=" + std::to_string(overall.modify_us / overall.blocks) +
            " avg_proof_enqueue_us=" +
                std::to_string(overall.proof_enqueue_us / overall.blocks) +
            " avg_proof_durable_wait_us=" +
                std::to_string(overall.proof_durable_wait_us / overall.blocks) +
            " avg_total_us=" + std::to_string(overall.total_us / overall.blocks) +
            " avg_end_to_end_us=" + std::to_string(overall.end_to_end_us / overall.blocks) +
            " slowest_total_height=" + std::to_string(overall.slowest_total_height) +
            " slowest_total_us=" + std::to_string(overall.slowest_total_us) +
            " slowest_end_to_end_height=" +
                std::to_string(overall.slowest_end_to_end_height) +
            " slowest_end_to_end_us=" + std::to_string(overall.slowest_end_to_end_us));
    }

    std::shared_ptr<utreexo::RecentProofCache> proof_cache;
    std::unique_ptr<utreexo::P2PServer> p2p_server;
    if (RequestedShutdownSignal() != 0) note_shutdown("before_p2p_start");
    if (options.p2p_port && shutdown_signal_number == 0) {
        constexpr uint64_t MIB{1024ULL * 1024};
        proof_cache = std::make_shared<utreexo::RecentProofCache>(
            options.p2p_proof_cache_blocks, options.p2p_proof_cache_mib * MIB);
        proof_cache->SetTip(sync.CurrentPoint()->height);
        if (!proof_store) sync.SetProofGeneration(true);
        const bool advertise_archive{proof_store && proof_store->Coverage().full_history};
        auto started{utreexo::P2PServer::Start(
            P2PConfig(options, advertise_archive), proof_cache, proof_store)};
        if (!started) {
            const bool allocation_failure{IsAllocationFailure(started.Error())};
            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_listen_failed",
                "bind=" + StringField(options.p2p_bind) +
                " port=" + std::to_string(*options.p2p_port) +
                " error=" + StringField(started.Error()) +
                " exit_code=" + std::to_string(allocation_failure ? 2 : 1));
            return allocation_failure ? 2 : 1;
        }
        p2p_server = started.Take();
        utreexo::Log(utreexo::LogLevel::INFO, "p2p_listening",
            "bind=" + StringField(options.p2p_bind) +
            " port=" + std::to_string(p2p_server->BoundPort()) +
            " services=" + std::string{advertise_archive ?
                "NODE_UTREEXO|NODE_UTREEXO_ARCHIVE" : "NODE_UTREEXO"} +
            " transport=v1 archive=" +
                std::string{advertise_archive ? "true" : "false"} +
            " cache_blocks=" + std::to_string(options.p2p_proof_cache_blocks) +
            " cache_bytes=" + std::to_string(options.p2p_proof_cache_mib * MIB) +
            " max_peers=" + std::to_string(options.p2p_max_peers) +
            " max_peers_per_ip=" + std::to_string(options.p2p_max_peers_per_ip) +
            " max_proof_requests=" + std::to_string(options.p2p_max_proof_requests) +
            " egress_bytes_per_second=" +
                std::to_string(options.p2p_egress_mib_per_second * MIB) +
            " egress_burst_bytes=" + std::to_string(options.p2p_egress_burst_mib * MIB) +
            " advertised_endpoint=" + StringField(options.p2p_advertise ?
                options.p2p_advertise->address + ":" +
                    std::to_string(options.p2p_advertise->port) : "none") +
            " gossip_seeds=" + std::to_string(options.p2p_gossip_seeds.size()) +
            " gossip_retry_seconds=" +
                std::to_string(options.p2p_gossip_retry_seconds) +
            " cached_proofs=0 cache_persistence=disposable" +
            (proof_store ?
                " proof_store=true proof_base_height=" +
                    std::to_string(proof_store->BasePoint().height) +
                    " proof_tip_height=" + std::to_string(proof_store->DurablePoint().height) :
                " proof_store=false note=proofs_become_available_as_new_blocks_are_followed"));
    }

    if (options.follow && shutdown_signal_number == 0) {
        if (!forest.IsOnline()) {
            utreexo::Log(utreexo::LogLevel::ERROR, "online_follow_failed",
                         "reason=online_switch_was_not_completed");
            return 1;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "online_follow_started",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " poll_interval_ms=" + std::to_string(options.poll_interval_ms) +
            " forest_wal_sync=per_block" +
            std::string{proof_store ? " proof_wal_sync=before_tip_publication" :
                                      " proof_wal_sync=disabled"});
        auto last_base_flush{Clock::now()};
        while (RequestedShutdownSignal() == 0) {
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
                if (proof_store) {
                    auto truncated{proof_store->Truncate(*sync.CurrentPoint())};
                    if (!truncated) {
                        utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_truncate_failed",
                            "height=" + std::to_string(sync.CurrentPoint()->height) +
                            " error=" + StringField(truncated.Error()) + " action=stop");
                        return 1;
                    }
                }
                if (proof_cache) proof_cache->DiscardAfter(sync.CurrentPoint()->height);
                utreexo::Log(utreexo::LogLevel::WARN, "online_reorg_rolled_back",
                    "disconnected_blocks=" + std::to_string(reconciled.Value()) +
                    " recovered_height=" + std::to_string(sync.CurrentPoint()->height));
            }
            utreexo::Result<uint32_t> current_tip{
                utreexo::Result<uint32_t>::Err("uninitialized online tip")};
            try {
                current_tip = sync.TipHeight();
            } catch (const std::bad_alloc&) {
                const auto storage{forest.OnlineUsage()};
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=online_tip_poll safe_height=" +
                        std::to_string(sync.CurrentPoint()->height) +
                    " durable_lsn=" + std::to_string(storage.current_lsn) +
                    " checkpoint_status=online_wal_durable action=stop exit_code=2"
                    " recovery=reopen_mmap_and_replay_wal");
                return 2;
            }
            if (!current_tip) {
                utreexo::Log(utreexo::LogLevel::WARN, "online_tip_poll_failed",
                             "error=" + StringField(current_tip.Error()) + " action=retry");
                std::this_thread::sleep_for(std::chrono::milliseconds(options.poll_interval_ms));
                continue;
            }
            if (sync.ChainHashes().size() <= current_tip.Value()) {
                auto started{start_prefetch(current_tip.Value())};
                if (!started) {
                    if (IsAllocationFailure(started.Error())) {
                        const auto storage{forest.OnlineUsage()};
                        utreexo::Log(utreexo::LogLevel::ERROR,
                            "memory_allocation_failed",
                            "phase=online_prefetch_start safe_height=" +
                                std::to_string(sync.CurrentPoint()->height) +
                            " durable_lsn=" + std::to_string(storage.current_lsn) +
                            " checkpoint_status=online_wal_durable action=stop exit_code=2"
                            " recovery=reopen_mmap_and_replay_wal");
                        return 2;
                    }
                    utreexo::Log(utreexo::LogLevel::ERROR, "online_prefetch_failed",
                                 "error=" + StringField(started.Error()));
                    return 1;
                }
                while (sync.ChainHashes().size() <= current_tip.Value() &&
                       RequestedShutdownSignal() == 0) {
                    const auto block_iteration_start{Clock::now()};
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
                        if (IsAllocationFailure(block.Error())) {
                            const auto storage{forest.OnlineUsage()};
                            utreexo::Log(utreexo::LogLevel::ERROR,
                                "memory_allocation_failed",
                                "phase=online_block_result safe_height=" +
                                    std::to_string(sync.CurrentPoint()->height) +
                                " durable_lsn=" + std::to_string(storage.current_lsn) +
                                " checkpoint_status=online_wal_durable action=stop exit_code=2"
                                " recovery=reopen_mmap_and_replay_wal error=" +
                                    StringField(block.Error()));
                            return 2;
                        }
                        utreexo::Log(utreexo::LogLevel::ERROR, "online_block_failed",
                            "height=" + std::to_string(sync.ChainHashes().size()) +
                            " error=" + StringField(block.Error()));
                        return 1;
                    }
                    uint64_t proof_commit_us{0};
                    if (proof_store) {
                        const auto proof_commit_start{Clock::now()};
                        if (!block.Value().proof) {
                            sync.StopPrefetch();
                            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_capture_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " reason=missing_generated_proof action=stop");
                            return 1;
                        }
                        auto post_state{
                            CaptureAccumulatorState(block.Value().delta.point, forest)};
                        if (!post_state) {
                            sync.StopPrefetch();
                            if (IsAllocationFailure(post_state.Error())) {
                                utreexo::Log(utreexo::LogLevel::ERROR,
                                    "memory_allocation_failed",
                                    "phase=online_proof_state_capture safe_forest_height=" +
                                        std::to_string(block.Value().delta.point.height) +
                                    " durable_proof_height=" +
                                        std::to_string(proof_store->DurablePoint().height) +
                                    " checkpoint_status=online_wal_durable action=stop"
                                    " exit_code=2 recovery=rollback_forest_wal_to_proof_tip");
                                return 2;
                            }
                            utreexo::Log(utreexo::LogLevel::ERROR,
                                "proof_store_state_capture_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " error=" + StringField(post_state.Error()) + " action=stop");
                            return 1;
                        }
                        utreexo::Result<void> queued{
                            utreexo::Result<void>::Err("uninitialized online proof enqueue")};
                        const auto enqueue_start{Clock::now()};
                        try {
                            queued = proof_store->Enqueue(
                                block.Value().delta,
                                proof_cache ? *block.Value().proof :
                                              std::move(*block.Value().proof),
                                post_state.Take());
                        } catch (const std::bad_alloc&) {
                            sync.StopPrefetch();
                            utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                                "phase=online_proof_pipeline safe_forest_height=" +
                                std::to_string(block.Value().delta.point.height) +
                                " durable_proof_height=" +
                                std::to_string(proof_store->DurablePoint().height) +
                                " action=stop recovery=rollback_forest_wal_to_proof_tip");
                            return 2;
                        }
                        block.Value().metrics.proof_enqueue_us = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                Clock::now() - enqueue_start).count());
                        if (!queued) {
                            sync.StopPrefetch();
                            if (IsAllocationFailure(queued.Error())) {
                                utreexo::Log(utreexo::LogLevel::ERROR,
                                    "memory_allocation_failed",
                                    "phase=online_proof_pipeline_enqueue safe_forest_height=" +
                                        std::to_string(block.Value().delta.point.height) +
                                    " durable_proof_height=" +
                                        std::to_string(proof_store->DurablePoint().height) +
                                    " checkpoint_status=online_wal_durable action=stop"
                                    " exit_code=2 recovery=rollback_forest_wal_to_proof_tip"
                                    " error=" + StringField(queued.Error()));
                                return 2;
                            }
                            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_enqueue_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " error=" + StringField(queued.Error()) +
                                " action=stop_recover_by_online_wal_rollback");
                            return 1;
                        }
                        const auto durable_wait_start{Clock::now()};
                        auto durable{proof_store->WaitDurable(block.Value().delta.point.height)};
                        block.Value().metrics.proof_durable_wait_us = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                Clock::now() - durable_wait_start).count());
                        if (!durable) {
                            sync.StopPrefetch();
                            if (IsAllocationFailure(durable.Error())) {
                                utreexo::Log(utreexo::LogLevel::ERROR,
                                    "memory_allocation_failed",
                                    "phase=online_proof_pipeline_commit safe_forest_height=" +
                                        std::to_string(block.Value().delta.point.height) +
                                    " durable_proof_height=" +
                                        std::to_string(proof_store->DurablePoint().height) +
                                    " checkpoint_status=online_wal_durable action=stop"
                                    " exit_code=2 recovery=rollback_forest_wal_to_proof_tip"
                                    " error=" + StringField(durable.Error()));
                                return 2;
                            }
                            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_commit_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " error=" + StringField(durable.Error()) +
                                " action=stop_recover_by_online_wal_rollback");
                            return 1;
                        }
                        proof_commit_us = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                Clock::now() - proof_commit_start).count());
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
                            if (IsAllocationFailure(published.Error())) {
                                utreexo::Log(utreexo::LogLevel::ERROR,
                                    "memory_allocation_failed",
                                    "phase=p2p_proof_cache_publish safe_forest_height=" +
                                        std::to_string(block.Value().delta.point.height) +
                                    " checkpoint_status=online_wal_and_proof_wal_durable"
                                    " action=stop exit_code=2"
                                    " recovery=reopen_mmap_and_proof_store error=" +
                                        StringField(published.Error()));
                                return 2;
                            }
                            utreexo::Log(utreexo::LogLevel::ERROR, "p2p_proof_capture_failed",
                                "height=" + std::to_string(block.Value().delta.point.height) +
                                " error=" + StringField(published.Error()) + " action=stop");
                            return 1;
                        }
                    }
                    block.Value().metrics.end_to_end_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            Clock::now() - block_iteration_start).count());
                    const auto storage{forest.OnlineUsage()};
                    const auto cache_stats{proof_cache ? proof_cache->Stats() :
                        utreexo::ProofCacheStats{}};
                    const auto proof_stats{proof_store ? proof_store->Stats() :
                        utreexo::ProofStoreStats{}};
                    utreexo::Log(utreexo::LogLevel::INFO, "online_block_committed",
                        "height=" + std::to_string(block.Value().delta.point.height) +
                        " block_hash=" + block.Value().delta.point.block_hash.ToBitcoinHex() +
                        " additions=" + std::to_string(block.Value().delta.additions.size()) +
                        " deletions=" + std::to_string(block.Value().delta.deletions.size()) +
                        " fetch_wait_us=" + std::to_string(block.Value().metrics.fetch_wait_us) +
                        " chain_check_us=" + std::to_string(block.Value().metrics.chain_check_us) +
                        " block_hash_us=" + std::to_string(block.Value().metrics.block_hash_us) +
                        " block_fetch_us=" + std::to_string(block.Value().metrics.block_fetch_us) +
                        " parse_us=" + std::to_string(block.Value().metrics.parse_us) +
                        " proof_policy_us=" +
                            std::to_string(block.Value().metrics.proof_policy_us) +
                        " prove_us=" + std::to_string(block.Value().metrics.prove_us) +
                        " verify_us=" + std::to_string(block.Value().metrics.verify_us) +
                        " modify_us=" + std::to_string(block.Value().metrics.modify_us) +
                        " proof_enqueue_us=" +
                            std::to_string(block.Value().metrics.proof_enqueue_us) +
                        " proof_durable_wait_us=" +
                            std::to_string(block.Value().metrics.proof_durable_wait_us) +
                        " total_us=" + std::to_string(block.Value().metrics.total_us) +
                        " end_to_end_us=" +
                            std::to_string(block.Value().metrics.end_to_end_us) +
                        " dirty_nodes=" + std::to_string(storage.dirty_nodes) +
                        " dirty_bytes=" + std::to_string(storage.dirty_bytes) +
                        " wal_bytes=" + std::to_string(storage.wal_bytes) +
                        " redo_wal_bytes=" + std::to_string(storage.redo_wal_bytes) +
                        " transaction_nodes=" + std::to_string(storage.last_transaction_nodes) +
                        " transaction_wal_bytes=" + std::to_string(storage.last_transaction_wal_bytes) +
                        " forest_wal_serialize_us=" +
                            std::to_string(storage.last_transaction_serialize_us) +
                        " forest_wal_segment_us=" +
                            std::to_string(storage.last_transaction_segment_us) +
                        " forest_wal_write_us=" +
                            std::to_string(storage.last_transaction_write_us) +
                        " forest_wal_sync_us=" +
                            std::to_string(storage.last_transaction_sync_us) +
                        " forest_wal_publish_us=" +
                            std::to_string(storage.last_transaction_publish_us) +
                        " forest_wal_total_us=" +
                            std::to_string(storage.last_transaction_total_us) +
                        " lsn=" + std::to_string(storage.current_lsn) +
                        (proof_store ? " proof_durable_height=" +
                                           std::to_string(proof_stats.durable_height) +
                                       " proof_commit_us=" +
                                           std::to_string(proof_commit_us) +
                                       " proof_data_bytes=" +
                                           std::to_string(proof_stats.data_bytes) +
                                       " proof_wal_bytes=" +
                                           std::to_string(proof_stats.wal_bytes) : "") +
                        (proof_cache ? " proof_cache_entries=" + std::to_string(cache_stats.entries) +
                                       " proof_cache_bytes=" + std::to_string(cache_stats.bytes) +
                                       " proof_cache_oversized_skips=" +
                                           std::to_string(cache_stats.oversized_skips) : ""));
                    LogProcessResources("online_block_committed",
                                        block.Value().delta.point.height);
                }
                sync.StopPrefetch();
                if (RequestedShutdownSignal() != 0) break;
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
        sync.StopPrefetch();
        if (RequestedShutdownSignal() != 0) note_shutdown("online_follow");
    }

    // Stop public readers before the final archive/forest persistence boundary.
    p2p_server.reset();
    if (proof_store) {
        const auto drained{proof_store->Drain()};
        if (!drained) {
            if (IsAllocationFailure(drained.Error())) {
                utreexo::Log(utreexo::LogLevel::ERROR, "memory_allocation_failed",
                    "phase=shutdown_proof_pipeline_drain safe_forest_height=" +
                        std::to_string(sync.CurrentPoint() ?
                            sync.CurrentPoint()->height : 0) +
                    " durable_proof_height=" +
                        std::to_string(proof_store->DurablePoint().height) +
                    " checkpoint_status=" + std::string{forest.IsOnline() ?
                        "online_wal_durable" : "previous_only"} +
                    " action=stop exit_code=2 recovery=" + std::string{forest.IsOnline() ?
                        "rollback_forest_wal_to_proof_tip" :
                        "restart_from_previous_checkpoint_or_genesis"} +
                    " error=" + StringField(drained.Error()));
                return 2;
            }
            utreexo::Log(utreexo::LogLevel::ERROR, "proof_store_drain_failed",
                "reason=clean_shutdown error=" + StringField(drained.Error()));
            return 1;
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
    bool final_checkpoint_saved{false};
    if (checkpoint_output_path && sync.CurrentPoint() && !forest.IsOnline()) {
        const auto saved{save_checkpoint(*sync.CurrentPoint(),
            shutdown_signal_number != 0 ? "signal" : "final")};
        if (!saved) {
            utreexo::Log(utreexo::LogLevel::ERROR, "checkpoint_save_failed",
                         "reason=final error=" + StringField(saved.Error()));
            return 1;
        }
        final_checkpoint_saved = true;
    } else if (checkpoint_output_path && sync.CurrentPoint() && forest.IsOnline()) {
        utreexo::Log(utreexo::LogLevel::INFO, "checkpoint_save_skipped",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " reason=online_native_state_is_durable bootstrap_checkpoint_preserved=true");
    } else if (shutdown_signal_number != 0 && sync.CurrentPoint() && !forest.IsOnline()) {
        utreexo::Log(utreexo::LogLevel::WARN, "shutdown_state_not_persisted",
            "height=" + std::to_string(sync.CurrentPoint()->height) +
            " reason=no_checkpoint_path recovery=restart_from_previous_checkpoint_or_genesis");
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
        std::optional<std::filesystem::path> reported_checkpoint_path;
        std::string_view reported_checkpoint_role{"none"};
        if (final_checkpoint_saved) {
            reported_checkpoint_path = checkpoint_output_path;
            reported_checkpoint_role = "recovery";
        } else if (options.checkpoint && std::filesystem::exists(*options.checkpoint)) {
            reported_checkpoint_path = options.checkpoint;
            reported_checkpoint_role = options.allow_untrusted_checkpoint ?
                "local" : "trusted_bootstrap";
        } else if (checkpoint_load_path) {
            reported_checkpoint_path = checkpoint_load_path;
            reported_checkpoint_role = loading_recovery_checkpoint ? "recovery" : "bootstrap";
        }
        if (reported_checkpoint_path) {
            std::error_code size_error;
            checkpoint_bytes = std::filesystem::file_size(*reported_checkpoint_path, size_error);
            if (size_error) checkpoint_bytes = 0;
        }
        utreexo::Log(utreexo::LogLevel::INFO, "milestone_manifest",
            "version=" UTREEXO_BRIDGE_VERSION
            " checkpoint_format=" + std::to_string(utreexo::CHECKPOINT_FORMAT_VERSION) +
            " forest_format=" +
            std::to_string(utreexo::PackedForest::FORMAT_VERSION) +
            " proof_store_format=" + std::to_string(utreexo::ProofStore::FORMAT_VERSION) +
            " active_chain_revalidated=" +
                std::string{active_point_revalidated ? "true" : "false"} +
            " height=" + std::to_string(sync.CurrentPoint()->height) +
            " block_hash=" + sync.CurrentPoint()->block_hash.ToBitcoinHex() +
            " num_leaves=" + std::to_string(forest.NumLeaves()) +
            " roots=" + RootsField(forest) +
            " checkpoint_bytes=" + std::to_string(checkpoint_bytes) +
            " checkpoint_role=" + std::string{reported_checkpoint_role} +
            " storage_mode=" + std::string{forest.IsOnline() ? "mmap_wal" : "ram_checkpoint"} +
            " online_base_bytes=" + std::to_string(forest.OnlineUsage().base_bytes) +
            " online_wal_bytes=" + std::to_string(forest.OnlineUsage().wal_bytes) +
            " online_base_lsn=" + std::to_string(forest.OnlineUsage().base_lsn) +
            (proof_store ? " proof_base_height=" +
                               std::to_string(proof_store->BasePoint().height) +
                           " proof_durable_height=" +
                               std::to_string(proof_store->DurablePoint().height) +
                           " proof_data_bytes=" +
                               std::to_string(proof_store->Stats().data_bytes) +
                           " proof_wal_bytes=" +
                               std::to_string(proof_store->Stats().wal_bytes) :
                           " proof_store=disabled"));
        LogProcessResources("sync_complete", sync.CurrentPoint()->height);
    }
    if (shutdown_signal_number != 0) {
        utreexo::Log(utreexo::LogLevel::INFO, "shutdown_complete",
            "signal=" + std::string{ShutdownSignalName(shutdown_signal_number)} +
            " height=" + std::to_string(sync.CurrentPoint() ?
                sync.CurrentPoint()->height : 0) +
            " proof_store_durable_height=" +
                std::to_string(proof_store ? proof_store->DurablePoint().height : 0) +
            " forest_persistence=" + std::string{forest.IsOnline() ?
                "mmap_wal_flushed" : (final_checkpoint_saved ? "checkpoint_saved" : "none")});
    } else {
        utreexo::Log(utreexo::LogLevel::INFO, "sync_complete",
                     "height=" +
                         std::to_string(sync.CurrentPoint() ? sync.CurrentPoint()->height : 0));
    }
    return 0;
}

int main(int argc, char** argv)
{
    try {
        return BridgeMain(argc, argv);
    } catch (const std::bad_alloc&) {
        EmergencyStderr(
            "level=error event=memory_allocation_failed phase=unhandled "
            "safe_height=last_durable_boundary_unknown checkpoint_status=previous_only "
            "action=stop exit_code=2 "
            "recovery=reopen_online_state_or_restart_from_previous_checkpoint\n");
        return 2;
    } catch (const std::exception& error) {
        try {
            utreexo::Log(utreexo::LogLevel::ERROR, "fatal_exception",
                "error=" + StringField(error.what()) + " action=stop exit_code=1");
        } catch (...) {
            EmergencyStderr(
                "level=error event=fatal_exception error=log_allocation_failed "
                "action=stop exit_code=1\n");
        }
        return 1;
    }
}
