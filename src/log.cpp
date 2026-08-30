// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/log.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace utreexo {
namespace {

std::atomic<LogLevel> g_log_level{LogLevel::INFO};
std::mutex g_log_mutex;

std::string Timestamp()
{
    const auto now{std::chrono::system_clock::now()};
    const std::time_t value{std::chrono::system_clock::to_time_t(now)};
    std::tm utc{};
    gmtime_r(&value, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

} // namespace

Result<LogLevel> ParseLogLevel(std::string_view text)
{
    if (text == "error") return Result<LogLevel>::Ok(LogLevel::ERROR);
    if (text == "warn") return Result<LogLevel>::Ok(LogLevel::WARN);
    if (text == "info") return Result<LogLevel>::Ok(LogLevel::INFO);
    if (text == "debug") return Result<LogLevel>::Ok(LogLevel::DEBUG);
    if (text == "trace") return Result<LogLevel>::Ok(LogLevel::TRACE);
    return Result<LogLevel>::Err("invalid log level (expected error, warn, info, debug, or trace)");
}

std::string_view LogLevelName(LogLevel level)
{
    switch (level) {
    case LogLevel::ERROR: return "error";
    case LogLevel::WARN: return "warn";
    case LogLevel::INFO: return "info";
    case LogLevel::DEBUG: return "debug";
    case LogLevel::TRACE: return "trace";
    }
    return "unknown";
}

void SetLogLevel(LogLevel level) { g_log_level.store(level, std::memory_order_relaxed); }
LogLevel GetLogLevel() { return g_log_level.load(std::memory_order_relaxed); }

bool LogEnabled(LogLevel level)
{
    return static_cast<uint8_t>(level) <= static_cast<uint8_t>(GetLogLevel());
}

void Log(LogLevel level, std::string_view event, std::string_view fields)
{
    if (!LogEnabled(level)) return;
    std::lock_guard<std::mutex> lock{g_log_mutex};
    std::ostream& output{level == LogLevel::ERROR ? std::cerr : std::cout};
    output << "timestamp=" << Timestamp()
           << " level=" << LogLevelName(level)
           << " event=" << event;
    if (!fields.empty()) output << ' ' << fields;
    output << '\n';
    output.flush();
}

} // namespace utreexo
