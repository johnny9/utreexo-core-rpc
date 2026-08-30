// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_LOG_H
#define UTREEXO_LOG_H

#include <utreexo/result.h>

#include <cstdint>
#include <string_view>

namespace utreexo {

enum class LogLevel : uint8_t { ERROR = 0, WARN = 1, INFO = 2, DEBUG = 3, TRACE = 4 };

Result<LogLevel> ParseLogLevel(std::string_view text);
std::string_view LogLevelName(LogLevel level);
void SetLogLevel(LogLevel level);
LogLevel GetLogLevel();
bool LogEnabled(LogLevel level);

/** Emit one UTC timestamped, key-value log record. Fields must not contain secrets. */
void Log(LogLevel level, std::string_view event, std::string_view fields = {});

} // namespace utreexo

#endif // UTREEXO_LOG_H
