// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/memory.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>

namespace utreexo {
namespace {

std::optional<std::string> ReadTextFile(const std::filesystem::path& path)
{
    std::ifstream input{path};
    if (!input) return std::nullopt;
    std::ostringstream contents;
    contents << input.rdbuf();
    if (!contents) return std::nullopt;
    return contents.str();
}

std::optional<std::filesystem::path> CgroupPath(const std::filesystem::path& root,
                                                std::string_view relative)
{
    while (!relative.empty() && relative.front() == '/') relative.remove_prefix(1);
    const std::filesystem::path relative_path{relative};
    for (const auto& component : relative_path) {
        if (component == "..") return std::nullopt;
    }
    return (root / relative_path).lexically_normal();
}

bool IsCgroupUnlimited(std::string_view contents)
{
    const auto first{contents.find_first_not_of(" \t\r\n")};
    if (first == std::string_view::npos) return false;
    const auto last{contents.find_last_not_of(" \t\r\n")};
    return contents.substr(first, last - first + 1) == "max";
}

#if defined(__linux__)
std::optional<uint64_t> ReadCgroupV2Available(std::string_view membership)
{
    std::istringstream lines{std::string{membership}};
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.starts_with("0::")) continue;
        return ReadCgroupV2HierarchyAvailableBytes(
            "/sys/fs/cgroup", std::string_view{line}.substr(3));
    }
    return std::nullopt;
}

std::optional<uint64_t> ReadCgroupV1Available(std::string_view membership)
{
    std::istringstream lines{std::string{membership}};
    std::string line;
    while (std::getline(lines, line)) {
        const auto first{line.find(':')};
        const auto second{first == std::string::npos ? std::string::npos : line.find(':', first + 1)};
        if (second == std::string::npos) continue;
        const std::string_view controllers{line.data() + first + 1, second - first - 1};
        bool has_memory{false};
        std::size_t start{0};
        while (start <= controllers.size()) {
            const auto comma{controllers.find(',', start)};
            const auto end{comma == std::string_view::npos ? controllers.size() : comma};
            if (controllers.substr(start, end - start) == "memory") has_memory = true;
            if (comma == std::string_view::npos) break;
            start = comma + 1;
        }
        if (!has_memory) continue;
        const std::filesystem::path root{"/sys/fs/cgroup/memory"};
        auto directory{CgroupPath(root, std::string_view{line}.substr(second + 1))};
        if (!directory) return std::nullopt;
        std::optional<uint64_t> tightest;
        while (true) {
            const auto limit_text{ReadTextFile(*directory / "memory.limit_in_bytes")};
            const auto current_text{ReadTextFile(*directory / "memory.usage_in_bytes")};
            if (!limit_text || !current_text) return std::nullopt;
            auto limit{ParseCgroupByteValue(*limit_text)};
            // Linux v1 reports a page-rounded value close to LONG_MAX when unlimited.
            if (limit && *limit < (uint64_t{1} << 60)) {
                const auto remaining{
                    CgroupAvailableBytes(limit, ParseCgroupByteValue(*current_text))};
                if (!remaining) return std::nullopt;
                if (!tightest || *remaining < *tightest) tightest = *remaining;
            }
            if (*directory == root) break;
            const auto parent{directory->parent_path()};
            if (parent.empty() || parent == *directory) return std::nullopt;
            directory = parent;
        }
        return tightest;
    }
    return std::nullopt;
}
#endif

} // namespace

std::optional<uint64_t> MemoryAvailability::EffectiveAvailableBytes() const
{
    if (system_available_bytes && cgroup_available_bytes) {
        return std::min(*system_available_bytes, *cgroup_available_bytes);
    }
    if (system_available_bytes) return system_available_bytes;
    return cgroup_available_bytes;
}

std::optional<uint64_t> ParseMeminfoAvailableBytes(std::string_view contents)
{
    std::istringstream lines{std::string{contents}};
    std::string name;
    uint64_t kib{0};
    std::string unit;
    while (lines >> name >> kib >> unit) {
        if (name != "MemAvailable:") {
            lines.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        if (unit != "kB" || kib > std::numeric_limits<uint64_t>::max() / 1'024) {
            return std::nullopt;
        }
        return kib * 1'024;
    }
    return std::nullopt;
}

std::optional<uint64_t> ParseCgroupByteValue(std::string_view contents)
{
    const auto first{contents.find_first_not_of(" \t\r\n")};
    if (first == std::string_view::npos) return std::nullopt;
    contents.remove_prefix(first);
    const auto last{contents.find_first_of(" \t\r\n")};
    const auto token{contents.substr(0, last)};
    if (token == "max") return std::nullopt;
    uint64_t value{0};
    const auto [end, error]{std::from_chars(token.data(), token.data() + token.size(), value)};
    if (error != std::errc{} || end != token.data() + token.size()) return std::nullopt;
    return value;
}

std::optional<uint64_t> CgroupAvailableBytes(std::optional<uint64_t> limit,
                                             std::optional<uint64_t> current)
{
    if (!limit || !current) return std::nullopt;
    return *current >= *limit ? 0 : *limit - *current;
}

std::optional<uint64_t> ReadCgroupV2HierarchyAvailableBytes(
    const std::filesystem::path& mount_root, std::string_view relative_path)
{
    const auto root{mount_root.lexically_normal()};
    auto directory{CgroupPath(root, relative_path)};
    if (!directory) return std::nullopt;
    std::optional<uint64_t> tightest;
    while (true) {
        const auto limit_text{ReadTextFile(*directory / "memory.max")};
        const auto current_text{ReadTextFile(*directory / "memory.current")};
        if (!limit_text || !current_text) return std::nullopt;
        const auto limit{ParseCgroupByteValue(*limit_text)};
        if (limit) {
            const auto remaining{
                CgroupAvailableBytes(limit, ParseCgroupByteValue(*current_text))};
            if (!remaining) return std::nullopt;
            if (!tightest || *remaining < *tightest) tightest = *remaining;
        } else {
            if (!IsCgroupUnlimited(*limit_text)) return std::nullopt;
        }
        if (*directory == root) break;
        const auto parent{directory->parent_path()};
        if (parent.empty() || parent == *directory) return std::nullopt;
        directory = parent;
    }
    return tightest;
}

MemoryAvailability ReadMemoryAvailability()
{
    MemoryAvailability availability;
#if defined(__linux__)
    if (const auto meminfo{ReadTextFile("/proc/meminfo")}) {
        availability.system_available_bytes = ParseMeminfoAvailableBytes(*meminfo);
    }
    if (const auto membership{ReadTextFile("/proc/self/cgroup")}) {
        availability.cgroup_available_bytes = ReadCgroupV2Available(*membership);
        if (!availability.cgroup_available_bytes) {
            availability.cgroup_available_bytes = ReadCgroupV1Available(*membership);
        }
    }
#endif
    return availability;
}

} // namespace utreexo
