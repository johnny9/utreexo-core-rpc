// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_MEMORY_H
#define UTREEXO_MEMORY_H

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

namespace utreexo {

struct MemoryAvailability {
    std::optional<uint64_t> system_available_bytes;
    std::optional<uint64_t> cgroup_available_bytes;

    /** The tightest known limit, or nullopt when neither source is available. */
    [[nodiscard]] std::optional<uint64_t> EffectiveAvailableBytes() const;
};

/** Parse Linux /proc/meminfo and return MemAvailable in bytes. */
[[nodiscard]] std::optional<uint64_t> ParseMeminfoAvailableBytes(std::string_view contents);

/** Parse a cgroup byte counter. The cgroup-v2 "max" value is unbounded. */
[[nodiscard]] std::optional<uint64_t> ParseCgroupByteValue(std::string_view contents);

/** Compute remaining cgroup capacity, saturating at zero. */
[[nodiscard]] std::optional<uint64_t> CgroupAvailableBytes(
    std::optional<uint64_t> limit, std::optional<uint64_t> current);

/** Read the tightest remaining capacity from a cgroup-v2 leaf and its ancestors. */
[[nodiscard]] std::optional<uint64_t> ReadCgroupV2HierarchyAvailableBytes(
    const std::filesystem::path& mount_root, std::string_view relative_path);

/** Read the host and current-process cgroup memory availability on Linux. */
[[nodiscard]] MemoryAvailability ReadMemoryAvailability();

} // namespace utreexo

#endif // UTREEXO_MEMORY_H
