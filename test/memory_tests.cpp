#include <test_framework.h>
#include <utreexo/memory.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>

#if defined(__linux__)
#include <unistd.h>
#endif

using namespace utreexo;

TEST(memory_parses_linux_memavailable)
{
    const auto parsed{ParseMeminfoAvailableBytes(
        "MemTotal:       32768000 kB\nMemFree: 1 kB\nMemAvailable: 2345678 kB\n")};
    CHECK(parsed.has_value());
    CHECK_EQ(*parsed, uint64_t{2'345'678} * 1'024);
    CHECK(!ParseMeminfoAvailableBytes("MemTotal: 2 kB\n"));
    CHECK(!ParseMeminfoAvailableBytes("MemAvailable: 2 MB\n"));
    CHECK(!ParseMeminfoAvailableBytes("MemAvailable: 18014398509481984 kB\n"));
}

TEST(memory_parses_cgroup_values_and_limits)
{
    CHECK_EQ(*ParseCgroupByteValue("  4294967296\n"), uint64_t{4'294'967'296});
    CHECK(!ParseCgroupByteValue("max\n"));
    CHECK(!ParseCgroupByteValue("42oops"));
    CHECK_EQ(*CgroupAvailableBytes(uint64_t{1'000}, uint64_t{250}), uint64_t{750});
    CHECK_EQ(*CgroupAvailableBytes(uint64_t{1'000}, uint64_t{1'500}), uint64_t{0});
    CHECK(!CgroupAvailableBytes(std::nullopt, uint64_t{1}));
}

TEST(memory_uses_tightest_known_availability)
{
    MemoryAvailability both{
        .system_available_bytes = uint64_t{9'000},
        .cgroup_available_bytes = uint64_t{4'000},
    };
    CHECK_EQ(*both.EffectiveAvailableBytes(), uint64_t{4'000});
    both.cgroup_available_bytes.reset();
    CHECK_EQ(*both.EffectiveAvailableBytes(), uint64_t{9'000});
    both.system_available_bytes.reset();
    CHECK(!both.EffectiveAvailableBytes());
}

#if defined(__linux__)
TEST(memory_reads_tightest_cgroup_v2_ancestor_limit)
{
    const auto root{std::filesystem::temp_directory_path() /
        ("utreexo-memory-test-" + std::to_string(::getpid()))};
    const auto parent{root / "parent"};
    const auto leaf{parent / "leaf"};
    std::filesystem::create_directories(leaf);
    const auto write = [](const std::filesystem::path& path, std::string_view value) {
        std::ofstream output{path};
        output << value << '\n';
        CHECK(output.good());
    };
    write(root / "memory.max", "max");
    write(root / "memory.current", "100");
    write(parent / "memory.max", "1000");
    write(parent / "memory.current", "400");
    write(leaf / "memory.max", "900");
    write(leaf / "memory.current", "500");

    const auto available{ReadCgroupV2HierarchyAvailableBytes(root, "/parent/leaf")};
    CHECK(available.has_value());
    CHECK_EQ(*available, uint64_t{400});
    CHECK(!ReadCgroupV2HierarchyAvailableBytes(root, "../outside"));

    std::error_code error;
    std::filesystem::remove_all(root, error);
    CHECK(!error);
}

TEST(memory_reads_live_linux_memavailable)
{
    const auto availability{ReadMemoryAvailability()};
    CHECK(availability.system_available_bytes.has_value());
    CHECK(*availability.system_available_bytes > 0);
    CHECK(availability.EffectiveAvailableBytes().has_value());
}
#endif
