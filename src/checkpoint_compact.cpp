// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
//
// Offline checkpoint compactor. It deliberately does not construct a PackedForest:
// the old-to-new NodeId table is mmap'ed from a temporary disk file, keeping peak
// resident memory bounded independently of the forest arena.
#include <utreexo/checkpoint.h>
#include <utreexo/log.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr uint32_t NO_NODE{UINT32_MAX};
constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
constexpr uint64_t FNV_PRIME{1099511628211ULL};
constexpr std::size_t NODE_BYTES{45};

template <typename T> bool ReadLE(std::istream& in, T& value)
{
    std::array<unsigned char, sizeof(T)> bytes{};
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in) return false;
    uint64_t v{0};
    for (std::size_t i{0}; i < bytes.size(); ++i) v |= uint64_t{bytes[i]} << (i * 8);
    value = static_cast<T>(v);
    return true;
}
template <typename T> void AppendLE(std::array<char, 8>& bytes, T value)
{
    for (std::size_t i{0}; i < sizeof(T); ++i) bytes[i] = static_cast<char>((uint64_t{value} >> (i * 8)) & 0xffU);
}
bool Copy(std::istream& in, std::ostream& out, uint64_t bytes)
{
    std::array<char, 1 << 20> buffer{};
    while (bytes != 0) {
        const auto take{static_cast<std::streamsize>(std::min<uint64_t>(bytes, buffer.size()))};
        in.read(buffer.data(), take);
        if (in.gcount() != take) return false;
        out.write(buffer.data(), take);
        if (!out) return false;
        bytes -= static_cast<uint64_t>(take);
    }
    return true;
}
uint64_t Checksum(const std::filesystem::path& path, uint64_t bytes, bool& ok)
{
    std::ifstream in{path, std::ios::binary};
    std::array<char, 1 << 20> buffer{};
    uint64_t hash{FNV_OFFSET};
    ok = static_cast<bool>(in);
    while (ok && bytes != 0) {
        const auto take{static_cast<std::streamsize>(std::min<uint64_t>(bytes, buffer.size()))};
        in.read(buffer.data(), take);
        if (in.gcount() != take) { ok = false; break; }
        for (std::streamsize i{0}; i < take; ++i) { hash ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]); hash *= FNV_PRIME; }
        bytes -= static_cast<uint64_t>(take);
    }
    return hash;
}
struct Header { uint64_t prefix_bytes{0}; uint64_t slots{0}; uint64_t leaves{0}; std::array<uint32_t, 64> roots{}; };
bool ParseHeader(std::istream& in, Header& h)
{
    std::array<char, 8> magic{}; uint32_t version{0}, height{0}; uint64_t chains{0};
    in.read(magic.data(), 8);
    if (!in || magic != std::array<char, 8>{'U','T','R','C','H','K','P','T'} || !ReadLE(in, version) ||
        version != utreexo::CHECKPOINT_FORMAT_VERSION || !ReadLE(in, height)) return false;
    in.ignore(32); if (!in || !ReadLE(in, chains) || chains > uint64_t{height} + 1) return false;
    in.ignore(static_cast<std::streamsize>(chains * 32));
    h.prefix_bytes = static_cast<uint64_t>(in.tellg());
    in.read(magic.data(), 8);
    if (!in || magic != std::array<char, 8>{'U','T','R','F','O','R','S','T'} || !ReadLE(in, version) ||
        !ReadLE(in, h.leaves) || !ReadLE(in, h.slots) || version != utreexo::PackedForest::FORMAT_VERSION ||
        h.slots >= NO_NODE) return false;
    for (auto& root : h.roots) if (!ReadLE(in, root) || (root != NO_NODE && root >= h.slots)) return false;
    return true;
}
bool RootHashesMatch(const std::filesystem::path& source, const Header& source_header,
                     const std::filesystem::path& compact, const uint32_t* map)
{
    std::ifstream input{source, std::ios::binary};
    std::ifstream output{compact, std::ios::binary};
    Header ignored_source, ignored_compact;
    if (!ParseHeader(input, ignored_source) || !ParseHeader(output, ignored_compact)) return false;
    const auto source_records{static_cast<uint64_t>(input.tellg())};
    const auto compact_records{static_cast<uint64_t>(output.tellg())};
    std::array<char, 32> source_hash{}, compact_hash{};
    for (const uint32_t root : source_header.roots) {
        if (root == NO_NODE) continue;
        const uint32_t compact_root{map[root]};
        input.seekg(static_cast<std::streamoff>(source_records + uint64_t{root} * NODE_BYTES + 1));
        output.seekg(static_cast<std::streamoff>(compact_records + uint64_t{compact_root} * NODE_BYTES + 1));
        input.read(source_hash.data(), static_cast<std::streamsize>(source_hash.size()));
        output.read(compact_hash.data(), static_cast<std::streamsize>(compact_hash.size()));
        if (!input || !output || source_hash != compact_hash) return false;
    }
    return true;
}
void Usage() { std::cerr << "Usage: utreexo-checkpoint-compact INPUT OUTPUT\n"; }
} // namespace

int main(int argc, char** argv)
{
    if (argc != 3) { Usage(); return 1; }
    const std::filesystem::path source{argv[1]}, destination{argv[2]};
    if (source == destination || std::filesystem::exists(destination)) {
        std::cerr << "Error: OUTPUT must be a new path, distinct from INPUT\n"; return 1;
    }
    std::error_code ec; const uint64_t source_size{std::filesystem::file_size(source, ec)};
    if (ec || source_size < 8) { std::cerr << "Error: cannot stat input checkpoint\n"; return 1; }
    bool checksum_ok{false}; const uint64_t checksum{Checksum(source, source_size - 8, checksum_ok)};
    std::ifstream check{source, std::ios::binary}; check.seekg(static_cast<std::streamoff>(source_size - 8)); uint64_t expected{0};
    if (!checksum_ok || !ReadLE(check, expected) || checksum != expected) { std::cerr << "Error: input checkpoint checksum mismatch\n"; return 1; }
    std::ifstream first{source, std::ios::binary}; Header header;
    if (!ParseHeader(first, header)) { std::cerr << "Error: unsupported or malformed checkpoint\n"; return 1; }
    const auto map_path{destination.string() + ".node-map.tmp"};
    const int map_fd{open(map_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600)};
    if (map_fd < 0 || ftruncate(map_fd, static_cast<off_t>(header.slots * sizeof(uint32_t))) != 0) { std::cerr << "Error: cannot create disk-backed node map: " << std::strerror(errno) << '\n'; if (map_fd >= 0) close(map_fd); return 1; }
    auto* map{static_cast<uint32_t*>(mmap(nullptr, static_cast<size_t>(header.slots * sizeof(uint32_t)), PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0))};
    if (map == MAP_FAILED) { std::cerr << "Error: cannot map node-ID table\n"; close(map_fd); return 1; }
    std::fill_n(map, static_cast<size_t>(header.slots), NO_NODE);
    uint64_t live{0}; std::array<char, NODE_BYTES> record{};
    for (uint64_t id{0}; id < header.slots; ++id) {
        first.read(record.data(), static_cast<std::streamsize>(record.size()));
        if (!first || static_cast<unsigned char>(record[0]) > 2) { std::cerr << "Error: malformed node record\n"; munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); return 1; }
        if (record[0] != 0) map[id] = static_cast<uint32_t>(live++);
    }
    for (const uint32_t root : header.roots) if (root != NO_NODE && map[root] == NO_NODE) { std::cerr << "Error: root refers to a free node\n"; munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); return 1; }
    const auto temporary{destination.string() + ".tmp"};
    std::ifstream in{source, std::ios::binary}; std::ofstream out{temporary, std::ios::binary | std::ios::trunc};
    if (!in || !out || !Copy(in, out, header.prefix_bytes)) { std::cerr << "Error: cannot copy checkpoint header\n"; munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); return 1; }
    // Consume old forest header and replace only its slot count and root IDs.
    in.clear(); in.seekg(0);
    Header ignored; if (!ParseHeader(in, ignored)) { std::cerr << "Error: input changed during compaction\n"; munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); return 1; }
    out.write("UTRFORST", 8); std::array<char, 8> le{};
    AppendLE(le, utreexo::PackedForest::FORMAT_VERSION); out.write(le.data(), 4); AppendLE(le, header.leaves); out.write(le.data(), 8); AppendLE(le, live); out.write(le.data(), 8);
    for (const uint32_t root : header.roots) { AppendLE(le, root == NO_NODE ? NO_NODE : map[root]); out.write(le.data(), 4); }
    for (uint64_t id{0}; id < header.slots; ++id) {
        in.read(record.data(), static_cast<std::streamsize>(record.size())); if (!in) { std::cerr << "Error: input changed during compaction\n"; return 1; }
        if (record[0] == 0) continue;
        for (const std::size_t offset : {std::size_t{33}, std::size_t{37}, std::size_t{41}}) { uint32_t link{0}; std::memcpy(&link, record.data() + offset, 4); if (link != NO_NODE) { if (link >= header.slots || map[link] == NO_NODE) { std::cerr << "Error: live node references invalid node\n"; return 1; } link = map[link]; } for (std::size_t b{0}; b < 4; ++b) record[offset + b] = static_cast<char>((uint64_t{link} >> (b * 8)) & 0xffU); }
        out.write(record.data(), static_cast<std::streamsize>(record.size())); if (!out) { std::cerr << "Error: writing compact checkpoint failed\n"; return 1; }
    }
    out.flush(); out.close();
    bool output_ok{false}; const uint64_t output_checksum{Checksum(temporary, std::filesystem::file_size(temporary), output_ok)};
    if (!output_ok) { std::cerr << "Error: compact checkpoint checksum pass failed\n"; return 1; }
    std::ofstream append{temporary, std::ios::binary | std::ios::app}; AppendLE(le, output_checksum); append.write(le.data(), 8); append.close();
    if (!RootHashesMatch(source, header, temporary, map)) { std::cerr << "Error: compact checkpoint root verification failed\n"; return 1; }
    munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); std::filesystem::remove(map_path, ec);
    const int output_fd{open(temporary.c_str(), O_RDONLY)};
    if (output_fd < 0 || fsync(output_fd) != 0) { std::cerr << "Error: cannot sync compact checkpoint\n"; if (output_fd >= 0) close(output_fd); return 1; }
    close(output_fd);
    std::filesystem::rename(temporary, destination, ec); if (ec) { std::cerr << "Error: cannot publish compact checkpoint: " << ec.message() << '\n'; return 1; }
    const auto parent{destination.parent_path().empty() ? std::filesystem::path{"."} : destination.parent_path()};
    const int directory_fd{open(parent.c_str(), O_RDONLY | O_DIRECTORY)};
    if (directory_fd < 0 || fsync(directory_fd) != 0) { std::cerr << "Error: compact checkpoint was published but directory sync failed\n"; if (directory_fd >= 0) close(directory_fd); return 1; }
    close(directory_fd);
    std::cout << "event=checkpoint_compacted source_slots=" << header.slots << " compact_slots=" << live << " leaves=" << header.leaves << " input_bytes=" << source_size << " output_bytes=" << std::filesystem::file_size(destination) << " roots=verified\n";
    return 0;
}
