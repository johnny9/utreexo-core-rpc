// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
//
// Offline checkpoint compactor. It deliberately does not construct a PackedForest:
// the old-to-new NodeId table is mmap'ed from a temporary disk file, keeping peak
// resident memory bounded independently of the forest arena.
#include <utreexo/checkpoint.h>
#include <utreexo/log.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <streambuf>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr uint32_t NO_NODE{UINT32_MAX};
constexpr uint64_t FNV_OFFSET{14695981039346656037ULL};
constexpr uint64_t FNV_PRIME{1099511628211ULL};
constexpr std::size_t NODE_BYTES{45};

class DescriptorStreamBuffer final : public std::streambuf
{
public:
    explicit DescriptorStreamBuffer(int descriptor) : m_descriptor{descriptor}
    {
        setp(m_buffer.data(), m_buffer.data() + m_buffer.size());
    }

protected:
    int_type overflow(int_type character) override
    {
        if (!FlushBuffer()) return traits_type::eof();
        if (!traits_type::eq_int_type(character, traits_type::eof())) {
            *pptr() = traits_type::to_char_type(character);
            pbump(1);
        }
        return traits_type::not_eof(character);
    }
    std::streamsize xsputn(const char* data, std::streamsize count) override
    {
        std::streamsize completed{0};
        while (completed < count) {
            if (pptr() == epptr() && !FlushBuffer()) break;
            const auto take{std::min(count - completed,
                static_cast<std::streamsize>(epptr() - pptr()))};
            std::memcpy(pptr(), data + completed, static_cast<std::size_t>(take));
            pbump(static_cast<int>(take));
            completed += take;
        }
        return completed;
    }
    int sync() override { return FlushBuffer() ? 0 : -1; }

private:
    bool FlushBuffer()
    {
        const std::size_t size{static_cast<std::size_t>(pptr() - pbase())};
        std::size_t offset{0};
        while (offset < size) {
            const ssize_t written{::write(m_descriptor, pbase() + offset, size - offset)};
            if (written < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (written == 0) return false;
            offset += static_cast<std::size_t>(written);
        }
        setp(m_buffer.data(), m_buffer.data() + m_buffer.size());
        return true;
    }

    int m_descriptor;
    std::array<char, 1024U * 1024U> m_buffer{};
};

int NoFollowFlag()
{
#ifdef O_NOFOLLOW
    return O_NOFOLLOW;
#else
    return 0;
#endif
}

bool InspectOwnedRegularFile(int descriptor, const std::filesystem::path& path,
                             std::string_view description, std::string& error)
{
    struct stat descriptor_status{};
    struct stat path_status{};
    if (fstat(descriptor, &descriptor_status) != 0 ||
        lstat(path.c_str(), &path_status) != 0) {
        error = "cannot inspect " + std::string{description} + ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISREG(descriptor_status.st_mode) || !S_ISREG(path_status.st_mode) ||
        descriptor_status.st_dev != path_status.st_dev ||
        descriptor_status.st_ino != path_status.st_ino) {
        error = std::string{description} + " must be an unaliased regular file";
        return false;
    }
    if (descriptor_status.st_nlink != 1) {
        error = std::string{description} + " must not be hard-linked to another path";
        return false;
    }
    return true;
}

int CreateFreshTemporary(const std::filesystem::path& path,
                         std::string_view description, bool acquire_lock,
                         std::string& error)
{
    int descriptor{open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
        NoFollowFlag(), 0600)};
    if (descriptor < 0 && errno == EEXIST) {
        struct stat path_status{};
        if (lstat(path.c_str(), &path_status) != 0) {
            error = "cannot inspect stale " + std::string{description} + ": " +
                    std::strerror(errno);
            return -1;
        }
        if (S_ISLNK(path_status.st_mode)) {
            error = std::string{description} + " must not be a symbolic link";
            return -1;
        }
        if (!S_ISREG(path_status.st_mode)) {
            error = std::string{description} + " must be a regular file";
            return -1;
        }
        const int stale{open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC |
            NoFollowFlag())};
        if (stale < 0 || !InspectOwnedRegularFile(stale, path, description, error)) {
            if (stale >= 0) close(stale);
            if (error.empty()) {
                error = "cannot open stale " + std::string{description} + ": " +
                        std::strerror(errno);
            }
            return -1;
        }
        if (acquire_lock && flock(stale, LOCK_EX | LOCK_NB) != 0) {
            error = std::string{description} + " is locked by another compactor";
            close(stale);
            return -1;
        }
        if (unlink(path.c_str()) != 0) {
            error = "cannot remove stale " + std::string{description} + ": " +
                    std::strerror(errno);
            close(stale);
            return -1;
        }
        close(stale);
        descriptor = open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC |
            NoFollowFlag(), 0600);
    }
    if (descriptor < 0) {
        error = "cannot create " + std::string{description} + ": " + std::strerror(errno);
        return -1;
    }
    if (!InspectOwnedRegularFile(descriptor, path, description, error)) {
        close(descriptor);
        return -1;
    }
    if (acquire_lock && flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        error = std::string{description} + " is locked by another compactor";
        close(descriptor);
        return -1;
    }
    return descriptor;
}

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
uint64_t Checksum(int descriptor, uint64_t bytes, bool& ok)
{
    std::array<char, 1 << 20> buffer{};
    uint64_t hash{FNV_OFFSET};
    uint64_t offset{0};
    ok = true;
    while (ok && offset < bytes) {
        std::size_t take{buffer.size()};
        const uint64_t remaining{bytes - offset};
        if (remaining < buffer.size()) take = static_cast<std::size_t>(remaining);
        if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
            ok = false;
            break;
        }
        const ssize_t count{pread(descriptor, buffer.data(), take,
                                  static_cast<off_t>(offset))};
        if (count < 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        if (count == 0 || static_cast<std::size_t>(count) > take) {
            ok = false;
            break;
        }
        const auto received{static_cast<std::size_t>(count)};
        for (std::size_t i{0}; i < received; ++i) {
            hash ^= static_cast<unsigned char>(buffer[i]);
            hash *= FNV_PRIME;
        }
        offset += received;
    }
    return hash;
}

bool SameExistingFile(const std::filesystem::path& first,
                      const std::filesystem::path& second)
{
    struct stat first_status{};
    struct stat second_status{};
    const auto same_identity = [](const struct stat& left, const struct stat& right) {
        return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
    };
    if (lstat(first.c_str(), &first_status) == 0 &&
        lstat(second.c_str(), &second_status) == 0 &&
        same_identity(first_status, second_status)) {
        return true;
    }
    // Follow INPUT aliases as well: INPUT may itself be a symlink whose target
    // is the predictable OUTPUT temporary name.
    return stat(first.c_str(), &first_status) == 0 &&
           stat(second.c_str(), &second_status) == 0 &&
           same_identity(first_status, second_status);
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
    const auto map_path{destination.string() + ".node-map.tmp"};
    const auto temporary{destination.string() + ".tmp"};
    std::error_code normalize_error;
    const auto source_normal{std::filesystem::absolute(source, normalize_error).lexically_normal()};
    if (normalize_error) { std::cerr << "Error: cannot resolve INPUT path\n"; return 1; }
    const auto destination_normal{
        std::filesystem::absolute(destination, normalize_error).lexically_normal()};
    if (normalize_error) { std::cerr << "Error: cannot resolve OUTPUT path\n"; return 1; }
    const auto map_normal{std::filesystem::absolute(map_path, normalize_error).lexically_normal()};
    if (normalize_error) { std::cerr << "Error: cannot resolve node-map path\n"; return 1; }
    const auto temporary_normal{
        std::filesystem::absolute(temporary, normalize_error).lexically_normal()};
    if (normalize_error) { std::cerr << "Error: cannot resolve temporary path\n"; return 1; }
    struct stat destination_status{};
    const bool destination_exists{lstat(destination.c_str(), &destination_status) == 0};
    if (!destination_exists && errno != ENOENT) {
        std::cerr << "Error: cannot inspect OUTPUT path: " << std::strerror(errno) << '\n';
        return 1;
    }
    if (source_normal == destination_normal || destination_exists) {
        std::cerr << "Error: OUTPUT must be a new path, distinct from INPUT\n"; return 1;
    }
    if (source_normal == map_normal || source_normal == temporary_normal ||
        SameExistingFile(source, map_path) || SameExistingFile(source, temporary)) {
        std::cerr << "Error: INPUT must not alias an OUTPUT temporary path\n";
        return 1;
    }
    std::error_code ec; const uint64_t source_size{std::filesystem::file_size(source, ec)};
    if (ec || source_size < 8) { std::cerr << "Error: cannot stat input checkpoint\n"; return 1; }
    bool checksum_ok{false}; const uint64_t checksum{Checksum(source, source_size - 8, checksum_ok)};
    std::ifstream check{source, std::ios::binary}; check.seekg(static_cast<std::streamoff>(source_size - 8)); uint64_t expected{0};
    if (!checksum_ok || !ReadLE(check, expected) || checksum != expected) { std::cerr << "Error: input checkpoint checksum mismatch\n"; return 1; }
    std::ifstream first{source, std::ios::binary}; Header header;
    if (!ParseHeader(first, header)) { std::cerr << "Error: unsupported or malformed checkpoint\n"; return 1; }
    std::string temporary_error;
    const int map_fd{CreateFreshTemporary(map_path, "disk-backed node map", true,
                                          temporary_error)};
    if (map_fd < 0 ||
        ftruncate(map_fd, static_cast<off_t>(header.slots * sizeof(uint32_t))) != 0) {
        std::cerr << "Error: " << (map_fd < 0 ? temporary_error :
            "cannot size disk-backed node map: " + std::string{std::strerror(errno)}) << '\n';
        if (map_fd >= 0) close(map_fd);
        return 1;
    }
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
    const int output_fd{CreateFreshTemporary(temporary, "compact checkpoint temporary file",
                                             false, temporary_error)};
    if (output_fd < 0) {
        std::cerr << "Error: " << temporary_error << '\n';
        munmap(map, static_cast<size_t>(header.slots * 4));
        close(map_fd);
        return 1;
    }
    DescriptorStreamBuffer output_buffer{output_fd};
    std::ostream out{&output_buffer};
    std::ifstream in{source, std::ios::binary};
    if (!in || !Copy(in, out, header.prefix_bytes)) { std::cerr << "Error: cannot copy checkpoint header\n"; munmap(map, static_cast<size_t>(header.slots * 4)); close(map_fd); close(output_fd); return 1; }
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
    out.flush();
    struct stat output_status{};
    if (!out || fstat(output_fd, &output_status) != 0 || output_status.st_size < 0) {
        std::cerr << "Error: cannot finish compact checkpoint\n";
        return 1;
    }
    const uint64_t payload_size{static_cast<uint64_t>(output_status.st_size)};
    bool output_ok{false};
    const uint64_t output_checksum{Checksum(output_fd, payload_size, output_ok)};
    if (!output_ok) { std::cerr << "Error: compact checkpoint checksum pass failed\n"; return 1; }
    AppendLE(le, output_checksum); out.write(le.data(), 8); out.flush();
    if (!out) { std::cerr << "Error: writing compact checkpoint checksum failed\n"; return 1; }
    if (!InspectOwnedRegularFile(output_fd, temporary,
                                 "compact checkpoint temporary file", temporary_error)) {
        std::cerr << "Error: " << temporary_error << '\n';
        return 1;
    }
    if (!RootHashesMatch(source, header, temporary, map)) { std::cerr << "Error: compact checkpoint root verification failed\n"; return 1; }
    if (fsync(output_fd) != 0) { std::cerr << "Error: cannot sync compact checkpoint\n"; return 1; }
    // link(2) is the portable POSIX no-replace publication primitive. Unlike
    // rename(2), it fails if OUTPUT appeared while this long compaction ran.
    if (link(temporary.c_str(), destination.c_str()) != 0) {
        std::cerr << "Error: cannot publish compact checkpoint without replacing OUTPUT: "
                  << std::strerror(errno) << '\n';
        return 1;
    }
    if (unlink(temporary.c_str()) != 0 ||
        !InspectOwnedRegularFile(output_fd, destination, "published compact checkpoint",
                                 temporary_error)) {
        std::cerr << "Error: compact checkpoint was linked but publication cleanup failed";
        if (!temporary_error.empty()) std::cerr << ": " << temporary_error;
        std::cerr << '\n';
        return 1;
    }
    const auto parent{destination.parent_path().empty() ? std::filesystem::path{"."} : destination.parent_path()};
    const int directory_fd{open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC |
        NoFollowFlag())};
    if (directory_fd < 0 || fsync(directory_fd) != 0) { std::cerr << "Error: compact checkpoint was published but directory sync failed\n"; if (directory_fd >= 0) close(directory_fd); return 1; }
    if (munmap(map, static_cast<size_t>(header.slots * 4)) != 0 || close(map_fd) != 0) {
        std::cerr << "Error: compact checkpoint was published but node map cleanup failed\n";
        close(directory_fd);
        return 1;
    }
    if (unlink(map_path.c_str()) != 0 || fsync(directory_fd) != 0) {
        std::cerr << "Error: compact checkpoint was published but temporary cleanup failed\n";
        close(directory_fd);
        return 1;
    }
    close(directory_fd);
    close(output_fd);
    std::cout << "event=checkpoint_compacted source_slots=" << header.slots << " compact_slots=" << live << " leaves=" << header.leaves << " input_bytes=" << source_size << " output_bytes=" << payload_size + 8 << " roots=verified\n";
    return 0;
}
