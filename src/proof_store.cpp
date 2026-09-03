// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/proof_store.h>

#include <utreexo/hash.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <vector>

namespace utreexo {
namespace {

constexpr std::array<std::byte, 8> DATA_MAGIC{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'D'}, std::byte{'A'}, std::byte{'T'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> DATA_COMMIT{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'D'}, std::byte{'O'}, std::byte{'N'}, std::byte{'E'}};
constexpr std::array<std::byte, 8> WAL_MAGIC{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'W'}, std::byte{'A'}, std::byte{'L'}, std::byte{'1'}};
constexpr std::array<std::byte, 8> WAL_COMMIT{
    std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
    std::byte{'C'}, std::byte{'M'}, std::byte{'T'}, std::byte{'1'}};
constexpr std::string_view OWNER_FILE{"FORMAT"};
constexpr std::string_view OWNER_CONTENT{"utreexo-proof-store-v1\n"};
constexpr uint32_t STORE_FORMAT{ProofStore::FORMAT_VERSION};
constexpr uint32_t LEGACY_STORE_FORMAT{1};
constexpr std::size_t DATA_HEADER_SIZE{88};
constexpr std::size_t STATE_PREFIX_SIZE{16};
constexpr std::size_t MAX_STATE_BODY_SIZE{STATE_PREFIX_SIZE + 64 * Hash256::SIZE};
constexpr std::size_t STATE_DIGEST_SIZE{Hash256::SIZE};
constexpr std::size_t MAX_STATE_SIZE{MAX_STATE_BODY_SIZE + STATE_DIGEST_SIZE};
constexpr std::size_t DATA_FOOTER_SIZE{Hash256::SIZE + DATA_COMMIT.size()};
constexpr std::size_t WAL_PREFIX_SIZE{136};
constexpr std::size_t WAL_RECORD_SIZE{WAL_PREFIX_SIZE + Hash256::SIZE + WAL_COMMIT.size()};
constexpr uint64_t INDEX_GROWTH_ENTRIES{4'096};

enum class WalKind : uint8_t { BASE = 1, CONNECT = 2, TRUNCATE = 3 };

std::string ErrnoMessage(std::string_view action)
{
    return std::string{action} + ": " + std::strerror(errno);
}

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & static_cast<T>(0xffU)));
        value >>= 8;
    }
}

void AppendHash(std::vector<std::byte>& output, const Hash256& hash)
{
    output.insert(output.end(), hash.Bytes().begin(), hash.Bytes().end());
}

class ByteReader
{
public:
    explicit ByteReader(std::span<const std::byte> bytes) : m_bytes{bytes} {}

    template <typename T>
    bool ReadLE(T& value)
    {
        static_assert(std::is_unsigned_v<T>);
        if (m_offset + sizeof(T) > m_bytes.size()) return false;
        uint64_t decoded{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            decoded |= static_cast<uint64_t>(std::to_integer<uint8_t>(m_bytes[m_offset++])) <<
                       (8 * i);
        }
        value = static_cast<T>(decoded);
        return true;
    }

    bool ReadBytes(std::span<std::byte> output)
    {
        if (m_offset + output.size() > m_bytes.size()) return false;
        std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(m_offset), output.size(),
                    output.begin());
        m_offset += output.size();
        return true;
    }

    bool ReadHash(Hash256& hash)
    {
        Hash256::Storage bytes{};
        if (!ReadBytes(bytes)) return false;
        hash = Hash256{bytes};
        return true;
    }

    bool Done() const { return m_offset == m_bytes.size(); }

private:
    std::span<const std::byte> m_bytes;
    std::size_t m_offset{0};
};

Result<void> PwriteAll(int descriptor, std::span<const std::byte> bytes, uint64_t file_offset)
{
    const uint64_t max_offset{static_cast<uint64_t>(std::numeric_limits<off_t>::max())};
    if (file_offset > max_offset || bytes.size() > max_offset - file_offset) {
        return Result<void>::Err("proof-store write offset exceeds the platform file limit");
    }
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t written{::pwrite(descriptor, bytes.data() + offset, bytes.size() - offset,
                                       static_cast<off_t>(file_offset + offset))};
        if (written < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("write proof store"));
        }
        if (written == 0) return Result<void>::Err("short proof-store write");
        offset += static_cast<std::size_t>(written);
    }
    return Result<void>::Ok();
}

Result<void> PreadExact(int descriptor, std::span<std::byte> bytes, uint64_t file_offset)
{
    const uint64_t max_offset{static_cast<uint64_t>(std::numeric_limits<off_t>::max())};
    if (file_offset > max_offset || bytes.size() > max_offset - file_offset) {
        return Result<void>::Err("proof-store read offset exceeds the platform file limit");
    }
    std::size_t offset{0};
    while (offset < bytes.size()) {
        const ssize_t received{::pread(descriptor, bytes.data() + offset, bytes.size() - offset,
                                       static_cast<off_t>(file_offset + offset))};
        if (received < 0) {
            if (errno == EINTR) continue;
            return Result<void>::Err(ErrnoMessage("read proof store"));
        }
        if (received == 0) return Result<void>::Err("proof-store file is truncated");
        offset += static_cast<std::size_t>(received);
    }
    return Result<void>::Ok();
}

Result<void> SyncFile(int descriptor, std::string_view description)
{
#if defined(__APPLE__)
    const int result{::fsync(descriptor)};
#else
    const int result{::fdatasync(descriptor)};
#endif
    if (result != 0) {
        return Result<void>::Err(ErrnoMessage(std::string{"sync "} + std::string{description}));
    }
    return Result<void>::Ok();
}

Result<void> SyncDirectory(const std::filesystem::path& directory)
{
    const int descriptor{::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (descriptor < 0) return Result<void>::Err(ErrnoMessage("open proof-store directory"));
    const int result{::fsync(descriptor)};
    const int saved_errno{errno};
    ::close(descriptor);
    errno = saved_errno;
    if (result != 0) return Result<void>::Err(ErrnoMessage("sync proof-store directory"));
    return Result<void>::Ok();
}

uint64_t FileSize(int descriptor, bool& ok)
{
    struct stat status{};
    ok = ::fstat(descriptor, &status) == 0 && status.st_size >= 0;
    return ok ? static_cast<uint64_t>(status.st_size) : 0;
}

struct OwnedFileIdentity {
    dev_t device{};
    ino_t inode{};
};

Result<OwnedFileIdentity> InspectOwnedFile(int descriptor,
                                          const std::filesystem::path& path,
                                          std::string_view description)
{
    struct stat descriptor_status{};
    if (::fstat(descriptor, &descriptor_status) != 0) {
        return Result<OwnedFileIdentity>::Err(
            ErrnoMessage(std::string{"stat "} + std::string{description}));
    }
    if (!S_ISREG(descriptor_status.st_mode)) {
        return Result<OwnedFileIdentity>::Err(
            std::string{description} + " must be a regular file");
    }

    // Verify that the directory entry still names the object we opened.
    // O_NOFOLLOW closes the normal symlink case where the platform provides it;
    // this check provides the same fail-closed property where it is absent and
    // also detects a concurrent final-component replacement.
    struct stat path_status{};
    if (::lstat(path.c_str(), &path_status) != 0) {
        return Result<OwnedFileIdentity>::Err(
            ErrnoMessage(std::string{"inspect "} + std::string{description}));
    }
    if (!S_ISREG(path_status.st_mode) ||
        path_status.st_dev != descriptor_status.st_dev ||
        path_status.st_ino != descriptor_status.st_ino) {
        return Result<OwnedFileIdentity>::Err(
            std::string{description} +
            " must be an unaliased regular file in the proof-store directory");
    }
    if (descriptor_status.st_nlink != 1) {
        return Result<OwnedFileIdentity>::Err(
            std::string{description} +
            " must not be hard-linked outside its proof-store path");
    }
    return Result<OwnedFileIdentity>::Ok(OwnedFileIdentity{
        .device = descriptor_status.st_dev,
        .inode = descriptor_status.st_ino,
    });
}

bool SameFile(const OwnedFileIdentity& first, const OwnedFileIdentity& second)
{
    return first.device == second.device && first.inode == second.inode;
}

int OwnedFileOpenFlags(bool create)
{
    int flags{O_RDWR | O_CLOEXEC};
    if (create) flags |= O_CREAT;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    return flags;
}

Result<bool> OwnerMarkerExists(const std::filesystem::path& directory)
{
    struct stat status{};
    if (::lstat((directory / OWNER_FILE).c_str(), &status) == 0) {
        return Result<bool>::Ok(true);
    }
    if (errno == ENOENT) return Result<bool>::Ok(false);
    return Result<bool>::Err(ErrnoMessage("inspect proof-store format marker"));
}

Result<void> ValidateOwnerMarker(const std::filesystem::path& directory)
{
    const auto path{directory / OWNER_FILE};
    // Re-establish the marker's durability barrier on every open. This also
    // makes a retry safe when a prior creation wrote a complete marker but its
    // fdatasync or containing-directory fsync reported failure.
    int flags{O_RDWR | O_CLOEXEC};
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor{::open(path.c_str(), flags)};
    if (descriptor < 0) {
        return Result<void>::Err(ErrnoMessage("open proof-store format marker"));
    }
    auto identity{InspectOwnedFile(descriptor, path, "proof-store format marker")};
    if (!identity) {
        ::close(descriptor);
        return Result<void>::Err(identity.Error());
    }
    bool size_ok{false};
    const uint64_t size{FileSize(descriptor, size_ok)};
    if (!size_ok) {
        const auto error{ErrnoMessage("stat proof-store format marker")};
        ::close(descriptor);
        return Result<void>::Err(error);
    }
    if (size != OWNER_CONTENT.size()) {
        ::close(descriptor);
        return Result<void>::Err("proof-store format marker has an unrecognized size");
    }
    std::array<std::byte, OWNER_CONTENT.size()> content{};
    auto read{PreadExact(descriptor, content, 0)};
    if (!read) {
        ::close(descriptor);
        return read;
    }
    if (!std::equal(content.begin(), content.end(),
                    reinterpret_cast<const std::byte*>(OWNER_CONTENT.data()))) {
        ::close(descriptor);
        return Result<void>::Err("proof-store format marker is unrecognized");
    }
    auto synced{SyncFile(descriptor, "proof-store format marker")};
    if (synced) {
        auto final_identity{
            InspectOwnedFile(descriptor, path, "proof-store format marker")};
        if (!final_identity) synced = Result<void>::Err(final_identity.Error());
    }
    const int close_result{::close(descriptor)};
    if (!synced) return synced;
    if (close_result != 0) {
        return Result<void>::Err(ErrnoMessage("close proof-store format marker"));
    }
    return Result<void>::Ok();
}

Result<void> CreateOwnerMarker(const std::filesystem::path& directory)
{
    const auto path{directory / OWNER_FILE};
    int flags{O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC};
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor{::open(path.c_str(), flags, 0600)};
    if (descriptor < 0) {
        return Result<void>::Err(ErrnoMessage("create proof-store format marker"));
    }
    auto identity{InspectOwnedFile(descriptor, path, "proof-store format marker")};
    Result<void> result{identity ? Result<void>::Ok() :
                                  Result<void>::Err(identity.Error())};
    if (result) {
        result = PwriteAll(descriptor,
            std::as_bytes(std::span<const char>{OWNER_CONTENT.data(), OWNER_CONTENT.size()}), 0);
    }
    if (result) result = SyncFile(descriptor, "proof-store format marker");
    if (result) {
        auto final_identity{InspectOwnedFile(descriptor, path, "proof-store format marker")};
        if (!final_identity) result = Result<void>::Err(final_identity.Error());
    }
    const int close_result{::close(descriptor)};
    if (!result) return result;
    if (close_result != 0) {
        return Result<void>::Err(ErrnoMessage("close proof-store format marker"));
    }
    return SyncDirectory(directory);
}

struct MarkerlessLayout {
    bool empty{true};
    bool has_index{false};
};

Result<MarkerlessLayout> InspectMarkerlessLayout(const std::filesystem::path& directory)
{
    MarkerlessLayout layout;
    bool has_data{false};
    bool has_wal{false};
    std::error_code error;
    std::filesystem::directory_iterator entries{directory, error};
    if (error) {
        return Result<MarkerlessLayout>::Err(
            "inspect markerless proof-store directory: " + error.message());
    }
    for (const auto& entry : entries) {
        layout.empty = false;
        const auto name{entry.path().filename().string()};
        if (name == "proofs.dat") {
            has_data = true;
        } else if (name == "index.wal") {
            has_wal = true;
        } else if (name == "height.index") {
            layout.has_index = true;
        } else {
            return Result<MarkerlessLayout>::Err(
                "markerless proof-store directory contains unrelated entry: " + name);
        }
    }
    if (!layout.empty && (!has_data || !has_wal)) {
        return Result<MarkerlessLayout>::Err(
            "markerless proof-store directory is incomplete");
    }
    return Result<MarkerlessLayout>::Ok(layout);
}

struct WalEvent {
    uint32_t format_version{STORE_FORMAT};
    WalKind kind{WalKind::BASE};
    ChainPoint point;
    Hash256 previous_hash;
    uint64_t data_offset{0};
    uint64_t data_size{0};
    Hash256 data_digest;
};

std::vector<std::byte> SerializeWal(const WalEvent& event)
{
    std::vector<std::byte> bytes;
    bytes.reserve(WAL_RECORD_SIZE);
    bytes.insert(bytes.end(), WAL_MAGIC.begin(), WAL_MAGIC.end());
    AppendLE(bytes, event.format_version);
    AppendLE(bytes, static_cast<uint32_t>(event.kind));
    AppendLE(bytes, event.point.height);
    AppendLE(bytes, uint32_t{0});
    AppendHash(bytes, event.point.block_hash);
    AppendHash(bytes, event.previous_hash);
    AppendLE(bytes, event.data_offset);
    AppendLE(bytes, event.data_size);
    AppendHash(bytes, event.data_digest);
    const Hash256 digest{Sha256(bytes)};
    AppendHash(bytes, digest);
    bytes.insert(bytes.end(), WAL_COMMIT.begin(), WAL_COMMIT.end());
    return bytes;
}

Result<WalEvent> ParseWal(std::span<const std::byte> bytes)
{
    if (bytes.size() != WAL_RECORD_SIZE) return Result<WalEvent>::Err("invalid proof WAL record size");
    if (!std::equal(WAL_COMMIT.begin(), WAL_COMMIT.end(), bytes.end() -
                    static_cast<std::ptrdiff_t>(WAL_COMMIT.size()))) {
        return Result<WalEvent>::Err("proof WAL commit marker is missing");
    }
    Hash256::Storage expected_bytes{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(WAL_PREFIX_SIZE), Hash256::SIZE,
                expected_bytes.begin());
    if (Sha256(bytes.first(WAL_PREFIX_SIZE)) != Hash256{expected_bytes}) {
        return Result<WalEvent>::Err("committed proof WAL checksum mismatch");
    }
    ByteReader reader{bytes.first(WAL_PREFIX_SIZE)};
    std::array<std::byte, WAL_MAGIC.size()> magic{};
    uint32_t version{0};
    uint32_t kind{0};
    uint32_t reserved{0};
    WalEvent event;
    if (!reader.ReadBytes(magic) || magic != WAL_MAGIC || !reader.ReadLE(version) ||
        version < LEGACY_STORE_FORMAT || version > STORE_FORMAT || !reader.ReadLE(kind) ||
        kind < static_cast<uint32_t>(WalKind::BASE) ||
        kind > static_cast<uint32_t>(WalKind::TRUNCATE) ||
        !reader.ReadLE(event.point.height) || !reader.ReadLE(reserved) || reserved != 0 ||
        !reader.ReadHash(event.point.block_hash) || !reader.ReadHash(event.previous_hash) ||
        !reader.ReadLE(event.data_offset) || !reader.ReadLE(event.data_size) ||
        !reader.ReadHash(event.data_digest) || !reader.Done()) {
        return Result<WalEvent>::Err("invalid proof WAL fields");
    }
    event.kind = static_cast<WalKind>(kind);
    event.format_version = version;
    return Result<WalEvent>::Ok(event);
}

Result<void> ValidateAccumulatorState(const AccumulatorState& state)
{
    if (state.roots.size() != static_cast<std::size_t>(std::popcount(state.num_leaves))) {
        return Result<void>::Err(
            "accumulator state root count does not match the number of occupied rows");
    }
    return Result<void>::Ok();
}

void AppendAccumulatorState(std::vector<std::byte>& output, const AccumulatorState& state)
{
    AppendLE(output, state.num_leaves);
    AppendLE(output, static_cast<uint32_t>(state.roots.size()));
    AppendLE(output, uint32_t{0});
    for (const auto& root : state.roots) AppendHash(output, root);
}

Hash256 AccumulatorStateDigest(const AccumulatorState& state)
{
    constexpr std::array<std::byte, 8> domain{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'S'}, std::byte{'T'}, std::byte{'A'}, std::byte{'2'}};
    std::vector<std::byte> authenticated;
    authenticated.reserve(domain.size() + sizeof(uint32_t) + Hash256::SIZE +
                          STATE_PREFIX_SIZE + state.roots.size() * Hash256::SIZE);
    authenticated.insert(authenticated.end(), domain.begin(), domain.end());
    AppendLE(authenticated, state.point.height);
    AppendHash(authenticated, state.point.block_hash);
    AppendAccumulatorState(authenticated, state);
    return Sha256(authenticated);
}

Hash256 RecordCommitment(const Hash256& record_digest, const Hash256& state_digest)
{
    constexpr std::array<std::byte, 8> domain{
        std::byte{'U'}, std::byte{'P'}, std::byte{'R'}, std::byte{'F'},
        std::byte{'C'}, std::byte{'M'}, std::byte{'T'}, std::byte{'2'}};
    std::array<std::byte, domain.size() + 2 * Hash256::SIZE> bytes{};
    std::copy(domain.begin(), domain.end(), bytes.begin());
    std::copy(record_digest.Bytes().begin(), record_digest.Bytes().end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(domain.size()));
    std::copy(state_digest.Bytes().begin(), state_digest.Bytes().end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(domain.size() + Hash256::SIZE));
    return Sha256(bytes);
}

Result<AccumulatorState> ParseAccumulatorState(std::span<const std::byte> bytes,
                                               const ChainPoint& point)
{
    ByteReader reader{bytes};
    uint64_t num_leaves{0};
    uint32_t root_count{0};
    uint32_t reserved{0};
    if (!reader.ReadLE(num_leaves) || !reader.ReadLE(root_count) ||
        !reader.ReadLE(reserved) || reserved != 0 || root_count > 64 ||
        bytes.size() != STATE_PREFIX_SIZE + static_cast<std::size_t>(root_count) * Hash256::SIZE) {
        return Result<AccumulatorState>::Err("stored accumulator state is malformed");
    }
    AccumulatorState state{.point = point, .num_leaves = num_leaves, .roots = {}};
    state.roots.reserve(root_count);
    for (uint32_t i{0}; i < root_count; ++i) {
        Hash256 root;
        if (!reader.ReadHash(root)) {
            return Result<AccumulatorState>::Err("stored accumulator state root is truncated");
        }
        state.roots.push_back(root);
    }
    if (!reader.Done()) return Result<AccumulatorState>::Err("stored accumulator state has trailing data");
    auto valid{ValidateAccumulatorState(state)};
    if (!valid) return Result<AccumulatorState>::Err(valid.Error());
    return Result<AccumulatorState>::Ok(std::move(state));
}

Result<AccumulatorState> ParseAuthenticatedState(std::span<const std::byte> bytes,
                                                  const ChainPoint& point)
{
    if (bytes.size() < STATE_PREFIX_SIZE + STATE_DIGEST_SIZE ||
        bytes.size() > MAX_STATE_SIZE) {
        return Result<AccumulatorState>::Err("stored authenticated state size is invalid");
    }
    const std::size_t body_size{bytes.size() - STATE_DIGEST_SIZE};
    auto state{ParseAccumulatorState(bytes.first(body_size), point)};
    if (!state) return state;
    Hash256::Storage digest_bytes{};
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(body_size),
                STATE_DIGEST_SIZE, digest_bytes.begin());
    if (Hash256{digest_bytes} != AccumulatorStateDigest(state.Value())) {
        return Result<AccumulatorState>::Err("stored accumulator state checksum mismatch");
    }
    return state;
}

struct PreparedProof {
    ChainPoint point;
    Hash256 previous_hash;
    std::vector<std::byte> record;
    Hash256 digest;
    uint64_t accounted_bytes{0};
};

struct ParsedProofRecord {
    CachedBlockProof proof;
    std::optional<AccumulatorState> state;
};

Result<PreparedProof> PrepareProof(BlockDelta delta, Proof proof,
                                   const AccumulatorState& state,
                                   uint64_t accounted_bytes, uint64_t max_record_bytes)
{
    const ChainPoint point{delta.point};
    const Hash256 previous_hash{delta.previous_block_hash};
    if (state.point != point) {
        return Result<PreparedProof>::Err("post-block accumulator state point does not match proof block");
    }
    auto valid_state{ValidateAccumulatorState(state)};
    if (!valid_state) return Result<PreparedProof>::Err(valid_state.Error());
    CachedBlockProof cached{
        .point = point,
        .proof = std::move(proof),
        .leaves = std::move(delta.proof_leaves),
    };
    auto payload{SerializeUtreexoProof(cached, GetUtreexoProofRequest{
        .block_hash = point.block_hash,
        .request_bitmap = 0x07,
        .proof_indexes = {},
        .leaf_indexes = {},
    })};
    if (!payload) return Result<PreparedProof>::Err(payload.Error());
    if (payload.Value().size() > max_record_bytes ||
        payload.Value().size() > std::numeric_limits<uint64_t>::max() -
                                     DATA_HEADER_SIZE - MAX_STATE_SIZE - DATA_FOOTER_SIZE) {
        return Result<PreparedProof>::Err("serialized block proof exceeds the proof-store record limit");
    }
    std::vector<std::byte> record;
    record.reserve(DATA_HEADER_SIZE + STATE_PREFIX_SIZE +
                   state.roots.size() * Hash256::SIZE + STATE_DIGEST_SIZE +
                   payload.Value().size() +
                   DATA_FOOTER_SIZE);
    record.insert(record.end(), DATA_MAGIC.begin(), DATA_MAGIC.end());
    AppendLE(record, STORE_FORMAT);
    AppendLE(record, point.height);
    AppendHash(record, point.block_hash);
    AppendHash(record, previous_hash);
    AppendLE(record, static_cast<uint64_t>(payload.Value().size()));
    AppendAccumulatorState(record, state);
    const Hash256 state_digest{AccumulatorStateDigest(state)};
    AppendHash(record, state_digest);
    record.insert(record.end(), payload.Value().begin(), payload.Value().end());
    const Hash256 record_digest{Sha256(record)};
    AppendHash(record, record_digest);
    record.insert(record.end(), DATA_COMMIT.begin(), DATA_COMMIT.end());
    return Result<PreparedProof>::Ok(PreparedProof{
        .point = point,
        .previous_hash = previous_hash,
        .record = std::move(record),
        .digest = RecordCommitment(record_digest, state_digest),
        .accounted_bytes = accounted_bytes,
    });
}

Result<PreparedProof> PrepareBaseState(const AccumulatorState& state,
                                       uint64_t /*max_record_bytes*/)
{
    auto valid_state{ValidateAccumulatorState(state)};
    if (!valid_state) return Result<PreparedProof>::Err(valid_state.Error());
    std::vector<std::byte> record;
    record.reserve(DATA_HEADER_SIZE + STATE_PREFIX_SIZE +
                   state.roots.size() * Hash256::SIZE + STATE_DIGEST_SIZE +
                   DATA_FOOTER_SIZE);
    record.insert(record.end(), DATA_MAGIC.begin(), DATA_MAGIC.end());
    AppendLE(record, STORE_FORMAT);
    AppendLE(record, state.point.height);
    AppendHash(record, state.point.block_hash);
    AppendHash(record, Hash256{});
    AppendLE(record, uint64_t{0});
    AppendAccumulatorState(record, state);
    const Hash256 state_digest{AccumulatorStateDigest(state)};
    AppendHash(record, state_digest);
    const Hash256 record_digest{Sha256(record)};
    AppendHash(record, record_digest);
    record.insert(record.end(), DATA_COMMIT.begin(), DATA_COMMIT.end());
    return Result<PreparedProof>::Ok(PreparedProof{
        .point = state.point,
        .previous_hash = {},
        .record = std::move(record),
        .digest = RecordCommitment(record_digest, state_digest),
        .accounted_bytes = 0,
    });
}

struct alignas(8) DiskIndexEntry {
    uint64_t data_offset{0};
    uint64_t data_size{0};
    Hash256::Storage block_hash{};
    Hash256::Storage data_digest{};
};
static_assert(sizeof(DiskIndexEntry) == 80);

bool EntryPresent(const DiskIndexEntry& entry) { return entry.data_size != 0; }

DiskIndexEntry EntryFromEvent(const WalEvent& event)
{
    return DiskIndexEntry{
        .data_offset = event.data_offset,
        .data_size = event.data_size,
        .block_hash = event.point.block_hash.Bytes(),
        .data_digest = event.data_digest.Bytes(),
    };
}

Hash256 EntryHash(const DiskIndexEntry& entry) { return Hash256{entry.block_hash}; }
Hash256 EntryDigest(const DiskIndexEntry& entry) { return Hash256{entry.data_digest}; }

uint64_t AccountedBytes(const BlockDelta& delta, const Proof& proof,
                        const AccumulatorState& state)
{
    uint64_t bytes{1'024};
    const auto add = [&bytes](uint64_t amount) {
        bytes = amount > std::numeric_limits<uint64_t>::max() - bytes ?
                    std::numeric_limits<uint64_t>::max() : bytes + amount;
    };
    add(static_cast<uint64_t>(proof.targets.size()) * sizeof(uint64_t));
    add(static_cast<uint64_t>(proof.hashes.size()) * Hash256::SIZE);
    add(static_cast<uint64_t>(delta.deletions.size()) * Hash256::SIZE);
    add(static_cast<uint64_t>(delta.proof_leaves.size()) * sizeof(CompactLeafData));
    for (const auto& leaf : delta.proof_leaves) add(leaf.script.size());
    add(static_cast<uint64_t>(state.roots.size()) * Hash256::SIZE +
        STATE_PREFIX_SIZE + STATE_DIGEST_SIZE);
    return bytes > std::numeric_limits<uint64_t>::max() / 4 ?
               std::numeric_limits<uint64_t>::max() : bytes * 4;
}

bool ValidProofRecordSize(uint64_t size, uint64_t max_payload)
{
    const uint64_t overhead{DATA_HEADER_SIZE + MAX_STATE_SIZE + DATA_FOOTER_SIZE};
    return size >= DATA_HEADER_SIZE + DATA_FOOTER_SIZE &&
           max_payload <= std::numeric_limits<uint64_t>::max() - overhead &&
           size <= max_payload + overhead;
}

} // namespace

class ProofStore::Impl
{
public:
    explicit Impl(ProofStoreConfig store_config) : config{std::move(store_config)} {}

    ~Impl() noexcept
    {
        // Destruction must still stop and join every worker after a pipeline failure.
        // In particular, producing the Result error from Drain() may itself allocate
        // while the process is already handling std::bad_alloc.
        try {
            static_cast<void>(Drain());
        } catch (...) {
            // The committed data/WAL boundary remains the recovery point.  The
            // no-allocation shutdown below abandons only uncommitted queued work.
        }
        {
            std::lock_guard lock{mutex};
            stopping = true;
        }
        input_ready.notify_all();
        output_ready.notify_all();
        space_available.notify_all();
        durable_changed.notify_all();
        for (auto& worker : serializers) if (worker.joinable()) worker.join();
        if (writer.joinable()) writer.join();
        if (index_map != nullptr) {
            static_cast<void>(::msync(index_map, static_cast<std::size_t>(index_bytes), MS_ASYNC));
            ::munmap(index_map, static_cast<std::size_t>(index_bytes));
        }
        if (index_fd >= 0) ::close(index_fd);
        if (data_fd >= 0) ::close(data_fd);
        if (wal_fd >= 0) ::close(wal_fd);
    }

    Result<void> Initialize()
    {
        if (config.directory.empty() || config.serializer_threads == 0 ||
            config.serializer_threads > 64 || config.group_commit_blocks == 0 ||
            config.group_commit_blocks > 4'096 || config.group_commit_delay_ms > 10'000 ||
            config.max_queued_blocks == 0 || config.max_queued_bytes == 0 ||
            config.max_record_bytes < 1'024 ||
            config.max_record_bytes > std::numeric_limits<uint32_t>::max()) {
            return Result<void>::Err("invalid proof-store configuration");
        }
        std::error_code directory_error;
        std::filesystem::create_directories(config.directory, directory_error);
        if (directory_error) return Result<void>::Err("create proof-store directory: " + directory_error.message());

        const auto data_path{config.directory / "proofs.dat"};
        const auto wal_path{config.directory / "index.wal"};
        const auto index_path{config.directory / "height.index"};
        auto marker_exists{OwnerMarkerExists(config.directory)};
        if (!marker_exists) return Result<void>::Err(marker_exists.Error());
        MarkerlessLayout markerless_layout;
        bool markerless_legacy{false};
        if (marker_exists.Value()) {
            auto marker_valid{ValidateOwnerMarker(config.directory)};
            if (!marker_valid) return marker_valid;
            auto marker_directory_synced{SyncDirectory(config.directory)};
            if (!marker_directory_synced) return marker_directory_synced;
        } else {
            auto inspected{InspectMarkerlessLayout(config.directory)};
            if (!inspected) return Result<void>::Err(inspected.Error());
            markerless_layout = inspected.Take();
            if (markerless_layout.empty) {
                // Ownership must reach stable storage before any mutable store file
                // can be created. A crash after this point is an owned partial store
                // and may safely use normal tail recovery on the next open.
                auto marker_created{CreateOwnerMarker(config.directory)};
                if (!marker_created) return marker_created;
            } else {
                markerless_legacy = true;
            }
        }

        // A markerless legacy store is opened without O_CREAT and is not changed
        // until every committed WAL record and referenced data record has passed a
        // strict scan. All normal/new stores already have a durable ownership marker.
        const int owned_file_flags{OwnedFileOpenFlags(!markerless_legacy)};
        data_fd = ::open(data_path.c_str(), owned_file_flags, 0600);
        if (data_fd < 0) return Result<void>::Err(ErrnoMessage("open proof data"));
        wal_fd = ::open(wal_path.c_str(), owned_file_flags, 0600);
        if (wal_fd < 0) return Result<void>::Err(ErrnoMessage("open proof index WAL"));
        if (!markerless_legacy || markerless_layout.has_index) {
            index_fd = ::open(index_path.c_str(), owned_file_flags, 0600);
            if (index_fd < 0) return Result<void>::Err(ErrnoMessage("open proof mmap index"));
        }

        // All three paths are mutable owned state. Validate them before the first
        // write, truncate, or mmap so a stale link cannot redirect recovery into a
        // checkpoint (or make two store roles overwrite the same inode).
        auto data_identity{InspectOwnedFile(data_fd, data_path, "proof data")};
        if (!data_identity) return Result<void>::Err(data_identity.Error());
        auto wal_identity{InspectOwnedFile(wal_fd, wal_path, "proof index WAL")};
        if (!wal_identity) return Result<void>::Err(wal_identity.Error());
        std::optional<OwnedFileIdentity> index_identity;
        if (index_fd >= 0) {
            auto inspected_index{InspectOwnedFile(index_fd, index_path, "proof mmap index")};
            if (!inspected_index) return Result<void>::Err(inspected_index.Error());
            index_identity = inspected_index.Take();
        }
        if (SameFile(data_identity.Value(), wal_identity.Value()) ||
            (index_identity &&
             (SameFile(data_identity.Value(), *index_identity) ||
              SameFile(wal_identity.Value(), *index_identity)))) {
            return Result<void>::Err(
                "proof-store data, WAL, and mmap index must be distinct files");
        }
        if (::flock(wal_fd, LOCK_EX | LOCK_NB) != 0) {
            return Result<void>::Err(ErrnoMessage("lock proof store"));
        }

        bool wal_size_ok{false};
        wal_end = FileSize(wal_fd, wal_size_ok);
        if (!wal_size_ok) return Result<void>::Err(ErrnoMessage("stat proof index WAL"));
        bool data_size_ok{false};
        uint64_t stored_data_size{FileSize(data_fd, data_size_ok)};
        if (!data_size_ok) return Result<void>::Err(ErrnoMessage("stat proof data"));

        if (!markerless_legacy && wal_end != 0 && wal_end <= WAL_RECORD_SIZE) {
            bool incomplete_base{wal_end < WAL_RECORD_SIZE};
            if (!incomplete_base) {
                std::array<std::byte, WAL_COMMIT.size()> marker{};
                auto marker_read{PreadExact(wal_fd, marker, WAL_RECORD_SIZE - WAL_COMMIT.size())};
                if (!marker_read) return marker_read;
                incomplete_base = marker != WAL_COMMIT;
            }
            if (incomplete_base) {
                if (stored_data_size > DATA_HEADER_SIZE + MAX_STATE_SIZE + DATA_FOOTER_SIZE) {
                    return Result<void>::Err(
                        "incomplete proof-store base WAL accompanies non-base proof data");
                }
                if (::ftruncate(wal_fd, 0) != 0) {
                    return Result<void>::Err(ErrnoMessage("truncate incomplete proof-store base"));
                }
                auto synced{SyncFile(wal_fd, "recovered empty proof index WAL")};
                if (!synced) return synced;
                if (::ftruncate(data_fd, 0) != 0) {
                    return Result<void>::Err(ErrnoMessage("truncate incomplete proof-store base data"));
                }
                synced = SyncFile(data_fd, "recovered empty proof data");
                if (!synced) return synced;
                wal_end = 0;
                stored_data_size = 0;
            }
        }

        std::vector<DiskIndexEntry> recovered;
        if (markerless_legacy) {
            // This path must remain side-effect-free until it proves that this is a
            // complete store produced by an older sidecar. In particular, do not
            // adopt crash debris or truncate an unrelated same-name file set.
            auto recovered_result{RecoverWal(recovered, stored_data_size, false)};
            if (!recovered_result) return recovered_result;
            auto marker_created{CreateOwnerMarker(config.directory)};
            if (!marker_created) return marker_created;
            if (index_fd < 0) {
                index_fd = ::open(index_path.c_str(), OwnedFileOpenFlags(true), 0600);
                if (index_fd < 0) {
                    return Result<void>::Err(ErrnoMessage("create proof mmap index"));
                }
                auto inspected_index{
                    InspectOwnedFile(index_fd, index_path, "proof mmap index")};
                if (!inspected_index) return Result<void>::Err(inspected_index.Error());
                if (SameFile(data_identity.Value(), inspected_index.Value()) ||
                    SameFile(wal_identity.Value(), inspected_index.Value())) {
                    return Result<void>::Err(
                        "proof-store data, WAL, and mmap index must be distinct files");
                }
            }
        } else if (wal_end == 0) {
            if (!config.create_base) {
                return Result<void>::Err("a new proof store requires a checkpoint base point");
            }
            if (!config.create_base_state) {
                return Result<void>::Err("a new proof store requires its base accumulator state");
            }
            if (config.create_base_state->point != *config.create_base) {
                return Result<void>::Err("proof-store base state point does not match its base");
            }
            if (stored_data_size != 0) {
                if (stored_data_size > DATA_HEADER_SIZE + MAX_STATE_SIZE + DATA_FOOTER_SIZE) {
                    return Result<void>::Err("proof data exists without an index WAL");
                }
                if (::ftruncate(data_fd, 0) != 0) {
                    return Result<void>::Err(
                        ErrnoMessage("truncate uncommitted proof-store base data"));
                }
                auto synced{SyncFile(data_fd, "uncommitted proof-store base data")};
                if (!synced) return synced;
            }
            base_point = *config.create_base;
            durable_point = base_point;
            enqueued_point = base_point;
            auto prepared_base{PrepareBaseState(*config.create_base_state,
                                                config.max_record_bytes)};
            if (!prepared_base) return Result<void>::Err(prepared_base.Error());
            auto data_written{PwriteAll(data_fd, prepared_base.Value().record, 0)};
            if (!data_written) return data_written;
            auto data_synced{SyncFile(data_fd, "proof base state")};
            if (!data_synced) return data_synced;
            data_end = prepared_base.Value().record.size();
            base_data_size = prepared_base.Value().record.size();
            base_data_digest = prepared_base.Value().digest;
            base_state = *config.create_base_state;
            ++data_syncs;
            WalEvent base_event{
                .format_version = STORE_FORMAT,
                .kind = WalKind::BASE,
                .point = base_point,
                .previous_hash = {},
                .data_offset = 0,
                .data_size = prepared_base.Value().record.size(),
                .data_digest = prepared_base.Value().digest,
            };
            const auto bytes{SerializeWal(base_event)};
            auto written{PwriteAll(wal_fd, bytes, 0)};
            if (!written) return written;
            auto synced{SyncFile(wal_fd, "proof index WAL")};
            if (!synced) return synced;
            wal_end = bytes.size();
            wal_syncs = 1;
        } else {
            auto recovered_result{RecoverWal(recovered, stored_data_size, true)};
            if (!recovered_result) return recovered_result;
        }
        auto mapped{MapIndex(recovered)};
        if (!mapped) return mapped;
        // Persist every O_CREAT entry before this store can publish a durable tip.
        // This is also deliberately done when reopening: an empty height.index is
        // rebuildable, and a retry after an earlier directory-sync failure must not
        // silently skip the sync merely because the entry is now visible.
        auto directory_synced{SyncDirectory(config.directory)};
        if (!directory_synced) return directory_synced;
        const auto parent{config.directory.has_parent_path() ?
            config.directory.parent_path() : std::filesystem::path{"."}};
        auto parent_synced{SyncDirectory(parent)};
        if (!parent_synced) return parent_synced;
        for (uint32_t index{0}; index < recovered.size(); ++index) {
            if (EntryPresent(recovered[index])) hash_to_height.emplace(EntryHash(recovered[index]), index);
        }
        for (uint32_t i{0}; i < config.serializer_threads; ++i) {
            serializers.emplace_back([this] { SerializerLoop(); });
        }
        writer = std::thread{[this] { WriterLoop(); }};
        return Result<void>::Ok();
    }

    Result<void> Enqueue(const BlockDelta& delta, Proof proof, AccumulatorState state)
    {
        const auto wait_start{std::chrono::steady_clock::now()};
        std::unique_lock operation_lock{operation_mutex};
        if (proof.targets.size() != delta.deletions.size() ||
            delta.proof_leaves.size() != delta.deletions.size()) {
            return Result<void>::Err("block proof does not align with its deletion leaves");
        }
        if (state.point != delta.point) {
            return Result<void>::Err("post-block accumulator state does not match the proof block");
        }
        auto valid_state{ValidateAccumulatorState(state)};
        if (!valid_state) return valid_state;
        const uint64_t accounted{AccountedBytes(delta, proof, state)};
        const uint64_t max_single_accounted{
            config.max_record_bytes > std::numeric_limits<uint64_t>::max() / 4 ?
                std::numeric_limits<uint64_t>::max() : config.max_record_bytes * 4};
        if (accounted > max_single_accounted) {
            return Result<void>::Err(
                "one proof exceeds the proof-store record memory limit");
        }
        const bool oversized_single{accounted > config.max_queued_bytes};
        std::unique_lock lock{mutex};
        const auto has_capacity = [&] {
            if (oversized_single) return queued_blocks == 0 && queued_bytes == 0;
            return queued_blocks < config.max_queued_blocks &&
                   queued_bytes <= config.max_queued_bytes - accounted;
        };
        if (!FailedLocked() && !stopping && !has_capacity() &&
            enqueued_point.height > durable_point.height) {
            ++enqueue_blocked;
            ++backpressure_flushes;
            flush_height = !flush_height ? enqueued_point.height :
                           std::max(*flush_height, enqueued_point.height);
            output_ready.notify_one();
        } else if (!FailedLocked() && !stopping && !has_capacity()) {
            ++enqueue_blocked;
        }
        space_available.wait(lock, [&] {
            return FailedLocked() || stopping || has_capacity();
        });
        if (FailedLocked()) return Result<void>::Err(FailureMessageLocked());
        if (stopping) return Result<void>::Err("proof store is stopping");
        if (delta.point.height != enqueued_point.height + 1 ||
            delta.previous_block_hash != enqueued_point.block_hash) {
            return Result<void>::Err("proof does not extend the enqueued archive tip");
        }
        if (hash_to_height.contains(delta.point.block_hash)) {
            return Result<void>::Err("proof archive already contains this block hash");
        }
        try {
            input.push_back(WorkItem{
                .delta = BlockDelta{
                    .point = delta.point,
                    .previous_block_hash = delta.previous_block_hash,
                    .additions = {},
                    .deletions = delta.deletions,
                    .proof_leaves = delta.proof_leaves,
                },
                .proof = std::move(proof),
                .state = std::move(state),
                .accounted_bytes = accounted,
            });
        } catch (const std::bad_alloc&) {
            return Result<void>::Err("proof pipeline allocation failed while enqueueing a block");
        } catch (const std::exception& exception) {
            return Result<void>::Err("proof pipeline enqueue failed: " +
                                     std::string{exception.what()});
        }
        ++queued_blocks;
        queued_bytes += accounted;
        peak_queued_blocks = std::max(peak_queued_blocks, queued_blocks);
        peak_queued_bytes = std::max(peak_queued_bytes, queued_bytes);
        peak_input_blocks = std::max(peak_input_blocks,
            static_cast<uint64_t>(input.size()));
        enqueue_wait_us += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - wait_start).count());
        enqueued_point = delta.point;
        lock.unlock();
        input_ready.notify_one();
        return Result<void>::Ok();
    }

    Result<void> WaitDurable(uint32_t height)
    {
        std::unique_lock lock{mutex};
        if (height > enqueued_point.height) {
            return Result<void>::Err("cannot wait beyond the enqueued proof tip");
        }
        if (height <= durable_point.height) return Result<void>::Ok();
        ++durability_waits;
        flush_height = !flush_height ? height : std::max(*flush_height, height);
        output_ready.notify_one();
        durable_changed.wait(lock, [&] {
            return FailedLocked() || durable_point.height >= height;
        });
        if (FailedLocked()) return Result<void>::Err(FailureMessageLocked());
        return Result<void>::Ok();
    }

    Result<bool> EnforceRecoveryWindow(uint32_t state_height, uint32_t max_lag)
    {
        if (max_lag == 0) {
            return Result<bool>::Err("proof recovery window must be nonzero");
        }
        {
            std::lock_guard lock{mutex};
            if (FailedLocked()) return Result<bool>::Err(FailureMessageLocked());
            if (state_height <= durable_point.height) return Result<bool>::Ok(false);
            if (state_height > enqueued_point.height) {
                return Result<bool>::Err(
                    "durable forest state is ahead of the enqueued proof archive");
            }
            if (state_height - durable_point.height < max_lag) {
                return Result<bool>::Ok(false);
            }
        }
        auto durable{WaitDurable(state_height)};
        if (!durable) return Result<bool>::Err(durable.Error());
        return Result<bool>::Ok(true);
    }

    Result<void> Drain()
    {
        uint32_t height{0};
        {
            std::lock_guard lock{mutex};
            if (FailedLocked()) return Result<void>::Err(FailureMessageLocked());
            height = enqueued_point.height;
        }
        return WaitDurable(height);
    }

    Result<void> Truncate(const ChainPoint& point)
    {
        std::unique_lock operation_lock{operation_mutex};
        auto drained{Drain()};
        if (!drained) return drained;
        WalEvent event;
        {
            std::lock_guard lock{mutex};
            if (point.height < base_point.height || point.height > durable_point.height) {
                return Result<void>::Err("proof-store truncation point is outside the active archive");
            }
            auto expected{HashAtLocked(point.height)};
            if (!expected || *expected != point.block_hash) {
                return Result<void>::Err("proof-store truncation hash does not match the archive");
            }
            if (point == durable_point) return Result<void>::Ok();
            event = WalEvent{
                .kind = WalKind::TRUNCATE,
                .point = point,
                .previous_hash = durable_point.block_hash,
                .data_offset = 0,
                .data_size = 0,
                .data_digest = {},
            };
        }
        const auto bytes{SerializeWal(event)};
        uint64_t write_offset{0};
        {
            std::lock_guard lock{mutex};
            write_offset = wal_end;
        }
        auto written{PwriteAll(wal_fd, bytes, write_offset)};
        if (!written) return written;
        const auto wal_sync_start{std::chrono::steady_clock::now()};
        auto synced{SyncFile(wal_fd, "proof index WAL truncation")};
        if (!synced) return synced;
        const uint64_t truncate_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - wal_sync_start).count())};
        {
            std::lock_guard lock{mutex};
            wal_end += bytes.size();
            ++wal_syncs;
            wal_sync_us += truncate_sync_us;
            const uint64_t keep{point.height - base_point.height};
            const uint64_t old{durable_point.height - base_point.height};
            for (uint64_t index{keep}; index < old; ++index) {
                if (EntryPresent(index_map[index])) hash_to_height.erase(EntryHash(index_map[index]));
                index_map[index] = {};
            }
            state_present.resize(static_cast<std::size_t>(keep));
            durable_point = point;
            enqueued_point = point;
        }
        return Result<void>::Ok();
    }

    Result<std::shared_ptr<const CachedBlockProof>> Read(const Hash256& block_hash) const
    {
        try {
            DiskIndexEntry entry;
            uint32_t height{0};
            Hash256 expected_previous;
            {
                std::lock_guard lock{mutex};
                const auto found{hash_to_height.find(block_hash)};
                if (found == hash_to_height.end()) {
                    ++misses;
                    return Result<std::shared_ptr<const CachedBlockProof>>::Ok({});
                }
                const uint64_t relative{found->second};
                entry = index_map[relative];
                height = base_point.height + 1 + found->second;
                expected_previous = found->second == 0 ? base_point.block_hash :
                                    EntryHash(index_map[relative - 1]);
                ++hits;
            }
            if (!ValidProofRecordSize(entry.data_size, config.max_record_bytes)) {
                return Result<std::shared_ptr<const CachedBlockProof>>::Err(
                    "proof index contains an invalid record size");
            }
            std::vector<std::byte> bytes(static_cast<std::size_t>(entry.data_size));
            auto read{PreadExact(data_fd, bytes, entry.data_offset)};
            if (!read) return Result<std::shared_ptr<const CachedBlockProof>>::Err(read.Error());
            auto parsed{ParseDataRecord(height, block_hash, expected_previous,
                                        EntryDigest(entry), bytes)};
            if (!parsed) return Result<std::shared_ptr<const CachedBlockProof>>::Err(parsed.Error());
            std::shared_ptr<const CachedBlockProof> result{
                std::make_shared<CachedBlockProof>(std::move(parsed.Value().proof))};
            return Result<std::shared_ptr<const CachedBlockProof>>::Ok(std::move(result));
        } catch (const std::bad_alloc&) {
            return Result<std::shared_ptr<const CachedBlockProof>>::Err(
                "proof archive allocation failed while reading a record");
        }
    }

    Result<std::optional<AccumulatorState>> StateAt(uint32_t height) const
    {
        try {
            DiskIndexEntry entry;
            Hash256 expected_previous;
            Hash256 block_hash;
            bool base_record{false};
            {
                std::lock_guard lock{mutex};
                if (height == base_point.height) {
                    if (!base_state) {
                        return Result<std::optional<AccumulatorState>>::Ok({});
                    }
                    entry = DiskIndexEntry{
                        .data_offset = 0,
                        .data_size = base_data_size,
                        .block_hash = base_point.block_hash.Bytes(),
                        .data_digest = base_data_digest.Bytes(),
                    };
                    block_hash = base_point.block_hash;
                    expected_previous = {};
                    base_record = true;
                } else {
                    if (height < base_point.height || height > durable_point.height) {
                        return Result<std::optional<AccumulatorState>>::Ok({});
                    }
                    const uint64_t relative{height - base_point.height - 1};
                    if (relative >= state_present.size() || !state_present[relative]) {
                        return Result<std::optional<AccumulatorState>>::Ok({});
                    }
                    entry = index_map[relative];
                    block_hash = EntryHash(entry);
                    expected_previous = relative == 0 ? base_point.block_hash :
                                        EntryHash(index_map[relative - 1]);
                }
            }
            auto state{ReadStateRecord(ChainPoint{height, block_hash}, expected_previous,
                                       entry, base_record)};
            if (!state) return Result<std::optional<AccumulatorState>>::Err(state.Error());
            return Result<std::optional<AccumulatorState>>::Ok(state.Take());
        } catch (const std::bad_alloc&) {
            return Result<std::optional<AccumulatorState>>::Err(
                "proof archive allocation failed while reading accumulator state");
        }
    }

    Result<std::optional<Hash256>> HashAt(uint32_t height) const
    {
        std::lock_guard lock{mutex};
        return Result<std::optional<Hash256>>::Ok(HashAtLocked(height));
    }

    ChainPoint BasePoint() const { std::lock_guard lock{mutex}; return base_point; }
    ChainPoint DurablePoint() const { std::lock_guard lock{mutex}; return durable_point; }
    ChainPoint EnqueuedPoint() const { std::lock_guard lock{mutex}; return enqueued_point; }

    ProofStoreCoverage Coverage() const
    {
        std::lock_guard lock{mutex};
        std::optional<uint32_t> start;
        if (durable_point.height == base_point.height) {
            if (base_state) start = base_point.height;
        } else {
            uint64_t relative{durable_point.height - base_point.height};
            while (relative != 0 && relative <= state_present.size() &&
                   state_present[relative - 1]) {
                start = base_point.height + static_cast<uint32_t>(relative);
                --relative;
            }
            if (relative == 0 && base_state) start = base_point.height;
        }
        const bool full{base_point.height == 0 && start && *start == 0};
        return ProofStoreCoverage{
            .base = base_point,
            .durable = durable_point,
            .state_start_height = start,
            .full_history = full,
        };
    }

    Result<ProofStoreScrubStats> Scrub(const std::function<bool()>& cancelled)
    {
        try {
            std::unique_lock operation_lock{operation_mutex};
            auto drained{Drain()};
            if (!drained) return Result<ProofStoreScrubStats>::Err(drained.Error());
            if (cancelled && cancelled()) {
                return Result<ProofStoreScrubStats>::Err("proof archive scrub cancelled");
            }

            ChainPoint base;
            ChainPoint tip;
            std::optional<AccumulatorState> expected_base_state;
            uint64_t base_size{0};
            Hash256 base_digest;
            std::vector<DiskIndexEntry> entries;
            {
                std::lock_guard lock{mutex};
                base = base_point;
                tip = durable_point;
                expected_base_state = base_state;
                base_size = base_data_size;
                base_digest = base_data_digest;
                entries.reserve(static_cast<std::size_t>(tip.height - base.height));
                for (uint64_t i{0}; i < tip.height - base.height; ++i) {
                    entries.push_back(index_map[i]);
                }
            }

            ProofStoreScrubStats stats{.durable = tip};
            if (expected_base_state) {
                if (cancelled && cancelled()) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof archive scrub cancelled");
                }
                if (base_size < DATA_HEADER_SIZE + STATE_PREFIX_SIZE +
                                        STATE_DIGEST_SIZE + DATA_FOOTER_SIZE ||
                    base_size > DATA_HEADER_SIZE + MAX_STATE_SIZE + DATA_FOOTER_SIZE) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof base state has an invalid record size");
                }
                std::vector<std::byte> bytes(static_cast<std::size_t>(base_size));
                auto read{PreadExact(data_fd, bytes, 0)};
                if (!read) return Result<ProofStoreScrubStats>::Err(read.Error());
                auto parsed{ParseBaseStateRecord(base, base_digest, bytes)};
                if (!parsed) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof base state: " + parsed.Error());
                }
                if (parsed.Value() != *expected_base_state) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof base state differs from the recovered archive state");
                }
                ++stats.states_verified;
                stats.bytes_verified += base_size;
            }

            Hash256 previous{base.block_hash};
            for (std::size_t i{0}; i < entries.size(); ++i) {
                if (cancelled && cancelled()) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof archive scrub cancelled");
                }
                const auto& entry{entries[i]};
                const uint32_t height{base.height + 1 + static_cast<uint32_t>(i)};
                if (!ValidProofRecordSize(entry.data_size, config.max_record_bytes)) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof height " + std::to_string(height) +
                        ": invalid record size");
                }
                std::vector<std::byte> bytes(static_cast<std::size_t>(entry.data_size));
                auto read{PreadExact(data_fd, bytes, entry.data_offset)};
                if (!read) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof height " + std::to_string(height) + ": " + read.Error());
                }
                auto parsed{ParseDataRecord(height, EntryHash(entry), previous,
                                            EntryDigest(entry), bytes)};
                if (!parsed) {
                    return Result<ProofStoreScrubStats>::Err(
                        "proof height " + std::to_string(height) + ": " + parsed.Error());
                }
                ++stats.proofs_verified;
                if (parsed.Value().state) ++stats.states_verified;
                stats.bytes_verified += entry.data_size;
                previous = EntryHash(entry);
            }
            stats.full_history = Coverage().full_history;
            return Result<ProofStoreScrubStats>::Ok(stats);
        } catch (const std::bad_alloc&) {
            return Result<ProofStoreScrubStats>::Err(
                "proof archive allocation failed during full scrub");
        }
    }

    ProofStoreStats Stats() const
    {
        std::lock_guard lock{mutex};
        return ProofStoreStats{
            .base_height = base_point.height,
            .durable_height = durable_point.height,
            .enqueued_height = enqueued_point.height,
            .active_proofs = durable_point.height - base_point.height,
            .data_bytes = data_end,
            .wal_bytes = wal_end,
            .index_bytes = index_bytes,
            .queued_blocks = queued_blocks,
            .queued_bytes = queued_bytes,
            .input_blocks = static_cast<uint64_t>(input.size()),
            .ready_blocks = static_cast<uint64_t>(ready.size()),
            .peak_queued_blocks = peak_queued_blocks,
            .peak_queued_bytes = peak_queued_bytes,
            .peak_input_blocks = peak_input_blocks,
            .peak_ready_blocks = peak_ready_blocks,
            .enqueue_blocked = enqueue_blocked,
            .backpressure_flushes = backpressure_flushes,
            .durability_waits = durability_waits,
            .serialized_proofs = serialized_proofs,
            .serialized_bytes = serialized_bytes,
            .largest_record_bytes = largest_record_bytes,
            .enqueue_wait_us = enqueue_wait_us,
            .serialization_us = serialization_us,
            .committed_proofs = committed_proofs,
            .committed_batches = committed_batches,
            .full_batches = full_batches,
            .partial_batches = partial_batches,
            .largest_batch_proofs = largest_batch_proofs,
            .commit_us = commit_us,
            .data_write_us = data_write_us,
            .data_syncs = data_syncs,
            .data_sync_us = data_sync_us,
            .wal_write_us = wal_write_us,
            .wal_syncs = wal_syncs,
            .wal_sync_us = wal_sync_us,
            .index_publish_us = index_publish_us,
            .hits = hits,
            .misses = misses,
        };
    }

private:
    struct WorkItem {
        BlockDelta delta;
        Proof proof;
        AccumulatorState state;
        uint64_t accounted_bytes{0};
    };

    Result<void> RecoverWal(std::vector<DiskIndexEntry>& recovered,
                            uint64_t stored_data_size,
                            bool allow_tail_recovery)
    {
        if (!allow_tail_recovery && wal_end % WAL_RECORD_SIZE != 0) {
            return Result<void>::Err(
                "markerless legacy proof store has an incomplete WAL tail");
        }
        const uint64_t complete_wal_size{wal_end - (wal_end % WAL_RECORD_SIZE)};
        if (complete_wal_size == 0) return Result<void>::Err("proof index WAL has no complete base record");
        uint64_t offset{0};
        uint64_t valid_wal_size{complete_wal_size};
        uint64_t recovered_data_end{0};
        bool saw_base{false};
        while (offset < complete_wal_size) {
            std::array<std::byte, WAL_RECORD_SIZE> bytes{};
            auto read{PreadExact(wal_fd, bytes, offset)};
            if (!read) return read;
            const bool committed{std::equal(
                WAL_COMMIT.begin(), WAL_COMMIT.end(),
                bytes.end() - static_cast<std::ptrdiff_t>(WAL_COMMIT.size()))};
            if (!committed && offset + WAL_RECORD_SIZE == complete_wal_size) {
                if (!allow_tail_recovery) {
                    return Result<void>::Err(
                        "markerless legacy proof store has an uncommitted WAL tail");
                }
                valid_wal_size = offset;
                break;
            }
            auto event{ParseWal(bytes)};
            if (!event) {
                return Result<void>::Err("proof index WAL offset " + std::to_string(offset) +
                                         ": " + event.Error());
            }
            if (!saw_base) {
                const bool legacy_base{event.Value().format_version == LEGACY_STORE_FORMAT};
                if (event.Value().kind != WalKind::BASE || event.Value().data_offset != 0 ||
                    !event.Value().previous_hash.IsNull() ||
                    (legacy_base && (event.Value().data_size != 0 ||
                                     !event.Value().data_digest.IsNull())) ||
                    (!legacy_base && (event.Value().data_size <
                                          DATA_HEADER_SIZE + STATE_PREFIX_SIZE +
                                              STATE_DIGEST_SIZE + DATA_FOOTER_SIZE ||
                                      event.Value().data_size > stored_data_size))) {
                    return Result<void>::Err("proof index WAL does not begin with a valid base");
                }
                base_point = event.Value().point;
                durable_point = base_point;
                enqueued_point = base_point;
                if (!legacy_base) {
                    auto envelope{ValidateDataEnvelope(event.Value(), true)};
                    if (!envelope) return Result<void>::Err(envelope.Error());
                    if (!envelope.Value()) {
                        return Result<void>::Err("proof-store base record has no accumulator state");
                    }
                    base_state = std::move(*envelope.Value());
                    base_data_size = event.Value().data_size;
                    base_data_digest = event.Value().data_digest;
                    recovered_data_end = event.Value().data_size;
                }
                saw_base = true;
            } else if (event.Value().kind == WalKind::CONNECT) {
                if (event.Value().point.height != durable_point.height + 1 ||
                    event.Value().previous_hash != durable_point.block_hash ||
                    event.Value().data_offset != recovered_data_end ||
                    !ValidProofRecordSize(event.Value().data_size,
                                          config.max_record_bytes) ||
                    event.Value().data_offset > stored_data_size ||
                    event.Value().data_size > stored_data_size - event.Value().data_offset) {
                    return Result<void>::Err("proof CONNECT WAL record is not contiguous");
                }
                auto envelope{ValidateDataEnvelope(event.Value(), false)};
                if (!envelope) return Result<void>::Err(envelope.Error());
                if (!allow_tail_recovery) {
                    // Legacy adoption is a one-time trust boundary. Validate the
                    // entire payload checksum and parse, not only the bounded state
                    // envelope normally needed for fast startup.
                    std::vector<std::byte> record(
                        static_cast<std::size_t>(event.Value().data_size));
                    auto record_read{PreadExact(data_fd, record,
                                                event.Value().data_offset)};
                    if (!record_read) return record_read;
                    auto parsed{ParseDataRecord(
                        event.Value().point.height,
                        event.Value().point.block_hash,
                        event.Value().previous_hash,
                        event.Value().data_digest,
                        record)};
                    if (!parsed) {
                        return Result<void>::Err(
                            "markerless legacy proof data failed validation: " +
                            parsed.Error());
                    }
                }
                const uint64_t relative{event.Value().point.height - base_point.height - 1};
                if (relative >= recovered.size()) recovered.resize(static_cast<std::size_t>(relative + 1));
                recovered[relative] = EntryFromEvent(event.Value());
                if (relative >= state_present.size()) {
                    state_present.resize(static_cast<std::size_t>(relative + 1));
                }
                state_present[relative] = envelope.Value().has_value();
                durable_point = event.Value().point;
                enqueued_point = durable_point;
                recovered_data_end += event.Value().data_size;
            } else if (event.Value().kind == WalKind::TRUNCATE) {
                if (event.Value().point.height < base_point.height ||
                    event.Value().point.height >= durable_point.height ||
                    event.Value().previous_hash != durable_point.block_hash ||
                    event.Value().data_offset != 0 || event.Value().data_size != 0 ||
                    !event.Value().data_digest.IsNull()) {
                    return Result<void>::Err("invalid proof TRUNCATE WAL record");
                }
                const Hash256 expected{event.Value().point.height == base_point.height ?
                    base_point.block_hash : EntryHash(recovered[event.Value().point.height -
                                                               base_point.height - 1])};
                if (expected != event.Value().point.block_hash) {
                    return Result<void>::Err("proof TRUNCATE WAL hash does not match active history");
                }
                recovered.resize(static_cast<std::size_t>(event.Value().point.height - base_point.height));
                state_present.resize(
                    static_cast<std::size_t>(event.Value().point.height - base_point.height));
                durable_point = event.Value().point;
                enqueued_point = durable_point;
            } else {
                return Result<void>::Err("proof WAL contains a second base record");
            }
            offset += WAL_RECORD_SIZE;
        }
        if (!saw_base) return Result<void>::Err("proof index WAL has no committed base record");
        if (valid_wal_size != wal_end) {
            if (!allow_tail_recovery) {
                return Result<void>::Err(
                    "markerless legacy proof store has a recoverable WAL tail");
            }
            if (::ftruncate(wal_fd, static_cast<off_t>(valid_wal_size)) != 0) {
                return Result<void>::Err(ErrnoMessage("truncate incomplete proof WAL tail"));
            }
            auto synced{SyncFile(wal_fd, "recovered proof index WAL")};
            if (!synced) return synced;
            wal_end = valid_wal_size;
        }
        data_end = recovered_data_end;
        if (stored_data_size < data_end) return Result<void>::Err("proof data is shorter than its durable WAL");
        if (stored_data_size != data_end) {
            if (!allow_tail_recovery) {
                return Result<void>::Err(
                    "markerless legacy proof store has an uncommitted data tail");
            }
            if (::ftruncate(data_fd, static_cast<off_t>(data_end)) != 0) {
                return Result<void>::Err(ErrnoMessage("truncate uncommitted proof data tail"));
            }
            auto synced{SyncFile(data_fd, "recovered proof data")};
            if (!synced) return synced;
        }
        return Result<void>::Ok();
    }

    Result<std::optional<AccumulatorState>> ValidateDataEnvelope(const WalEvent& event,
                                                                 bool base) const
    {
        std::array<std::byte, DATA_HEADER_SIZE> header{};
        auto read{PreadExact(data_fd, header, event.data_offset)};
        if (!read) return Result<std::optional<AccumulatorState>>::Err(read.Error());
        ByteReader reader{header};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 block_hash;
        Hash256 previous_hash;
        uint64_t payload_size{0};
        if (!reader.ReadBytes(magic) || magic != DATA_MAGIC || !reader.ReadLE(version) ||
            version < LEGACY_STORE_FORMAT || version > STORE_FORMAT ||
            version != event.format_version || !reader.ReadLE(height) || !reader.ReadHash(block_hash) ||
            !reader.ReadHash(previous_hash) || !reader.ReadLE(payload_size) || !reader.Done() ||
            height != event.point.height || block_hash != event.point.block_hash ||
            previous_hash != event.previous_hash || (base && payload_size != 0)) {
            return Result<std::optional<AccumulatorState>>::Err(
                "proof data header does not match its WAL record");
        }
        std::optional<AccumulatorState> state;
        if (event.data_size < DATA_HEADER_SIZE + DATA_FOOTER_SIZE) {
            return Result<std::optional<AccumulatorState>>::Err(
                "proof data record is shorter than its envelope");
        }
        const uint64_t body_size{event.data_size - DATA_HEADER_SIZE - DATA_FOOTER_SIZE};
        if (version == LEGACY_STORE_FORMAT) {
            if (base || payload_size != body_size) {
                return Result<std::optional<AccumulatorState>>::Err(
                    "legacy proof data size does not match its WAL record");
            }
        } else {
            if (body_size < STATE_PREFIX_SIZE + STATE_DIGEST_SIZE ||
                payload_size > body_size - STATE_PREFIX_SIZE - STATE_DIGEST_SIZE) {
                return Result<std::optional<AccumulatorState>>::Err(
                    "state-bearing proof data is truncated");
            }
            const uint64_t state_size{body_size - payload_size};
            if (state_size < STATE_PREFIX_SIZE + STATE_DIGEST_SIZE ||
                state_size > MAX_STATE_SIZE) {
                return Result<std::optional<AccumulatorState>>::Err(
                    "stored accumulator state size is invalid");
            }
            std::vector<std::byte> state_bytes(static_cast<std::size_t>(state_size));
            auto state_read{PreadExact(data_fd, state_bytes,
                                       event.data_offset + DATA_HEADER_SIZE)};
            if (!state_read) {
                return Result<std::optional<AccumulatorState>>::Err(state_read.Error());
            }
            auto parsed{ParseAuthenticatedState(state_bytes, event.point)};
            if (!parsed) {
                return Result<std::optional<AccumulatorState>>::Err(parsed.Error());
            }
            state = parsed.Take();
        }
        std::array<std::byte, DATA_FOOTER_SIZE> footer{};
        read = PreadExact(data_fd, footer, event.data_offset + event.data_size - DATA_FOOTER_SIZE);
        if (!read) return Result<std::optional<AccumulatorState>>::Err(read.Error());
        Hash256::Storage digest{};
        std::copy_n(footer.begin(), Hash256::SIZE, digest.begin());
        const Hash256 record_digest{digest};
        const Hash256 commitment{version == LEGACY_STORE_FORMAT ? record_digest :
            RecordCommitment(record_digest, AccumulatorStateDigest(*state))};
        if (commitment != event.data_digest || !std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(),
                        footer.begin() + static_cast<std::ptrdiff_t>(Hash256::SIZE))) {
            return Result<std::optional<AccumulatorState>>::Err(
                "proof data footer does not match its WAL record");
        }
        if (base) {
            std::vector<std::byte> bytes(static_cast<std::size_t>(event.data_size));
            auto record_read{PreadExact(data_fd, bytes, event.data_offset)};
            if (!record_read) {
                return Result<std::optional<AccumulatorState>>::Err(record_read.Error());
            }
            auto parsed{ParseBaseStateRecord(event.point, event.data_digest, bytes)};
            if (!parsed) {
                return Result<std::optional<AccumulatorState>>::Err(parsed.Error());
            }
            state = parsed.Take();
        }
        return Result<std::optional<AccumulatorState>>::Ok(std::move(state));
    }

    Result<void> MapIndex(const std::vector<DiskIndexEntry>& recovered)
    {
        const uint64_t needed{std::max<uint64_t>(INDEX_GROWTH_ENTRIES, recovered.size())};
        index_capacity = ((needed + INDEX_GROWTH_ENTRIES - 1) / INDEX_GROWTH_ENTRIES) *
                         INDEX_GROWTH_ENTRIES;
        if (index_capacity > std::numeric_limits<uint64_t>::max() / sizeof(DiskIndexEntry)) {
            return Result<void>::Err("proof mmap index is too large");
        }
        index_bytes = index_capacity * sizeof(DiskIndexEntry);
        if (::ftruncate(index_fd, static_cast<off_t>(index_bytes)) != 0) {
            return Result<void>::Err(ErrnoMessage("size proof mmap index"));
        }
        void* mapping{::mmap(nullptr, static_cast<std::size_t>(index_bytes),
                             PROT_READ | PROT_WRITE, MAP_SHARED, index_fd, 0)};
        if (mapping == MAP_FAILED) return Result<void>::Err(ErrnoMessage("mmap proof height index"));
        index_map = static_cast<DiskIndexEntry*>(mapping);
        std::fill_n(index_map, static_cast<std::size_t>(index_capacity), DiskIndexEntry{});
        std::copy(recovered.begin(), recovered.end(), index_map);
        return Result<void>::Ok();
    }

    Result<void> EnsureIndexCapacityLocked(uint64_t entries)
    {
        if (entries <= index_capacity) return Result<void>::Ok();
        const uint64_t capacity{((entries + INDEX_GROWTH_ENTRIES - 1) / INDEX_GROWTH_ENTRIES) *
                                INDEX_GROWTH_ENTRIES};
        if (capacity > std::numeric_limits<uint64_t>::max() / sizeof(DiskIndexEntry)) {
            return Result<void>::Err("proof mmap index capacity overflow");
        }
        const uint64_t bytes{capacity * sizeof(DiskIndexEntry)};
        if (::ftruncate(index_fd, static_cast<off_t>(bytes)) != 0) {
            return Result<void>::Err(ErrnoMessage("grow proof height index"));
        }
        void* mapping{::mmap(nullptr, static_cast<std::size_t>(bytes),
                             PROT_READ | PROT_WRITE, MAP_SHARED, index_fd, 0)};
        if (mapping == MAP_FAILED) return Result<void>::Err(ErrnoMessage("remap proof height index"));
        auto* grown_map{static_cast<DiskIndexEntry*>(mapping)};
        std::fill_n(grown_map + index_capacity,
                    static_cast<std::size_t>(capacity - index_capacity),
                    DiskIndexEntry{});
        if (::munmap(index_map, static_cast<std::size_t>(index_bytes)) != 0) {
            const int saved_errno{errno};
            static_cast<void>(::munmap(grown_map, static_cast<std::size_t>(bytes)));
            errno = saved_errno;
            return Result<void>::Err(ErrnoMessage("unmap old proof height index"));
        }
        index_map = grown_map;
        index_capacity = capacity;
        index_bytes = bytes;
        return Result<void>::Ok();
    }

    Result<AccumulatorState> ReadStateRecord(const ChainPoint& expected_point,
                                             const Hash256& expected_previous,
                                             const DiskIndexEntry& entry,
                                             bool base) const
    {
        if (!ValidProofRecordSize(entry.data_size, config.max_record_bytes)) {
            return Result<AccumulatorState>::Err(
                "proof state index contains an invalid record size");
        }
        std::array<std::byte, DATA_HEADER_SIZE> header{};
        auto read{PreadExact(data_fd, header, entry.data_offset)};
        if (!read) return Result<AccumulatorState>::Err(read.Error());
        ByteReader header_reader{header};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 block_hash;
        Hash256 previous;
        uint64_t payload_size{0};
        if (!header_reader.ReadBytes(magic) || magic != DATA_MAGIC ||
            !header_reader.ReadLE(version) || version != STORE_FORMAT ||
            !header_reader.ReadLE(height) || !header_reader.ReadHash(block_hash) ||
            !header_reader.ReadHash(previous) || !header_reader.ReadLE(payload_size) ||
            !header_reader.Done() || height != expected_point.height ||
            block_hash != expected_point.block_hash || previous != expected_previous ||
            payload_size > config.max_record_bytes || (base && payload_size != 0)) {
            return Result<AccumulatorState>::Err(
                "proof state header is inconsistent with its index");
        }

        std::array<std::byte, STATE_PREFIX_SIZE> prefix{};
        read = PreadExact(data_fd, prefix, entry.data_offset + DATA_HEADER_SIZE);
        if (!read) return Result<AccumulatorState>::Err(read.Error());
        ByteReader prefix_reader{prefix};
        uint64_t num_leaves{0};
        uint32_t root_count{0};
        uint32_t reserved{0};
        if (!prefix_reader.ReadLE(num_leaves) || !prefix_reader.ReadLE(root_count) ||
            !prefix_reader.ReadLE(reserved) || !prefix_reader.Done() || reserved != 0 ||
            root_count > 64 ||
            root_count != static_cast<uint32_t>(std::popcount(num_leaves))) {
            return Result<AccumulatorState>::Err("stored accumulator state prefix is invalid");
        }
        const uint64_t state_size{STATE_PREFIX_SIZE +
            static_cast<uint64_t>(root_count) * Hash256::SIZE + STATE_DIGEST_SIZE};
        const uint64_t fixed_size{DATA_HEADER_SIZE + state_size + DATA_FOOTER_SIZE};
        if (entry.data_size < fixed_size || payload_size != entry.data_size - fixed_size) {
            return Result<AccumulatorState>::Err(
                "proof state size is inconsistent with its record");
        }
        std::vector<std::byte> state_bytes(static_cast<std::size_t>(state_size));
        read = PreadExact(data_fd, state_bytes, entry.data_offset + DATA_HEADER_SIZE);
        if (!read) return Result<AccumulatorState>::Err(read.Error());
        auto state{ParseAuthenticatedState(state_bytes, expected_point)};
        if (!state) return state;

        std::array<std::byte, DATA_FOOTER_SIZE> footer{};
        read = PreadExact(data_fd, footer,
                          entry.data_offset + entry.data_size - DATA_FOOTER_SIZE);
        if (!read) return Result<AccumulatorState>::Err(read.Error());
        Hash256::Storage record_digest_bytes{};
        std::copy_n(footer.begin(), Hash256::SIZE, record_digest_bytes.begin());
        const Hash256 commitment{RecordCommitment(
            Hash256{record_digest_bytes}, AccumulatorStateDigest(state.Value()))};
        if (commitment != EntryDigest(entry) ||
            !std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(),
                        footer.begin() + static_cast<std::ptrdiff_t>(Hash256::SIZE))) {
            return Result<AccumulatorState>::Err(
                "proof state commitment does not match its WAL record");
        }
        return state;
    }

    Result<ParsedProofRecord> ParseDataRecord(uint32_t expected_height,
                                              const Hash256& expected_hash,
                                              const Hash256& expected_previous,
                                              const Hash256& expected_digest,
                                              std::span<const std::byte> bytes) const
    {
        if (bytes.size() < DATA_HEADER_SIZE + DATA_FOOTER_SIZE) {
            return Result<ParsedProofRecord>::Err("stored proof record is truncated");
        }
        if (!std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(), bytes.end() -
                        static_cast<std::ptrdiff_t>(DATA_COMMIT.size()))) {
            return Result<ParsedProofRecord>::Err("stored proof commit marker is missing");
        }
        Hash256::Storage digest_bytes{};
        std::copy_n(bytes.end() - static_cast<std::ptrdiff_t>(DATA_FOOTER_SIZE),
                    Hash256::SIZE, digest_bytes.begin());
        const Hash256 stored_digest{digest_bytes};
        if (Sha256(bytes.first(bytes.size() - DATA_FOOTER_SIZE)) != stored_digest) {
            return Result<ParsedProofRecord>::Err("stored proof checksum mismatch");
        }
        ByteReader reader{bytes.first(DATA_HEADER_SIZE)};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 hash;
        Hash256 previous;
        uint64_t payload_size{0};
        if (!reader.ReadBytes(magic) || magic != DATA_MAGIC || !reader.ReadLE(version) ||
            version < LEGACY_STORE_FORMAT || version > STORE_FORMAT ||
            !reader.ReadLE(height) || !reader.ReadHash(hash) ||
            !reader.ReadHash(previous) || !reader.ReadLE(payload_size) || !reader.Done() ||
            height != expected_height || hash != expected_hash || previous != expected_previous) {
            return Result<ParsedProofRecord>::Err("stored proof header is inconsistent");
        }
        std::size_t payload_offset{DATA_HEADER_SIZE};
        std::optional<AccumulatorState> state;
        const std::size_t body_size{bytes.size() - DATA_HEADER_SIZE - DATA_FOOTER_SIZE};
        if (version == LEGACY_STORE_FORMAT) {
            if (payload_size != body_size) {
                return Result<ParsedProofRecord>::Err("legacy proof record size is inconsistent");
            }
        } else {
            if (body_size < STATE_PREFIX_SIZE + STATE_DIGEST_SIZE ||
                payload_size > body_size - STATE_PREFIX_SIZE - STATE_DIGEST_SIZE) {
                return Result<ParsedProofRecord>::Err("state-bearing proof record is truncated");
            }
            const std::size_t state_size{body_size - static_cast<std::size_t>(payload_size)};
            if (state_size < STATE_PREFIX_SIZE + STATE_DIGEST_SIZE ||
                state_size > MAX_STATE_SIZE) {
                return Result<ParsedProofRecord>::Err("stored accumulator state size is invalid");
            }
            auto parsed_state{ParseAuthenticatedState(
                bytes.subspan(DATA_HEADER_SIZE, state_size),
                ChainPoint{expected_height, expected_hash})};
            if (!parsed_state) return Result<ParsedProofRecord>::Err(parsed_state.Error());
            state = parsed_state.Take();
            payload_offset += state_size;
        }
        const Hash256 commitment{version == LEGACY_STORE_FORMAT ? stored_digest :
            RecordCommitment(stored_digest, AccumulatorStateDigest(*state))};
        if (commitment != expected_digest) {
            return Result<ParsedProofRecord>::Err(
                "stored proof commitment does not match its WAL record");
        }
        auto proof{ParseFullUtreexoProof(height,
            bytes.subspan(payload_offset, static_cast<std::size_t>(payload_size)))};
        if (!proof) return Result<ParsedProofRecord>::Err(proof.Error());
        if (proof.Value().point.block_hash != expected_hash) {
            return Result<ParsedProofRecord>::Err(
                "stored proof payload hash does not match its record");
        }
        return Result<ParsedProofRecord>::Ok(ParsedProofRecord{
            .proof = proof.Take(),
            .state = std::move(state),
        });
    }

    Result<AccumulatorState> ParseBaseStateRecord(const ChainPoint& expected_point,
                                                   const Hash256& expected_digest,
                                                   std::span<const std::byte> bytes) const
    {
        if (bytes.size() < DATA_HEADER_SIZE + STATE_PREFIX_SIZE +
                               STATE_DIGEST_SIZE + DATA_FOOTER_SIZE) {
            return Result<AccumulatorState>::Err("stored base-state record is truncated");
        }
        if (!std::equal(DATA_COMMIT.begin(), DATA_COMMIT.end(), bytes.end() -
                        static_cast<std::ptrdiff_t>(DATA_COMMIT.size()))) {
            return Result<AccumulatorState>::Err("stored base-state commit marker is missing");
        }
        Hash256::Storage digest_bytes{};
        std::copy_n(bytes.end() - static_cast<std::ptrdiff_t>(DATA_FOOTER_SIZE),
                    Hash256::SIZE, digest_bytes.begin());
        const Hash256 stored_digest{digest_bytes};
        if (Sha256(bytes.first(bytes.size() - DATA_FOOTER_SIZE)) != stored_digest) {
            return Result<AccumulatorState>::Err("stored base-state checksum mismatch");
        }
        ByteReader reader{bytes.first(DATA_HEADER_SIZE)};
        std::array<std::byte, DATA_MAGIC.size()> magic{};
        uint32_t version{0};
        uint32_t height{0};
        Hash256 hash;
        Hash256 previous;
        uint64_t payload_size{0};
        if (!reader.ReadBytes(magic) || magic != DATA_MAGIC || !reader.ReadLE(version) ||
            version != STORE_FORMAT || !reader.ReadLE(height) || !reader.ReadHash(hash) ||
            !reader.ReadHash(previous) || !reader.ReadLE(payload_size) || !reader.Done() ||
            height != expected_point.height || hash != expected_point.block_hash ||
            !previous.IsNull() || payload_size != 0) {
            return Result<AccumulatorState>::Err("stored base-state header is inconsistent");
        }
        auto state{ParseAuthenticatedState(
            bytes.subspan(DATA_HEADER_SIZE,
                          bytes.size() - DATA_HEADER_SIZE - DATA_FOOTER_SIZE),
            expected_point)};
        if (!state) return state;
        if (RecordCommitment(stored_digest, AccumulatorStateDigest(state.Value())) !=
            expected_digest) {
            return Result<AccumulatorState>::Err(
                "stored base-state commitment does not match its WAL record");
        }
        return state;
    }

    std::optional<Hash256> HashAtLocked(uint32_t height) const
    {
        if (height == base_point.height) return base_point.block_hash;
        if (height < base_point.height || height > durable_point.height) return std::nullopt;
        const uint64_t relative{height - base_point.height - 1};
        if (relative >= index_capacity || !EntryPresent(index_map[relative])) return std::nullopt;
        return EntryHash(index_map[relative]);
    }

    void SetFailure(std::string error)
    {
        {
            std::lock_guard lock{mutex};
            if (!FailedLocked()) failure = std::move(error);
        }
        input_ready.notify_all();
        output_ready.notify_all();
        space_available.notify_all();
        durable_changed.notify_all();
    }

    void SetEmergencyFailure(const char* error)
    {
        {
            std::lock_guard lock{mutex};
            if (!FailedLocked()) emergency_failure = error;
        }
        input_ready.notify_all();
        output_ready.notify_all();
        space_available.notify_all();
        durable_changed.notify_all();
    }

    bool FailedLocked() const { return failure.has_value() || emergency_failure != nullptr; }

    std::string FailureMessageLocked() const
    {
        return failure ? *failure : std::string{emergency_failure};
    }

    void SerializerLoop()
    {
        while (true) {
            WorkItem item;
            {
                std::unique_lock lock{mutex};
                input_ready.wait(lock, [&] { return FailedLocked() || stopping || !input.empty(); });
                if (FailedLocked() || (stopping && input.empty())) return;
                item = std::move(input.front());
                input.pop_front();
            }
            try {
                const uint32_t height{item.delta.point.height};
                const auto serialization_start{std::chrono::steady_clock::now()};
                auto prepared{PrepareProof(std::move(item.delta), std::move(item.proof),
                                           item.state,
                                           item.accounted_bytes, config.max_record_bytes)};
                if (!prepared) {
                    SetFailure("proof serialization failed at height " +
                               std::to_string(height) + ": " + prepared.Error());
                    return;
                }
                {
                    std::lock_guard lock{mutex};
                    if (FailedLocked()) return;
                    ++serialized_proofs;
                    serialized_bytes += prepared.Value().record.size();
                    largest_record_bytes = std::max<uint64_t>(largest_record_bytes,
                                                               prepared.Value().record.size());
                    serialization_us += static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - serialization_start).count());
                    ready.emplace(prepared.Value().point.height, prepared.Take());
                    peak_ready_blocks = std::max(peak_ready_blocks,
                        static_cast<uint64_t>(ready.size()));
                }
                output_ready.notify_one();
            } catch (const std::bad_alloc&) {
                SetEmergencyFailure("proof serializer allocation failed");
                return;
            } catch (const std::exception& exception) {
                try {
                    SetFailure("proof serializer exception: " + std::string{exception.what()});
                } catch (...) {
                    SetEmergencyFailure("proof serializer exception (detail unavailable)");
                }
                return;
            }
        }
    }

    std::size_t ContiguousReadyLocked() const
    {
        std::size_t count{0};
        uint32_t height{durable_point.height + 1};
        while (count < config.group_commit_blocks && ready.contains(height)) {
            ++count;
            ++height;
        }
        return count;
    }

    std::size_t CommitThresholdLocked() const
    {
        uint64_t target{static_cast<uint64_t>(durable_point.height) +
                        config.group_commit_blocks};
        if (flush_height && *flush_height > durable_point.height) {
            target = std::min<uint64_t>(target, *flush_height);
        } else if (stopping && enqueued_point.height > durable_point.height) {
            target = std::min<uint64_t>(target, enqueued_point.height);
        }
        return static_cast<std::size_t>(std::max<uint64_t>(
            1, target - durable_point.height));
    }

    void WriterLoop()
    {
        while (true) {
            try {
                std::vector<PreparedProof> batch;
                {
                    std::unique_lock lock{mutex};
                    output_ready.wait(lock, [&] {
                        return FailedLocked() ||
                               ready.contains(durable_point.height + 1) || stopping;
                    });
                    if (FailedLocked()) return;
                    if (stopping && durable_point.height == enqueued_point.height) return;
                    if (!ready.contains(durable_point.height + 1)) continue;
                    const auto deadline{std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(config.group_commit_delay_ms)};
                    while (ContiguousReadyLocked() < CommitThresholdLocked()) {
                        if (config.group_commit_delay_ms == 0) {
                            output_ready.wait(lock);
                        } else {
                            if (output_ready.wait_until(lock, deadline) == std::cv_status::timeout) break;
                        }
                        if (FailedLocked()) return;
                    }
                    const std::size_t count{ContiguousReadyLocked()};
                    for (std::size_t i{0}; i < count; ++i) {
                        const uint32_t height{durable_point.height + 1 + static_cast<uint32_t>(i)};
                        auto found{ready.find(height)};
                        batch.push_back(std::move(found->second));
                        ready.erase(found);
                    }
                }
                auto committed{CommitBatch(batch)};
                if (!committed) {
                    SetFailure("proof-store commit failed: " + committed.Error());
                    return;
                }
            } catch (const std::bad_alloc&) {
                SetEmergencyFailure("proof writer allocation failed");
                return;
            } catch (const std::exception& exception) {
                try {
                    SetFailure("proof writer exception: " + std::string{exception.what()});
                } catch (...) {
                    SetEmergencyFailure("proof writer exception (detail unavailable)");
                }
                return;
            }
        }
    }

    Result<void> CommitBatch(const std::vector<PreparedProof>& batch)
    {
        if (batch.empty()) return Result<void>::Ok();
        const auto commit_start{std::chrono::steady_clock::now()};
        std::vector<WalEvent> events;
        events.reserve(batch.size());
        uint64_t next_data_offset{0};
        uint64_t next_wal_offset{0};
        {
            std::lock_guard lock{mutex};
            next_data_offset = data_end;
            next_wal_offset = wal_end;
        }
        const auto data_write_start{std::chrono::steady_clock::now()};
        for (const auto& proof : batch) {
            auto written{PwriteAll(data_fd, proof.record, next_data_offset)};
            if (!written) return written;
            events.push_back(WalEvent{
                .kind = WalKind::CONNECT,
                .point = proof.point,
                .previous_hash = proof.previous_hash,
                .data_offset = next_data_offset,
                .data_size = proof.record.size(),
                .data_digest = proof.digest,
            });
            next_data_offset += proof.record.size();
        }
        const uint64_t batch_data_write_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - data_write_start).count())};
        const auto data_sync_start{std::chrono::steady_clock::now()};
        auto data_synced{SyncFile(data_fd, "proof data")};
        if (!data_synced) return data_synced;
        const uint64_t batch_data_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - data_sync_start).count())};

        const auto wal_write_start{std::chrono::steady_clock::now()};
        std::vector<std::byte> wal_bytes;
        wal_bytes.reserve(events.size() * WAL_RECORD_SIZE);
        for (const auto& event : events) {
            auto serialized{SerializeWal(event)};
            wal_bytes.insert(wal_bytes.end(), serialized.begin(), serialized.end());
        }
        auto wal_written{PwriteAll(wal_fd, wal_bytes, next_wal_offset)};
        if (!wal_written) return wal_written;
        const uint64_t batch_wal_write_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - wal_write_start).count())};
        const auto wal_sync_start{std::chrono::steady_clock::now()};
        auto wal_synced{SyncFile(wal_fd, "proof index WAL")};
        if (!wal_synced) return wal_synced;
        const uint64_t batch_wal_sync_us{static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - wal_sync_start).count())};
        const auto index_publish_start{std::chrono::steady_clock::now()};
        {
            std::lock_guard lock{mutex};
            const uint64_t required{events.back().point.height - base_point.height};
            auto capacity{EnsureIndexCapacityLocked(required)};
            if (!capacity) return capacity;
            data_end = next_data_offset;
            wal_end = next_wal_offset + wal_bytes.size();
            ++data_syncs;
            ++wal_syncs;
            for (std::size_t i{0}; i < events.size(); ++i) {
                const auto& event{events[i]};
                const uint64_t relative{event.point.height - base_point.height - 1};
                index_map[relative] = EntryFromEvent(event);
                hash_to_height[event.point.block_hash] = static_cast<uint32_t>(relative);
                if (relative >= state_present.size()) {
                    state_present.resize(static_cast<std::size_t>(relative + 1));
                }
                state_present[relative] = true;
                durable_point = event.point;
                --queued_blocks;
                queued_bytes -= batch[i].accounted_bytes;
            }
            committed_proofs += static_cast<uint64_t>(events.size());
            ++committed_batches;
            if (events.size() >= config.group_commit_blocks) {
                ++full_batches;
            } else {
                ++partial_batches;
            }
            largest_batch_proofs = std::max(largest_batch_proofs,
                static_cast<uint64_t>(events.size()));
            commit_us += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - commit_start).count());
            if (flush_height && durable_point.height >= *flush_height) flush_height.reset();
            data_write_us += batch_data_write_us;
            data_sync_us += batch_data_sync_us;
            wal_write_us += batch_wal_write_us;
            wal_sync_us += batch_wal_sync_us;
            index_publish_us += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - index_publish_start).count());
        }
        durable_changed.notify_all();
        space_available.notify_all();
        return Result<void>::Ok();
    }

    ProofStoreConfig config;
    int data_fd{-1};
    int wal_fd{-1};
    int index_fd{-1};
    DiskIndexEntry* index_map{nullptr};
    uint64_t index_capacity{0};
    uint64_t index_bytes{0};
    uint64_t data_end{0};
    uint64_t wal_end{0};
    uint64_t base_data_size{0};
    Hash256 base_data_digest;

    mutable std::mutex mutex;
    std::mutex operation_mutex;
    std::condition_variable input_ready;
    std::condition_variable output_ready;
    std::condition_variable space_available;
    std::condition_variable durable_changed;
    std::deque<WorkItem> input;
    std::map<uint32_t, PreparedProof> ready;
    std::vector<std::thread> serializers;
    std::thread writer;
    bool stopping{false};
    std::optional<std::string> failure;
    const char* emergency_failure{nullptr};
    std::optional<uint32_t> flush_height;
    ChainPoint base_point;
    ChainPoint durable_point;
    ChainPoint enqueued_point;
    std::optional<AccumulatorState> base_state;
    std::vector<bool> state_present;
    std::unordered_map<Hash256, uint32_t, Hash256Hasher> hash_to_height;
    uint64_t queued_blocks{0};
    uint64_t queued_bytes{0};
    uint64_t peak_queued_blocks{0};
    uint64_t peak_queued_bytes{0};
    uint64_t peak_input_blocks{0};
    uint64_t peak_ready_blocks{0};
    uint64_t enqueue_blocked{0};
    uint64_t backpressure_flushes{0};
    uint64_t durability_waits{0};
    uint64_t serialized_proofs{0};
    uint64_t serialized_bytes{0};
    uint64_t largest_record_bytes{0};
    uint64_t enqueue_wait_us{0};
    uint64_t serialization_us{0};
    uint64_t committed_proofs{0};
    uint64_t committed_batches{0};
    uint64_t full_batches{0};
    uint64_t partial_batches{0};
    uint64_t largest_batch_proofs{0};
    uint64_t commit_us{0};
    uint64_t data_write_us{0};
    uint64_t data_syncs{0};
    uint64_t data_sync_us{0};
    uint64_t wal_write_us{0};
    uint64_t wal_syncs{0};
    uint64_t wal_sync_us{0};
    uint64_t index_publish_us{0};
    mutable uint64_t hits{0};
    mutable uint64_t misses{0};
};

ProofStore::ProofStore(std::unique_ptr<Impl> impl) : m_impl{std::move(impl)} {}
ProofStore::~ProofStore() = default;

Result<std::shared_ptr<ProofStore>> ProofStore::Open(ProofStoreConfig config)
{
    try {
        auto impl{std::make_unique<Impl>(std::move(config))};
        auto initialized{impl->Initialize()};
        if (!initialized) return Result<std::shared_ptr<ProofStore>>::Err(initialized.Error());
        return Result<std::shared_ptr<ProofStore>>::Ok(
            std::shared_ptr<ProofStore>{new ProofStore{std::move(impl)}});
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<ProofStore>>::Err(
            "proof-store allocation failed while opening");
    } catch (const std::exception& exception) {
        return Result<std::shared_ptr<ProofStore>>::Err(
            "proof-store open failed: " + std::string{exception.what()});
    }
}

Result<void> ProofStore::Enqueue(const BlockDelta& delta, Proof proof,
                                 AccumulatorState state)
{
    return m_impl->Enqueue(delta, std::move(proof), std::move(state));
}

Result<void> ProofStore::WaitDurable(uint32_t height) { return m_impl->WaitDurable(height); }
Result<bool> ProofStore::EnforceRecoveryWindow(uint32_t state_height, uint32_t max_lag)
{
    return m_impl->EnforceRecoveryWindow(state_height, max_lag);
}
Result<void> ProofStore::Drain() { return m_impl->Drain(); }
Result<void> ProofStore::Truncate(const ChainPoint& point) { return m_impl->Truncate(point); }

Result<std::shared_ptr<const CachedBlockProof>> ProofStore::Read(const Hash256& block_hash) const
{
    return m_impl->Read(block_hash);
}

Result<std::optional<AccumulatorState>> ProofStore::StateAt(uint32_t height) const
{
    return m_impl->StateAt(height);
}

Result<std::optional<Hash256>> ProofStore::HashAt(uint32_t height) const
{
    return m_impl->HashAt(height);
}

ChainPoint ProofStore::BasePoint() const { return m_impl->BasePoint(); }
ChainPoint ProofStore::DurablePoint() const { return m_impl->DurablePoint(); }
ChainPoint ProofStore::EnqueuedPoint() const { return m_impl->EnqueuedPoint(); }
ProofStoreCoverage ProofStore::Coverage() const { return m_impl->Coverage(); }
ProofStoreStats ProofStore::Stats() const { return m_impl->Stats(); }
Result<ProofStoreScrubStats> ProofStore::Scrub(const std::function<bool()>& cancelled)
{
    return m_impl->Scrub(cancelled);
}

Result<ChainPoint> FindHighestActiveArchivePoint(
    const ProofStore& store, const ChainPoint& lower_bound,
    uint32_t active_tip_height,
    const std::function<Result<Hash256>(uint32_t)>& active_hash)
{
    try {
        if (!active_hash) {
            return Result<ChainPoint>::Err("active-chain hash resolver is unavailable");
        }
        const ChainPoint base{store.BasePoint()};
        const ChainPoint archive_tip{store.DurablePoint()};
        if (lower_bound.height < base.height || lower_bound.height > archive_tip.height) {
            return Result<ChainPoint>::Err(
                "archive active-chain lower bound is outside the durable archive");
        }
        auto archived_lower{store.HashAt(lower_bound.height)};
        if (!archived_lower) return Result<ChainPoint>::Err(archived_lower.Error());
        if (!archived_lower.Value() || *archived_lower.Value() != lower_bound.block_hash) {
            return Result<ChainPoint>::Err(
                "archive active-chain lower bound does not match the archive");
        }
        if (archive_tip.height > active_tip_height) {
            return Result<ChainPoint>::Err(
                "active chain is shorter than the durable proof archive");
        }

        uint32_t candidate{archive_tip.height};
        while (true) {
            auto archived{store.HashAt(candidate)};
            if (!archived) return Result<ChainPoint>::Err(archived.Error());
            if (!archived.Value()) {
                return Result<ChainPoint>::Err(
                    "proof archive has a height gap during active-chain alignment");
            }
            auto active{active_hash(candidate)};
            if (!active) {
                return Result<ChainPoint>::Err(
                    "active-chain hash lookup failed at height " +
                    std::to_string(candidate) + ": " + active.Error());
            }
            if (active.Value() == *archived.Value()) {
                const ChainPoint common{candidate, *archived.Value()};
                // Re-read the selected point immediately before the caller may
                // durably truncate. A concurrent Core reorg must fail closed.
                auto confirmed{active_hash(candidate)};
                if (!confirmed) {
                    return Result<ChainPoint>::Err(
                        "active-chain confirmation failed at height " +
                        std::to_string(candidate) + ": " + confirmed.Error());
                }
                if (confirmed.Value() != common.block_hash) {
                    return Result<ChainPoint>::Err(
                        "active chain changed during proof-archive alignment");
                }
                return Result<ChainPoint>::Ok(common);
            }
            if (candidate == lower_bound.height) break;
            --candidate;
        }
        return Result<ChainPoint>::Err(
            "proof archive has no active-chain point at or above the online forest");
    } catch (const std::bad_alloc&) {
        return Result<ChainPoint>::Err(
            "allocation failed during proof-archive active-chain alignment");
    } catch (const std::exception& exception) {
        return Result<ChainPoint>::Err(
            "proof-archive active-chain alignment failed: " +
            std::string{exception.what()});
    }
}

} // namespace utreexo
