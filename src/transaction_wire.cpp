// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/transaction_wire.h>

#include <algorithm>
#include <bit>
#include <limits>
#include <type_traits>
#include <utility>

namespace utreexo::txwire {
namespace {

constexpr uint64_t PADDING{std::numeric_limits<uint64_t>::max()};
constexpr uint64_t MAX_INPUTS{MAX_TX_PAYLOAD / 41};
constexpr uint64_t MAX_HASHES{MAX_TX_PAYLOAD / Hash256::SIZE};
constexpr uint64_t MAX_SCRIPT_BYTES{10'000};

template <typename T>
void AppendLE(std::vector<std::byte>& output, T value)
{
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i{0}; i < sizeof(T); ++i) {
        output.push_back(static_cast<std::byte>(value & 0xffU));
        value >>= 8;
    }
}

void AppendBytes(std::vector<std::byte>& output, std::span<const std::byte> bytes)
{
    output.insert(output.end(), bytes.begin(), bytes.end());
}

uint64_t CompactSizeBytes(uint64_t value)
{
    if (value < 253) return 1;
    if (value <= UINT16_MAX) return 3;
    if (value <= UINT32_MAX) return 5;
    return 9;
}

void AppendCompactSize(std::vector<std::byte>& output, uint64_t value)
{
    if (value < 253) {
        output.push_back(static_cast<std::byte>(value));
    } else if (value <= UINT16_MAX) {
        output.push_back(std::byte{253});
        AppendLE(output, static_cast<uint16_t>(value));
    } else if (value <= UINT32_MAX) {
        output.push_back(std::byte{254});
        AppendLE(output, static_cast<uint32_t>(value));
    } else {
        output.push_back(std::byte{255});
        AppendLE(output, value);
    }
}

// All reads check the remaining span before advancing or converting to size_t.
// No allocation is driven directly by an unchecked CompactSize.
class Reader
{
public:
    explicit Reader(std::span<const std::byte> bytes) : m_bytes{bytes} {}

    template <typename T>
    bool LE(T& value)
    {
        static_assert(std::is_unsigned_v<T>);
        if (Remaining() < sizeof(T)) return false;
        uint64_t result{0};
        for (std::size_t i{0}; i < sizeof(T); ++i) {
            result |= uint64_t{std::to_integer<uint8_t>(m_bytes[m_offset++])} << (8 * i);
        }
        value = static_cast<T>(result);
        return true;
    }

    bool CompactSize(uint64_t& value)
    {
        uint8_t prefix{0};
        if (!LE(prefix)) return false;
        value = prefix;
        if (prefix < 253) return true;
        if (prefix == 253) {
            uint16_t number{0};
            if (!LE(number) || number < 253) return false;
            value = number;
            return true;
        }
        if (prefix == 254) {
            uint32_t number{0};
            if (!LE(number) || number <= UINT16_MAX) return false;
            value = number;
            return true;
        }
        return LE(value) && value > UINT32_MAX;
    }

    bool Skip(uint64_t size)
    {
        if (size > Remaining()) return false;
        m_offset += static_cast<std::size_t>(size);
        return true;
    }

    bool Hash(Hash256& hash)
    {
        if (Remaining() < Hash256::SIZE) return false;
        Hash256::Storage bytes;
        std::copy_n(m_bytes.begin() + static_cast<std::ptrdiff_t>(m_offset), bytes.size(), bytes.begin());
        hash = Hash256{bytes};
        return Skip(bytes.size());
    }

    std::size_t Offset() const { return m_offset; }
    std::size_t Remaining() const { return m_bytes.size() - m_offset; }

private:
    std::span<const std::byte> m_bytes;
    std::size_t m_offset{0};
};

bool IsRequestType(uint32_t type)
{
    return type == MSG_UTREEXO_TX || type == MSG_WITNESS_UTREEXO_TX;
}

bool UniquePositions(std::span<const uint64_t> positions)
{
    if (std::find(positions.begin(), positions.end(), PADDING) != positions.end()) return false;
    std::vector<uint64_t> sorted{positions.begin(), positions.end()};
    std::sort(sorted.begin(), sorted.end());
    return std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end();
}

template <typename T>
auto& Positions(T& group)
{
    if constexpr (requires { group.proof_positions; }) return group.proof_positions;
    else return group.confirmed_targets;
}

template <typename T>
constexpr uint64_t PositionLimit()
{
    if constexpr (std::is_same_v<T, TransactionProofRequest>) return MAX_HASHES;
    else return MAX_INPUTS;
}

template <typename T>
Result<std::vector<T>> ParseGroups(std::span<const std::byte> payload, uint64_t max_payload_bytes)
{
    using R = Result<std::vector<T>>;
    if (payload.size() > std::min<uint64_t>(max_payload_bytes, MAX_INVENTORY_PAYLOAD)) {
        return R::Err("transaction inventory payload exceeds maximum");
    }
    Reader reader{payload};
    uint64_t count{0};
    if (!reader.CompactSize(count) || count > MAX_INVENTORY || reader.Remaining() != count * 36) {
        return R::Err("invalid transaction inventory count, length, or CompactSize");
    }
    std::vector<T> groups;
    bool attachable{false};
    bool padded{false};
    for (uint64_t i{0}; i < count; ++i) {
        uint32_t type{0};
        Hash256 hash;
        if (!reader.LE(type) || !reader.Hash(hash)) return R::Err("truncated inventory vector");
        if (type == MSG_UTREEXO_PROOF_HASH) {
            if (!attachable || padded) return R::Err("misplaced or over-padded proof inventory vector");
            Reader packed{hash.Span()};
            for (unsigned int slot{0}; slot < 4; ++slot) {
                uint64_t pos{0};
                if (!packed.LE(pos)) return R::Err("truncated packed position");
                if (pos == PADDING) {
                    if (slot == 0) return R::Err("redundant empty proof inventory vector");
                    padded = true;
                } else {
                    if (padded) return R::Err("non-padding position after padding");
                    auto& positions{Positions(groups.back())};
                    if (positions.size() >= PositionLimit<T>()) return R::Err("too many packed positions");
                    positions.push_back(pos);
                }
            }
            continue;
        }
        if constexpr (std::is_same_v<T, TransactionProofRequest>) attachable = IsRequestType(type);
        else attachable = type == MSG_TX;
        padded = false;
        if (attachable) {
            T group;
            group.txid = hash;
            if constexpr (std::is_same_v<T, TransactionProofRequest>) group.inventory_type = type;
            groups.push_back(std::move(group));
        }
    }
    for (const auto& group : groups) {
        if (!UniquePositions(Positions(group))) return R::Err("duplicate packed positions");
    }
    return R::Ok(std::move(groups));
}

template <typename T>
Result<std::vector<std::byte>> SerializeGroups(std::span<const T> groups, uint64_t max_payload_bytes)
{
    using R = Result<std::vector<std::byte>>;
    if (groups.size() > MAX_INVENTORY) return R::Err("too many transaction inventory groups");
    uint64_t count{0};
    for (const auto& group : groups) {
        if constexpr (std::is_same_v<T, TransactionProofRequest>) {
            if (!IsRequestType(group.inventory_type)) return R::Err("invalid Utreexo transaction request type");
        }
        const auto& positions{Positions(group)};
        if (positions.size() > PositionLimit<T>()) return R::Err("too many packed positions");
        count += 1 + (positions.size() + 3) / 4;
        if (count > MAX_INVENTORY) return R::Err("too many transaction inventory vectors");
    }
    const uint64_t bytes{CompactSizeBytes(count) + count * 36};
    if (bytes > std::min<uint64_t>(max_payload_bytes, MAX_INVENTORY_PAYLOAD)) {
        return R::Err("transaction inventory payload exceeds maximum");
    }
    for (const auto& group : groups) {
        if (!UniquePositions(Positions(group))) return R::Err("duplicate or reserved packed position");
    }
    std::vector<std::byte> output;
    output.reserve(static_cast<std::size_t>(bytes));
    AppendCompactSize(output, count);
    for (const auto& group : groups) {
        uint32_t type{MSG_TX};
        if constexpr (std::is_same_v<T, TransactionProofRequest>) type = group.inventory_type;
        AppendLE(output, type);
        AppendBytes(output, group.txid.Span());
        const auto& positions{Positions(group)};
        for (std::size_t i{0}; i < positions.size(); i += 4) {
            AppendLE(output, MSG_UTREEXO_PROOF_HASH);
            for (std::size_t j{0}; j < 4; ++j) {
                AppendLE(output, i + j < positions.size() ? positions[i + j] : PADDING);
            }
        }
    }
    return R::Ok(std::move(output));
}

struct TransactionLayout {
    std::size_t input_start{4};
    std::size_t outputs_end{0};
    std::size_t size{0};
    bool witness{false};
};

Result<TransactionLayout> ScanTransaction(
    std::span<const std::byte> bytes, std::vector<OutPoint>* inputs = nullptr,
    std::vector<std::size_t>* vout_offsets = nullptr)
{
    using R = Result<TransactionLayout>;
    Reader reader{bytes};
    TransactionLayout layout;
    uint64_t count{0};
    if (!reader.Skip(4) || !reader.CompactSize(count)) return R::Err("truncated transaction version or input count");
    if (count == 0) {
        uint8_t flag{0};
        if (!reader.LE(flag) || flag != 1) return R::Err("invalid transaction witness flag");
        layout.witness = true;
        layout.input_start = reader.Offset();
        if (!reader.CompactSize(count)) return R::Err("invalid witness transaction input count");
    }
    if (count == 0 || count > MAX_INPUTS || count > reader.Remaining() / 41) {
        return R::Err("invalid transaction input count");
    }
    const uint64_t input_count{count};
    if (inputs) inputs->reserve(static_cast<std::size_t>(count));
    if (vout_offsets) vout_offsets->reserve(static_cast<std::size_t>(count));
    for (uint64_t i{0}; i < input_count; ++i) {
        OutPoint outpoint;
        if (!reader.Hash(outpoint.txid)) return R::Err("truncated transaction outpoint hash");
        if (vout_offsets) vout_offsets->push_back(reader.Offset());
        uint64_t script_size{0};
        if (!reader.LE(outpoint.index) || !reader.CompactSize(script_size) ||
            !reader.Skip(script_size) || !reader.Skip(4)) {
            return R::Err("invalid transaction input script or sequence");
        }
        if (inputs) inputs->push_back(outpoint);
    }
    if (!reader.CompactSize(count) || count == 0 || count > reader.Remaining() / 9) {
        return R::Err("invalid transaction output count");
    }
    for (uint64_t i{0}; i < count; ++i) {
        uint64_t script_size{0};
        if (!reader.Skip(8) || !reader.CompactSize(script_size) || !reader.Skip(script_size)) {
            return R::Err("invalid transaction output script");
        }
    }
    layout.outputs_end = reader.Offset();
    if (layout.witness) {
        bool has_witness{false};
        for (uint64_t i{0}; i < input_count; ++i) {
            if (!reader.CompactSize(count) || count > reader.Remaining()) {
                return R::Err("invalid transaction witness item count");
            }
            has_witness |= count != 0;
            for (uint64_t j{0}; j < count; ++j) {
                uint64_t item_size{0};
                if (!reader.CompactSize(item_size) || !reader.Skip(item_size)) {
                    return R::Err("invalid transaction witness item");
                }
            }
        }
        if (!has_witness) return R::Err("superfluous witness serialization");
    }
    if (!reader.Skip(4)) return R::Err("truncated transaction locktime");
    layout.size = reader.Offset();
    return R::Ok(layout);
}

Hash256 DoubleSha256(std::span<const std::byte> bytes)
{
    return Sha256(Sha256(bytes).Span());
}

void WriteVout(std::span<std::byte> bytes, std::size_t offset, uint32_t vout)
{
    for (std::size_t i{0}; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>(vout & 0xffU);
        vout >>= 8;
    }
}

Result<uint64_t> LeafBytes(const CompactLeafData& leaf)
{
    // v0.6 decodes header and amount through signed integers.
    if (leaf.header_code > INT32_MAX || leaf.amount > INT64_MAX ||
        static_cast<uint8_t>(leaf.script_type) > static_cast<uint8_t>(ScriptPubkeyType::WITNESS_V0_SCRIPT_HASH)) {
        return Result<uint64_t>::Err("invalid confirmed compact leaf header, amount, or script type");
    }
    if (leaf.script_type != ScriptPubkeyType::OTHER) {
        if (!leaf.script.empty()) return Result<uint64_t>::Err("standard compact leaf contains a script");
        return Result<uint64_t>::Ok(13);
    }
    if (leaf.script.size() > MAX_SCRIPT_BYTES) return Result<uint64_t>::Err("compact leaf script exceeds maximum");
    return Result<uint64_t>::Ok(13 + CompactSizeBytes(leaf.script.size()) + leaf.script.size());
}

// Safe for rows=63 too: no shifts by 64, unlike naive (2 << rows) arithmetic.
uint64_t RowStart(unsigned int row, unsigned int rows)
{
    const uint64_t mask{rows == 63 ? UINT64_MAX : (uint64_t{1} << (rows + 1)) - 1};
    return mask ^ (mask >> row);
}

unsigned int Row(uint64_t pos, unsigned int rows)
{
    return static_cast<unsigned int>(std::countl_one(pos << (63 - rows)));
}

uint64_t WirePosition(uint64_t pos, unsigned int rows)
{
    const auto row{Row(pos, rows)};
    return RowStart(row, 63) + (pos - RowStart(row, rows));
}

Result<std::vector<uint64_t>> NativeProofPositions(const Proof& proof, uint64_t num_leaves)
{
    using R = Result<std::vector<uint64_t>>;
    if (num_leaves > (uint64_t{1} << 63)) return R::Err("unsupported forest leaf count");
    const auto rows{num_leaves == 0 ? 0U : static_cast<unsigned int>(std::bit_width(num_leaves - 1))};
    std::vector<std::pair<uint64_t, uint64_t>> intervals;
    intervals.reserve(proof.targets.size());
    for (const uint64_t target : proof.targets) {
        if (target >= (rows == 63 ? UINT64_MAX : (uint64_t{1} << (rows + 1)) - 1)) {
            return R::Err("target outside forest position space");
        }
        const auto row{Row(target, rows)};
        const uint64_t offset{target - RowStart(row, rows)};
        if (offset >= (num_leaves >> row)) return R::Err("target outside populated forest");
        const uint64_t start{offset << row};
        intervals.emplace_back(start, start + ((uint64_t{1} << row) - 1));
    }
    std::sort(intervals.begin(), intervals.end());
    for (std::size_t i{1}; i < intervals.size(); ++i) {
        if (intervals[i].first <= intervals[i - 1].second) return R::Err("duplicate or overlapping proof targets");
    }
    std::vector<uint64_t> pending{proof.targets};
    std::sort(pending.begin(), pending.end());
    std::vector<uint64_t> needed;
    // Merge siblings row by row, bounding memory by the input and hash limits.
    for (unsigned int row{0}; row <= rows && !pending.empty(); ++row) {
        std::vector<uint64_t> next;
        next.reserve(pending.size());
        for (std::size_t i{0}; i < pending.size(); ++i) {
            const uint64_t pos{pending[i]};
            if (Row(pos, rows) != row) {
                next.push_back(pos);
                continue;
            }
            const uint64_t offset{pos - RowStart(row, rows)};
            const uint64_t on_row{num_leaves >> row};
            if ((on_row & 1U) != 0 && offset == on_row - 1) continue; // root
            if (i + 1 < pending.size() && (pos ^ 1U) == pending[i + 1]) {
                ++i;
            } else {
                if (needed.size() >= MAX_HASHES) return R::Err("too many transaction proof hashes");
                needed.push_back(pos ^ 1U);
            }
            next.push_back((pos >> 1) | (uint64_t{1} << rows));
        }
        std::sort(next.begin(), next.end());
        pending = std::move(next);
    }
    if (needed.size() != proof.hashes.size()) return R::Err("full proof hash count does not match targets");
    return R::Ok(std::move(needed));
}

} // namespace

Result<std::vector<TransactionAnnouncement>> ParseTransactionAnnouncements(
    std::span<const std::byte> payload, uint64_t max_payload_bytes)
{
    return ParseGroups<TransactionAnnouncement>(payload, max_payload_bytes);
}

Result<std::vector<std::byte>> SerializeTransactionAnnouncements(
    std::span<const TransactionAnnouncement> announcements, uint64_t max_payload_bytes)
{
    return SerializeGroups(announcements, max_payload_bytes);
}

Result<std::vector<TransactionProofRequest>> ParseTransactionProofRequests(
    std::span<const std::byte> payload, uint64_t max_payload_bytes)
{
    return ParseGroups<TransactionProofRequest>(payload, max_payload_bytes);
}

Result<std::vector<std::byte>> SerializeTransactionProofRequests(
    std::span<const TransactionProofRequest> requests, uint64_t max_payload_bytes)
{
    return SerializeGroups(requests, max_payload_bytes);
}

Result<Transaction> Transaction::Parse(std::span<const std::byte> raw, uint64_t max_payload_bytes)
{
    if (raw.size() > std::min<uint64_t>(max_payload_bytes, MAX_TX_PAYLOAD)) {
        return Result<Transaction>::Err("raw transaction payload exceeds maximum");
    }
    auto layout{ScanTransaction(raw)};
    if (!layout) return Result<Transaction>::Err(layout.Error());
    if (layout.Value().size != raw.size()) return Result<Transaction>::Err("trailing raw transaction bytes");
    Transaction tx;
    auto collected{ScanTransaction(raw, &tx.m_inputs, &tx.m_vout_offsets)};
    if (!collected) return Result<Transaction>::Err(collected.Error());
    tx.m_bytes.assign(raw.begin(), raw.end());
    tx.m_has_witness = layout.Value().witness;
    tx.m_wtxid = DoubleSha256(raw);
    tx.m_txid = tx.m_wtxid;
    if (tx.m_has_witness) {
        std::vector<std::byte> stripped;
        stripped.reserve(layout.Value().outputs_end + 2);
        AppendBytes(stripped, raw.first(4));
        AppendBytes(stripped, raw.subspan(layout.Value().input_start,
                                         layout.Value().outputs_end - layout.Value().input_start));
        AppendBytes(stripped, raw.last(4));
        tx.m_txid = DoubleSha256(stripped);
    }
    return Result<Transaction>::Ok(std::move(tx));
}

PreparedTransactionProof::PreparedTransactionProof(
    Transaction transaction, Proof proof, std::vector<std::optional<CompactLeafData>> leaves,
    std::vector<uint64_t> proof_positions, uint64_t base_payload_bytes)
    : m_transaction{std::move(transaction)}, m_proof{std::move(proof)},
      m_input_leaves{std::move(leaves)}, m_proof_positions{std::move(proof_positions)},
      m_base_payload_bytes{base_payload_bytes} {}

uint64_t Transaction::MemoryUsage() const
{
    return sizeof(*this) + m_bytes.capacity() + m_inputs.capacity() * sizeof(OutPoint) +
        m_vout_offsets.capacity() * sizeof(std::size_t);
}

uint64_t PreparedTransactionProof::MemoryUsage() const
{
    uint64_t bytes{sizeof(*this) + m_transaction.MemoryUsage() - sizeof(Transaction) +
        m_proof.targets.capacity() * sizeof(uint64_t) + m_proof.hashes.capacity() * sizeof(Hash256) +
        m_proof_positions.capacity() * sizeof(uint64_t) +
        m_input_leaves.capacity() * sizeof(std::optional<CompactLeafData>)};
    for (const auto& leaf : m_input_leaves) if (leaf) bytes += leaf->script.capacity();
    return bytes;
}

Result<PreparedTransactionProof> PreparedTransactionProof::Create(
    Transaction transaction, Proof proof, std::vector<std::optional<CompactLeafData>> input_leaves,
    uint64_t num_leaves)
{
    using R = Result<PreparedTransactionProof>;
    if (transaction.Inputs().empty() || transaction.Bytes().empty() ||
        input_leaves.size() != transaction.Inputs().size() || proof.targets.size() > MAX_INPUTS ||
        proof.hashes.size() > MAX_HASHES) return R::Err("invalid prepared transaction proof counts");
    uint64_t confirmed{0};
    uint64_t base_bytes{transaction.Bytes().size() + CompactSizeBytes(proof.targets.size())};
    for (std::size_t i{0}; i < input_leaves.size(); ++i) {
        if (transaction.Inputs()[i].index > (UINT32_MAX >> 1)) {
            return R::Err("transaction vout cannot be losslessly flagged");
        }
        if (!input_leaves[i]) continue;
        ++confirmed;
        auto bytes{LeafBytes(*input_leaves[i])};
        if (!bytes) return R::Err(bytes.Error());
        base_bytes += bytes.Value();
        if (base_bytes >= MAX_TX_PAYLOAD) return R::Err("prepared transaction metadata exceeds payload maximum");
    }
    if (confirmed != proof.targets.size()) return R::Err("confirmed input and proof target counts differ");
    auto positions{NativeProofPositions(proof, num_leaves)};
    if (!positions) return R::Err(positions.Error());
    const auto rows{num_leaves == 0 ? 0U : static_cast<unsigned int>(std::bit_width(num_leaves - 1))};
    for (auto& target : proof.targets) {
        target = WirePosition(target, rows);
        base_bytes += CompactSizeBytes(target);
    }
    if (base_bytes >= MAX_TX_PAYLOAD) return R::Err("prepared transaction targets exceed payload maximum");
    for (auto& pos : positions.Value()) pos = WirePosition(pos, rows);
    return R::Ok(PreparedTransactionProof{std::move(transaction), std::move(proof),
        std::move(input_leaves), positions.Take(), base_bytes});
}

TransactionAnnouncement PreparedTransactionProof::Announcement() const
{
    return {m_transaction.Txid(), m_proof.targets};
}

TransactionProofRequest PreparedTransactionProof::FullRequest(uint32_t inventory_type) const
{
    return {m_transaction.Txid(), inventory_type, m_proof_positions};
}

Result<uint64_t> PreparedTransactionProof::Measure(
    const TransactionProofRequest& request, uint64_t max_payload_bytes) const
{
    using R = Result<uint64_t>;
    if (!IsRequestType(request.inventory_type) || request.txid != m_transaction.Txid()) {
        return R::Err("Utreexo transaction request type or txid mismatch");
    }
    const auto& positions{request.proof_positions};
    if (positions.size() > m_proof_positions.size()) return R::Err("too many requested proof positions");
    const uint64_t bytes{m_base_payload_bytes + CompactSizeBytes(positions.size()) + positions.size() * Hash256::SIZE};
    if (bytes > std::min<uint64_t>(max_payload_bytes, MAX_TX_PAYLOAD)) {
        return R::Err("utreexotx response exceeds payload maximum");
    }
    for (const auto pos : positions) {
        const auto found{std::lower_bound(m_proof_positions.begin(), m_proof_positions.end(), pos)};
        if (found == m_proof_positions.end() || *found != pos) return R::Err("requested position is not a transaction proof node");
    }
    if (!UniquePositions(positions)) return R::Err("duplicate requested proof positions");
    return R::Ok(bytes);
}

Result<std::vector<std::byte>> PreparedTransactionProof::Serialize(
    const TransactionProofRequest& request, uint64_t max_payload_bytes) const
{
    using R = Result<std::vector<std::byte>>;
    auto measured{Measure(request, max_payload_bytes)};
    if (!measured) return R::Err(measured.Error());
    std::vector<std::byte> output;
    output.reserve(static_cast<std::size_t>(measured.Value()));
    AppendCompactSize(output, m_proof.targets.size());
    for (const auto target : m_proof.targets) AppendCompactSize(output, target);
    AppendCompactSize(output, request.proof_positions.size());
    for (const auto pos : request.proof_positions) {
        const auto index{static_cast<std::size_t>(std::lower_bound(m_proof_positions.begin(), m_proof_positions.end(), pos) - m_proof_positions.begin())};
        AppendBytes(output, m_proof.hashes[index].Span());
    }
    const auto tx_start{output.size()};
    AppendBytes(output, m_transaction.Bytes());
    for (std::size_t i{0}; i < m_input_leaves.size(); ++i) {
        const uint32_t flagged{(m_transaction.Inputs()[i].index << 1) | (m_input_leaves[i] ? 0U : 1U)};
        WriteVout(output, tx_start + m_transaction.m_vout_offsets[i], flagged);
    }
    // No remember indexes or leaf count: this is MsgUtreexoTx, not block UData.
    for (const auto& leaf : m_input_leaves) {
        if (!leaf) continue;
        AppendLE(output, leaf->header_code);
        AppendLE(output, leaf->amount);
        output.push_back(static_cast<std::byte>(leaf->script_type));
        if (leaf->script_type == ScriptPubkeyType::OTHER) {
            AppendCompactSize(output, leaf->script.size());
            AppendBytes(output, leaf->script);
        }
    }
    return R::Ok(std::move(output));
}

Result<DecodedTransactionProof> ParseUtreexoTransaction(
    std::span<const std::byte> payload, uint64_t max_payload_bytes)
{
    using R = Result<DecodedTransactionProof>;
    if (payload.size() > std::min<uint64_t>(max_payload_bytes, MAX_TX_PAYLOAD)) {
        return R::Err("utreexotx payload exceeds maximum");
    }
    Reader reader{payload};
    Proof proof;
    uint64_t count{0};
    if (!reader.CompactSize(count) || count > MAX_INPUTS || count > reader.Remaining()) {
        return R::Err("invalid utreexotx target count");
    }
    proof.targets.reserve(static_cast<std::size_t>(count));
    for (uint64_t i{0}; i < count; ++i) {
        uint64_t target{0};
        if (!reader.CompactSize(target) || target == PADDING) return R::Err("invalid utreexotx target");
        proof.targets.push_back(target);
    }
    if (!reader.CompactSize(count) || count > MAX_HASHES || count > reader.Remaining() / Hash256::SIZE) {
        return R::Err("invalid utreexotx proof hash count");
    }
    proof.hashes.resize(static_cast<std::size_t>(count));
    for (auto& hash : proof.hashes) {
        if (!reader.Hash(hash)) return R::Err("truncated utreexotx proof hash");
    }
    const auto tx_start{reader.Offset()};
    auto layout{ScanTransaction(payload.subspan(tx_start))};
    if (!layout) return R::Err(layout.Error());
    std::vector<OutPoint> inputs;
    std::vector<std::size_t> offsets;
    auto collected{ScanTransaction(payload.subspan(tx_start, layout.Value().size), &inputs, &offsets)};
    if (!collected) return R::Err(collected.Error());
    if (!reader.Skip(layout.Value().size)) return R::Err("truncated utreexotx transaction");
    const auto confirmed{static_cast<std::size_t>(std::count_if(inputs.begin(), inputs.end(),
        [](const auto& input) { return (input.index & 1U) == 0; }))};
    if (confirmed != proof.targets.size() || confirmed > reader.Remaining() / 13 ||
        (confirmed == 0 && !proof.hashes.empty())) return R::Err("utreexotx confirmed input/proof counts differ");
    std::vector<std::optional<CompactLeafData>> leaves(inputs.size());
    for (std::size_t i{0}; i < inputs.size(); ++i) {
        if ((inputs[i].index & 1U) != 0) continue;
        CompactLeafData leaf;
        uint8_t type{0};
        if (!reader.LE(leaf.header_code) || !reader.LE(leaf.amount) || !reader.LE(type)) {
            return R::Err("truncated confirmed compact leaf");
        }
        leaf.script_type = static_cast<ScriptPubkeyType>(type);
        if (leaf.script_type == ScriptPubkeyType::OTHER) {
            uint64_t size{0};
            if (!reader.CompactSize(size) || size > MAX_SCRIPT_BYTES || size > reader.Remaining()) {
                return R::Err("invalid compact leaf script length");
            }
            const auto script{payload.subspan(reader.Offset(), static_cast<std::size_t>(size))};
            leaf.script.assign(script.begin(), script.end());
            if (!reader.Skip(size)) return R::Err("truncated compact leaf script");
        }
        auto measured{LeafBytes(leaf)};
        if (!measured) return R::Err(measured.Error());
        leaves[i] = std::move(leaf);
    }
    if (reader.Remaining() != 0 || !UniquePositions(proof.targets)) return R::Err("trailing utreexotx bytes or duplicate targets");
    const auto flagged{payload.subspan(tx_start, layout.Value().size)};
    std::vector<std::byte> raw{flagged.begin(), flagged.end()};
    for (std::size_t i{0}; i < inputs.size(); ++i) WriteVout(raw, offsets[i], inputs[i].index >> 1);
    auto transaction{Transaction::Parse(raw)};
    if (!transaction) return R::Err(transaction.Error());
    return R::Ok(DecodedTransactionProof{transaction.Take(), std::move(proof), std::move(leaves)});
}

} // namespace utreexo::txwire
