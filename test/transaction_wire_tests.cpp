#include <test_framework.h>
#include <utreexo/p2p.h>
#include <utreexo/position.h>
#include <utreexo/transaction_wire.h>
#include <utreexo/transaction_cache.h>
#include <thread>

#include <algorithm>
#include <array>
#include <limits>
#include <numeric>
#include <string_view>

using namespace utreexo;
using namespace utreexo::txwire;

namespace {

struct LeafVector {
    bool confirmed;
    uint32_t header;
    uint64_t amount;
    uint8_t type;
    std::string_view script;
};

struct TxVector {
    std::string_view name;
    std::string_view raw;
    std::string_view txid;
    std::string_view wtxid;
    std::string_view announcement;
    std::string_view request;
    std::string_view response;
    uint64_t num_leaves;
    std::vector<uint64_t> native_targets;
    std::vector<uint64_t> wire_targets;
    std::vector<uint64_t> proof_positions;
    std::vector<uint64_t> requested_positions;
    uint32_t inventory_type;
    std::vector<std::string_view> proof_hashes;
    std::vector<std::string_view> target_hashes;
    std::vector<std::string_view> roots;
    std::vector<LeafVector> leaves;
};

#include "data/utreexod_tx_vectors.h"

std::vector<std::byte> Unhex(std::string_view hex)
{
    CHECK_EQ(hex.size() % 2, 0U);
    const auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        CHECK(c >= 'a' && c <= 'f');
        return static_cast<uint8_t>(c - 'a' + 10);
    };
    std::vector<std::byte> bytes;
    for (std::size_t i{0}; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return bytes;
}

std::vector<Hash256> Hashes(const std::vector<std::string_view>& hexes)
{
    std::vector<Hash256> hashes;
    hashes.reserve(hexes.size());
    for (const auto hex : hexes) hashes.push_back(Hash256::FromHex(hex).Value());
    return hashes;
}

std::vector<std::optional<CompactLeafData>> Leaves(const TxVector& vector)
{
    std::vector<std::optional<CompactLeafData>> leaves;
    for (const auto& leaf : vector.leaves) {
        if (!leaf.confirmed) leaves.push_back(std::nullopt);
        else leaves.emplace_back(CompactLeafData{leaf.header, leaf.amount,
            static_cast<ScriptPubkeyType>(leaf.type), Unhex(leaf.script)});
    }
    return leaves;
}

PreparedTransactionProof Prepare(const TxVector& vector)
{
    auto result{PreparedTransactionProof::Create(Transaction::Parse(Unhex(vector.raw)).Take(),
        Proof{vector.native_targets, Hashes(vector.proof_hashes)}, Leaves(vector), vector.num_leaves)};
    if (!result) throw std::runtime_error{std::string{vector.name} + ": " + result.Error()};
    return result.Take();
}

void AppendLE(std::vector<std::byte>& bytes, uint64_t value, unsigned int width)
{
    for (unsigned int i{0}; i < width; ++i) {
        bytes.push_back(static_cast<std::byte>(value & 0xffU));
        value >>= 8;
    }
}

void CompactSize(std::vector<std::byte>& bytes, uint64_t value)
{
    if (value < 253) AppendLE(bytes, value, 1);
    else if (value <= UINT16_MAX) { bytes.push_back(std::byte{253}); AppendLE(bytes, value, 2); }
    else if (value <= UINT32_MAX) { bytes.push_back(std::byte{254}); AppendLE(bytes, value, 4); }
    else { bytes.push_back(std::byte{255}); AppendLE(bytes, value, 8); }
}

std::vector<std::byte> MinimalTransaction(uint32_t vout = 0, bool witness = false, uint64_t output_script_bytes = 0)
{
    std::vector<std::byte> raw;
    AppendLE(raw, 2, 4);
    if (witness) { raw.push_back(std::byte{0}); raw.push_back(std::byte{1}); }
    CompactSize(raw, 1);
    raw.insert(raw.end(), 32, std::byte{0xab});
    AppendLE(raw, vout, 4);
    CompactSize(raw, 0);
    AppendLE(raw, UINT32_MAX, 4);
    CompactSize(raw, 1);
    AppendLE(raw, 1, 8);
    CompactSize(raw, output_script_bytes);
    raw.insert(raw.end(), static_cast<std::size_t>(output_script_bytes), std::byte{0x51});
    if (witness) { CompactSize(raw, 1); CompactSize(raw, 0); }
    AppendLE(raw, 0, 4);
    return raw;
}

const CompactLeafData SIMPLE_LEAF{200, 1000, ScriptPubkeyType::OTHER, {std::byte{0x51}}};

} // namespace

TEST(transaction_codec_matches_pinned_utreexod_vectors)
{
    for (const auto& vector : TX_VECTORS) {
        try {
            const auto raw{Unhex(vector.raw)};
            auto prepared{Prepare(vector)};
            const auto& tx{prepared.Tx()};
            CHECK_EQ(tx.Txid().ToBitcoinHex(), vector.txid);
            CHECK_EQ(tx.Wtxid().ToBitcoinHex(), vector.wtxid);
            CHECK_EQ(tx.HasWitness(), vector.txid != vector.wtxid);
            CHECK(std::ranges::equal(tx.Bytes(), raw));
            CHECK_EQ(prepared.WireProof().targets, vector.wire_targets);
            CHECK(std::ranges::equal(prepared.ProofPositions(), vector.proof_positions));
            auto valid{VerifyProof(Proof{vector.native_targets, Hashes(vector.proof_hashes)},
                Hashes(vector.target_hashes), Hashes(vector.roots), vector.num_leaves)};
            CHECK(valid);
            CHECK(valid.Value());

            const auto announcement{prepared.Announcement()};
            const std::array announcements{announcement};
            CHECK_EQ(SerializeTransactionAnnouncements(announcements).Value(), Unhex(vector.announcement));
            CHECK_EQ(ParseTransactionAnnouncements(Unhex(vector.announcement)).Value(),
                     std::vector<TransactionAnnouncement>{announcement});
            const TransactionProofRequest request{tx.Txid(), vector.inventory_type, vector.requested_positions};
            const std::array requests{request};
            CHECK_EQ(SerializeTransactionProofRequests(requests).Value(), Unhex(vector.request));
            CHECK_EQ(ParseTransactionProofRequests(Unhex(vector.request)).Value(),
                     std::vector<TransactionProofRequest>{request});

            // Repeated full/partial/empty responses must never shift cached vouts.
            for (int repeat{0}; repeat < 3; ++repeat) {
                const auto response{prepared.Serialize(request)};
                CHECK(response);
                CHECK_EQ(response.Value(), Unhex(vector.response));
                auto decoded{ParseUtreexoTransaction(response.Value())};
                CHECK(decoded);
                CHECK(std::ranges::equal(decoded.Value().transaction.Bytes(), raw));
                CHECK_EQ(decoded.Value().transaction.Txid(), tx.Txid());
                CHECK_EQ(decoded.Value().transaction.Wtxid(), tx.Wtxid());
                CHECK_EQ(decoded.Value().input_leaves, Leaves(vector));
                CHECK_EQ(decoded.Value().proof.targets, vector.wire_targets);
                CHECK_EQ(decoded.Value().proof.hashes.size(), vector.requested_positions.size());
                for (std::size_t i{0}; i < vector.requested_positions.size(); ++i) {
                    const auto found{std::ranges::find(vector.proof_positions, vector.requested_positions[i])};
                    const auto index{static_cast<std::size_t>(found - vector.proof_positions.begin())};
                    CHECK_EQ(decoded.Value().proof.hashes[i], prepared.WireProof().hashes[index]);
                }
                CHECK(std::ranges::equal(tx.Bytes(), raw));
                CHECK_EQ(tx.Txid().ToBitcoinHex(), vector.txid);
                CHECK_EQ(tx.Wtxid().ToBitcoinHex(), vector.wtxid);
                CHECK(prepared.Serialize(prepared.FullRequest()));
            }

            auto packet{EncodeP2PMessage(BitcoinNetwork::REGTEST, "utreexotx", Unhex(vector.response))};
            CHECK(packet);
            auto message{DecodeP2PMessage(BitcoinNetwork::REGTEST, packet.Value())};
            CHECK(message);
            CHECK_EQ(message.Value().command, "utreexotx");
            CHECK(ParseUtreexoTransaction(message.Value().payload));
        } catch (const std::exception& error) {
            throw std::runtime_error{std::string{vector.name} + ": " + error.what()};
        }
    }
}

TEST(transaction_codec_rejects_truncated_reference_payloads)
{
    for (const auto& vector : TX_VECTORS) {
        const auto raw{Unhex(vector.raw)};
        const auto response{Unhex(vector.response)};
        for (std::size_t size{0}; size < raw.size(); ++size) CHECK(!Transaction::Parse(std::span{raw}.first(size)));
        for (std::size_t size{0}; size < response.size(); ++size) CHECK(!ParseUtreexoTransaction(std::span{response}.first(size)));
        for (const auto hex : {vector.announcement, vector.request}) {
            const auto payload{Unhex(hex)};
            for (std::size_t size{0}; size < payload.size(); ++size) {
                CHECK(!ParseTransactionAnnouncements(std::span{payload}.first(size)));
                CHECK(!ParseTransactionProofRequests(std::span{payload}.first(size)));
            }
        }
    }
}

TEST(transaction_codec_enforces_exact_payload_limits)
{
    for (const auto& vector : TX_VECTORS) {
        const auto raw{Unhex(vector.raw)};
        const auto response{Unhex(vector.response)};
        const auto inv{Unhex(vector.announcement)};
        const auto getdata{Unhex(vector.request)};
        const auto prepared{Prepare(vector)};
        const auto request{ParseTransactionProofRequests(getdata).Value().front()};
        CHECK(Transaction::Parse(raw, raw.size()));
        CHECK(!Transaction::Parse(raw, raw.size() - 1));
        CHECK(prepared.Serialize(request, response.size()));
        CHECK(!prepared.Serialize(request, response.size() - 1));
        CHECK(ParseUtreexoTransaction(response, response.size()));
        CHECK(!ParseUtreexoTransaction(response, response.size() - 1));
        CHECK(ParseTransactionAnnouncements(inv, inv.size()));
        CHECK(!ParseTransactionAnnouncements(inv, inv.size() - 1));
        CHECK(ParseTransactionProofRequests(getdata, getdata.size()));
        CHECK(!ParseTransactionProofRequests(getdata, getdata.size() - 1));
        const std::array announcements{prepared.Announcement()};
        const std::array requests{request};
        CHECK(SerializeTransactionAnnouncements(announcements, inv.size()));
        CHECK(!SerializeTransactionAnnouncements(announcements, inv.size() - 1));
        CHECK(SerializeTransactionProofRequests(requests, getdata.size()));
        CHECK(!SerializeTransactionProofRequests(requests, getdata.size() - 1));
    }
    auto raw{MinimalTransaction(0, false, MAX_TX_PAYLOAD - 64)};
    CHECK_EQ(raw.size(), MAX_TX_PAYLOAD);
    CHECK(Transaction::Parse(raw));
    // Even a zero-hash, all-unconfirmed response needs a two-byte batch proof.
    CHECK(!PreparedTransactionProof::Create(Transaction::Parse(raw).Take(), {}, {std::nullopt}, 0));
    raw.push_back(std::byte{0});
    CHECK(!Transaction::Parse(raw, UINT64_MAX));
    CHECK(!ParseUtreexoTransaction(raw, UINT64_MAX));

    // Preparing a full proof does not force an oversized full response on a
    // consumer that only needs a subset. Count actual selected hashes.
    raw = MinimalTransaction(0, false, MAX_TX_PAYLOAD - 144);
    auto prepared{PreparedTransactionProof::Create(Transaction::Parse(raw).Take(),
        Proof{{0}, {Hash256{}, Hash256{}, Hash256{}}}, {SIMPLE_LEAF}, 8)};
    CHECK(prepared);
    auto request{prepared.Value().FullRequest()};
    CHECK(!prepared.Value().Serialize(request, UINT64_MAX));
    request.proof_positions.resize(1);
    CHECK(prepared.Value().Serialize(request));
}

TEST(transaction_inventory_packs_four_little_endian_positions)
{
    const TransactionAnnouncement announcement{Hash256{}, {0, 253, 0x0102030405060708ULL, UINT64_MAX - 1}};
    const std::array announcements{announcement};
    const auto encoded{SerializeTransactionAnnouncements(announcements).Value()};
    CHECK_EQ(encoded.size(), 73U);
    CHECK_EQ(encoded[0], std::byte{2});
    const auto positions{Unhex("0000000000000000fd000000000000000807060504030201feffffffffffffff")};
    CHECK(std::ranges::equal(std::span{encoded}.subspan(41), positions));
    CHECK_EQ(ParseTransactionAnnouncements(encoded).Value().front(), announcement);

    const std::array multiple{TransactionAnnouncement{Hash256{}, {5}}, TransactionAnnouncement{Hash256{}, {7, 0, 2, 3, 9}}};
    CHECK_EQ(ParseTransactionAnnouncements(SerializeTransactionAnnouncements(multiple).Value()).Value(),
             (std::vector<TransactionAnnouncement>{multiple.begin(), multiple.end()}));
    const auto empty{SerializeTransactionAnnouncements({}).Value()};
    CHECK_EQ(empty, Unhex("00"));
    CHECK(ParseTransactionAnnouncements(empty).Value().empty());
    CHECK(ParseTransactionProofRequests(SerializeTransactionProofRequests({}).Value()).Value().empty());
}

TEST(transaction_inventory_rejects_noncanonical_counts_and_padding)
{
    const std::array announcements{TransactionAnnouncement{Hash256{}, {5, 0}}};
    const auto valid{SerializeTransactionAnnouncements(announcements).Value()};
    auto bad{valid};
    bad.insert(bad.begin(), {std::byte{253}, std::byte{2}});
    bad[2] = std::byte{0}; // fd0200: noncanonical count
    CHECK(!ParseTransactionAnnouncements(bad));
    bad = valid;
    bad.push_back(std::byte{0});
    CHECK(!ParseTransactionAnnouncements(bad));
    bad = valid;
    bad[0] = std::byte{3};
    CHECK(!ParseTransactionAnnouncements(bad));
    // Data after the first padding slot is never silently ignored.
    bad = valid;
    bad.back() = std::byte{0};
    CHECK(!ParseTransactionAnnouncements(bad));
    bad = valid;
    std::fill(bad.begin() + 41, bad.begin() + 49, std::byte{0xff});
    CHECK(!ParseTransactionAnnouncements(bad));
    // An extra all-padding vector, including after a fully packed group, is invalid.
    for (const auto count : {2U, 4U}) {
        const std::array group{TransactionAnnouncement{Hash256{}, std::vector<uint64_t>{0, 1, 2, 3}}};
        bad = count == 2 ? valid : SerializeTransactionAnnouncements(group).Value();
        bad[0] = std::byte{3};
        AppendLE(bad, MSG_UTREEXO_PROOF_HASH, 4);
        bad.insert(bad.end(), 32, std::byte{0xff});
        CHECK(!ParseTransactionAnnouncements(bad));
    }
    bad = valid;
    std::copy_n(bad.begin() + 41, 8, bad.begin() + 49);
    CHECK(!ParseTransactionAnnouncements(bad));
    bad = valid;
    bad[1] = static_cast<std::byte>(MSG_UTREEXO_PROOF_HASH); // orphan vector
    CHECK(!ParseTransactionAnnouncements(bad));
    bad = valid;
    bad[1] = std::byte{2}; // proof vectors cannot attach to a block
    CHECK(!ParseTransactionAnnouncements(bad));
    CHECK(!ParseTransactionProofRequests(bad));
    CHECK(!ParseTransactionProofRequests(valid)); // ordinary MSG_TX is not a proof request
    for (const auto& positions : {std::vector<uint64_t>{0, 0}, std::vector<uint64_t>{UINT64_MAX}}) {
        const std::array group{TransactionAnnouncement{Hash256{}, positions}};
        CHECK(!SerializeTransactionAnnouncements(group));
        const std::array request{TransactionProofRequest{Hash256{}, MSG_UTREEXO_TX, positions}};
        CHECK(!SerializeTransactionProofRequests(request));
    }
}

TEST(transaction_getdata_preserves_groups_and_ignores_unrelated_inventory)
{
    const auto prepared{Prepare(TX_VECTORS.front())};
    const std::array requests{prepared.FullRequest(),
        TransactionProofRequest{Hash256{}, MSG_WITNESS_UTREEXO_TX, {}}, prepared.FullRequest()};
    auto payload{SerializeTransactionProofRequests(requests).Value()};
    // Insert an ordinary block and tx, then an unknown type at the end.
    std::vector<std::byte> unrelated;
    for (const auto type : {2U, MSG_TX, 0x12345678U}) {
        AppendLE(unrelated, type, 4);
        unrelated.insert(unrelated.end(), 32, std::byte{0});
    }
    payload[0] = static_cast<std::byte>(std::to_integer<uint8_t>(payload[0]) + 3);
    payload.insert(payload.begin() + 1, unrelated.begin(), unrelated.end());
    CHECK_EQ(ParseTransactionProofRequests(payload).Value(),
             (std::vector<TransactionProofRequest>{requests.begin(), requests.end()}));
    const std::array invalid{TransactionProofRequest{Hash256{}, MSG_TX, {}}};
    CHECK(!SerializeTransactionProofRequests(invalid));
}

TEST(transaction_inventory_bounds_counts_before_allocation)
{
    std::vector<std::byte> payload;
    CompactSize(payload, MAX_INVENTORY);
    for (uint32_t i{0}; i < MAX_INVENTORY; ++i) {
        AppendLE(payload, 2, 4);
        payload.insert(payload.end(), 32, std::byte{0});
    }
    CHECK(ParseTransactionAnnouncements(payload).Value().empty());
    CHECK(ParseTransactionProofRequests(payload).Value().empty());
    AppendLE(payload, 2, 4);
    payload.insert(payload.end(), 32, std::byte{0});
    CHECK(!ParseTransactionProofRequests(payload, UINT64_MAX));
    for (const auto count : {uint64_t{MAX_INVENTORY + 1}, UINT64_MAX}) {
        std::vector<std::byte> prefix;
        CompactSize(prefix, count);
        CHECK(!ParseTransactionAnnouncements(prefix));
        CHECK(!ParseTransactionProofRequests(prefix));
        CHECK(!ParseUtreexoTransaction(prefix));
        prefix.insert(prefix.begin(), {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}});
        CHECK(!Transaction::Parse(prefix));
    }
    const std::array oversized_ann{TransactionAnnouncement{Hash256{}, std::vector<uint64_t>(MAX_TX_PAYLOAD / 41 + 1)}};
    CHECK(!SerializeTransactionAnnouncements(oversized_ann));
    const std::array oversized_req{TransactionProofRequest{Hash256{}, MSG_UTREEXO_TX, std::vector<uint64_t>(MAX_TX_PAYLOAD / 32 + 1)}};
    CHECK(!SerializeTransactionProofRequests(oversized_req));
    std::vector<TransactionAnnouncement> too_many(MAX_INVENTORY + 1);
    CHECK(!SerializeTransactionAnnouncements(too_many));
    too_many.resize(MAX_INVENTORY);
    too_many.front().confirmed_targets = {0}; // groups fit, packed vectors do not
    CHECK(!SerializeTransactionAnnouncements(too_many));
}

TEST(raw_transaction_rejects_noncanonical_and_ambiguous_encodings)
{
    const auto raw{MinimalTransaction()};
    CHECK_EQ(raw.size(), 60U);
    for (const auto offset : {4U, 41U, 46U, 55U}) {
        auto bad{raw};
        const auto value{bad[offset]};
        bad.erase(bad.begin() + offset);
        bad.insert(bad.begin() + offset, {std::byte{253}, value, std::byte{0}});
        CHECK(!Transaction::Parse(bad));
    }
    auto bad{raw};
    bad[46] = std::byte{0};
    CHECK(!Transaction::Parse(bad));
    bad = raw;
    bad[41] = std::byte{252};
    CHECK(!Transaction::Parse(bad));
    bad = raw;
    bad[55] = std::byte{252};
    CHECK(!Transaction::Parse(bad));
    bad = raw;
    bad.push_back(std::byte{0});
    CHECK(!Transaction::Parse(bad));
    const auto witness{MinimalTransaction(0, true)};
    CHECK(Transaction::Parse(witness)); // one empty stack item is still witness
    for (const auto flag : {0U, 2U, 3U, 255U}) {
        bad = witness;
        bad[5] = static_cast<std::byte>(flag);
        CHECK(!Transaction::Parse(bad));
    }
    bad = witness;
    bad.erase(bad.end() - 5); // all stacks empty: reject superfluous marker/flag
    bad[bad.size() - 5] = std::byte{0};
    CHECK(!Transaction::Parse(bad));
    for (const auto offset : {witness.size() - 6, witness.size() - 5}) {
        bad = witness;
        const auto value{bad[offset]};
        bad.erase(bad.begin() + static_cast<std::ptrdiff_t>(offset));
        bad.insert(bad.begin() + static_cast<std::ptrdiff_t>(offset), {std::byte{253}, value, std::byte{0}});
        CHECK(!Transaction::Parse(bad));
    }
    bad = witness;
    bad[bad.size() - 6] = std::byte{252};
    CHECK(!Transaction::Parse(bad));
    bad = witness;
    bad[bad.size() - 5] = std::byte{252};
    CHECK(!Transaction::Parse(bad));
}

TEST(transaction_proof_requests_select_nodes_not_targets_or_indexes)
{
    const auto prepared{Prepare(TX_VECTORS.front())};
    auto request{prepared.FullRequest()};
    CHECK(prepared.Serialize(request));
    request.proof_positions.clear();
    CHECK(ParseUtreexoTransaction(prepared.Serialize(request).Value()).Value().proof.hashes.empty());
    for (const uint64_t pos : std::array<uint64_t, 4>{0, 5, 9, UINT64_MAX}) { // targets, native-row node, padding
        request.proof_positions = {pos};
        CHECK(!prepared.Serialize(request));
    }
    request.proof_positions = {1, 1};
    CHECK(!prepared.Serialize(request));
    request = prepared.FullRequest();
    request.txid = Hash256{};
    CHECK(!prepared.Serialize(request));
    request = prepared.FullRequest();
    request.inventory_type = MSG_TX;
    CHECK(!prepared.Serialize(request));
    CHECK_EQ(prepared.Serialize(prepared.FullRequest(MSG_UTREEXO_TX)).Value(),
             prepared.Serialize(prepared.FullRequest(MSG_WITNESS_UTREEXO_TX)).Value());
}

TEST(transaction_preparation_validates_counts_positions_leaves_and_vout_overflow)
{
    const auto& vector{TX_VECTORS.front()};
    const auto prepare = [&](Proof proof, std::vector<std::optional<CompactLeafData>> leaves, uint64_t num_leaves) {
        return PreparedTransactionProof::Create(Transaction::Parse(Unhex(vector.raw)).Take(),
            std::move(proof), std::move(leaves), num_leaves);
    };
    const Proof valid{vector.native_targets, Hashes(vector.proof_hashes)};
    CHECK(!prepare(valid, {}, vector.num_leaves));
    CHECK(!prepare({}, Leaves(vector), vector.num_leaves));
    CHECK(!prepare(Proof{valid.targets, {}}, Leaves(vector), vector.num_leaves));
    for (const auto& targets : {std::vector<uint64_t>{0, 0}, std::vector<uint64_t>{0, 8},
             std::vector<uint64_t>{8, 12}, std::vector<uint64_t>{UINT64_MAX, 0}, std::vector<uint64_t>{16, 0}}) {
        CHECK(!prepare(Proof{targets, valid.hashes}, Leaves(vector), vector.num_leaves));
    }
    CHECK(!prepare(valid, Leaves(vector), 0));
    CHECK(!prepare(valid, Leaves(vector), UINT64_MAX));
    for (int mutation{0}; mutation < 6; ++mutation) {
        auto leaves{Leaves(vector)};
        auto& leaf{*leaves.front()};
        if (mutation == 0) leaf.header_code = UINT32_MAX;
        if (mutation == 1) leaf.amount = UINT64_MAX;
        // Intentional malformed metadata; a fixed uint8_t enum can represent 5.
        // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
        if (mutation == 2) leaf.script_type = static_cast<ScriptPubkeyType>(5);
        if (mutation == 3) leaf.script_type = ScriptPubkeyType::PUBKEY_HASH; // nonempty script
        if (mutation == 4) leaf.script.resize(10'001);
        if (mutation == 5) leaves[1] = SIMPLE_LEAF; // mismatched confirmed count
        CHECK(!prepare(valid, std::move(leaves), vector.num_leaves));
    }
    for (const auto vout : {0x80000000U, UINT32_MAX}) {
        const auto raw{MinimalTransaction(vout)};
        CHECK(Transaction::Parse(raw)); // raw parser does not silently truncate identity
        CHECK(!PreparedTransactionProof::Create(Transaction::Parse(raw).Take(), {}, {std::nullopt}, 0));
        CHECK(!PreparedTransactionProof::Create(Transaction::Parse(raw).Take(), Proof{{0}, {}}, {SIMPLE_LEAF}, 1));
    }
    const auto raw{MinimalTransaction(UINT32_MAX >> 1)};
    auto prepared{PreparedTransactionProof::Create(Transaction::Parse(raw).Take(), {}, {std::nullopt}, 0)};
    CHECK(prepared);
    const auto decoded{ParseUtreexoTransaction(prepared.Value().Serialize(prepared.Value().FullRequest()).Value())};
    CHECK(decoded);
    CHECK(std::ranges::equal(decoded.Value().transaction.Bytes(), raw));
}

TEST(transaction_proof_validates_sparse_and_maximum_row_positions)
{
    const auto tx{Transaction::Parse(MinimalTransaction()).Take()};
    // A row-one position outside a three-leaf forest must not drive proof traversal.
    CHECK(!PreparedTransactionProof::Create(tx, Proof{{5}, {}}, {SIMPLE_LEAF}, 3));
    // The maximum 63-row root is representable, UINT64_MAX is reserved padding.
    auto root{PreparedTransactionProof::Create(tx, Proof{{UINT64_MAX - 1}, {}}, {SIMPLE_LEAF}, uint64_t{1} << 63)};
    CHECK(root);
    CHECK_EQ(root.Value().WireProof().targets.front(), UINT64_MAX - 1);
    CHECK(root.Value().ProofPositions().empty());
    CHECK(ParseUtreexoTransaction(root.Value().Serialize(root.Value().FullRequest()).Value()));
}

TEST(utreexotx_rejects_malformed_batch_proofs_flags_and_compact_leaves)
{
    const auto tx{Transaction::Parse(MinimalTransaction()).Take()};
    const auto prepared{PreparedTransactionProof::Create(tx, Proof{{0}, {}}, {SIMPLE_LEAF}, 1).Take()};
    const auto valid{prepared.Serialize(prepared.FullRequest()).Value()};
    CHECK_EQ(valid.size(), 3U + 60U + 15U); // no remember field or leaf-data count
    auto bad{valid};
    bad.push_back(std::byte{0});
    CHECK(!ParseUtreexoTransaction(bad));
    for (const auto offset : {0U, 1U, 2U, 76U}) { // target count/position, hash count, script length
        bad = valid;
        const auto value{bad[offset]};
        bad.erase(bad.begin() + offset);
        bad.insert(bad.begin() + offset, {std::byte{253}, value, std::byte{0}});
        CHECK(!ParseUtreexoTransaction(bad));
    }
    bad = valid;
    bad[3 + 37] |= std::byte{1}; // unconfirmed bit conflicts with target/leaf count
    CHECK(!ParseUtreexoTransaction(bad));
    for (const auto offset : {66U, 74U, 75U, 76U}) { // signed header/amount, type, script length
        bad = valid;
        bad[offset] = std::byte{0xff};
        CHECK(!ParseUtreexoTransaction(bad));
    }
    bad = valid;
    bad[2] = std::byte{0xfe}; // huge/truncated hash count
    CHECK(!ParseUtreexoTransaction(bad));
    bad = valid;
    bad.erase(bad.begin() + 1);
    std::vector<std::byte> reserved;
    CompactSize(reserved, UINT64_MAX);
    bad.insert(bad.begin() + 1, reserved.begin(), reserved.end());
    CHECK(!ParseUtreexoTransaction(bad));
    bad = Unhex(TX_VECTORS.front().response);
    bad[2] = bad[1]; // duplicate targets
    CHECK(!ParseUtreexoTransaction(bad));
}

TEST(transaction_preparation_matches_native_forest_after_deletions)
{
    PackedForest forest;
    std::vector<Hash256> hashes;
    for (uint8_t i{0}; i < 35; ++i) {
        Hash256::Storage hash{};
        hash[0] = static_cast<std::byte>(i + 1);
        hashes.emplace_back(hash);
        CHECK(forest.Add(hashes.back()));
    }
    for (std::size_t i{0}; i < hashes.size(); i += 3) CHECK(forest.Delete(hashes[i]));
    const auto tx{Transaction::Parse(MinimalTransaction()).Take()};
    for (std::size_t i{0}; i < hashes.size(); ++i) {
        if (i % 3 == 0) continue;
        const std::array target{hashes[i]};
        const auto proof{forest.Prove(target).Value()};
        auto prepared{PreparedTransactionProof::Create(tx, proof, {SIMPLE_LEAF}, forest.NumLeaves())};
        CHECK(prepared);
        CHECK_EQ(prepared.Value().WireProof().hashes, proof.hashes);
        CHECK_EQ(prepared.Value().ProofPositions().size(),
                 position::ProofPositions(proof.targets, forest.NumLeaves(), position::TreeRows(forest.NumLeaves())).size());
        CHECK(prepared.Value().Serialize(prepared.Value().FullRequest()));
    }
}

TEST(transaction_cache_bounds_anchor_and_announcement_identity)
{
    const ChainPoint point{943013, Hash256::FromHex(std::string(64, '1')).Value()};
    auto first{Prepare(TX_VECTORS[0])};
    auto second{Prepare(TX_VECTORS[4])};
    auto third{Prepare(TX_VECTORS[12])};
    const auto first_id{first.Tx().Txid()};
    const auto second_id{second.Tx().Txid()};
    const auto third_id{third.Tx().Txid()};
    CHECK(first_id != second_id && second_id != third_id);
    TransactionProofCache cache{{2, 1024 * 1024, std::chrono::seconds(60)}};
    CHECK(!cache.Publish(point, first));
    cache.Activate(point);
    CHECK(cache.Publish(point, first).Value());
    const auto old{cache.Find(first_id)};
    CHECK(old);
    CHECK(cache.Publish(point, second).Value());
    uint64_t cursor{0};
    auto announcements{cache.AnnouncementsAfter(cursor, 1)};
    CHECK_EQ(announcements.size(), 1U);
    CHECK_EQ(announcements.front().announcement.txid, first_id);
    CHECK_EQ(announcements.front().sequence, old->sequence);
    CHECK_EQ(cache.AnnouncementsAfter(cursor, 1).front().announcement.txid, second_id);
    CHECK(cache.AnnouncementsAfter(cursor).empty());
    CHECK(cache.Publish(point, third).Value());
    CHECK(!cache.Find(first_id));
    CHECK_EQ(cache.Stats().evicted, 1U);
    CHECK_EQ(cache.Stats().entries, 2U);
    const auto next{ChainPoint{point.height + 1, Hash256::FromHex(std::string(64, '2')).Value()}};
    cache.Invalidate();
    CHECK(!cache.Stats().ready);
    CHECK_EQ(cache.Stats().bytes, 0U);
    CHECK(!cache.Find(second_id));
    CHECK(!cache.Publish(point, first));
    cache.Activate(next);
    CHECK(!cache.Publish(point, first));
    CHECK(cache.Publish(next, first).Value());
    uint64_t stale_cursor{0};
    CHECK(cache.AnnouncementsAfter(stale_cursor, 64, 2048, 0).empty());
    CHECK_EQ(stale_cursor, 0U);
    CHECK(!cache.Find(first_id, old->sequence));
    CHECK(cache.Find(first_id)->sequence > old->sequence);
    // An in-flight immutable preparation remains coherent after withdrawal.
    CHECK_EQ(old->proof.Serialize(old->proof.FullRequest()).Value(), first.Serialize(first.FullRequest()).Value());
    cache.Erase(first_id);
    CHECK_EQ(cache.Stats().entries, 0U);
}

TEST(transaction_cache_enforces_bytes_and_expiry)
{
    const ChainPoint point{1, Hash256{}};
    auto proof{Prepare(TX_VECTORS[0])};
    TransactionProofCache measured{{2, 1024 * 1024, std::chrono::seconds(60)}};
    measured.Activate(point);
    CHECK(measured.Publish(point, proof).Value());
    const auto bytes{measured.Stats().bytes};
    CHECK(bytes >= proof.MemoryUsage());
    TransactionProofCache too_small{{2, bytes - 1, std::chrono::seconds(60)}};
    too_small.Activate(point);
    CHECK(!too_small.Publish(point, proof).Value());
    CHECK_EQ(too_small.Stats().oversized, 1U);
    CHECK_EQ(too_small.Stats().bytes, 0U);
    TransactionProofCache exact{{2, bytes, std::chrono::seconds(1)}};
    exact.Activate(point);
    CHECK(exact.Publish(point, proof).Value());
    CHECK_EQ(exact.Stats().bytes, bytes);
    std::this_thread::sleep_for(std::chrono::milliseconds(1050));
    CHECK(!exact.Find(proof.Tx().Txid()));
    CHECK_EQ(exact.Stats().expired, 1U);
    CHECK_EQ(exact.Stats().bytes, 0U);
}
