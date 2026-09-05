// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_TRANSACTION_WIRE_H
#define UTREEXO_TRANSACTION_WIRE_H

#include <utreexo/forest.h>
#include <utreexo/leaf.h>

#include <optional>
#include <span>
#include <vector>

namespace utreexo::txwire {

// These constants and formats are pinned to utreexod v0.6.0, not the draft BIP.
inline constexpr uint32_t MSG_TX{1};
inline constexpr uint32_t MSG_UTREEXO_PROOF_HASH{6};
inline constexpr uint32_t MSG_UTREEXO_TX{MSG_TX | (1U << 24)};
inline constexpr uint32_t MSG_WITNESS_UTREEXO_TX{MSG_UTREEXO_TX | (1U << 30)};
inline constexpr uint32_t MAX_INVENTORY{50'000};
inline constexpr uint32_t MAX_INVENTORY_PAYLOAD{9 + MAX_INVENTORY * 36};
inline constexpr uint32_t MAX_TX_PAYLOAD{4'000'000};

struct TransactionAnnouncement {
    Hash256 txid;
    /** Confirmed input targets, in input order, in the v0.6 63-row space. */
    std::vector<uint64_t> confirmed_targets;
    auto operator<=>(const TransactionAnnouncement&) const = default;
};

struct TransactionProofRequest {
    Hash256 txid;
    uint32_t inventory_type{MSG_UTREEXO_TX};
    /** Proof-node positions, NOT input targets. Empty means zero additional hashes.
     * A full request explicitly lists every needed proof-node position. */
    std::vector<uint64_t> proof_positions;
    auto operator<=>(const TransactionProofRequest&) const = default;
};

/** inv/getdata payloads (without the Bitcoin transport envelope). Unrelated
 * inventory is skipped on decode; orphan/misplaced proof vectors are rejected.
 * Padding is allowed only at the end of the final hash of each group. */
Result<std::vector<TransactionAnnouncement>> ParseTransactionAnnouncements(
    std::span<const std::byte> payload, uint64_t max_payload_bytes = MAX_INVENTORY_PAYLOAD);
Result<std::vector<std::byte>> SerializeTransactionAnnouncements(
    std::span<const TransactionAnnouncement> announcements,
    uint64_t max_payload_bytes = MAX_INVENTORY_PAYLOAD);
Result<std::vector<TransactionProofRequest>> ParseTransactionProofRequests(
    std::span<const std::byte> payload, uint64_t max_payload_bytes = MAX_INVENTORY_PAYLOAD);
Result<std::vector<std::byte>> SerializeTransactionProofRequests(
    std::span<const TransactionProofRequest> requests,
    uint64_t max_payload_bytes = MAX_INVENTORY_PAYLOAD);

/** Structurally checked, immutable ordinary Bitcoin transaction. Parsing is not
 * transaction policy or consensus validation. Hashes are computed only after
 * canonical encodings, all lengths/counts, and the entire payload are checked. */
class Transaction
{
public:
    static Result<Transaction> Parse(std::span<const std::byte> raw,
                                     uint64_t max_payload_bytes = MAX_TX_PAYLOAD);
    std::span<const std::byte> Bytes() const { return m_bytes; }
    const Hash256& Txid() const { return m_txid; }
    const Hash256& Wtxid() const { return m_wtxid; }
    bool HasWitness() const { return m_has_witness; }
    std::span<const OutPoint> Inputs() const { return m_inputs; }
    uint64_t MemoryUsage() const;

private:
    Transaction() = default;
    std::vector<std::byte> m_bytes;
    std::vector<OutPoint> m_inputs;
    std::vector<std::size_t> m_vout_offsets;
    Hash256 m_txid;
    Hash256 m_wtxid;
    bool m_has_witness{false};
    friend class PreparedTransactionProof;
};

/** Owned proof preparation suitable for a bounded cache. No mempool state or
 * policy lives here. Create takes a full PackedForest proof in its native
 * TreeRows(num_leaves) space and converts it to the pinned v0.6 wire space.
 * Callers must capture the proof and metadata at the same chain tip and expire
 * the preparation when that tip changes. nullopt marks an unconfirmed input. */
class PreparedTransactionProof
{
public:
    static Result<PreparedTransactionProof> Create(
        Transaction transaction, Proof proof,
        std::vector<std::optional<CompactLeafData>> input_leaves, uint64_t num_leaves);

    const Transaction& Tx() const { return m_transaction; }
    const Proof& WireProof() const { return m_proof; }
    std::span<const uint64_t> ProofPositions() const { return m_proof_positions; }
    uint64_t MemoryUsage() const;
    TransactionAnnouncement Announcement() const;
    TransactionProofRequest FullRequest(uint32_t inventory_type = MSG_UTREEXO_TX) const;
    Result<uint64_t> Measure(const TransactionProofRequest& request,
                             uint64_t max_payload_bytes = MAX_TX_PAYLOAD) const;

    /** Select hashes in request order. Both request variants retain witnesses,
     * as required by v0.6 compact-leaf reconstruction. Never alters Tx(). */
    Result<std::vector<std::byte>> Serialize(
        const TransactionProofRequest& request, uint64_t max_payload_bytes = MAX_TX_PAYLOAD) const;

private:
    PreparedTransactionProof(Transaction transaction, Proof proof,
                             std::vector<std::optional<CompactLeafData>> leaves,
                             std::vector<uint64_t> proof_positions, uint64_t base_payload_bytes);
    Transaction m_transaction;
    Proof m_proof;
    std::vector<std::optional<CompactLeafData>> m_input_leaves;
    std::vector<uint64_t> m_proof_positions;
    uint64_t m_base_payload_bytes;
};

struct DecodedTransactionProof {
    Transaction transaction;
    Proof proof;
    std::vector<std::optional<CompactLeafData>> input_leaves;
};

/** Decode proof, flagged transaction, and confirmed leaves, with no leaf count.
 * Restores ordinary transaction bytes and identities. Proof verification and
 * assigning partial hashes to requested positions remain the caller's job. */
Result<DecodedTransactionProof> ParseUtreexoTransaction(
    std::span<const std::byte> payload, uint64_t max_payload_bytes = MAX_TX_PAYLOAD);

} // namespace utreexo::txwire

#endif // UTREEXO_TRANSACTION_WIRE_H
