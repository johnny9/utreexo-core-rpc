// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/transaction_relay.h>
#include <utreexo/log.h>

#include <algorithm>
#include <set>
#include <stdexcept>

namespace utreexo {
namespace {
UniValue TxidParams(const Hash256& txid)
{
    UniValue params{UniValue::VARR};
    params.push_back(txid.ToBitcoinHex());
    return params;
}

Result<std::vector<std::byte>> DecodeHex(std::string_view hex, std::size_t limit)
{
    using R = Result<std::vector<std::byte>>;
    if (hex.size() % 2 != 0 || hex.size() / 2 > limit) return R::Err("hex data exceeds transaction metadata bounds");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    // Check all bytes before allocating.
    for (const char c : hex) if (nibble(c) < 0) return R::Err("invalid transaction metadata hex");
    std::vector<std::byte> bytes(hex.size() / 2);
    for (std::size_t i{0}; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>((nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]));
    }
    return R::Ok(std::move(bytes));
}

// A failed RPC must not turn a confirmed input into an unconfirmed input.
bool MissingTransaction(const std::string& error)
{
    if (!error.starts_with("Bitcoin Core RPC error:")) return false;
    UniValue value;
    const auto json{std::string_view{error}.substr(std::string_view{"Bitcoin Core RPC error:"}.size())};
    return value.read(json) && value.isObject() && value["code"].isNum() && value["code"].getInt<int>() == -5;
}
} // namespace

TransactionRelay::TransactionRelay(CoreRpcClient client, PackedForest& forest, SequentialSync& sync,
                                   std::shared_ptr<TransactionProofCache> cache, TransactionRelayConfig config)
    : m_client{std::move(client)}, m_forest{forest}, m_sync{sync}, m_cache{std::move(cache)}, m_config{config}
{
    if (!m_cache || config.batch_size == 0 || config.batch_size > 1024 ||
        config.recovery_interval.count() <= 0 || config.recovery_interval > std::chrono::minutes(5)) {
        throw std::invalid_argument{"invalid Core transaction relay settings"};
    }
}

Result<void> TransactionRelay::CheckTip(const ChainPoint& point)
{
    auto tip{m_client.Call("getbestblockhash")};
    if (!tip) return Result<void>::Err(tip.Error());
    if (!tip.Value().isStr() || tip.Value().get_str() != point.block_hash.ToBitcoinHex()) {
        return Result<void>::Err("Core tip differs from transaction proof accumulator");
    }
    return Result<void>::Ok();
}

Result<bool> TransactionRelay::Prepare(txwire::Transaction tx, const ChainPoint& point)
{
    auto member{m_client.Call("getmempoolentry", TxidParams(tx.Txid()))};
    if (!member) return MissingTransaction(member.Error()) ? Result<bool>::Ok(false) : Result<bool>::Err(member.Error());
    if (!member.Value()["wtxid"].isStr() || member.Value()["wtxid"].get_str() != tx.Wtxid().ToBitcoinHex()) {
        return Result<bool>::Err("Core mempool witness identity differs from relayed transaction");
    }
    std::vector<Hash256> hashes;
    std::vector<std::optional<CompactLeafData>> leaves;
    hashes.reserve(tx.Inputs().size());
    leaves.reserve(tx.Inputs().size());
    for (const auto& input : tx.Inputs()) {
        auto params{TxidParams(input.txid)};
        params.push_back(input.index);
        params.push_back(false); // Ignore Core's mempool spends of confirmed UTXOs.
        auto output{m_client.Call("gettxout", std::move(params))};
        if (!output) return Result<bool>::Err(output.Error());
        if (output.Value().isNull()) {
            auto parent{m_client.Call("getmempoolentry", TxidParams(input.txid))};
            if (!parent) return MissingTransaction(parent.Error()) ? Result<bool>::Ok(false) : Result<bool>::Err(parent.Error());
            leaves.emplace_back(std::nullopt);
            continue;
        }
        const auto& value{output.Value()};
        if (!value.isObject() || !value["bestblock"].isStr() ||
            value["bestblock"].get_str() != point.block_hash.ToBitcoinHex()) {
            return Result<bool>::Err("confirmed input metadata is anchored at a different Core tip");
        }
        const auto confirmations{value["confirmations"].getInt<uint64_t>()};
        if (confirmations == 0 || confirmations > uint64_t{point.height} + 1) {
            return Result<bool>::Err("invalid confirmed input height");
        }
        const auto height{static_cast<uint32_t>(uint64_t{point.height} + 1 - confirmations)};
        if (height >= m_sync.ChainHashes().size()) return Result<bool>::Err("confirmed input block hash is unavailable");
        auto amount{ParseBitcoinAmount(value["value"])};
        if (!amount) return Result<bool>::Err(amount.Error());
        auto script{DecodeHex(value["scriptPubKey"]["hex"].get_str(), 10'000)};
        if (!script) return Result<bool>::Err(script.Error());
        LeafData leaf{m_sync.ChainHashes()[height], input, height, value["coinbase"].get_bool(),
                      {amount.Value(), script.Take()}};
        hashes.push_back(LeafHash(leaf));
        leaves.emplace_back(CompactLeaf(leaf));
    }
    auto proof{m_forest.Prove(hashes)};
    if (!proof) return Result<bool>::Err("confirmed inputs not provable at Core tip: " + proof.Error());
    std::vector<Hash256> roots;
    for (const auto& root : m_forest.Roots()) if (root) roots.push_back(*root);
    auto verified{VerifyProof(proof.Value(), hashes, roots, m_forest.NumLeaves())};
    if (!verified || !verified.Value()) return Result<bool>::Err("generated transaction proof did not verify");
    auto prepared{txwire::PreparedTransactionProof::Create(std::move(tx), proof.Take(), std::move(leaves), m_forest.NumLeaves())};
    if (!prepared) return Result<bool>::Err(prepared.Error());
    auto current{CheckTip(point)};
    if (!current) return Result<bool>::Err(current.Error());
    member = m_client.Call("getmempoolentry", TxidParams(prepared.Value().Tx().Txid()));
    if (!member) return MissingTransaction(member.Error()) ? Result<bool>::Ok(false) : Result<bool>::Err(member.Error());
    if (member.Value()["wtxid"].get_str() != prepared.Value().Tx().Wtxid().ToBitcoinHex()) return Result<bool>::Ok(false);
    const auto txid{prepared.Value().Tx().Txid()};
    auto published{m_cache->Publish(point, prepared.Take())};
    if (published && published.Value()) Log(LogLevel::INFO, "transaction_proof_prepared",
        "txid=" + txid.ToBitcoinHex() + " height=" + std::to_string(point.height));
    return published;
}

Result<std::vector<Hash256>> TransactionRelay::RecoveryCandidates()
{
    using R = Result<std::vector<Hash256>>;
    auto inventory{m_client.CallRaw("getrawmempool")};
    if (!inventory) return R::Err(inventory.Error());
    // Scan the bounded RPC response without retaining a second mempool. Only
    // the existing bounded cache's ids and one preparation batch are retained.
    auto retained{m_cache->Txids()};
    std::set<Hash256> missing{retained.begin(), retained.end()};
    std::vector<Hash256> candidates;
    candidates.reserve(m_config.batch_size);
    auto json{inventory.Value().Value()};
    std::size_t offset{0};
    auto whitespace = [&] { while (offset < json.size() &&
        (json[offset] == ' ' || json[offset] == '\n' || json[offset] == '\r' || json[offset] == '\t')) ++offset; };
    whitespace();
    if (offset == json.size() || json[offset++] != '[') return R::Err("Core mempool inventory is not an array");
    uint64_t count{0};
    uint64_t next_cursor{m_scan_cursor};
    whitespace();
    if (offset < json.size() && json[offset] != ']') for (;;) {
        if (json.size() - offset < 66 || json[offset] != '"' || json[offset + 65] != '"') return R::Err("invalid Core mempool transaction id");
        auto txid{Hash256::FromBitcoinHex(json.substr(offset + 1, 64))};
        if (!txid) return R::Err(txid.Error());
        offset += 66;
        missing.erase(txid.Value());
        if (count >= m_scan_cursor && candidates.size() < m_config.batch_size) {
            next_cursor = count + 1;
            if (!m_cache->Find(txid.Value())) candidates.push_back(txid.Take());
        }
        ++count;
        whitespace();
        if (offset == json.size()) return R::Err("truncated Core mempool inventory");
        if (json[offset] == ']') break;
        if (json[offset++] != ',') return R::Err("invalid Core mempool inventory separator");
        whitespace();
    }
    if (offset == json.size() || json[offset++] != ']') return R::Err("truncated Core mempool inventory");
    whitespace();
    if (offset != json.size()) return R::Err("trailing Core mempool inventory data");
    m_scan_cursor = next_cursor >= count ? 0 : next_cursor;
    for (const auto& txid : missing) m_cache->Erase(txid);
    return R::Ok(std::move(candidates));
}

Result<void> TransactionRelay::Poll(std::vector<txwire::Transaction> incoming)
{
    // All failures withdraw published proofs. Core can change tip or membership
    // between RPCs; readers must never silently receive a newly anchored proof.
    auto work = [&]() -> Result<void> {
        const auto point{m_sync.CurrentPoint()};
        if (!point) return Result<void>::Err("transaction relay requires an accumulator chain point");
        auto current{CheckTip(*point)};
        if (!current) return current;
        const auto epoch{m_cache->Stats().epoch};
        if (epoch != m_epoch) { m_scan_cursor = 0; m_next_recovery = {}; m_epoch = epoch; }
        m_cache->Activate(*point);
        for (auto& tx : incoming) {
            if (m_cache->Find(tx.Txid())) continue;
            auto prepared{Prepare(std::move(tx), *point)};
            if (!prepared) return Result<void>::Err(prepared.Error());
        }
        if (std::chrono::steady_clock::now() >= m_next_recovery) {
            auto candidates{RecoveryCandidates()};
            if (!candidates) return Result<void>::Err(candidates.Error());
            for (const auto& txid : candidates.Value()) {
                auto raw{m_client.Call("getrawtransaction", TxidParams(txid))};
                if (!raw) {
                    if (MissingTransaction(raw.Error())) continue;
                    return Result<void>::Err(raw.Error());
                }
                auto bytes{DecodeHex(raw.Value().get_str(), txwire::MAX_TX_PAYLOAD)};
                if (!bytes) return Result<void>::Err(bytes.Error());
                auto tx{txwire::Transaction::Parse(bytes.Value())};
                if (!tx || tx.Value().Txid() != txid) return Result<void>::Err("invalid Core recovery transaction");
                auto prepared{Prepare(tx.Take(), *point)};
                if (!prepared) return Result<void>::Err(prepared.Error());
            }
            // A full batch may have more inventory to recover; yield to chain
            // synchronization and service the next batch on the next poll.
            m_next_recovery = std::chrono::steady_clock::now() +
                (candidates.Value().size() == m_config.batch_size ? std::chrono::seconds(0) : m_config.recovery_interval);
        }
        return CheckTip(*point);
    };
    try {
        auto result{work()};
        if (!result) m_cache->Invalidate();
        return result;
    } catch (const std::exception& error) {
        m_cache->Invalidate();
        return Result<void>::Err("Core transaction metadata error: " + std::string{error.what()});
    }
}

} // namespace utreexo
