// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/sync.h>

#include <chrono>
#include <limits>

namespace utreexo {

SequentialSync::SequentialSync(BlockSource& source, PackedForest& forest,
                               std::vector<Hash256> chain_hashes)
    : m_source{source}, m_forest{forest}, m_chain_hashes{std::move(chain_hashes)}
{
}

Result<uint32_t> SequentialSync::TipHeight() { return m_source.TipHeight(); }

std::optional<ChainPoint> SequentialSync::CurrentPoint() const
{
    if (m_chain_hashes.empty()) return std::nullopt;
    return ChainPoint{static_cast<uint32_t>(m_chain_hashes.size() - 1), m_chain_hashes.back()};
}

Result<ProcessedBlock> SequentialSync::ProcessNext()
{
    using Clock = std::chrono::steady_clock;
    const auto micros = [](Clock::time_point start) -> uint64_t {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - start).count());
    };
    const auto total_start{Clock::now()};
    BlockProcessingMetrics metrics;
    if (m_chain_hashes.size() > std::numeric_limits<uint32_t>::max()) {
        return Result<ProcessedBlock>::Err("chain height exceeds the sidecar format");
    }
    if (!m_chain_hashes.empty()) {
        const auto chain_check_start{Clock::now()};
        const uint32_t current_height{static_cast<uint32_t>(m_chain_hashes.size() - 1)};
        auto active_hash{m_source.BlockHash(current_height)};
        if (!active_hash) return Result<ProcessedBlock>::Err(active_hash.Error());
        if (active_hash.Value() != m_chain_hashes.back()) {
            return Result<ProcessedBlock>::Err(
                "active-chain reorganization detected at or below the sidecar tip; restore the last stable checkpoint");
        }
        metrics.chain_check_us = micros(chain_check_start);
    }

    const uint32_t height{static_cast<uint32_t>(m_chain_hashes.size())};
    const auto block_hash_start{Clock::now()};
    auto expected_hash{m_source.BlockHash(height)};
    if (!expected_hash) return Result<ProcessedBlock>::Err(expected_hash.Error());
    metrics.block_hash_us = micros(block_hash_start);
    const auto block_fetch_start{Clock::now()};
    auto json{m_source.BlockWithPrevouts(expected_hash.Value())};
    if (!json) return Result<ProcessedBlock>::Err(json.Error());
    metrics.block_fetch_us = micros(block_fetch_start);

    const auto resolver{[this](uint32_t creation_height) -> Result<Hash256> {
        if (creation_height >= m_chain_hashes.size()) {
            return Result<Hash256>::Err("creation height is not in the processed chain-hash index");
        }
        return Result<Hash256>::Ok(m_chain_hashes[creation_height]);
    }};
    const auto parse_start{Clock::now()};
    auto delta{ParseVerboseBlock(json.Value(), resolver)};
    if (!delta) return Result<ProcessedBlock>::Err(delta.Error());
    metrics.parse_us = micros(parse_start);
    if (delta.Value().point.height != height || delta.Value().point.block_hash != expected_hash.Value()) {
        return Result<ProcessedBlock>::Err("getblock result does not match the requested active-chain block");
    }
    if (height > 0 && delta.Value().previous_block_hash != m_chain_hashes.back()) {
        return Result<ProcessedBlock>::Err("block does not connect to the sidecar chain tip");
    }

    const auto modify_start{Clock::now()};
    const auto modified{m_forest.Modify(delta.Value().additions, delta.Value().deletions)};
    if (!modified) return Result<ProcessedBlock>::Err("could not apply block transition: " + modified.Error());
    metrics.modify_us = micros(modify_start);
    m_chain_hashes.push_back(expected_hash.Value());
    metrics.total_us = micros(total_start);
    return Result<ProcessedBlock>::Ok(ProcessedBlock{delta.Take(), metrics});
}

} // namespace utreexo
