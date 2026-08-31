// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#include <utreexo/sync.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <limits>
#include <mutex>
#include <new>
#include <thread>

namespace utreexo {

struct SequentialSync::PrefetchState {
    struct Item {
        uint32_t height;
        Result<FetchedBlock> result;
    };

    std::mutex mutex;
    std::condition_variable changed;
    std::deque<Item> queue;
    std::thread worker;
    std::exception_ptr exception;
    bool stop{false};
    bool done{false};
};

SequentialSync::SequentialSync(BlockSource& source, PackedForest& forest,
                               std::vector<Hash256> chain_hashes)
    : m_source{source}, m_forest{forest}, m_chain_hashes{std::move(chain_hashes)}
{
}

SequentialSync::~SequentialSync() { StopPrefetch(); }

Result<uint32_t> SequentialSync::TipHeight() { return m_source.TipHeight(); }

Result<void> SequentialSync::StartPrefetch(uint32_t target_height)
{
    if (m_prefetch) return Result<void>::Err("block prefetch is already active");
    if (m_chain_hashes.size() > static_cast<std::size_t>(target_height) + 1) {
        return Result<void>::Ok();
    }
    m_chain_hashes.reserve(static_cast<std::size_t>(target_height) + 1);
    m_prefetch = std::make_unique<PrefetchState>();
    PrefetchState* state{m_prefetch.get()};
    const uint32_t first_height{static_cast<uint32_t>(m_chain_hashes.size())};
    state->worker = std::thread{[this, state, first_height, target_height] {
        try {
            for (uint32_t height{first_height}; height <= target_height; ++height) {
                {
                    std::unique_lock lock{state->mutex};
                    state->changed.wait(lock, [state] {
                        return state->stop || state->queue.size() < 2;
                    });
                    if (state->stop) break;
                }
                auto fetched{m_source.FetchBlock(height)};
                const bool success{static_cast<bool>(fetched)};
                {
                    std::lock_guard lock{state->mutex};
                    state->queue.push_back(PrefetchState::Item{height, std::move(fetched)});
                }
                state->changed.notify_all();
                if (!success || height == std::numeric_limits<uint32_t>::max()) break;
            }
        } catch (...) {
            std::lock_guard lock{state->mutex};
            state->exception = std::current_exception();
        }
        {
            std::lock_guard lock{state->mutex};
            state->done = true;
        }
        state->changed.notify_all();
    }};
    return Result<void>::Ok();
}

void SequentialSync::StopPrefetch()
{
    if (!m_prefetch) return;
    {
        std::lock_guard lock{m_prefetch->mutex};
        m_prefetch->stop = true;
    }
    m_prefetch->changed.notify_all();
    if (m_prefetch->worker.joinable()) m_prefetch->worker.join();
    m_prefetch.reset();
}

Result<FetchedBlock> SequentialSync::NextFetchedBlock(uint32_t height)
{
    if (!m_prefetch) return m_source.FetchBlock(height);
    std::unique_lock lock{m_prefetch->mutex};
    m_prefetch->changed.wait(lock, [this] {
        return !m_prefetch->queue.empty() || m_prefetch->done;
    });
    if (m_prefetch->queue.empty()) {
        const auto exception{m_prefetch->exception};
        lock.unlock();
        if (exception) {
            try {
                std::rethrow_exception(exception);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception& error) {
                return Result<FetchedBlock>::Err("block prefetch failed: " + std::string{error.what()});
            } catch (...) {
                return Result<FetchedBlock>::Err("block prefetch failed with an unknown exception");
            }
        }
        return Result<FetchedBlock>::Err("block prefetch ended before the requested height");
    }
    auto item{std::move(m_prefetch->queue.front())};
    m_prefetch->queue.pop_front();
    lock.unlock();
    m_prefetch->changed.notify_all();
    if (item.height != height) {
        return Result<FetchedBlock>::Err("block prefetch returned a non-contiguous height");
    }
    return std::move(item.result);
}

Result<void> SequentialSync::ValidateCurrentPoint()
{
    const auto point{CurrentPoint()};
    if (!point) return Result<void>::Err("cannot validate an empty chain point");
    auto active_hash{m_source.BlockHash(point->height)};
    if (!active_hash) return Result<void>::Err(active_hash.Error());
    if (active_hash.Value() != point->block_hash) {
        return Result<void>::Err(
            "active-chain reorganization detected at or below the sidecar tip; restore the last stable checkpoint");
    }
    return Result<void>::Ok();
}

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
    const uint32_t height{static_cast<uint32_t>(m_chain_hashes.size())};
    auto fetched{NextFetchedBlock(height)};
    if (!fetched) return Result<ProcessedBlock>::Err(fetched.Error());
    if (fetched.Value().height != height) {
        return Result<ProcessedBlock>::Err("fetched block height does not match the requested height");
    }
    metrics.block_hash_us = fetched.Value().block_hash_us;
    metrics.block_fetch_us = fetched.Value().block_fetch_us;

    const auto resolver{[this](uint32_t creation_height) -> Result<Hash256> {
        if (creation_height >= m_chain_hashes.size()) {
            return Result<Hash256>::Err("creation height is not in the processed chain-hash index");
        }
        return Result<Hash256>::Ok(m_chain_hashes[creation_height]);
    }};
    const auto parse_start{Clock::now()};
    auto delta{ParseVerboseBlockJson(fetched.Value().json.Value(), resolver)};
    if (!delta) return Result<ProcessedBlock>::Err(delta.Error());
    metrics.parse_us = micros(parse_start);
    if (delta.Value().point.height != height || delta.Value().point.block_hash != fetched.Value().hash) {
        return Result<ProcessedBlock>::Err("getblock result does not match the requested active-chain block");
    }
    if (height > 0 && delta.Value().previous_block_hash != m_chain_hashes.back()) {
        return Result<ProcessedBlock>::Err("block does not connect to the sidecar chain tip");
    }

    const auto modify_start{Clock::now()};
    const auto modified{m_forest.Modify(delta.Value().additions, delta.Value().deletions)};
    if (!modified) return Result<ProcessedBlock>::Err("could not apply block transition: " + modified.Error());
    metrics.modify_us = micros(modify_start);
    m_chain_hashes.push_back(fetched.Value().hash);
    metrics.total_us = micros(total_start);
    return Result<ProcessedBlock>::Ok(ProcessedBlock{delta.Take(), metrics});
}

} // namespace utreexo
