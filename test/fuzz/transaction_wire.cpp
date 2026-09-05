#include <utreexo/transaction_wire.h>

#include <array>
#include <cstdlib>
#include <span>

using namespace utreexo;
using namespace utreexo::txwire;

namespace {

const PreparedTransactionProof& Prepared()
{
    static const auto proof = [] {
        // One ordinary input, one empty-script output. Use nonzero vout=7 to
        // expose cumulative flag shifts under repeated request serialization.
        std::array<std::byte, 60> raw{};
        raw[0] = std::byte{2};
        raw[4] = std::byte{1};
        raw[5] = std::byte{1};
        raw[37] = std::byte{7};
        raw[46] = std::byte{1};
        const CompactLeafData leaf{200, 1000, ScriptPubkeyType::OTHER, {std::byte{0x51}}};
        return PreparedTransactionProof::Create(Transaction::Parse(raw).Take(),
            Proof{{0}, {Hash256{}, Hash256{}, Hash256{}}}, {leaf}, 8).Take();
    }();
    return proof;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    const auto bytes{std::span{reinterpret_cast<const std::byte*>(data), size}};
    static_cast<void>(Transaction::Parse(bytes));
    static_cast<void>(ParseUtreexoTransaction(bytes));
    auto announcements{ParseTransactionAnnouncements(bytes)};
    if (announcements) {
        auto encoded{SerializeTransactionAnnouncements(announcements.Value())};
        if (!encoded || ParseTransactionAnnouncements(encoded.Value()).Value() != announcements.Value()) std::abort();
    }
    auto requests{ParseTransactionProofRequests(bytes)};
    if (requests) {
        auto encoded{SerializeTransactionProofRequests(requests.Value())};
        if (!encoded || ParseTransactionProofRequests(encoded.Value()).Value() != requests.Value()) std::abort();
        for (auto& request : requests.Value()) {
            request.txid = Prepared().Tx().Txid();
            auto response{Prepared().Serialize(request)};
            if (!response) continue;
            auto decoded{ParseUtreexoTransaction(response.Value())};
            if (!decoded || decoded.Value().transaction.Txid() != Prepared().Tx().Txid() ||
                Prepared().Serialize(request).Value() != response.Value()) std::abort();
        }
    }
    return 0;
}
