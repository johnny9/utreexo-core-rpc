#include <utreexo/p2p.h>

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    const auto bytes{std::span{reinterpret_cast<const std::byte*>(data), size}};
    static_cast<void>(utreexo::ParseGetUtreexoProof(bytes));
    for (const auto network : {
             utreexo::BitcoinNetwork::MAINNET,
             utreexo::BitcoinNetwork::TESTNET3,
             utreexo::BitcoinNetwork::SIGNET,
             utreexo::BitcoinNetwork::REGTEST}) {
        auto message{utreexo::DecodeP2PMessage(network, bytes, 1024U * 1024U)};
        if (message && message.Value().command == "getuproof") {
            static_cast<void>(utreexo::ParseGetUtreexoProof(message.Value().payload));
        }
    }
    return 0;
}
