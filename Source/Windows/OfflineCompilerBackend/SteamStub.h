#pragma once

#include <cstdint>

namespace FEX::Windows {
enum class TryDecryptSteamStubResult { NotPresent = 0, DecryptSuccess, DecryptFailure };
TryDecryptSteamStubResult TryDecryptSteamStubIfPresent(uint64_t BaseAddress);
} // namespace FEX::Windows
