#pragma once

#include <cstdint>
#include <FEXCore/Utils/CompilerDefs.h>

namespace FEX::Windows::FAB {
  struct FEX_PACKED Header {
    char Magic[3] = {'F', 'A', 'B'};
    uint8_t FormatVersion {1};
    uint8_t SteamStubPresent;
    uint32_t NumImages;
  };

  struct FEX_PACKED ImageDesc {
    uint64_t FileOffset;
    char UniqueId[];
  };

  struct FEX_PACKED Trailer {
    uint64_t ImageDescSectionOffset;
  };
}