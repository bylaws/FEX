// SPDX-License-Identifier: MIT
#pragma once

#include "fmt/color.h"
#include <cstdint>
#include <mutex>
#include <map>
#include <shared_mutex>
#include <string_view>
#include <span>

#include "Module.h"
#include "Common/CodeMap.h"
#include <FEXCore/Utils/CompilerDefs.h>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
/**
 * @brief Tracks mapped PE code images
 */
class ImageTracker {
public:
  ImageTracker(FEXCore::Context::Context& CTX);
  void HandleImageMap(std::string_view Path, uint64_t Address, bool MainImage);
  void HandleImageUnmap(uint64_t Address);

  void MarkGuestBlockEntry(uint64_t Address);

  class IOQueue {
  private:
    static constexpr size_t IOQueueSize = 0x10000;
    HANDLE File;
    std::array<uint8_t, IOQueueSize> Buffer;
    RTL_CRITICAL_SECTION CS;
    RTL_CONDITION_VARIABLE ReadCV;
    RTL_CONDITION_VARIABLE WriteCV;
    size_t ReadPointer{0};
    size_t WritePointer{0};

    static void ThreadEntry(IOQueue *Self) {
      Self->ThreadProc();
    }

    void ThreadProc();

  public:
    IOQueue(HANDLE File);

    bool StartThread();

    void Append(std::span<uint8_t> Data);
  };

  std::optional<IOQueue> CodeMapWriteQueue;

private:
  struct MappedImageInfo {
    std::string FullPath;
    uint32_t PETimeDateStamp;
    uint32_t PESizeOfImage;
    uint32_t CodeMapId;

    std::string GetUniqueId() const {
      return fmt::format("{}-{:08X}{:08X}", FEX::Windows::BaseName(FullPath), PETimeDateStamp, PESizeOfImage);
    } 
  };

  struct AOTImageInfo {
    uint8_t* Data;
  };

  FEXCore::Context::Context& CTX;

  uint8_t *MappedAOTBundle = nullptr;
  uint64_t AOTBundleSize = 0;

  void LoadAOTBundle(uint64_t MainImageAddress);

  std::shared_mutex ImagesLock;
  uint32_t NextCodeMapId{0};
  std::map<uint64_t, MappedImageInfo> MappedImages;
  std::map<std::string, AOTImageInfo> AOTImages;
  std::map<std::string, uint32_t> ImageCodeMapIds;
};

} // namespace FEX::Windows
