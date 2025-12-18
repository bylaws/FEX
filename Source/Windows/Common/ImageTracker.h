// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <mutex>
#include <map>
#include <shared_mutex>
#include <string_view>

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CodeCache.h>

#include "Common/VolatileMetadata.h"
#include "Module.h"

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
#ifdef _M_ARM_64EC
using ArchImageNtHeaders = IMAGE_NT_HEADERS64;
using ArchImageLoadConfigDirectory = _IMAGE_LOAD_CONFIG_DIRECTORY64;
#else
using ArchImageNtHeaders = IMAGE_NT_HEADERS32;
using ArchImageLoadConfigDirectory = _IMAGE_LOAD_CONFIG_DIRECTORY32;
#endif

/**
 * @brief Tracks mapped PE code images
 */
class ImageTracker : public FEXCore::CodeMapOpener {
public:
  ImageTracker(FEXCore::Context::Context& CTX);
  FEXCore::ExecutableFileSectionInfo HandleImageMap(std::string_view Path, uint64_t Address, bool MainImage);
  void HandleImageUnmap(uint64_t Address, uint64_t Size);

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(uint64_t Address);

  int OpenCodeMapFile() override;

private:
  struct MappedImageInfo {
    FEXCore::ExecutableFileInfo Info;
    FEXCore::ExecutableFileSectionInfo SectionInfo;

    MappedImageInfo(std::string_view Path, uint64_t Address,
      ArchImageNtHeaders* Nt, fextl::unordered_map<uint32_t, FEXCore::GuestRelocationType> Relocations);
  };

  struct AOTImageInfo {
    std::byte* Data;
  };

  FEXCore::Context::Context& CTX;

  void LoadAOTBundle(MappedImageInfo& Info);

  FEX_CONFIG_OPT(ExtendedVolatileMetadataConfig, EXTENDEDVOLATILEMETADATA);
  fextl::unordered_map<fextl::string, FEX::VolatileMetadata::ExtendedVolatileMetadata> ExtendedMetaData;

  std::shared_mutex ImagesLock;
  std::map<uint64_t, MappedImageInfo> MappedImages;
  std::map<fextl::string, AOTImageInfo> AOTImages;
  std::map<fextl::string, uint32_t> ImageCodeMapIds;

  std::string ActiveCodeMapPath;
};

} // namespace FEX::Windows