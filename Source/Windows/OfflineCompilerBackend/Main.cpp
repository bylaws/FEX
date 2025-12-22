// SPDX-License-Identifier: MIT

#include <cstdio>
#include <fstream>
#include <optional>
#include <string>
#include <vector>
#include <filesystem>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdint>

#include <fcntl.h>
#include <io.h>
#include <fmt/printf.h>

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/LogManager.h>

#include "Common/ArgumentLoader.h"
#include "Common/Config.h"
#include "Common/CPUFeatures.h"
#include "Common/Handle.h"
#include "Common/ImageTracker.h"
#include "Common/InvalidationTracker.h"
#include "Common/Logging.h"
#include "Common/Module.h"
#include "Common/OvercommitTracker.h"
#include "Common/PortabilityInfo.h"

#include "SteamStub.h"
#include "DummyHandlers.h"

namespace {
std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::ImageTracker> ImageTracker;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;

struct ImageInfo {
  FEXCore::ExecutableFileInfo Info;
  FEXCore::CodeMap::ParsedContents Contents;
  bool RecompileCode {};

  bool CheckNeedsRecompile(const std::filesystem::path& CodeMapPath, const std::filesystem::path& CachePath) {
    std::error_code ec;
    const auto CodeMapTime = std::filesystem::last_write_time(CodeMapPath, ec);
    if (ec) {
      return true;
    }

    const auto CacheTime = std::filesystem::last_write_time(CachePath, ec);
    if (ec) {
      return true;
    }

    return CodeMapTime > CacheTime;
  }
};

void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

void AssertHandler(const char* Message) {
  fmt::print("[ASSERT] {}\n", Message);
}

bool RelocateMappedImage(HMODULE Module) {
  const auto* NtHeaders = reinterpret_cast<FEX::Windows::ArchImageNtHeaders*>(RtlImageNtHeader(Module));
  if (!NtHeaders) {
    return false;
  }

  const auto BaseAddress = reinterpret_cast<uintptr_t>(Module);
  const auto PreferredBase = NtHeaders->OptionalHeader.ImageBase;
  const auto Delta = static_cast<intptr_t>(BaseAddress - PreferredBase);

  // Wine will automatically relocate all DLLs to their mapped address, but PE relocations must still be applied so
  // FEXCore can correctly transform them into FEX relocations
  if (Delta == 0) {
    return true;
  }

  ULONG RelocSize = 0;
  auto* RelocBlock =
    reinterpret_cast<IMAGE_BASE_RELOCATION*>(RtlImageDirectoryEntryToData(Module, true, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocSize));

  if (!RelocBlock || RelocSize == 0) {
    return true;
  }

  // Reprotect all sections as RW to apply relocations, saving their prior protections
  struct SectionPatchState {
    void* Address;
    SIZE_T Size;
    DWORD PreviousProtection;
  };
  std::vector<SectionPatchState> SectionStates;
  SectionStates.reserve(NtHeaders->FileHeader.NumberOfSections);

  auto* SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
  const auto* SectionHeaderEnd = SectionHeader + NtHeaders->FileHeader.NumberOfSections;
  for (; SectionHeader != SectionHeaderEnd; ++SectionHeader) {
    if (SectionHeader->SizeOfRawData == 0) {
      continue;
    }

    const auto SecAddr = reinterpret_cast<void*>(BaseAddress + SectionHeader->VirtualAddress);
    const SIZE_T SecSize = SectionHeader->Misc.VirtualSize;

    DWORD OldProt = 0;
    if (!VirtualProtect(SecAddr, SecSize, PAGE_READWRITE, &OldProt)) {
      return false;
    }

    SectionStates.push_back({SecAddr, SecSize, OldProt});
  }

  // Apply relocations to all sections
  const uintptr_t RelocEnd = reinterpret_cast<uintptr_t>(RelocBlock) + RelocSize;
  const uint32_t ImageSize = NtHeaders->OptionalHeader.SizeOfImage;

  while (reinterpret_cast<uintptr_t>(RelocBlock) < RelocEnd && RelocBlock->SizeOfBlock) {
    if (RelocBlock->VirtualAddress >= ImageSize) {
      return false;
    }

    const auto Count = (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
    const auto PageAddress = BaseAddress + RelocBlock->VirtualAddress;

    RelocBlock = LdrProcessRelocationBlock(PageAddress, Count, reinterpret_cast<USHORT*>(RelocBlock + 1), Delta);

    if (!RelocBlock) {
      return false;
    }
  }

  // Restore sections to previous protection states
  for (const auto& State : SectionStates) {
    DWORD Ignored;
    if (!VirtualProtect(State.Address, State.Size, State.PreviousProtection, &Ignored)) {
      return false;
    }
  }

  LogMan::Msg::IFmt("Relocated image {:X} -> {:X}", PreferredBase, BaseAddress);
  return true;
}

#ifdef _M_ARM_64EC
void* MapView(HANDLE SectionHandle) {
  return MapViewOfFile(SectionHandle, FILE_MAP_EXECUTE | FILE_MAP_READ, 0, 0, 0);
}
#else
void* MapView(HANDLE SectionHandle) {
  void* BaseAddress = nullptr;
  SIZE_T ViewSize = 0;
  LARGE_INTEGER Offset {};

  // Map images in the lower 32-bits for WOW64 so relocations can be correctly applied
  const ULONG_PTR ZeroBits = 0x7fffffff;

  NTSTATUS Status =
    NtMapViewOfSection(SectionHandle, GetCurrentProcess(), &BaseAddress, ZeroBits, 0, &Offset, &ViewSize, ViewShare, 0, PAGE_EXECUTE_READ);

  if (Status < 0) {
    return nullptr;
  }

  return BaseAddress;
}
#endif

struct MappedImage {
  uint64_t BaseAddress;
  FEXCore::ExecutableFileSectionInfo SectionInfo;
  ImageInfo Info;
};

struct TryMapImagesResult {
  std::vector<MappedImage> MappedImages;
  bool SteamStubPresent {};
};

TryMapImagesResult
TryMapImages(std::unordered_map<FEXCore::CodeMapFileId, ImageInfo>&& Images) {
  TryMapImagesResult Result;

  for (auto& [ID, Info] : Images) {
    if (!Info.RecompileCode || Info.Contents.Blocks.empty()) {
      continue;
    }

    FEX::Windows::ScopedHandle File {CreateFileA(Info.Contents.Filename.c_str(), GENERIC_READ | SYNCHRONIZE,
                                                 FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!File) {
      LogMan::Msg::EFmt("Couldn't find image: {}", Info.Contents.Filename);
      continue;
    }

    FEX::Windows::ScopedHandle Section {CreateFileMappingA(*File, nullptr, SEC_IMAGE | PAGE_EXECUTE_READ, 0, 0, nullptr)};
    if (!Section) {
      LogMan::Msg::EFmt("Couldn't create section for image: {}", Info.Contents.Filename);
      continue;
    }

    void* Mapping = MapView(*Section);
    if (!Mapping) {
      LogMan::Msg::EFmt("Couldn't map section for image: {}", Info.Contents.Filename);
      continue;
    }

    if (!RelocateMappedImage(reinterpret_cast<HMODULE>(Mapping))) {
      LogMan::Msg::EFmt("Failed to apply image relocations");
      continue;
    }

    uint64_t BaseAddress = reinterpret_cast<uint64_t>(Mapping);
    LogMan::Msg::IFmt("Mapped image: {} @ {:X}", Info.Contents.Filename, BaseAddress);

    InvalidationTracker->HandleImageMap(FEX::Windows::BaseName(Info.Contents.Filename), BaseAddress);
    auto SectionInfo = ImageTracker->HandleImageMap(Info.Contents.Filename, BaseAddress, Info.Contents.IsExecutable);

    auto Res = FEX::Windows::TryDecryptSteamStubIfPresent(BaseAddress);
    if (Res == FEX::Windows::TryDecryptSteamStubResult::DecryptFailure) {
      LogMan::Msg::EFmt("Unsupported SteamStub!");
      continue;
    } else if (Res == FEX::Windows::TryDecryptSteamStubResult::DecryptSuccess) {
      Result.SteamStubPresent = true;
    }

    Result.MappedImages.push_back(MappedImage {.BaseAddress = BaseAddress, .SectionInfo = SectionInfo, .Info = std::move(Info)});
  }

  return Result;
}

} // namespace

class AOTSyscallHandler : public FEXCore::HLE::SyscallHandler {
public:
  AOTSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    return 0;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    return ImageTracker->LookupExecutableFileSection(Address);
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {}

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {}

  void MarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->MarkRange(Start, Length);
  }

  void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) override {
    OvercommitTracker->UnmarkRange(Start, Length);
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    return InvalidationTracker->QueryExecutableRange(Address);
  }

  void PreCompile() override {}
};

LONG ExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo) {
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
    if (OvercommitTracker->HandleAccessViolation(FaultAddress)) {
      return EXCEPTION_CONTINUE_EXECUTION;
    }
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  if (argc < 4) {
    fmt::print("Usage: {} <main_image_name> <image_cache_dir> <codemap_file>\n", argv[0]);
    return 1;
  }

  fextl::string MainImageName {argv[1]};
  std::filesystem::path ImageCacheDir {argv[2]};
  std::ifstream CodeMap(argv[3], std::ios_base::binary);
  if (!CodeMap) {
    fmt::print("Could not open {}\n", argv[3]);
    return 1;
  }

  FEX::Config::LoadConfig(MainImageName, _environ, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();

#ifdef _M_ARM64EC
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
#else
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
#endif

  const auto CacheDir = std::filesystem::path(FEX::Config::GetCacheDirectory());
  const auto ReadyDir = CacheDir / "codemap" / "ready";
  const auto MetadataPath = ImageCacheDir / "metadata";

  const auto NtDll = GetModuleHandle("ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");

  auto HostFeatures = FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine);

  std::unordered_map<FEXCore::CodeMapFileId, ImageInfo> Images;
  std::unordered_set<std::string> ToPreserve;

  auto Parsed = FEXCore::CodeMap::ParseCodeMap(CodeMap);

  for (auto& [ID, Contents] : Parsed) {
    FEXCore::ExecutableFileInfo FEXInfo {.FileId = ID, .Filename = Contents.Filename};

    const auto BaseFilename = FEXCore::CodeMap::GetBaseFilename(FEXInfo, false);
    const auto LibCodeMapPath = ReadyDir / BaseFilename;
    const auto LibCachePath = ImageCacheDir / BaseFilename;

    // Handle dependencies by loading their specific codemap
    if (!Contents.IsExecutable && Contents.Blocks.empty()) {
      std::ifstream DepCodeMap(LibCodeMapPath, std::ios_base::binary);
      if (!DepCodeMap) {
        fmt::print("Could not open dependency codemap: {}\n", LibCodeMapPath.string());
      } else {
        auto DepParsed = FEXCore::CodeMap::ParseCodeMap(DepCodeMap);
        if (auto DepIt = DepParsed.find(ID); DepIt != DepParsed.end()) {
          Contents = std::move(DepIt->second);
        }
      }
    }

    LogMan::Msg::IFmt("Parsed {} codemap entries for {} ({})", Contents.Blocks.size(), Contents.Filename, ID);

    auto [It, _] = Images.emplace(ID, ImageInfo {.Info = std::move(FEXInfo), .Contents = std::move(Contents), .RecompileCode = false});

    auto& CurrentImage = It->second;
    CurrentImage.RecompileCode = CurrentImage.CheckNeedsRecompile(LibCodeMapPath, LibCachePath);
    ToPreserve.emplace(BaseFilename);
  }

  OvercommitTracker.emplace(IsWine);

  fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  fextl::unique_ptr<AOTSyscallHandler> SyscallHandler = fextl::make_unique<AOTSyscallHandler>();
  fextl::unique_ptr<FEXCore::Context::Context> CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  CTX->GetCodeCache().InitiateCacheGeneration();

  AddVectoredExceptionHandler(1, ExceptionHandler);

  std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;
  InvalidationTracker.emplace(*CTX, Threads);
  ImageTracker.emplace(*CTX, true);

  // Images that don't need recompile will be filtered out here
  auto [MappedImages, IsSteamStubPresent] = TryMapImages(std::move(Images));

  auto* Thread = CTX->CreateThread(0, 0);
  auto Frame = Thread->CurrentFrame;
  FEXCore::Core::CPUState::gdt_segment Segments[32] {};

#ifdef _M_ARM64EC
  static constexpr size_t DefaultCS {FEXCore::Core::CPUState::DEFAULT_USER_CS};
#else
  static constexpr size_t DefaultCS {4};
#endif

  // Setup initial code-segment GDT
  auto& GDT = Segments[DefaultCS];
  FEXCore::Core::CPUState::SetGDTBase(&GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(&GDT, 0xF'FFFFU);
#ifdef _M_ARM64EC
  GDT.L = 1; // L = Long Mode = 64-bit
  GDT.D = 0; // D = Default Operand SIze = Reserved
#else
  GDT.L = 0; // L = Long Mode = 32-bit
  GDT.D = 1; // D = Default Operand Size = 32-bit
#endif

  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &Segments[0];
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &Segments[0];
  Frame->State.cs_idx = DefaultCS << 3;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(GDT);

  if (!std::filesystem::exists(ImageCacheDir)) {
    if (!std::filesystem::create_directories(ImageCacheDir)) {
      LogMan::Msg::EFmt("Error creating directory {}", ImageCacheDir.string());
      return 1;
    }
  }

  for (auto& Image : MappedImages) {
    LogMan::Msg::IFmt("Compiling module {}: {} entrypoints", Image.Info.Contents.Filename, Image.Info.Contents.Blocks.size());
    CTX->ClearCodeCache(Thread, true);

    for (uint64_t EntryPoint : Image.Info.Contents.Blocks) {
      CTX->CompileRIP(Thread, Image.BaseAddress + EntryPoint);
    }

    auto Filename = ImageCacheDir / FEXCore::CodeMap::GetBaseFilename(Image.SectionInfo.FileInfo, false);
    auto StagingFilename = Filename;
    StagingFilename += ".new";

    int fd = _open(StagingFilename.string().c_str(), _O_CREAT | _O_WRONLY | _O_BINARY, 0644);
    if (fd != -1) {
      CTX->GetCodeCache().SaveData(*Thread, fd, Image.SectionInfo, Image.BaseAddress);
      _close(fd);

      std::error_code ec;
      std::filesystem::rename(StagingFilename, Filename, ec);
    } else {
      LogMan::Msg::EFmt("Failed to open output file: {}", StagingFilename.string());
    }
  }

  for (const auto& entry : std::filesystem::directory_iterator(ImageCacheDir)) {
    if (entry.is_regular_file()) {
      const auto filename = entry.path().filename().string();
      if (ToPreserve.find(filename) == ToPreserve.end()) {
        std::error_code ec;
        if (std::filesystem::remove(entry.path(), ec)) {
          LogMan::Msg::IFmt("Deleted stale file: {}", filename);
        }
      }
    }
  }

  return 0;
}