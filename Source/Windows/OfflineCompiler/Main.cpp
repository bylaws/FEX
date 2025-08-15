// SPDX-License-Identifier: MIT
// TODO: Things that affect code gen:
// VIXL_SIMULATOR preprocessor define
// FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS (?)

#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include "Common/Module.h"
#include "FEXCore/HLE/SyscallHandler.h"

#include <FEXCore/Core/Context.h>

#include "Common/ArgumentLoader.h"
#include "Common/Logging.h"
#include "Common/FEXAOTBundle.h"
#include "Common/Config.h"
#include "Common/InvalidationTracker.h"
#include "Common/OvercommitTracker.h"
#include "DummyHandlers.h"
#include "Common/CPUFeatures.h"
#include "Common/CodeMap.h"
#include "Common/Module.h"
#include "Common/PortabilityInfo.h"
#include "FEXCore/Utils/LogManager.h"
#include "SteamStub.h"

#include <FEXCore/Core/HostFeatures.h>

#include <OptionParser.h>

#include <xxhash.h>

#include <fmt/printf.h>

#include <fstream>


static void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

static void AssertHandler(const char* Message) {
  fmt::print("[ASSERT] {}\n", Message);
}

std::optional<FEX::Windows::InvalidationTracker> InvalidationTracker;
std::optional<FEX::Windows::OvercommitTracker> OvercommitTracker;

class AOTSyscallHandler : public FEXCore::HLE::SyscallHandler {
public:
  AOTSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    return {.NumArgs = 0, .HasReturn = false, .HostSyscallNumber = -1};
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
    //InvalidationTracker->ReprotectRWXIntervals(Start, Length);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override {
  }

  void MarkGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t Entry) override {
  }

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


LONG ExceptionHandler(_EXCEPTION_POINTERS *ExceptionInfo) {
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
    if (OvercommitTracker->HandleAccessViolation(FaultAddress))
      return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

struct MappedImage {
  HANDLE Section;
  uint64_t BaseAddress;
  uint64_t FileOffset;
  FEX::CodeMap::ParsedImage Info;
};

struct MapImagesResult {
  std::vector<MappedImage> MappedImages;
  bool SteamStubPresent;
};

MapImagesResult TryMapImages(std::vector<FEX::CodeMap::ParsedImage> &&ParsedImages) {
  MapImagesResult Result;
  for (auto& Image : ParsedImages) {
    if (Image.EntryPoints.empty()) {
       continue;
    }
    HANDLE File = CreateFileA(Image.FullPath.c_str(), GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING,  FILE_ATTRIBUTE_NORMAL, nullptr);
    if (File == INVALID_HANDLE_VALUE) {
      LogMan::Msg::EFmt("Couldn't find image: {}", Image.FullPath);
      continue;
    }

    HANDLE Section = CreateFileMappingA(File, nullptr, SEC_IMAGE | PAGE_EXECUTE_READ, 0, 0, nullptr);
    CloseHandle(File);
    if (Section == INVALID_HANDLE_VALUE) {
      LogMan::Msg::EFmt("Couldn't create section for image: {}", Image.FullPath);
      continue;
    }

    uint64_t BaseAddress = reinterpret_cast<uint64_t>(MapViewOfFile(Section, FILE_MAP_EXECUTE | FILE_MAP_READ, 0, 0, 0));
    if (!BaseAddress) {
      LogMan::Msg::EFmt("Couldn't map section for image: {}", Image.FullPath);
      CloseHandle(Section);
      continue;
    }

    LogMan::Msg::IFmt("Mapped image: {} @ {:X}", Image.FullPath, BaseAddress);

    auto Res = FEX::Windows::TryDecryptSteamStubIfPresent(BaseAddress);
    if (Res == FEX::Windows::TryDecryptSteamStubResult::DecryptFailure) {
      LogMan::Msg::EFmt("Unsupported SteamStub!");
      continue;
    } else if (Res == FEX::Windows::TryDecryptSteamStubResult::DecryptSuccess) {
      Result.SteamStubPresent = true;
    }

    // TODO: validate uniqueID
    InvalidationTracker->HandleImageMap(FEX::Windows::BaseName(Image.FullPath), BaseAddress);

    std::sort(Image.EntryPoints.begin(), Image.EntryPoints.end());

    Result.MappedImages.push_back({
      .Section = Section,
      .BaseAddress = BaseAddress,
      .Info = std::move(Image)
    });
  }

  return Result;
}

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  auto ParsedImages = FEX::CodeMap::ParseCodeMap(argv[1]);

  for (const auto& Image : ParsedImages) {
    LogMan::Msg::IFmt("Parsed {} codemap entries for {} ({})", Image.EntryPoints.size(), Image.FullPath, Image.UniqueId);
  }

  auto MainImageName = fextl::string{FEX::Windows::BaseName(ParsedImages[0].FullPath)};
  FEX::Config::LoadConfig(nullptr, MainImageName, nullptr, FEX::ReadPortabilityInformation());
  FEXCore::Config::ReloadMetaLayer();
  // Not applicable to Windows
  FEXCore::Config::Set(FEXCore::Config::ConfigOption::CONFIG_TSOAUTOMIGRATION, "0");
#ifdef _M_ARM64EC
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_64BIT);
#else
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
  FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_32BIT);
#endif
  fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  fextl::unique_ptr<AOTSyscallHandler> SyscallHandler = fextl::make_unique<AOTSyscallHandler>();
  const auto NtDll = GetModuleHandle("ntdll.dll");
  const bool IsWine = !!GetProcAddress(NtDll, "wine_get_version");
  OvercommitTracker.emplace(IsWine);
  auto HostFeatures = FEX::Windows::CPUFeatures::FetchHostFeatures(IsWine);
  fextl::unique_ptr<FEXCore::Context::Context> CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore();
  AddVectoredExceptionHandler(1, ExceptionHandler);
  std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*> Threads;
  InvalidationTracker.emplace(*CTX, Threads);
  auto [MappedImages, SteamStubPresent] = TryMapImages(std::move(ParsedImages));
  auto* Thread = CTX->CreateThread(0, 0);

  // FEX AOT bundle
  int fd = open(fmt::format("{}\\{}.fab",  getenv("LOCALAPPDATA"), MappedImages[0].Info.UniqueId).c_str(), _O_CREAT | _O_APPEND | _O_BINARY | _O_RDWR);
  FEX::Windows::FAB::Header Header {
    .SteamStubPresent = SteamStubPresent,
    .NumImages = static_cast<uint32_t>(MappedImages.size()),
  };
  write(fd, &Header, sizeof(Header));

  for (auto& Image : MappedImages) {
    LogMan::Msg::IFmt("Compiling module {}: {} entrypoints", Image.Info.FullPath, Image.Info.EntryPoints.size());
    CTX->ClearCodeCache(Thread, true);

    Image.FileOffset = static_cast<uint64_t>(lseek64(fd, 0, SEEK_CUR));
    for (uint64_t EntryPoint : Image.Info.EntryPoints) {
      CTX->CompileRIP(Thread, Image.BaseAddress + EntryPoint);
    }
    CTX->FinalizeAOTIRCache(*Thread, fd, Image.BaseAddress);
  }


  FEX::Windows::FAB::Trailer Trailer {
    .ImageDescSectionOffset = static_cast<uint64_t>(lseek64(fd, 0, SEEK_END))
  };

  std::vector<uint8_t> Buffer;
  for (const auto& Image : MappedImages) {
    Buffer.resize(sizeof(FEX::Windows::FAB::ImageDesc) + Image.Info.UniqueId.size() + 1);
    auto Desc = new (Buffer.data()) FEX::Windows::FAB::ImageDesc();
    Desc->FileOffset = Image.FileOffset;
    memcpy(Desc->UniqueId, Image.Info.UniqueId.c_str(), Image.Info.UniqueId.size() + 1);
    write(fd, Buffer.data(), Buffer.size());
  }

  write(fd, &Trailer, sizeof(FEX::Windows::FAB::Trailer));

  close(fd);

  return 0;
}
