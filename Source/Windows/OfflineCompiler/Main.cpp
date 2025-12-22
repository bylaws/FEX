// SPDX-License-Identifier: MIT

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <map>

#include <fmt/printf.h>
#include <fcntl.h>
#include <io.h>
#include <winternl.h>

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include "Common/Config.h"

#include "Common/ImageTracker.h"


namespace {
void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

void AssertHandler(const char* Message) {
  fmt::print("[ASSERT] {}\n", Message);
}

struct CodeMapDesc {
  std::unordered_map<FEXCore::CodeMapFileId, FEXCore::ExecutableFileInfo> Dependencies;
  FEXCore::CodeMap::ParsedContents Contents;

  explicit CodeMapDesc(FEXCore::CodeMap::ParsedContents InContents)
    : Contents {std::move(InContents)} {}
};

struct PEInfo {
  uint32_t TimeDateStamp;
  uint32_t SizeOfImage;
  bool Is64Bit;
};

// Global cache to store PE info to avoid re-reading files multiple times
static std::map<std::filesystem::path, std::optional<PEInfo>> GlobalPEInfoCache;

std::optional<PEInfo> GetPEInfo(const std::filesystem::path& Path) {
  auto It = GlobalPEInfoCache.find(Path);
  if (It != GlobalPEInfoCache.end()) {
    return It->second;
  }

  auto LoadInfo = [](const std::filesystem::path& Path) -> std::optional<PEInfo> {
    std::ifstream File(Path, std::ios::binary);
    if (!File) {
      return std::nullopt;
    }

    IMAGE_DOS_HEADER DosHeader {};
    if (!File.read(reinterpret_cast<char*>(&DosHeader), sizeof(DosHeader))) {
      return std::nullopt;
    }

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
      return std::nullopt;
    }

    File.seekg(DosHeader.e_lfanew, std::ios::beg);
    if (File.fail()) {
      return std::nullopt;
    }

    uint32_t PeSignature = 0;
    if (!File.read(reinterpret_cast<char*>(&PeSignature), sizeof(PeSignature))) {
      return std::nullopt;
    }
    if (PeSignature != IMAGE_NT_SIGNATURE) {
      return std::nullopt;
    }

    IMAGE_FILE_HEADER FileHeader {};
    if (!File.read(reinterpret_cast<char*>(&FileHeader), sizeof(FileHeader))) {
      return std::nullopt;
    }

    uint16_t OptMagic = 0;
    auto OptHeaderPos = File.tellg();
    if (!File.read(reinterpret_cast<char*>(&OptMagic), sizeof(OptMagic))) {
      return std::nullopt;
    }
    File.seekg(OptHeaderPos, std::ios::beg);

    uint32_t SizeOfImage = 0;
    bool Is64Bit = false;

    if (OptMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      IMAGE_OPTIONAL_HEADER64 OptHeader64 {};
      if (!File.read(reinterpret_cast<char*>(&OptHeader64), sizeof(OptHeader64))) {
        return std::nullopt;
      }
      SizeOfImage = OptHeader64.SizeOfImage;
      Is64Bit = true;
    } else if (OptMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      IMAGE_OPTIONAL_HEADER32 OptHeader32 {};
      if (!File.read(reinterpret_cast<char*>(&OptHeader32), sizeof(OptHeader32))) {
        return std::nullopt;
      }
      SizeOfImage = OptHeader32.SizeOfImage;
      Is64Bit = false;
    } else {
      return std::nullopt;
    }

    return PEInfo {.TimeDateStamp = FileHeader.TimeDateStamp, .SizeOfImage = SizeOfImage, .Is64Bit = Is64Bit};
  };

  auto Result = LoadInfo(Path);
  GlobalPEInfoCache[Path] = Result;
  if (!Result) {
    LogMan::Msg::EFmt("Bad PE file: {}", Path.string());
  }
  return Result;
}

FEXCore::CodeMapFileId GetFileId(const std::filesystem::path& Path) {
  auto Info = GetPEInfo(Path);
  if (!Info) {
    return {};
  }
  return FEX::Windows::ComputeCodeMapId(Path.filename().string(), Info->TimeDateStamp, Info->SizeOfImage);
}

void WriteCodeMap(FEXCore::ExecutableFileInfo& File, const std::filesystem::path& OutputPath, const fextl::set<uint64_t>& Blocks,
                  bool IsExecutable, const std::unordered_map<FEXCore::CodeMapFileId, FEXCore::ExecutableFileInfo>& Dependencies) {

  std::string OutputPathStr = OutputPath.string();
  LogMan::Msg::IFmt("Writing {} blocks to {}", Blocks.size(), OutputPathStr);

  struct WindowsCodeMapOpener : FEXCore::CodeMapOpener {
    int FD = -1;

    WindowsCodeMapOpener(const std::string& Filename) {
      FD = open(Filename.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_APPEND | _O_BINARY, 0644);
    }

    int OpenCodeMapFile() override {
      return FD;
    }
  };

  WindowsCodeMapOpener Opener(OutputPathStr);
  if (Opener.FD == -1) {
    LogMan::Msg::EFmt("Failed to open output file: {}", OutputPathStr);
    return;
  }

  FEXCore::CodeMapWriter OutputCodeMap(Opener, true);

  OutputCodeMap.AppendLibraryLoad(File);

  if (IsExecutable) {
    OutputCodeMap.AppendSetMainExecutable(File);
    for (const auto& [_, Dependency] : Dependencies) {
      OutputCodeMap.AppendLibraryLoad(Dependency);
    }
  }

  for (const auto& Block : Blocks) {
    OutputCodeMap.AppendBlock(FEXCore::ExecutableFileSectionInfo {File, 0}, Block);
  }
}

fextl::map<FEXCore::CodeMapFileId, CodeMapDesc> LoadPendingCodeMaps(const std::filesystem::path& PendingDir) {
  fextl::map<FEXCore::CodeMapFileId, CodeMapDesc> Merged;

  for (const auto& Entry : std::filesystem::directory_iterator(PendingDir)) {
    if (!Entry.is_regular_file()) {
      continue;
    }

    std::ifstream CodeMapStream(Entry.path(), std::ios_base::binary);
    if (!CodeMapStream) {
      LogMan::Msg::EFmt("Could not open pending map: {}", Entry.path().string());
      continue;
    }

    auto Parsed = FEXCore::CodeMap::ParseCodeMap(CodeMapStream);
    CodeMapStream.close();

    for (auto& [ID, Contents] : Parsed) {
      auto [It, Inserted] = Merged.try_emplace(ID, Contents);

      if (!Inserted) {
        It->second.Contents.Blocks.merge(Contents.Blocks);
      }

      if (It->second.Contents.IsExecutable) {
        for (const auto& [DepID, DepContents] : Parsed) {
          if (DepID != ID) {
            It->second.Dependencies.try_emplace(DepID, FEXCore::ExecutableFileInfo {.FileId = DepID, .Filename = DepContents.Filename});
          }
        }
      }
    }

    // Now codemaps are parsed and merged into an in-memory map delete the temp on-disk files
    std::error_code ec;
    std::filesystem::remove(Entry.path(), ec);
  }

  return Merged;
}

void MergeAndWriteCodeMap(FEXCore::CodeMapFileId ID, CodeMapDesc& Desc, const std::filesystem::path& ReadyDir) {
  FEXCore::ExecutableFileInfo Info {.FileId = ID, .Filename = Desc.Contents.Filename};
  auto OutputPath = ReadyDir / FEXCore::CodeMap::GetBaseFilename(Info, false);

  if (std::filesystem::exists(OutputPath)) {
    if (std::ifstream OrigCodeMap {OutputPath, std::ios_base::binary}) {
      auto Parsed = FEXCore::CodeMap::ParseCodeMap(OrigCodeMap);

      for (auto& [OrigID, OrigContents] : Parsed) {
        if (OrigID == ID) {
          Desc.Contents.Blocks.merge(OrigContents.Blocks);
        } else {
          Desc.Dependencies.try_emplace(OrigID, FEXCore::ExecutableFileInfo {.FileId = OrigID, .Filename = OrigContents.Filename});
        }
      }
    }
    std::error_code ec;
    std::filesystem::remove(OutputPath, ec);
  }

  WriteCodeMap(Info, OutputPath, Desc.Contents.Blocks, Desc.Contents.IsExecutable, Desc.Dependencies);
}

HANDLE LaunchOfflineCompiler(const std::filesystem::path& CodeMapPath, const FEXCore::ExecutableFileInfo& MainInfo) {
  auto PEInfo = GetPEInfo(MainInfo.Filename);
  if (!PEInfo) {
    LogMan::Msg::EFmt("Could not query PE Info for executable: {}", MainInfo.Filename);
    return INVALID_HANDLE_VALUE;
  }
  std::string ExeName;
  if (PEInfo->Is64Bit) {
    ExeName = "FEXOfflineCompilerBackendARM64EC.exe";
  } else {
    ExeName = "FEXOfflineCompilerBackendWOW64.exe";
  }

  std::string MainImageName = std::filesystem::path(MainInfo.Filename).filename().string();

  const auto CacheDir = std::filesystem::path(FEX::Config::GetCacheDirectory());
  const auto ImageCacheDir = CacheDir / "cache" / FEXCore::CodeMap::GetBaseFilename(MainInfo, false);

  std::string Args = fmt::format("\"{}\" \"{}\" \"{}\" \"{}\"", ExeName, MainImageName, ImageCacheDir.string(), CodeMapPath.string());

  LogMan::Msg::IFmt("Launching {} for {}", ExeName, MainImageName);

  STARTUPINFOA si {};
  PROCESS_INFORMATION pi {};
  si.cb = sizeof(si);

  if (!CreateProcessA(nullptr, Args.data(), nullptr, nullptr, false, 0, nullptr, nullptr, &si, &pi)) {
    LogMan::Msg::EFmt("Failed to launch offline compiler for {}", CodeMapPath.string());
    return INVALID_HANDLE_VALUE;
  }

  CloseHandle(pi.hThread);
  return pi.hProcess;
}

// Returns the ExecutableFileInfo of the main executable if valid, nullopt otherwise
std::optional<FEXCore::ExecutableFileInfo> ValidateAndPruneCodeMap(const std::filesystem::path& Path) {
  std::ifstream CodeMapStream(Path, std::ios_base::binary);
  if (!CodeMapStream) {
    return std::nullopt;
  }
  auto ParsedMap = FEXCore::CodeMap::ParseCodeMap(CodeMapStream);
  CodeMapStream.close();

  if (ParsedMap.empty()) {
    std::filesystem::remove(Path);
    return std::nullopt;
  }
  auto MainIt = ParsedMap.size() == 1 ?
                  ParsedMap.begin() :
                  std::find_if(ParsedMap.begin(), ParsedMap.end(), [](const auto& KV) { return KV.second.IsExecutable; });

  if (MainIt == ParsedMap.end()) {
    std::filesystem::remove(Path);
    return std::nullopt;
  }

  if (GetFileId(MainIt->second.Filename) != MainIt->first) {
    std::filesystem::remove(Path);
    return std::nullopt;
  }

  if (MainIt->second.IsExecutable) {
    FEXCore::ExecutableFileInfo MainInfo {.FileId = MainIt->first, .Filename = MainIt->second.Filename};

    std::unordered_map<FEXCore::CodeMapFileId, FEXCore::ExecutableFileInfo> ValidDependencies;
    bool DependenciesChanged = false;

    for (const auto& [DepID, DepContent] : ParsedMap) {
      if (DepID == MainIt->first) {
        continue;
      }
      if (GetFileId(DepContent.Filename) == DepID) {
        ValidDependencies.try_emplace(DepID, FEXCore::ExecutableFileInfo {.FileId = DepID, .Filename = DepContent.Filename});
      } else {
        DependenciesChanged = true;
      }
    }

    if (DependenciesChanged) {
      WriteCodeMap(MainInfo, Path, MainIt->second.Blocks, MainIt->second.IsExecutable, ValidDependencies);
    }

    return std::make_optional(std::move(MainInfo));
  }

  return std::nullopt;
}

void AggregatePendingCodeMaps() {
  const auto CacheDir = std::filesystem::path(FEX::Config::GetCacheDirectory());
  const auto PendingDir = CacheDir / "codemap" / "new";
  const auto ReadyDir = CacheDir / "codemap" / "ready";

  std::error_code ec;

  if (std::filesystem::exists(PendingDir, ec)) {
    std::filesystem::create_directories(ReadyDir, ec);
    if (ec) {
      LogMan::Msg::EFmt("Failed to create ready codemap directory");
      return;
    }

    // Load and merge then write out split codemaps
    auto Merged = LoadPendingCodeMaps(PendingDir);

    for (auto& [ID, Desc] : Merged) {
      MergeAndWriteCodeMap(ID, Desc, ReadyDir);
    }
  }

  std::vector<HANDLE> CompilerProcesses;

  if (std::filesystem::exists(ReadyDir)) {
    for (const auto& Entry : std::filesystem::directory_iterator(ReadyDir)) {
      if (!Entry.is_regular_file()) {
        continue;
      }

      // Ensure all ready codemaps and their dependencies match their on-disk target images, deleting those that aren't
      if (auto MainInfo = ValidateAndPruneCodeMap(Entry.path())) {
        HANDLE hProcess = LaunchOfflineCompiler(Entry.path(), *MainInfo);
        if (hProcess != INVALID_HANDLE_VALUE) {
          CompilerProcesses.push_back(hProcess);
        }
      }
    }
  }

  if (!CompilerProcesses.empty()) {
    for (HANDLE hProc : CompilerProcesses) {
      WaitForSingleObject(hProc, INFINITE);
      CloseHandle(hProc);
    }

    LogMan::Msg::IFmt("All compilation processes finished.");
  }
}

} // anonymous namespace

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  AggregatePendingCodeMaps();

  return 0;
}