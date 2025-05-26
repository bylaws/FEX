// SPDX-License-Identifier: MIT
// TODO: Things that affect code gen:
// VIXL_SIMULATOR preprocessor define
// FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS (?)

#include "../FEXLoader/ELFCodeLoader.h"

#include <FEXCore/Core/Context.h>

#include <Common/Config.h>
#include <Common/FEXServerClient.h>
#include <Common/HostFeatures.h>

#include <FEXCore/Core/HostFeatures.h>

#include <OptionParser.h>

#include <sys/wait.h>
#include <xxhash.h>

#include <fmt/printf.h>

#include <fstream>
#include <PEParser.h>

// TODO: Change FinalizeAOTIRCache to take VAFileStart as a parameter instead...
static uintptr_t VAFileStart = 0;
static FEXCore::HLE::SyscallOSABI SyscallOSABI = {};

extern "C" {
extern std::optional<int> CodeDumpFD;
}

class AOTSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEX::HLE::SyscallMmapInterface {
public:
  AOTSyscallHandler() {
    // TODO: From command line
    OSABI = SyscallOSABI;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    // Don't do anything
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    // TODO: Should fill this in properly (from command line?)
    return {0, false, 0};
  }

  // These are no-ops implementations of the SyscallHandler API
  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) override {
    return {(FEXCore::IR::AOTIRCacheEntry*)1, VAFileStart};
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override {
    // TODO: Not sure about this
    return {0, UINT64_MAX, true};
  }

  void ForEachVMAMapping(FEXCore::Core::InternalThreadState*, std::function<void(uint64_t)>) override {}

  FEXCore::IR::AOTIRCacheEntry* Entry = nullptr;

  void* GuestMmap(FEXCore::Core::InternalThreadState*, void* addr, size_t Size, int prot, int Flags, int fd, off_t offset) override {
    auto Ret = mmap(addr, Size, prot, Flags, fd, offset);
    if (Ret != MAP_FAILED && VAFileStart == 0) {
      VAFileStart = reinterpret_cast<uintptr_t>(Ret);
    }
    return Ret;
  }

  uint64_t GuestMunmap(FEXCore::Core::InternalThreadState*, void* addr, uint64_t length) override {
    return munmap(addr, length);
  }
};

class DummySignalDelegator final : public FEXCore::SignalDelegator {};

static void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fmt::print("[{}] {}\n", LogMan::DebugLevelStr(Level), Message);
}

static void AssertHandler(const char* Message) {
  fmt::print("[ASSERT] {}\n", Message);
}

struct FileIdWithPath {
  std::string FileId;
  std::string Filename;

  bool operator<(const FileIdWithPath& Oth) const noexcept {
    return FileId < Oth.FileId;
  }
};

template<>
struct std::hash<FileIdWithPath> {
  std::size_t operator()(const FileIdWithPath& Val) const noexcept {
    return std::hash<std::string>{}(Val.FileId);
  }
};

std::map<FileIdWithPath, fextl::set<uintptr_t>> ParseCodeMap(std::ifstream& Codemap) {
  std::map<FileIdWithPath, fextl::set<uintptr_t>> Ret;
  while (true) {
    std::string Filename;
    std::getline(Codemap, Filename, '\0');
    std::string FileId;
    std::getline(Codemap, FileId, '\0');
    uint64_t Start, Size;
    Codemap.read(reinterpret_cast<char*>(&Start), sizeof(Start));
    Codemap.read(reinterpret_cast<char*>(&Size), sizeof(Size));
    if (!Codemap) {
      break;
    }
    Ret[{ FileId, Filename }].insert(Start);
  }
  return Ret;
}

int CombineCodeMaps(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--output").help("Filename for output code map");

  optparse::Values Options = Parser.parse_args(argc, argv);
  auto Inputs = Parser.args();
  if (Inputs.empty()) {
    Parser.print_usage();
    return EXIT_FAILURE;
  }

  if (!Options.is_set("output")) {
    fmt::print("{}: error: Output not specified (--output)\n", argv[0]);
    return EXIT_FAILURE;
  }

  std::map<FileIdWithPath, fextl::set<uintptr_t>> CodeMaps;

  for (auto& Input : Inputs) {
    std::ifstream Codemap(Input.c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", Input);
      return EXIT_FAILURE;
    }

    auto NewCodeMap = ParseCodeMap(Codemap);
    for (auto& [Filename, Blocks] : NewCodeMap) {
      CodeMaps[Filename].merge(Blocks);
    }
  }

  std::ofstream Output(Options.get("output"), std::ios_base::binary);
  if (!Output) {
    fmt::print("Could not open {} for writing\n", (std::string)Options.get("output"));
    return EXIT_FAILURE;
  }
  for (auto& [File, Blocks] : CodeMaps) {
    fmt::print("Parsed {} codemap entries for {} ({})\n", Blocks.size(), File.Filename, File.FileId);

    for (auto& Block : Blocks) {
      Output.write(File.Filename.c_str(), File.Filename.size() + 1);
      Output.write(File.FileId.c_str(), File.FileId.size() + 1);
      Output.write(reinterpret_cast<const char*>(&Block), sizeof(Block));
      uint64_t Size = 0; // TODO: Not sure if we should track really this
      Output.write(reinterpret_cast<char*>(&Size), sizeof(Size));
    }
  }

  return 0;
}

int CodeMapToFossilize(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--output").help("Output filename for Fossilize database (.foz)");

  optparse::Values Options = Parser.parse_args(argc, argv);
  auto Input = Parser.args();
  if (Input.size() != 1) {
    Parser.print_usage();
    return EXIT_FAILURE;
  }

  if (!Options.is_set("output")) {
    fmt::print("{}: error: Output not specified (--output)\n", argv[0]);
    return EXIT_FAILURE;
  }

  std::map<FileIdWithPath, fextl::set<uintptr_t>> CodeMaps;

  {
    std::ifstream Codemap(Input.front().c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", Input);
      return EXIT_FAILURE;
    }

    auto NewCodeMap = ParseCodeMap(Codemap);
    for (auto& [Filename, Blocks] : NewCodeMap) {
      CodeMaps[Filename].merge(Blocks);
    }
  }

  if (CodeMaps.size() > 1) {
    fmt::print("Cannot export multi-file code map. Use FEX's auto-split code maps instead.\n");
    return EXIT_FAILURE;
  }

  std::ofstream Output(Options.get("output"), std::ios_base::binary);
  if (!Output) {
    fmt::print("Could not open {} for writing\n", (std::string)Options.get("output"));
    return EXIT_FAILURE;
  }
  Output << fmt::format("{}FOSSILIZEDB\0\0\0\6", '\x81') << std::flush;
  for (auto& [File, Blocks] : CodeMaps) {
    // First, record application info: Tag (RESOURCE_APPLICATION_INFO = 0) + null hash
    Output << fmt::format("{:024x}{:016x}", 0, 0) << std::flush;
    // TODO: Encode FileId as well
    auto payload = R"({"version":6,"applicationInfo":{"applicationName":")" + File.Filename + R"("},"physicalDeviceFeatures":{}})";
    uint32_t payload_size = payload.size();
    Output.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));
    // flags = 1 (uncompressed), no CRC
    Output << fmt::format("\1\0\0\0\0\0\0\0");
    Output.write(reinterpret_cast<const char*>(&payload_size), sizeof(payload_size));
    Output << payload;

    // Second, record block offsets
    for (auto& Block : Blocks) {
      // Tag (RESOURCE_FEX_CODE_MAP_ENTRY = 10) + block offset ("hash")
      // Empty payload, flags = 1 (uncompressed), no CRC
      Output << fmt::format("{:024x}{:016x}\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0", 10, Block);
    }
    break;
  }

  return 0;
}

int GenerateCache(int argc, const char** argv) {
  optparse::OptionParser Parser {};
  Parser.add_option("--host-dcache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-icache-line-size").type("long").help("Target DCache line size to use when compiling code (default: detect from host)");
  Parser.add_option("--host-features").type("long").help("Target HostFeatures to use when compiling code (default: detect from host)");

  Parser.add_option("--smc").type("long").help("Strategy for self-modifying-code (default: none)");

  Parser.add_option("--codemap").help("Path to code map");
  Parser.add_option("--limit").action("store_true").help("Limit processing to the given binary");

  optparse::Values Options = Parser.parse_args(argc, argv);
  if (Parser.args().size() != 2) {
    Parser.print_usage();
    return 1;
  }

  FileIdWithPath ProgramName = { (std::string)Parser.args()[1], (std::string)Parser.args()[0] };

  fextl::set<uintptr_t> InitialBranchTargets;

  if (Options.is_set("codemap")) {
    std::ifstream Codemap(((std::string)Options.get("codemap")).c_str(), std::ios_base::binary);
    if (!Codemap) {
      fmt::print("Could not open {}\n", (std::string)Options.get("codemap"));
      return 1;
    }

    fextl::set<std::string> Files;

    auto Data = ParseCodeMap(Codemap);

    for (auto& [File, Blocks] : Data) {
      fmt::print("Parsed {} codemap entries for {} ({})\n", Blocks.size(), File.Filename, File.FileId);
    }

    for (auto& [File, Blocks] : Data) {
      if (File.FileId == ProgramName.FileId) {
        // Continue as normal
      } else if (!Options.is_set("limit")) {
        // Process in fork
        auto child_pid = fork();
        if (child_pid == 0) {
          ProgramName = File;
          break;
        } else {
          int status;
          ::wait(&status);
          if (status != 0) {
            fmt::print("CHILD PROCESS FAILED\n");
            return 1;
          }
        }
      }
    }

    if (!Data.contains(ProgramName)) {
      throw std::runtime_error(fmt::format("Input code map {} did not contain {} ({})", (std::string)Options.get("codemap"), ProgramName.Filename, ProgramName.FileId));
    }

    InitialBranchTargets.merge(Data.at(ProgramName));
  }

  // TODO: Support compiling from an FD

  // TODO: Generate substitute config?
  FEX::Config::InitializeConfigs({});
  FEXCore::Config::Initialize();

  // TODO: From command line
  // FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, "0");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MULTIBLOCK, "1");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_MAXINST, "5000");
  FEXCore::Config::Set(FEXCore::Config::CONFIG_X87REDUCEDPRECISION, "0"); // TODO: Why was this enabled??
  FEXCore::Config::Set(FEXCore::Config::CONFIG_ABILOCALFLAGS, "0"); // TODO: Is this needed?

  // TODO: Consider re-enabling it for code statistics
  FEXCore::Config::Set(FEXCore::Config::CONFIG_DISABLETELEMETRY, "1");

  bool Is64Bit;
  bool LoadedFromPE = false;
  std::variant<std::monostate, PEParser, ELFCodeLoader> Loader;
  {
    auto fd = open(ProgramName.Filename.c_str(), O_RDONLY);
    Loader = PEParser {fd};
    auto& Parser = std::get<PEParser>(Loader);
    if (Parser) {
      Is64Bit = Parser.Is64Bit;

      auto SyscallHandler = std::make_unique<AOTSyscallHandler>();
      // TODO: Handle relocation in case ImageBase is already blocked?
      Parser.MapMemory(SyscallHandler.get(), fd);
      LoadedFromPE = true;
    }
    close(fd);
  }

  if (!LoadedFromPE) {
    Loader.emplace<ELFCodeLoader>(ProgramName.Filename.c_str(), -1, "", fextl::vector<fextl::string>{ProgramName.Filename.c_str()}, fextl::vector<fextl::string>{}, nullptr, nullptr, true /* skip interpreter */);
    auto& ELFLoader = std::get<ELFCodeLoader>(Loader);
    if (!ELFLoader.ELFWasLoaded()) {
      fmt::print("Invalid or unsupported ELF file.\n");
      return EXIT_FAILURE;
    }
    Is64Bit = ELFLoader.Is64BitMode();
  }
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Is64Bit ? "1" : "0");

  // Disable TSO auto migration for now.
  // TODO: How should this be handled? Should two variants of the cache be generated and loaded as required? Should the codemap record whether the library is ever used in a single-threaded context?
  FEXCore::Config::Set(FEXCore::Config::CONFIG_TSOAUTOMIGRATION, "0");

  // TODO: OS_GENERIC?
  SyscallOSABI = Is64Bit ? FEXCore::HLE::SyscallOSABI::OS_LINUX64 : FEXCore::HLE::SyscallOSABI::OS_LINUX32;

  if (!Is64Bit) {
    // This has a couple of issues that need to be fixed
    fmt::print("Cache generation for 32-bit not supported yet\n");
    return 0;
  }

  // Load HostFeatures
  // NOTE: Config must be fully initialized for detection to work
  FEXCore::HostFeatures HostFeatures {};
  // TODO: Setup   FEX_CONFIG_OPT(ForceSVEWidth, FORCESVEWIDTH);


  const auto DetectedFeatures = FEX::FetchHostFeatures();
  if (Options.is_set("host-features")) {
    uint32_t RawValue = Options.get("host-features");
    memcpy(reinterpret_cast<char*>(&HostFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           &RawValue, sizeof(RawValue));
  } else {
    memcpy(reinterpret_cast<char*>(&HostFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           reinterpret_cast<const char*>(&DetectedFeatures) + offsetof(FEXCore::HostFeatures, ICacheLineSize) + sizeof(HostFeatures.ICacheLineSize),
           sizeof(uint32_t));
  }
  if (Options.is_set("host-dcache-line-size")) {
    HostFeatures.DCacheLineSize = Options.get("host-dcache-line-size");
  } else {
    HostFeatures.DCacheLineSize = DetectedFeatures.DCacheLineSize;
  }
  if (Options.is_set("host-icache-line-size")) {
    HostFeatures.ICacheLineSize = Options.get("host-icache-line-size");
  } else {
    HostFeatures.ICacheLineSize = DetectedFeatures.ICacheLineSize;
  }
  HostFeatures = DetectedFeatures;

  FEX_CONFIG_OPT(MultiBlock, MULTIBLOCK);

  // TODO: Verify the file exists
  if (!std::filesystem::exists(ProgramName.Filename)) {
    fmt::print("File {} does not exist\n", ProgramName.Filename);
    // TODO: Pressure vessel hits this
    return /*EXIT_FAILURE*/ 0;
  }

  FEXCore::Context::InitializeStaticTables(Is64Bit ? FEXCore::Context::MODE_64BIT : FEXCore::Context::MODE_32BIT);

  auto CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);

  auto SignalDelegation = std::make_unique<DummySignalDelegator>();
  // TODO: Is this needed?
  // auto ThunkHandler = FEX::HLE::CreateThunkHandler();

  auto SyscallHandler = std::make_unique<AOTSyscallHandler>();

  // TODO: How to handle VDSO with code caching? Does this need purpose-specific FEX relocations?

  if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
    // ELFLoader->SetVDSOBase(VDSOMapping.VDSOBase); // TODO: Check interaction with disk caching?
    ELFLoader->CalculateHWCaps(CTX.get());
  }

  CTX->SetSignalDelegator(SignalDelegation.get());
  CTX->SetSyscallHandler(SyscallHandler.get());

  if (!CTX->InitCore()) {
    return 1;
  }

  auto ParentThread = new FEX::HLE::ThreadStateObject;
  {
    auto& ThreadStateObject = ParentThread;

    ThreadStateObject->ThreadInfo.parent_tid = 0;
    ThreadStateObject->ThreadInfo.PID = ::getpid();
    ThreadStateObject->ThreadInfo.TID = FHU::Syscalls::gettid();

    ThreadStateObject->Thread =
      CTX->CreateThread(0, 0);

    // TODO: Does ThreadStateObject->persona affect codegen?
  }

  if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
    auto ElfBase = ELFLoader->LoadElfFile(ELFLoader->MainElf, nullptr, SyscallHandler.get());
    if (!ElfBase.has_value()) {
      ERROR_AND_DIE_FMT("Failed to load ELF file {} ({})", ProgramName.Filename, ProgramName.FileId);
    }
  }

  {
    decltype(InitialBranchTargets) InitialBranchTargets2;
    for (auto Offset : InitialBranchTargets) {
      InitialBranchTargets2.insert(Offset + VAFileStart);
    }
    InitialBranchTargets = std::move(InitialBranchTargets2);
  }

  const auto SMCChecks = Options.is_set("smc") ? static_cast<FEXCore::Config::ConfigSMCChecks>(static_cast<long>(Options.get("smc"))) :
                                                 FEXCore::Config::CONFIG_SMC_NONE;

  // TODO: From command line
  // TODO: Use full TSO configuration
  FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
  if (TSOEnabled) {
    // TODO: Fetch from command line
    // CTX->SetHardwareTSOSupport(true);
  }

  CodeDumpFD = -1;
  {
    uint64_t Progress = 0;
    const int NumItems = InitialBranchTargets.size();

    std::string TaskName = fmt::format("Compiling {} blocks", NumItems, NumItems);

    winsize TerminalSize;
    bool PrintProgress = (ioctl(STDOUT_FILENO, TIOCGWINSZ, &TerminalSize) == 0 && TerminalSize.ws_col > 30);
    if (PrintProgress) {
      TerminalSize.ws_col -= 5; // Percentage display
      TerminalSize.ws_col -= TaskName.size() + 1;
    } else {
      fmt::println("Compiling {} code blocks...", NumItems);
    }

    for (auto Addr : InitialBranchTargets) {
      CTX->CompileRIP(ParentThread->Thread, Addr);
      ++Progress;
      if (!PrintProgress || (Progress % 10 && Progress + 10 < NumItems)) {
        continue;
      }

      std::string Bar;
      for (int i = 0; i < TerminalSize.ws_col * Progress / NumItems; ++i) {
        Bar += "█";
      }
      auto SubIndex = (TerminalSize.ws_col * Progress * 8 / NumItems % 8);
      const char* BlockCharacters[] = {
       "", "▏", "▎", "▍", "▌", "▋", "▊", "▉"
      };
      Bar += BlockCharacters[SubIndex];
      // \r: Move to beginning of the line
      // {:{}}: Move to the end of the line by printing an empty string with padding
      // {:3}: Reserve 3 characters for percentage number
      fmt::print("\r{} {}{:{}}{:3}%", TaskName, Bar, "", TerminalSize.ws_col - TerminalSize.ws_col * Progress / NumItems + (SubIndex == 0), Progress * 100 / NumItems);
      std::fflush(stdout);
    }
    if (PrintProgress) {
      fmt::print("\n");
    }

    std::filesystem::create_directories("/tmp/fexcache");

    // TODO: Consider O_EXCL so that this fails to overwrite existing files?
    auto Filename = fmt::format("/tmp/fexcache/{}", ProgramName.FileId);
    auto FilenameNew = Filename + ".new";
    int fd = open(FilenameNew.c_str(), O_CREAT | O_WRONLY, 0644);
    if (auto* ELFLoader = std::get_if<ELFCodeLoader>(&Loader)) {
      CTX->FinalizeAOTIRCache(*ParentThread->Thread, fd, ELFLoader->MainElfBase);
    } else {
      CTX->FinalizeAOTIRCache(*ParentThread->Thread, fd, std::get<PEParser>(Loader).ImageBase);
    }
    std::filesystem::rename(FilenameNew.c_str(), Filename.c_str());
    fmt::print("Successfully populated cache {}\n\n", Filename);
    close(fd);
  }
  return 0;
}

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  std::vector<const char*> Args {argv + 1, argv + argc};
  auto CommandName = std::string {basename(argv[0])} + " " + (argc > 1 ? argv[1] : "");
  Args[0] = CommandName.c_str();

  if (argc >= 2 && argv[1] == std::string_view {"combine"}) {
    return CombineCodeMaps(argc - 1, Args.data());
  } else if (argc >= 2 && argv[1] == std::string_view {"generate"}) {
    return GenerateCache(argc - 1, Args.data());
  } else if (argc >= 2 && argv[1] == std::string_view {"to-foz"}) {
    return CodeMapToFossilize(argc - 1, Args.data());
  } else {
    fmt::print("Usage: {} <command>\n\n", basename(argv[0]));
    fmt::print("Commands:\n");
    fmt::print("  combine\tCombine code maps and prepare them for cache generation\n");
    fmt::print("  generate\tTrigger cache generation from combined code map\n");
    return EXIT_FAILURE;
  }
}
