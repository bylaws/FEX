// SPDX-License-Identifier: MIT
#include "FEXHeaderUtils/Syscalls.h"
#include "Logger.h"
#include "SquashFS.h"

#include <Common/AsyncNet.h>
#include <Common/FEXServerClient.h>
#include <FEXCore/Utils/EnumUtils.h>

#include <fmt/ranges.h>

#include <atomic>
#include <cassert>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <poll.h>
#include <string>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <vector>


#include "Tools/FEXLoader/ELFCodeLoader.h"
#include "Linux/Utils/ELFParser.h"
#include "FEXCore/Core/Context.h"
#include "Common/HostFeatures.h"
// #include "DummyHandlers.h"
#include "Tools/LinuxEmulation/LinuxSyscalls/x64/Syscalls.h"

#include <xxhash.h>

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

namespace ProcessPipe {
constexpr int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
int ServerLockFD {-1};
std::optional<fasio::tcp_acceptor> ServerAcceptor;
std::optional<fasio::tcp_acceptor> ServerFSAcceptor;
int NumClients = 0;
time_t RequestTimeout {10};
bool Foreground {false};
std::vector<struct pollfd> PollFDs {};

// FD count watching
constexpr size_t static MAX_FD_DISTANCE = 32;
rlimit MaxFDs {};
std::atomic<size_t> NumFilesOpened {};

size_t GetNumFilesOpen() {
  // Walk /proc/self/fd/ to see how many open files we currently have
  const std::filesystem::path self {"/proc/self/fd/"};

  return std::distance(std::filesystem::directory_iterator {self}, std::filesystem::directory_iterator {});
}

void GetMaxFDs() {
  // Get our kernel limit for the number of open files
  if (getrlimit(RLIMIT_NOFILE, &MaxFDs) != 0) {
    fprintf(stderr, "[FEXMountDaemon] getrlimit(RLIMIT_NOFILE) returned error %d %s\n", errno, strerror(errno));
  }

  // Walk /proc/self/fd/ to see how many open files we currently have
  NumFilesOpened = GetNumFilesOpen();
}

void CheckRaiseFDLimit() {
  if (NumFilesOpened < (MaxFDs.rlim_cur - MAX_FD_DISTANCE)) {
    // No need to raise the limit.
    return;
  }

  if (MaxFDs.rlim_cur == MaxFDs.rlim_max) {
    fprintf(stderr, "[FEXMountDaemon] Our open FD limit is already set to max and we are wanting to increase it\n");
    fprintf(stderr, "[FEXMountDaemon] FEXMountDaemon will now no longer be able to track new instances of FEX\n");
    fprintf(stderr, "[FEXMountDaemon] Current limit is %zd(hard %zd) FDs and we are at %zd\n", MaxFDs.rlim_cur, MaxFDs.rlim_max,
            GetNumFilesOpen());
    fprintf(stderr, "[FEXMountDaemon] Ask your administrator to raise your kernel's hard limit on open FDs\n");
    return;
  }

  rlimit NewLimit = MaxFDs;

  // Just multiply by two
  NewLimit.rlim_cur <<= 1;

  // Now limit to the hard max
  NewLimit.rlim_cur = std::min(NewLimit.rlim_cur, NewLimit.rlim_max);

  if (setrlimit(RLIMIT_NOFILE, &NewLimit) != 0) {
    fprintf(stderr, "[FEXMountDaemon] Couldn't raise FD limit to %zd even though our hard limit is %zd\n", NewLimit.rlim_cur, NewLimit.rlim_max);
  } else {
    // Set the new limit
    MaxFDs = NewLimit;
  }
}

bool InitializeServerPipe() {
  auto ServerFolder = FEXServerClient::GetServerLockFolder();

  std::error_code ec {};
  if (!std::filesystem::exists(ServerFolder, ec)) {
    // Doesn't exist, create the the folder as a user convenience
    if (!std::filesystem::create_directories(ServerFolder, ec)) {
      LogMan::Msg::EFmt("Couldn't create server pipe folder at: {}", ServerFolder);
      return false;
    }
  }

  auto ServerLockPath = FEXServerClient::GetServerLockFile();

  // Now this is some tricky locking logic to ensure that we only ever have one server running
  // The logic is as follows:
  // - Try to make the lock file
  // - If Exists then check to see if it is a stale handle
  //   - Stale checking means opening the file that we know exists
  //   - Then we try getting a write lock
  //   - If we fail to get the write lock, then leave
  //   - Otherwise continue down the codepath and degrade to read lock
  // - Else try to acquire a write lock to ensure only one FEXServer exists
  //
  // - Once a write lock is acquired, downgrade it to a read lock
  //   - This ensures that future FEXServers won't race to create multiple read locks
  int Ret = open(ServerLockPath.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_EXCL, USER_PERMS);
  ServerLockFD = Ret;

  if (Ret == -1 && errno == EEXIST) {
    // If the lock exists then it might be a stale connection.
    // Check the lock status to see if another process is still alive.
    ServerLockFD = open(ServerLockPath.c_str(), O_RDWR | O_CLOEXEC, USER_PERMS);
    if (ServerLockFD != -1) {
      // Now that we have opened the file, try to get a write lock.
      struct flock lk {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
      };
      Ret = fcntl(ServerLockFD, F_SETLK, &lk);

      if (Ret != -1) {
        // Write lock was gained, we can now continue onward.
      } else {
        // We couldn't get a write lock, this means that another process already owns a lock on the lock
        close(ServerLockFD);
        ServerLockFD = -1;
        return false;
      }
    } else {
      // File couldn't get opened even though it existed?
      // Must have raced something here.
      return false;
    }
  } else if (Ret == -1) {
    // Unhandled error.
    LogMan::Msg::EFmt("Unable to create FEXServer named lock file at: {} {} {}", ServerLockPath, errno, strerror(errno));
    return false;
  } else {
    // FIFO file was created. Try to get a write lock
    struct flock lk {
      .l_type = F_WRLCK,
      .l_whence = SEEK_SET,
      .l_start = 0,
      .l_len = 0,
    };
    Ret = fcntl(ServerLockFD, F_SETLK, &lk);

    if (Ret == -1) {
      // Couldn't get a write lock, something else must have got it
      close(ServerLockFD);
      ServerLockFD = -1;
      return false;
    }
  }

  // Now that a write lock is held, downgrade it to a read lock
  struct flock lk {
    .l_type = F_RDLCK,
    .l_whence = SEEK_SET,
    .l_start = 0,
    .l_len = 0,
  };
  Ret = fcntl(ServerLockFD, F_SETLK, &lk);

  if (Ret == -1) {
    // This shouldn't occur
    LogMan::Msg::EFmt("Unable to downgrade a write lock to a read lock {} {} {}", ServerLockPath, errno, strerror(errno));
    close(ServerLockFD);
    ServerLockFD = -1;
    return false;
  }

  return true;
}

static fasio::poll_reactor Reactor;

void HandleSocketData(fasio::tcp_socket&);

bool InitializeServerSocket(bool abstract) {
  fextl::string ServerSocketName;
  if (abstract) {
    ServerSocketName = FEXServerClient::GetServerSocketName();
  } else {
    ServerSocketName = FEXServerClient::GetServerSocketPath();
    // Unlink the socket file if it exists
    // We are being asked to create a daemon, not error check
    // We don't care if this failed or not
    unlink(ServerSocketName.c_str());
  }
  auto Acceptor = fasio::tcp_acceptor::create(Reactor, abstract, ServerSocketName);
  if (!Acceptor) {
    LogMan::Msg::EFmt("Failed to create FEXServer socket: error {} ({})", errno, strerror(errno));
    return false;
  }

  Acceptor->async_accept([](fasio::error ec, std::optional<fasio::tcp_socket> Socket) {
    if (ec != fasio::error::success) {
      if (ec == fasio::error::generic_errno) {
        LogMan::Msg::EFmt("FEXServer failed to establish client connection: error {} ({})", errno, strerror(errno));
      }
      // Ignore error and wait for next connection
      return fasio::post_callback::repeat;
    }

    int FD = Socket->FD;
    ++NumClients;
    Reactor.bind_handler(
      pollfd {
        .fd = FD,
        .events = POLLIN | POLLPRI | POLLRDHUP,
        .revents = 0,
      },
      [Socket = std::move(Socket).value()](fasio::error ec) mutable {
        if (ec != fasio::error::success) {
          close(Socket.FD);
          --NumClients;
          return fasio::post_callback::drop;
        }
        HandleSocketData(Socket);
        // Wait for next data
        return fasio::post_callback::repeat;
      });

    // Wait for next connection
    return fasio::post_callback::repeat;
  });

  (abstract ? ServerAcceptor : ServerFSAcceptor) = std::move(Acceptor).value();
  return true;
}

void SendEmptyErrorPacket(fasio::tcp_socket& Socket) {
  FEXServerClient::FEXServerResultPacket Res {
    .Header {
      .Type = FEXServerClient::PacketType::TYPE_ERROR,
    },
  };

  fasio::mutable_buffer Data = {.Data = std::as_writable_bytes(std::span(&Res, 1))};
  fasio::error ec;
  write(Socket, Data, ec);
}

void SendFDSuccessPacket(fasio::tcp_socket& Socket, int FD) {
  FEXServerClient::FEXServerResultPacket Res {
    .Header {
      .Type = FEXServerClient::PacketType::TYPE_SUCCESS,
    },
  };

  fasio::mutable_buffer Data = {.Data = std::as_writable_bytes(std::span(&Res, 1)), .FD = &FD};
  fasio::error ec;
  write(Socket, Data, ec);
}

int32_t EmbedSubprocess(const char* path, char* const* args) {
  pid_t pid = fork();
  if (pid == 0) {
    execvp(path, args);
    _exit(-1);
  } else {
    int32_t Status {};
    while (waitpid(pid, &Status, 0) == -1 && errno == EINTR)
      ;
    if (WIFEXITED(Status)) {
      return (int8_t)WEXITSTATUS(Status);
    }
  }

  return -1;
}

static int RunOfflineCompiler(FileIdWithPath SourceBinary, const char* CodeMap) {
    const char* ExecveArgs[] = { "FEXOfflineCompiler", "generate", SourceBinary.Filename.c_str(), SourceBinary.FileId.c_str(), "--codemap", CodeMap, nullptr };
    return EmbedSubprocess("FEXOfflineCompiler", const_cast<char* const*>(&ExecveArgs[0]));
};

void HandleSocketData(fasio::tcp_socket& Socket) {
  std::vector<uint8_t> Data(1500);

  // Get the current number of FDs of the process before we start handling sockets.
  GetMaxFDs();

  // fasio::mutable_buffer buffer = {std::as_writable_bytes(std::span(Data))};
  fasio::mutable_buffer buffer = {std::as_writable_bytes(std::span(Data).subspan(0, 4))};
  int inFD = -1;
  buffer.FD = &inFD;

  {
    fasio::error ec;

    auto Read = Socket.read_some(buffer, ec);
    if (ec == fasio::error::success) {
      assert(Read >= sizeof(FEXServerClient::FEXServerRequestPacket));
      buffer = {buffer.Data.subspan(0, Read)};
    } else if (ec == fasio::error::generic_errno) {
      perror("read");
      return;
    } else {
      return;
    }
  }

  while (buffer.size() > 0) {
    FEXServerClient::FEXServerRequestPacket* Req = reinterpret_cast<FEXServerClient::FEXServerRequestPacket*>(Data.data());
    switch (Req->Header.Type) {
    case FEXServerClient::PacketType::TYPE_KILL:
      Reactor.stop_async();
      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::BasicRequest);
      break;
    case FEXServerClient::PacketType::TYPE_GET_LOG_FD: {
      if (Logger::LogThreadRunning()) {
        int fds[2] {};
        pipe2(fds, 0);
        // 0 = Read
        // 1 = Write
        Logger::AppendLogFD(fds[0]);

        SendFDSuccessPacket(Socket, fds[1]);

        // Close the write side now, doesn't matter to us
        close(fds[1]);

        // Check if we need to increase the FD limit.
        ++NumFilesOpened;
        CheckRaiseFDLimit();
      } else {
        // Log thread isn't running. Let FEXInterpreter know it can't have one.
        SendEmptyErrorPacket(Socket);
      }

      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::Header);
      break;
    }
    case FEXServerClient::PacketType::TYPE_GET_ROOTFS_PATH: {
      const fextl::string& MountFolder = SquashFS::GetMountFolder();

      FEXServerClient::FEXServerResultPacket Res {
        .MountPath {
          .Header {
            .Type = FEXServerClient::PacketType::TYPE_GET_ROOTFS_PATH,
          },
          .Length = MountFolder.size() + 1,
        },
      };

      char Null {};

      fasio::mutable_buffer Data[] = {
        {.Data = std::as_writable_bytes(std::span(&Res, 1))},
        {.Data = std::as_writable_bytes(std::span(const_cast<fextl::string&>(MountFolder)))},
        {.Data = std::as_writable_bytes(std::span(&Null, 1))},
      };
      fasio::error ec;
      write(Socket, Chained(Data), ec);

      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::BasicRequest);
      break;
    }
    case FEXServerClient::PacketType::TYPE_GET_PID_FD: {
      int FD = FHU::Syscalls::pidfd_open(::getpid(), 0);

      if (FD < 0) {
        // Couldn't get PIDFD due to too old of kernel.
        // Return a pipe to track the same information.
        //
        int fds[2];
        pipe2(fds, O_CLOEXEC);
        SendFDSuccessPacket(Socket, fds[0]);

        // Close the read side now, doesn't matter to us
        close(fds[0]);

        // Check if we need to increase the FD limit.
        ++NumFilesOpened;
        CheckRaiseFDLimit();

        // Write side will naturally close on process exit, letting the other process know we have exited.
      } else {
        SendFDSuccessPacket(Socket, FD);

        // Close the FD now since we've sent it
        close(FD);
      }

      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::Header);
      break;
    }

    case FEXServerClient::PacketType::TYPE_QUERY_CODE_CACHE: {
      char Tmp[PATH_MAX];
      int TmpLen = FEX::get_fdpath(inFD, Tmp);
      assert(TmpLen != -1);

      // TODO: Move to common code
      // TODO: Use file id from ELF build id instead
      // TODO: Capture external configuration more accurately
      std::filesystem::path Path { std::string_view(Tmp, TmpLen) };
      auto Filename = Path.filename().string();
      auto filename_hash = XXH3_64bits(Tmp, TmpLen);
      auto fileid = fmt::format("{}-{:016x}-{}{}{}", Filename, filename_hash,
                                /*(SMCChecks == FEXCore::Config::CONFIG_SMC_FULL) ? 'S' :*/ 's', /*TSOEnabled*/true ? 'T' : 't',
                                /*CTX->Config.ABILocalFlags ? 'L' :*/ 'l');

      FileIdWithPath MainFileId = { fileid, std::string(Tmp, TmpLen) };
      fmt::print("Requested cache for: {}\n", MainFileId.Filename);

      // Detect code maps by incrementing index
      // TODO: If there are any (or more than N) pending code maps, stop handing out new code map FDs
      std::vector<std::string> CodeMaps;
      for (int Index = 0; true; ++Index) {
        auto CodeMap = fmt::format("/tmp/fexcode/{}.{}.bin", Filename, Index);
        auto FD = open(CodeMap.c_str(), O_RDONLY);
        if (FD == -1) {
          break;
        }

        // Acquire exclusive lock to ensure the client process is done writing data.
        // Also ensure the file is non-empty, otherwise we're racing the client in acquiring the initial lock.
        // TODO: The file could also end up empty if another thread crashes during dumping
        struct stat FileStats;
        fstat(FD, &FileStats);
        if (FileStats.st_size == 0 || flock(FD, LOCK_EX | LOCK_NB) != 0) {
          fmt::print("Code map {} is still in use, skipping\n", CodeMap);
          // Still being written to by a client process, so skip this file
          // TODO: Rename from X.n.bin to X.0.bin (once the latter has been removed!) to ensure we'll catch it on next run
          close(FD);
          continue;
        }
        close(FD);
        CodeMaps.push_back(CodeMap);
      }

// TODO: Eh.
auto ParseCodeMap = [](std::ifstream& Codemap) {
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
    Ret[FileIdWithPath{FileId, Filename}].insert(Start);
  }
  return Ret;
};

      // Trigger recompile if unprocessed (pending but finalized) code maps exist
      // TODO: Debounce this though. Only recompile if "time_since_last_offline_compile * size_of_codemap / size_of_existing_cache > N"
      if (!CodeMaps.empty()) {
        fmt::print("Found {} new code maps, triggering cache generation\n", CodeMaps.size());

        // 1. Parse NEW code maps
        std::map<FileIdWithPath, fextl::set<uintptr_t>> IncomingCodeMap;
        for (auto& CodeMap : CodeMaps) {
          std::ifstream Incoming(CodeMap);
          for (auto& [Filename, Blocks] : ParseCodeMap(Incoming)) {
            IncomingCodeMap[Filename].merge(Blocks);
          }
        }

        // 2. For each referenced library, add referenced offsets to that library's reference code map
        for (const auto& [File, NewBlocks] : IncomingCodeMap) {
          if (File.FileId == MainFileId.FileId) {
            continue;
          }

          fmt::print("Processing library {} ({})\n", File.Filename, File.FileId);

          const auto& BinaryName = File.FileId;
          {
            auto Blocks = NewBlocks;

            if (auto ReferenceCodeMap = std::ifstream("/tmp/fexcode/merged." + BinaryName)) {
              auto PreviousBlocks = ParseCodeMap(ReferenceCodeMap)[File];
              auto NumPreviousBlocks = PreviousBlocks.size();
              Blocks.merge(PreviousBlocks);
              if (Blocks.size() == NumPreviousBlocks) {
                // No blocks added; skip this library
                fmt::print("No new blocks; skipping (current {})\n", NumPreviousBlocks);
                continue;
              } else {
                fmt::print("Found {} new blocks (previous {})\n", Blocks.size() - NumPreviousBlocks, NumPreviousBlocks);
              }
            }

            {
              std::ofstream Output("/tmp/fexcode/merged." + BinaryName, std::ios_base::out | std::ios_base::trunc);
              fmt::print("Writing {} blocks to {}\n", Blocks.size(), "/tmp/fexcode/merged." + BinaryName);
              for (auto& Block : Blocks) {
                Output.write(File.Filename.c_str(), File.Filename.size() + 1);
                Output.write(File.FileId.c_str(), File.FileId.size() + 1);
                Output.write(reinterpret_cast<const char*>(&Block), sizeof(Block));
                uint64_t Size = 0; // TODO: Not sure if we should actually track this
                Output.write(reinterpret_cast<char*>(&Size), sizeof(Size));
              }
            }

            // Export Fossilize database
            {
              auto MergedFilename = "/tmp/fexcode/merged." + BinaryName;
              auto MergedFozFilename = MergedFilename + ".foz";
              const char* ExecveArgs[] = { "FEXOfflineCompiler", "to-foz", MergedFilename.c_str(), "--output", MergedFozFilename.c_str(), nullptr };
              EmbedSubprocess("FEXOfflineCompiler", const_cast<char* const*>(&ExecveArgs[0]));
            }
          }

          // Generate cache for each referenced library (if it has new code map entries)
          // TODO: For libraries that are loaded in a sandbox (e.g. pressure vessel), this will fail. We should retry once the library is actually loaded at runtime
          int Status = RunOfflineCompiler(File, ("/tmp/fexcode/merged." + BinaryName).c_str());
          if (Status != 0) {
            fmt::println("ERROR: Cache generation failed with status {}", Status);
          }
        }

        // 3. Merge all code maps into executable (TODO: We only do this to have a list of referenced libraries per executable; this list should just be a dedicated section in the code map!)
        // TODO: Either way, consider processing this *before* any of the libraries
        const auto MergedFilename = "/tmp/fexcode/merged." + MainFileId.FileId;
        do {
          auto& Blocks = IncomingCodeMap[MainFileId];
          if (auto ReferenceCodeMap = std::ifstream(MergedFilename)) {
            auto PreviousBlocks = ParseCodeMap(ReferenceCodeMap)[MainFileId];
            auto NumPreviousBlocks = PreviousBlocks.size();
            Blocks.merge(PreviousBlocks);
            if (Blocks.size() == NumPreviousBlocks) {
              // No blocks added; skip this binary
              break;
            } else {
              fmt::print("Found {} new blocks (previous {})\n", Blocks.size() - NumPreviousBlocks, NumPreviousBlocks);
            }
          }

          {
            std::ofstream Output(MergedFilename, std::ios_base::out | std::ios_base::trunc);
            for (auto& Block : Blocks) {
              Output.write(MainFileId.Filename.c_str(), MainFileId.Filename.size() + 1);
              Output.write(MainFileId.FileId.c_str(), MainFileId.FileId.size() + 1);
              Output.write(reinterpret_cast<const char*>(&Block), sizeof(Block));
              uint64_t Size = 0; // TODO: Not sure if we should track really this
              Output.write(reinterpret_cast<char*>(&Size), sizeof(Size));
            }
          }

          // 3.1. Export Fossilize database
          {
            auto MergedFozFilename = MergedFilename + ".foz";
            const char* ExecveArgs[] = { "FEXOfflineCompiler", "to-foz", MergedFilename.c_str(), "--output", MergedFozFilename.c_str(), nullptr };
            EmbedSubprocess("FEXOfflineCompiler", const_cast<char* const*>(&ExecveArgs[0]));
          }

          // 4. Trigger offline-compile for the main executable
          // TODO: Use a BACKGROUND PROCESS for this
          int Status = RunOfflineCompiler(MainFileId, MergedFilename.c_str());
          if (Status != 0) {
            fmt::println("ERROR: Cache generation failed with status {}", Status);
          }
        } while (false);

        // 3.5. Delete all NEW code maps
        for (auto& CodeMapFile : CodeMaps) {
          std::filesystem::remove(CodeMapFile);
          // TODO: Rename any pending (not finalized) code maps to PROGRAMNAME.0.bin so it will be found on the next run
        }
      }

      // 4. Return FD for generated cache to client
      auto CacheFD = open(fileid.c_str(), O_RDONLY);
      FEXServerClient::FEXServerResultPacket Res {
        .Header {
          .Type = FEXServerClient::PacketType::TYPE_SUCCESS,
        },
      };

      fasio::mutable_buffer Data = {.Data = std::as_writable_bytes(std::span(&Res, 1)), .FD = (CacheFD != -1 ? std::optional { &CacheFD } : std::nullopt)};
      fasio::error ec;
      write(Socket, Data, ec);
      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::Header);
      break;
    }

    case FEXServerClient::PacketType::TYPE_QUERY_CODE_MAP: {
      // TODO: Keep a map of clients that are already writing a code map.
      //       No more than one instance of each application should write code
      //       maps to avoid spamming the file system for high-frequency
      //       invocations of the same program!

      char Tmp[PATH_MAX];
      int TmpLen = FEX::get_fdpath(inFD, Tmp);
      assert(TmpLen != -1);
      fmt::print("Requested code map FD for: {}\n", std::string_view(Tmp, TmpLen));
      std::filesystem::path BinaryPath = std::string_view(Tmp, TmpLen);

      FEXServerClient::FEXServerResultPacket Res {
        .Header {
          .Type = FEXServerClient::PacketType::TYPE_SUCCESS,
        },
      };

      // Find first code map that doesn't exist yet
      int Index = 0;
      std::string Filename;
      do {
        Filename = fmt::format("/tmp/fexcode/{}.{}.bin", BinaryPath.filename().string(), Index++);
      } while (std::filesystem::exists(Filename));
      // TODO: Add ".pending" to filename and make TYPE_QUERY_CODE_CACHE rename it once it has no more users

      std::filesystem::create_directories("/tmp/fexcode");
      auto CodeDumpFD = open(Filename.c_str(), O_CREAT | O_CLOEXEC | O_WRONLY, 0644);

      fasio::mutable_buffer Data = {.Data = std::as_writable_bytes(std::span(&Res, 1)), .FD = (CodeDumpFD != -1 ? std::optional { &CodeDumpFD } : std::nullopt)};
      fasio::error ec;
      write(Socket, Data, ec);
      buffer += sizeof(FEXServerClient::FEXServerRequestPacket::Header);
      close(CodeDumpFD);
      break;
    }

    // Invalid
    case FEXServerClient::PacketType::TYPE_ERROR:
    default:
      // Something sent us an invalid packet. Drop this client and continue
      LogMan::Msg::EFmt("Invalid FEXServer packet received: {:02x}", fmt::join(buffer.Data, ""));
      close(Socket.FD);
      return;
    }
  }
}

void CloseConnections() {
  // Close the server pipe so new processes will know to spin up a new FEXServer.
  // This one is closing
  close(ServerLockFD);

  // Close the server socket so no more connections can be started
  ServerAcceptor.reset();
  ServerFSAcceptor.reset();
}

void WaitForRequests() {
  Reactor.enable_async_stop();

  while (true) {
    std::optional Timeout = std::chrono::seconds {RequestTimeout};
    if (Foreground || NumClients > 0) {
      Timeout.reset();
    }
    auto Result = Reactor.run_one(Timeout);
    if (Result != fasio::error::success || Reactor.stopped()) {
      Reactor.cleanup();
      break;
    }
  }

  LogMan::Msg::DFmt("[FEXServer] Shutting Down");

  CloseConnections();
}

void SetConfiguration(bool Foreground, uint32_t PersistentTimeout) {
  ProcessPipe::Foreground = Foreground;
  ProcessPipe::RequestTimeout = PersistentTimeout;
}

void Shutdown() {
  Reactor.stop_async();
}
} // namespace ProcessPipe
