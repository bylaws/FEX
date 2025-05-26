// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: SMC/MMan Tracking
$end_info$
*/

#include "Common/FDUtils.h"

#include <filesystem>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/personality.h>

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <Linux/Utils/ELFParser.h>
#include <PEParser.h>

namespace FEX::HLE {
// SMC interactions
bool SyscallHandler::HandleSegfault(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  const auto FaultAddress = (uintptr_t)((siginfo_t*)info)->si_addr;

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  auto CallRetStackInfo = ThreadObject->GetCallRetStackInfo();
  if (FaultAddress >= CallRetStackInfo.AllocationBase && FaultAddress < CallRetStackInfo.AllocationEnd) {
    // Reset REG_CALLRET_SP to the default location to allow for underflows/overflows
    ArchHelpers::Context::SetArmReg(ucontext, 25, CallRetStackInfo.DefaultLocation);
    return true;
  }

  {
    // Can't use the deferred signal lock in the SIGSEGV handler.
    auto lk = FEXCore::MaskSignalsAndLockMutex<std::shared_lock>(_SyscallHandler->VMATracking.Mutex);

    auto VMATracking = &_SyscallHandler->VMATracking;

    // If the write spans two pages, they will be flushed one at a time (generating two faults)
    auto Entry = VMATracking->FindVMAEntry(FaultAddress);

    // If an untracked address, or the mapping wasn't writable, it can't be handled here
    if (Entry == VMATracking->VMAs.end() || !Entry->second.Prot.Writable) {
      return false;
    }

    auto FaultBase = FEXCore::AlignDown(FaultAddress, FEXCore::Utils::FEX_PAGE_SIZE);

    auto UnprotectRegionCallback = [](uintptr_t Start, uintptr_t Length) {
      auto rv = mprotect((void*)Start, Length, PROT_READ | PROT_WRITE);
      LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", Start, Length);
    };

    if (Entry->second.Flags.Shared) {
      LOGMAN_THROW_A_FMT(Entry->second.Resource, "VMA tracking error");

      auto Offset = FaultBase - Entry->first + Entry->second.Offset;

      auto VMA = Entry->second.Resource->FirstVMA;
      LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

      // Flush all mirrors, remap the page writable as needed
      do {
        if (VMA->Offset <= Offset && (VMA->Offset + VMA->Length) > Offset) {
          auto FaultBaseMirrored = Offset - VMA->Offset + VMA->Base;

          if (VMA->Prot.Writable) {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
          } else {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }
      } while ((VMA = VMA->ResourceNextVMA));
    } else {
      _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);

    auto CTX = Thread->CTX;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !CTX->IsCurrentBlockSingleInst(Thread) &&
        CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
      // If we are not in a single-instruction block, and the SMC write address could intersect with the current block,
      // reconstruct the context and repeat the faulting instruction as a single-instruction block so any SMC it performs
      // is immediately picked up.
      ThreadObject->SignalInfo.Delegator->SpillSRA(Thread, ucontext, Thread->CurrentFrame->InSyscallInfo & 0xFFFF);

      // Adjust context to return to the dispatcher, reloading SRA from thread state
      const auto& Config = ThreadObject->SignalInfo.Delegator->GetConfig();
      ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
      ArchHelpers::Context::SetArmReg(ucontext, 1, 1); // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
    }

    return true;
  }
}

void SyscallHandler::MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  const auto Base = Start & FEXCore::Utils::FEX_PAGE_MASK;
  const auto Top = FEXCore::AlignUp(Start + Length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_MTRACK) {
      return;
    }

    auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

    // Find the first mapping at or after the range ends, or ::end().
    // Top points to the address after the end of the range
    auto Mapping = VMATracking.VMAs.lower_bound(Top);

    while (Mapping != VMATracking.VMAs.begin()) {
      Mapping--;

      const auto MapBase = Mapping->first;
      const auto MapTop = MapBase + Mapping->second.Length;

      if (MapTop <= Base) {
        // Mapping ends before the Range start, exit
        break;
      } else {
        const auto ProtectBase = std::max(MapBase, Base);
        const auto ProtectSize = std::min(MapTop, Top) - ProtectBase;

        if (Mapping->second.Flags.Shared) {
          LOGMAN_THROW_A_FMT(Mapping->second.Resource, "VMA tracking error");

          const auto OffsetBase = ProtectBase - Mapping->first + Mapping->second.Offset;
          const auto OffsetTop = OffsetBase + ProtectSize;

          auto VMA = Mapping->second.Resource->FirstVMA;
          LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

          do {
            auto VMAOffsetBase = VMA->Offset;
            auto VMAOffsetTop = VMA->Offset + VMA->Length;
            auto VMABase = VMA->Base;

            if (VMA->Prot.Writable && VMAOffsetBase < OffsetTop && VMAOffsetTop > OffsetBase) {

              const auto MirroredBase = std::max(VMAOffsetBase, OffsetBase);
              const auto MirroredSize = std::min(OffsetTop, VMAOffsetTop) - MirroredBase;

              auto rv = mprotect((void*)(MirroredBase - VMAOffsetBase + VMABase), MirroredSize, PROT_READ);
              LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", MirroredBase, MirroredSize);
            }
          } while ((VMA = VMA->ResourceNextVMA));

        } else if (Mapping->second.Prot.Writable) {
          int rv = mprotect((void*)ProtectBase, ProtectSize, PROT_READ);

          LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", ProtectBase, ProtectSize);
        }
      }
    }
  }
}

void SyscallHandler::InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, Start, Length);
}

// Used for AOT
FEXCore::HLE::AOTIRCacheEntryLookupResult SyscallHandler::LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

  // Get the first mapping after GuestAddr, or end
  // GuestAddr is inclusive
  // If the write spans two pages, they will be flushed one at a time (generating two faults)
  auto EntryIt = VMATracking.FindVMAEntry(GuestAddr);
  if (EntryIt == VMATracking.VMAs.end()) {
    return {nullptr, 0};
  }
  const auto* Entry = &EntryIt->second;

  uint64_t VAFileStart = 0;
  if (Entry->Resource) {
    // TODO: Probably shouldn't be needed. However, currently the Wine workaround in VMATracking doesn't set up Offset, so this wouldn't work otherwise
    if (Entry->Offset == 0) {
      Entry = Entry->Resource->FirstVMA;
    }
    // Compute base address for the library using ELF program headers.
    //
    // This can't cleanly be inferred from the virtual memory mappings.

    // TODO: This information should probably be included in the cache file instead of reparsing it at runtime
    for (auto& phdr : Entry->Resource->ProgramHeaders) {
      // Check for exact match in the mapping offset. This resolves ambiguities when ELF sections are overlapping
      // TODO: Exact offset match won't work for mappings that are split by unmapping a page in the middle. This happens e.g. for steam.exe.so.

      // File offset of the first page of the fd mapped into memory
      auto SectionStartOffset = phdr.p_offset - (phdr.p_vaddr & 0xfff);
      // TODO: Assert SectionStartOffset is page-aligned

      if (Entry->Offset >= SectionStartOffset && Entry->Offset < (phdr.p_offset + phdr.p_filesz) - (phdr.p_vaddr & 0xfff)) {

          // Compute VA offset relative to the base mapping
          // NOTE: We're essentially computing the VA of the base mapping here instead of using the true base address. This allows FEXOfflineCompiler to process mappings without reading the ELF file.
          //       TODO: This is kind of pointless though (since FEXOfflineCompiler does read the mappings to map the ELF file to begin with)
          if (VAFileStart) {
            // TODO: Still hit during Steam startup
            // ERROR_AND_DIE_FMT("Duplicate program header match?");
          }

          // TODO: For steam.exe.so (e.g. steam.exe as launched by God of War), this will generate offsets that don't match objdump output...
          VAFileStart = Entry->Base - (phdr.p_vaddr - (phdr.p_offset & 0xfff)) + (Entry->Resource->ProgramHeaders[0].p_vaddr - (Entry->Resource->ProgramHeaders[0].p_offset & 0xfff))
                        - (Entry->Offset - SectionStartOffset);
      }
    }
  }

  // TODO: Should Entry->second.Resource ever be 0 ?
  return {Entry->Resource ? Entry->Resource->AOTIRCacheEntry : nullptr,
          VAFileStart, (uintptr_t)EntryIt->first, (uintptr_t)EntryIt->first + (uintptr_t)EntryIt->second.Length};
}

FEXCore::HLE::ExecutableRangeInfo SyscallHandler::QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);

  auto Entry = VMATracking.FindVMAEntry(Address);
  if (Entry == VMATracking.VMAs.end() ||
      (!Entry->second.Prot.Executable && (!(ThreadObject->persona & READ_IMPLIES_EXEC) || !Entry->second.Prot.Readable))) {
    return {0, 0, false};
  }
  return {Entry->first, Entry->second.Length, Entry->second.Prot.Writable};
}

void SyscallHandler::ForEachVMAMapping(FEXCore::Core::InternalThreadState* Thread, std::function<void(uint64_t)> Func) {
  // TODO: Disabled while load-full-cache-on-load is enabled
  // auto lk = FEXCore::/*GuardSignalDeferringSection*/ GuardSignalDeferringSectionWithFallback<std::shared_lock>(VMATracking.Mutex, Thread);

  for (const auto& [Base, Entry] : VMATracking.VMAs) {
    if (Entry.Prot.Executable) {
      fmt::print(stderr, "Visiting VMA entry {:#x} / {:#x}: {}\n", Base, Entry.Base - Entry.Offset,
                 *((fextl::string*)((char*)Entry.Resource->AOTIRCacheEntry + 32)) /* FileId */);
      Func(Base);
    }
  }
}

fextl::vector<Elf64_Phdr> GetHeaders(int fd) {
  // TODO: Is it safe to modify the FD's read cursor here?
  auto dupfd = dup(fd);
  ELFParser Parser;
  auto pos = lseek(dupfd, 0, SEEK_CUR);
  {
    // Check if this is a PE binary first
    PEParser Parser(dupfd);
    if (Parser) {
      fextl::vector<Elf64_Phdr> ElfSections;
      ElfSections.push_back({.p_offset = 0, .p_vaddr = Parser.ImageBase, .p_filesz = 0x1000 /* TODO: use size of headers? */ });
      for (auto& Section : Parser.Sections) {
        // Convert to elf header
        Elf64_Phdr ElfSection {};
        ElfSection.p_offset = Section.PointerToRawData;
        ElfSection.p_vaddr = Parser.ImageBase + Section.VirtualAddress;
        ElfSection.p_filesz = Section.SizeOfRawData;
        ElfSections.push_back(ElfSection);
      }
      return ElfSections;
    }
  };

  Parser.ReadElf(dupfd);
  lseek(dupfd, pos, SEEK_SET);
  return std::move(Parser.phdrs);
}

void* SyscallHandler::GuestMmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags,
                                int fd, off_t offset) {
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  if (flags & MAP_SHARED) {
    CTX->MarkMemoryShared(Thread);
  }

  FEXCore::IR::AOTIRCacheEntry* Entry = nullptr;

  {
    // NOTE: Frontend calls this with a nullptr Thread during initialization, but
    //       providing this code with a valid Thread object earlier would allow
    //       us to be more optimal by using GuardSignalDeferringSection instead
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    bool Map32Bit = !Is64Bit || (flags & FEX::HLE::X86_64_MAP_32BIT);
    if (Map32Bit) {
      Result = (uint64_t)Get32BitAllocator()->Mmap((void*)addr, length, prot, flags, fd, offset);
      if (FEX::HLE::HasSyscallError(Result)) {
        return reinterpret_cast<void*>(Result);
      }
      LOGMAN_THROW_A_FMT(Is64Bit || (Result >> 32) == 0 || (Result >> 32) == 0xFFFFFFFF, "values must fit to 32 bits");
    } else {
      Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, prot, flags, fd, offset));
      if (Result == ~0ULL) {
        return reinterpret_cast<void*>(-errno);
      }
    }

    Entry = FEX::HLE::_SyscallHandler->TrackMmap(Thread, Result, length, prot, flags, fd, offset);
  }

  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, Result, Size);

  if (Entry) {
    // TODO: Move this to first compile?
    CTX->FetchAOTIRCacheEntry(Thread, Result);
  }

  return reinterpret_cast<void*>(Result);
}

uint64_t SyscallHandler::GuestMunmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length) {
  LOGMAN_THROW_A_FMT(Is64Bit || (reinterpret_cast<uintptr_t>(addr) >> 32) == 0, "values must fit to 32 bits: {}", fmt::ptr(addr));
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    // Frontend calls this with nullptr Thread during initialization.
    // This is why `GuardSignalDeferringSectionWithFallback` is used here.
    // To be more optimal the frontend should provide this code with a valid Thread object earlier.
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    if (reinterpret_cast<uintptr_t>(addr) < 0x1'0000'0000ULL) {
      Result = FEX::HLE::_SyscallHandler->Get32BitAllocator()->Munmap(addr, length);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    } else {
      Result = ::munmap(addr, length);
      if (Result == -1) {
        return -errno;
      }
    }
    FEX::HLE::_SyscallHandler->TrackMunmap(Thread, addr, length);
  }
  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), Size);

  return Result;
}

uint64_t SyscallHandler::GuestMremap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* old_address, size_t old_size,
                                     size_t new_size, int flags, void* new_address) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(FEX::HLE::_SyscallHandler->VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::mremap(old_address, old_size, new_size, flags, new_address));
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result =
        reinterpret_cast<uint64_t>(FEX::HLE::_SyscallHandler->Get32BitAllocator()->Mremap(old_address, old_size, new_size, flags, new_address));
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }
    FEX::HLE::_SyscallHandler->TrackMremap(Thread, reinterpret_cast<uint64_t>(old_address), old_size, new_size, flags, Result);
  }

  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessaryOnRemap(Thread, reinterpret_cast<uint64_t>(old_address), Result, old_size, new_size);
  return Result;
}

uint64_t SyscallHandler::GuestMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(FEX::HLE::_SyscallHandler->VMATracking.Mutex, Thread);
    Result = ::mprotect(addr, len, prot);
    if (Result == -1) {
      return -errno;
    }

    FEX::HLE::_SyscallHandler->TrackMprotect(Thread, addr, len, prot);
  }

  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), len);

  // Handle Wine case
  if (prot & PROT_EXEC) {
    auto VMAEntry = VMATracking.FindVMAEntry(reinterpret_cast<uint64_t>(addr));
    if (VMAEntry != VMATracking.VMAs.end() && VMAEntry->second.Resource) {
      LogMan::Msg::IFmt("TRIGGERING DELAYED CACHE LOAD FOR WINE");
      CTX->FetchAOTIRCacheEntry(Thread, reinterpret_cast<uint64_t>(addr));
    }
  }

  return Result;
}

uint64_t SyscallHandler::GuestShmat(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, int shmid, const void* shmaddr, int shmflg) {
  auto CTX = Thread->CTX;
  uint64_t Result {};
  uint64_t Length {};
  CTX->MarkMemoryShared(Thread);

  {
    auto lk = FEXCore::GuardSignalDeferringSection(FEX::HLE::_SyscallHandler->VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::shmat(shmid, shmaddr, shmflg));
      if (Result == -1) {
        return -errno;
      }
    } else {
      uint32_t Addr;
      Result = FEX::HLE::_SyscallHandler->Get32BitAllocator()->Shmat(shmid, shmaddr, shmflg, &Addr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
      Result = Addr;
    }

    shmid_ds stat;

    [[maybe_unused]] auto res = shmctl(shmid, IPC_STAT, &stat);
    LOGMAN_THROW_A_FMT(res != -1, "shmctl IPC_STAT failed");

    Length = stat.shm_segsz;
    FEX::HLE::_SyscallHandler->TrackShmat(Thread, shmid, Result, shmflg, Length);
  }

  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, Result, Length);
  return Result;
}

uint64_t SyscallHandler::GuestShmdt(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, const void* shmaddr) {
  uint64_t Result {};
  uint64_t Length {};
  {
    auto lk = FEXCore::GuardSignalDeferringSection(FEX::HLE::_SyscallHandler->VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = ::shmdt(shmaddr);
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = FEX::HLE::_SyscallHandler->Get32BitAllocator()->Shmdt(shmaddr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }

    Length = FEX::HLE::_SyscallHandler->TrackShmdt(Thread, reinterpret_cast<uintptr_t>(shmaddr));
  }

  FEX::HLE::_SyscallHandler->InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uintptr_t>(shmaddr), Length);
  return Result;
}

// MMan Tracking
FEXCore::IR::AOTIRCacheEntry* SyscallHandler::TrackMmap(FEXCore::Core::InternalThreadState* Thread, uint64_t addr, size_t length, int prot, int flags, int fd, off_t offset) {
  const auto UnalignedSize = length;

  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  // Wine maps executables differently from normal Linux applications (see map_image_into_view in Wine's virtual.c):
  // * Anonymous memory is mmap'ed for the entire application
  // * The PE header is mmap'ed onto this range with PROT_EXEC
  // * The remaining PE sections are each mapped onto this range, however mmap will fail for unaligned PE sections
  //   * As a fallback, Wine will copy the file contents manually on the anonymous range
  bool WineCase = false;

  VMATracking::MappedResource* Resource = nullptr;

  if ((flags & (MAP_ANONYMOUS | MAP_FIXED)) == MAP_FIXED && (prot & PROT_EXEC) && UnalignedSize <= 4096) {
    // Detect mmap of PE_HEADER
    auto VMAEntry = VMATracking.FindVMAEntry(addr);
    if (VMAEntry != VMATracking.VMAs.end() && VMAEntry->first == addr /* TODO: Technically the range could have been merged with another one... */ && !VMAEntry->second.Resource) {
      LogMan::Msg::IFmt("Detected PE header mmap at address {:#x}\n", addr);
      WineCase = true;
    }
  }

  if (!(flags & MAP_ANONYMOUS)) {
    struct stat64 buf;
    fstat64(fd, &buf);
    VMATracking::MRID mrid {buf.st_dev, buf.st_ino};

    char Tmp[PATH_MAX];
    auto PathLength = FEX::get_fdpath(fd, Tmp);

    if (PathLength != -1) {
      Tmp[PathLength] = '\0';
      auto [Iter, Inserted] = VMATracking.EmplaceMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
      Resource = &Iter->second;

      if (Inserted) {
        // Resource->AOTIRCacheEntry = CTX->LoadAOTIRCacheEntry(fextl::string(Tmp, PathLength));
        auto Filename = fextl::string(Tmp, PathLength);

        // LogMan::Msg::IFmt("Loading object {}", Filename);

        Resource->Iterator = Iter;
      }
    }
  } else if (flags & MAP_SHARED) {
    VMATracking::MRID mrid {VMATracking::SpecialDev::Anon, AnonSharedId++};

    auto [Iter, Inserted] = VMATracking.EmplaceMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
    LOGMAN_THROW_A_FMT(Inserted == true, "VMA tracking error");
    Resource = &Iter->second;
    Resource->Iterator = Iter;
  } else {
    Resource = nullptr;
  }

  if (Resource && Resource->ProgramHeaders.empty() && VMATracking::VMAProt::fromProt(prot).Executable) {
    Resource->ProgramHeaders = GetHeaders(fd);
  }

  VMATracking.TrackVMARange(CTX, Resource, addr, offset, Size, VMATracking::VMAFlags::fromFlags(flags), VMATracking::VMAProt::fromProt(prot));

  // Load cache when the first executable mapping is loaded.
  // Some important use cases to consider:
  // - Mapping a non-executable file won't trigger search for code cache files
  // - Celeste loads gameoverlayrenderer.so as read-only at first and then as executable at a different base location
  // - Libraries may be mapped as read-only before being mprotect'ed as executable
  // - During God of War launch, steam.exe's steam.exe.so will unmap one page from its `.init` section
  // - A plugin-like library may be reloaded to a different base address throughout program execution
  // TODO: Reload the cache if the same library is reloaded to a different address!
  if (Resource && VMATracking::VMAProt::fromProt(prot).Executable) {
    char Tmp[PATH_MAX];
    auto PathLength = FEX::get_fdpath(fd, Tmp);
    auto Filename = fextl::string(Tmp, PathLength);
    LogMan::Msg::IFmt("LOADING AOT CACHE ENTRY: {}", Filename);
    // TODO: Identify via ELF build id instead
    Resource->AOTIRCacheEntry = CTX->LoadAOTIRCacheEntry(std::move(Filename));
    if (Thread) {
      if (!WineCase) {
        return Resource->AOTIRCacheEntry;
      } else {
        // Delayed until mprotect
      }
    } else {
      fmt::print(stderr, "SKIPPING ENTRY PREFETCH SINCE NO THREAD EXISTS YET\n");
    }
  }

  return nullptr;
}

void SyscallHandler::TrackMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length) {
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  VMATracking.DeleteVMARange(CTX, reinterpret_cast<uintptr_t>(addr), Size);
}

void SyscallHandler::TrackMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Size = FEXCore::AlignUp(len, FEXCore::Utils::FEX_PAGE_SIZE);

  VMATracking.ChangeProtectionFlags(reinterpret_cast<uintptr_t>(addr), Size, VMATracking::VMAProt::fromProt(prot));
}

void SyscallHandler::TrackMremap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, size_t OldSize, size_t NewSize, int flags,
                                 uint64_t NewAddress) {
  OldSize = FEXCore::AlignUp(OldSize, FEXCore::Utils::FEX_PAGE_SIZE);
  NewSize = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE);

  const auto OldVMA = VMATracking.FindVMAEntry(OldAddress);

  const auto OldResource = OldVMA->second.Resource;
  const auto OldOffset = OldVMA->second.Offset + OldAddress - OldVMA->first;
  const auto OldFlags = OldVMA->second.Flags;
  const auto OldProt = OldVMA->second.Prot;

  LOGMAN_THROW_A_FMT(OldVMA != VMATracking.VMAs.end(), "VMA Tracking corruption");

  if (OldSize == 0) {
    // Mirror existing mapping
    // must be a shared mapping
    LOGMAN_THROW_A_FMT(OldResource != nullptr, "VMA Tracking error");
    LOGMAN_THROW_A_FMT(OldFlags.Shared, "VMA Tracking error");
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  } else {

#ifndef MREMAP_DONTUNMAP
// MREMAP_DONTUNMAP is kernel 5.7+ and might not exist
#define MREMAP_DONTUNMAP 4
#endif
    if (!(flags & MREMAP_DONTUNMAP)) {
      VMATracking.DeleteVMARange(CTX, OldAddress, OldSize, OldResource);
    }

    // Make anonymous mapping
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  }
}

void SyscallHandler::TrackShmat(FEXCore::Core::InternalThreadState* Thread, int shmid, uint64_t shmaddr, int shmflg, uint64_t Length) {
  VMATracking::MRID mrid {VMATracking::SpecialDev::SHM, static_cast<uint64_t>(shmid)};

  auto [Iter, Inserted] = VMATracking.EmplaceMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, Length, {}, {}});
  auto Resource = &Iter->second;
  if (Inserted) {
    Resource->Iterator = Iter;
  }
  VMATracking.TrackVMARange(CTX, Resource, shmaddr, 0, Length, VMATracking::VMAFlags::fromFlags(MAP_SHARED), VMATracking::VMAProt::fromSHM(shmflg));
}

uint64_t SyscallHandler::TrackShmdt(FEXCore::Core::InternalThreadState* Thread, uint64_t shmaddr) {
  return VMATracking.DeleteSHMRegion(CTX, reinterpret_cast<uintptr_t>(shmaddr));
}

void SyscallHandler::TrackMadvise(FEXCore::Core::InternalThreadState* Thread, uintptr_t Base, uintptr_t Size, int advice) {
  Size = FEXCore::AlignUp(Size, FEXCore::Utils::FEX_PAGE_SIZE);
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    // TODO
  }
}

} // namespace FEX::HLE
