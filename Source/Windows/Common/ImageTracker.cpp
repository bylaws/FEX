// SPDX-License-Identifier: MIT

#include <mutex>
#include <span>

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/fextl/fmt.h>

#include <string>
#include <windef.h>
#include <winternl.h>
#include <fileapi.h>

#include "Common/CodeMap.h"
#include "FEXAOTBundle.h"
#include "Handle.h"
#include "Module.h"
#include "ImageTracker.h"


namespace FEX::Windows {
ImageTracker::ImageTracker(FEXCore::Context::Context& CTX) : CTX{CTX} {
  auto CodeMapPath = fmt::format("{}\\{}-{}.cmap", getenv("TEMP"), BaseName(GetExecutableFilePath()), GetCurrentProcessId());
  HANDLE File = CreateFileA(CodeMapPath.c_str(), GENERIC_WRITE | GENERIC_READ | FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (File != INVALID_HANDLE_VALUE) {
    CodeMapWriteQueue.emplace(File);
    if (!CodeMapWriteQueue->StartThread()) {
      CodeMapWriteQueue.reset();
    }
  }
}

void ImageTracker::HandleImageMap(std::string_view Path, uint64_t Address, bool MainImage) {
  std::unique_lock Lk{ImagesLock};

  const auto Module = reinterpret_cast<HMODULE>(Address);
  IMAGE_NT_HEADERS* Nt = RtlImageNtHeader(Module);
  auto [It, Inserted] = MappedImages.insert_or_assign(Address, MappedImageInfo{
    .FullPath = std::string{Path},
    .PETimeDateStamp = Nt->FileHeader.TimeDateStamp,
    .PESizeOfImage = Nt->OptionalHeader.SizeOfImage,
  });

  if (!Inserted) {
    return;
  }
  if (MainImage) {
    LOGMAN_MSG_A_FMT(NextCodeMapId == 0, "The main image must be the first mapped image!");
    LoadAOTBundle(Address);
  }

  std::string UniqueId = It->second.GetUniqueId();
  if (auto CodeMapIdIt = ImageCodeMapIds.find(UniqueId); CodeMapIdIt != ImageCodeMapIds.end()) {
    It->second.CodeMapId = CodeMapIdIt->second;
  } else if (CodeMapWriteQueue) {
    size_t FullPathTermSize = It->second.FullPath.size() + 1;
    size_t UniqueIdTermSize = UniqueId.size() + 1;

    std::vector<uint8_t> Buffer(sizeof(FEX::CodeMap::ItemImageLoadAnnouncement) + FullPathTermSize + UniqueIdTermSize);
    size_t Offset = 0;
    new (Buffer.data() + Offset) FEX::CodeMap::ItemImageLoadAnnouncement();
    Offset += sizeof(FEX::CodeMap::ItemImageLoadAnnouncement);
    memcpy(Buffer.data() + Offset, It->second.FullPath.c_str(), FullPathTermSize);
    Offset += FullPathTermSize;
    memcpy(Buffer.data() + Offset, UniqueId.data(),  UniqueIdTermSize);

    // ImagesLock must stay locked here as this effectively allocates the CodeMapId
    ImageCodeMapIds[UniqueId] = NextCodeMapId;
    It->second.CodeMapId = NextCodeMapId;
    NextCodeMapId++;
    CodeMapWriteQueue->Append(Buffer);
  }

  auto AOTImage = AOTImages.find(UniqueId);
  if (AOTImage != AOTImages.end() && MainImage) {
    CTX.FetchAOTIRCacheEntry(AOTImage->second.Data, Address);
  }
}

void ImageTracker::HandleImageUnmap(uint64_t Address) {
  std::unique_lock Lk{ImagesLock};
  MappedImages.erase(Address);
}

void ImageTracker::MarkGuestBlockEntry(uint64_t Address) {
  if (!CodeMapWriteQueue) {
    return;
  }

  FEX::CodeMap::ItemEntryPoint Item{};

  {
    std::shared_lock Lk{ImagesLock};
    auto Succ  =MappedImages.upper_bound(Address);
    if (Succ == MappedImages.begin()) return;
    auto Pred = std::prev(Succ);
    if (Address >= Pred->first + Pred->second.PESizeOfImage) return;

    Item.ImageId = Pred->second.CodeMapId;
    Item.Offset = Address - Pred->first;
  }
  CodeMapWriteQueue->Append(std::span<uint8_t>(reinterpret_cast<uint8_t *>(&Item), sizeof(Item)));
}

ImageTracker::IOQueue::IOQueue(HANDLE File) : File(File) {
  RtlInitializeConditionVariable(&ReadCV);
  RtlInitializeConditionVariable(&WriteCV);
  RtlInitializeCriticalSection(&CS);
}

bool ImageTracker::IOQueue::StartThread() {
  HANDLE Thread;
  return !NtCreateThreadEx(&Thread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(), reinterpret_cast<PRTL_THREAD_START_ROUTINE>(ThreadEntry), this,
                           THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER |
                           THREAD_CREATE_FLAGS_SKIP_LOADER_INIT | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE,
                           0, 0, 0, nullptr );
}

void ImageTracker::IOQueue::ThreadProc() {
  size_t PrevWritePointer = 0;
  bool HadIOError = false;
  while (true) {
    RtlEnterCriticalSection(&CS);
    ReadPointer = PrevWritePointer;
    RtlWakeConditionVariable(&WriteCV);
    while (ReadPointer == WritePointer) {
      // Wake up every 100ms to write out anything pending, as ReadCV is only signalled when the queue is >25% full,
      constexpr LARGE_INTEGER Timeout = {.QuadPart = -1000000};
      RtlSleepConditionVariableCS(&ReadCV, &CS, &Timeout);
    }

    PrevWritePointer = WritePointer;
    RtlLeaveCriticalSection(&CS);

    if (HadIOError) {
      continue;
    }

    bool WrapAround = PrevWritePointer < ReadPointer;
    size_t FirstReadSize = WrapAround ? (IOQueueSize - ReadPointer) : PrevWritePointer - ReadPointer;

    DWORD Written;
    WriteFile(File, Buffer.data() + ReadPointer, static_cast<DWORD>(FirstReadSize), &Written, nullptr);
    if (Written != FirstReadSize) {
      HadIOError = true;
    } else if (WrapAround) {
      WriteFile(File, Buffer.data(), static_cast<DWORD>(PrevWritePointer), &Written, nullptr);
      if (Written != PrevWritePointer) {
        HadIOError = true;
      }
    }
  }
}

void ImageTracker::IOQueue::Append(std::span<uint8_t> Data) {
    RtlEnterCriticalSection(&CS);
    
    auto getFreeSpace = [&]() {
      return (ReadPointer < WritePointer ? IOQueueSize - WritePointer + ReadPointer : ReadPointer - WritePointer) - 1;
    };

    while (getFreeSpace() < Data.size()) {
      RtlSleepConditionVariableCS(&WriteCV, &CS, nullptr);
    }

    bool WrapAround = WritePointer + Data.size() >= IOQueueSize;
    size_t FirstWriteSize = WrapAround ? (IOQueueSize - WritePointer) : Data.size();
    size_t SecondWriteSize = WrapAround ? WritePointer + Data.size() - IOQueueSize : 0;

    memcpy(Buffer.data() + WritePointer, Data.data(), FirstWriteSize);
    WritePointer += FirstWriteSize;
    if (WrapAround) {
      memcpy(Buffer.data(), Data.data() + FirstWriteSize, SecondWriteSize);
      WritePointer = SecondWriteSize;
    }

    if (getFreeSpace() < IOQueueSize / 4) {
      RtlWakeConditionVariable(&ReadCV);
    }

    RtlLeaveCriticalSection(&CS);
}

void ImageTracker::LoadAOTBundle(uint64_t MainImageAddress) {
  std::string Path = fmt::format("{}\\{}.fab", getenv("LOCALAPPDATA"), MappedImages[MainImageAddress].GetUniqueId());
  auto FileHandle = ScopedHandle{CreateFileA(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)};
  if (*FileHandle == INVALID_HANDLE_VALUE) {
    return;
  }

  IO_STATUS_BLOCK IOSB;
  FILE_STANDARD_INFORMATION StandardInfo;
  if (NtQueryInformationFile(*FileHandle, &IOSB, &StandardInfo, sizeof(StandardInfo), FileStandardInformation)) {
    return;
  }
  AOTBundleSize = StandardInfo.EndOfFile.QuadPart;
  ScopedHandle SectionHandle;
  if (NtCreateSection(&*SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ, nullptr, nullptr, PAGE_EXECUTE_READ,
                      SEC_COMMIT, *FileHandle)) {
    return;
  }
  SIZE_T MappedSize = 0;
  if (NtMapViewOfSection(*SectionHandle, NtCurrentProcess(), reinterpret_cast<void **>(&MappedAOTBundle), 0, 0, nullptr,
                         &MappedSize, ViewUnmap, MEM_RESERVE | MEM_TOP_DOWN,PAGE_EXECUTE_READ)) {
    return;
  }
  if (AOTBundleSize < sizeof(FAB::Header) + sizeof(FAB::Trailer)) {
    return;
  }

  auto* Header = reinterpret_cast<FAB::Header*>(MappedAOTBundle);
  if (Header->Magic[0] != 'F' || Header->Magic[1] != 'A' || Header->Magic[2] != 'B') {
    return;
  }
  if (Header->FormatVersion != 1) {
    return;
  }
  auto DescEndPtr = MappedAOTBundle + AOTBundleSize - sizeof(FAB::Trailer);
  auto Trailer = reinterpret_cast<FAB::Trailer*>(DescEndPtr);
  auto DescBeginPtr = MappedAOTBundle + Trailer->ImageDescSectionOffset;
  auto DescIt = DescBeginPtr;
  for (uint32_t i = 0; i < Header->NumImages; ++i) {
    if (DescIt >= DescEndPtr) {
      return;

    }
    auto Desc = reinterpret_cast<FAB::ImageDesc*>(DescIt);
    std::string UniqueId{Desc->UniqueId};
    AOTImages[UniqueId] = {
      .Data = MappedAOTBundle + Desc->FileOffset
    };
    DescIt += sizeof(FAB::ImageDesc) + UniqueId.size() + 1;
  }

  LogMan::Msg::EFmt("Loaded AOT bundle: {:X} - {:X}", reinterpret_cast<uintptr_t>(MappedAOTBundle),
                    reinterpret_cast<uintptr_t>(MappedAOTBundle) + AOTBundleSize);
}
} // namespace FEX::Windows
