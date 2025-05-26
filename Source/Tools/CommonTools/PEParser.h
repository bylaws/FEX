#pragma once

#include "LinuxSyscalls/Syscalls.h"
#include <cstdint>
#include <unistd.h>

struct PEParser {
  struct PEHeader {
    uint32_t Magic;
    uint8_t Machine[2];
    uint16_t SectionCount;
    char Other[0xc];
    uint16_t OptionalHeaderSize;
    uint16_t Characteristics;
  };

  // IMAGE_SECTION_HEADER
  struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t Other[3];
    uint32_t Characteristics;
  };

  bool IsValid = false;

  PEHeader PEHeader;

  uint64_t ImageBase;
  uint32_t ImageSize; // 32-bit even on 64-bit
  bool Is64Bit;

  PEParser(int fd) {
    char magic[2];
    pread(fd, magic, sizeof(magic), 0);
    // Check for DOS header
    if (magic[0] != 'M' || magic[1] != 'Z') {
      return;
    }
    LogMan::Msg::EFmt("Detected PE file");

    uint32_t PEOffset = 0;
    pread(fd, &PEOffset, sizeof(PEOffset), 60);
    pread(fd, &PEHeader, sizeof(PEHeader), PEOffset);
    if (PEHeader.Magic != 0x4550 /* "PE" */) {
      return;
    }
    LogMan::Msg::EFmt("Verified PE magic");

    const auto SizeofPEHeader = sizeof(PEHeader);
    pread(fd, &magic, sizeof(magic), PEOffset + SizeofPEHeader);
    if (magic[0] == 0xb && (magic[1] == 0x2 || magic[1] == 0x1)) {
      // TODO: Check optional header size first
      LogMan::Msg::EFmt("Verified optional header magic");
    } else {
      return;
    }
    Is64Bit = (magic[1] == 0x2);

    uint16_t OptionalHeaderMagic;
    pread(fd, &OptionalHeaderMagic, sizeof(OptionalHeaderMagic), PEOffset + SizeofPEHeader);
    LogMan::Throw::AFmt(!Is64Bit || (OptionalHeaderMagic == 0x20b), "");
    LogMan::Throw::AFmt(Is64Bit || (OptionalHeaderMagic == 0x10b), "");
    // TODO: Optional header layout may be different on 32-bit...
    if (Is64Bit) {
      pread(fd, &ImageBase, sizeof(ImageBase), PEOffset + SizeofPEHeader + 0x18);
      pread(fd, &ImageSize, sizeof(ImageSize), PEOffset + SizeofPEHeader + 0x38);
    } else {
      uint32_t ImageBase32;
      uint32_t ImageSize32;
      pread(fd, &ImageBase32, sizeof(ImageBase32), PEOffset + SizeofPEHeader + 0x1c);
      pread(fd, &ImageSize32, sizeof(ImageSize32), PEOffset + SizeofPEHeader + 0x38);
      ImageBase = ImageBase32;
      ImageSize = ImageSize32;
    }
    LogMan::Msg::EFmt("ImageBase {:#x}", ImageBase);
    LogMan::Msg::EFmt("ImageSize {:#x}", ImageSize);

    Sections.reserve(PEHeader.SectionCount);
    for (int i = 0; i < PEHeader.SectionCount; ++i) {
      SectionHeader Section;
      pread(fd, &Section, sizeof(Section), PEOffset + SizeofPEHeader + PEHeader.OptionalHeaderSize + i * sizeof(SectionHeader));
      Sections.push_back(Section);
    }

    IsValid = true;
  }

  static int MapProtectionFlags(const SectionHeader& Section) {
    int ret = 0;
    if (Section.Characteristics & 0x20000000) {
      ret |= PROT_EXEC;
    }
    if (Section.Characteristics & 0x40000000) {
      ret |= PROT_READ;
    }
    if (Section.Characteristics & 0x80000000) {
      ret |= PROT_WRITE;
    }
    return ret;
  }

  // Returns true on success
  bool MapMemory(FEX::HLE::SyscallMmapInterface* const Handler, int fd) {
    const int MapType = MAP_PRIVATE | MAP_DENYWRITE | MAP_FIXED;

    void* rv = Handler->GuestMmap(nullptr, (void*)ImageBase, ImageSize, PROT_READ | PROT_WRITE | PROT_EXEC, MapType | MAP_ANONYMOUS, -1, 0);
    if (rv == MAP_FAILED) {
      LogMan::Msg::EFmt("MapFile: Some PE mapping failed, {}\n", errno);
      return false;
    }

    rv = Handler->GuestMmap(nullptr, (void*)ImageBase, 0x1000, PROT_READ | PROT_WRITE, MapType, fd, 0);
    if (rv == MAP_FAILED) {
      LogMan::Msg::EFmt("MapFile: Some PE mapping failed, {}, fd: {}\n", errno, fd);
      return false;
    }
    for (const auto& Header : Sections) {
      int MapProt = MapProtectionFlags(Header);

      auto addr = ImageBase + Header.VirtualAddress;
      // auto size = FEXCore::AlignUp(Header.SizeOfRawData, FEXCore::Utils::FEX_PAGE_SIZE);
      auto off = Header.PointerToRawData;

      // if (size == 0) {
      //   ERROR_AND_DIE_FMT("TODO: Zero-size map");
      //   // continue;
      // }

      pread(fd, (void*)addr, Header.SizeOfRawData, off);
      // void* rv = Handler->GuestMmap(nullptr, (void*)addr, size, MapProt, MapType, fd, off);
      // if (rv == MAP_FAILED) {
      //   LogMan::Msg::EFmt("MapFile: Some PE mapping failed, {}, fd: {}\n", errno, fd);
      //   return false;
      // }
    }
    return true;
  }

  fextl::vector<SectionHeader> Sections;

  explicit operator bool() const {
    return IsValid;
  }
};
