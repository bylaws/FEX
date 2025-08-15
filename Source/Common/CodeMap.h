#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>

namespace FEX::CodeMap {
struct FEX_PACKED ItemHeader {
  enum class Type : uint8_t {
    ImageLoadAnnouncement = 0,
    EntryPoint,
  } Type;
};

struct FEX_PACKED ItemEntryPoint {
  ItemHeader Header {
    .Type = ItemHeader::Type::EntryPoint,
  };
  uint32_t ImageId;
  uint64_t Offset;
};

struct FEX_PACKED ItemImageLoadAnnouncement {
  ItemHeader Header {
    .Type = ItemHeader::Type::ImageLoadAnnouncement,
  };
  char FilePath_UniqueId[];
};


struct ParsedImage {
  std::string FullPath;
  std::string UniqueId;
  std::vector<uint64_t> EntryPoints;
};

inline std::vector<ParsedImage> ParseCodeMap(std::string_view Path) {
  std::ifstream ifs(std::string {Path}, std::ios::binary);
  if (!ifs) {
    LogMan::Msg::EFmt("Failed to open file: {}", Path);
  }

  std::vector<ParsedImage> Images;

  while (ifs.peek() != EOF) {
    ItemHeader Header;
    ifs.read(reinterpret_cast<char*>(&Header), sizeof(Header));
    if (!ifs) {
      if (ifs.gcount() == 0) {
        break;
      }
      return Images;
    }

    switch (Header.Type) {
    case ItemHeader::Type::ImageLoadAnnouncement: {
      ParsedImage NewImage;
      std::getline(ifs, NewImage.FullPath, '\0');
      std::getline(ifs, NewImage.UniqueId, '\0');
      if (!ifs) {
        return Images;
      }

      Images.push_back(std::move(NewImage));
      break;
    }

    case ItemHeader::Type::EntryPoint: {
      uint32_t ImageId;
      uint64_t Offset;
      ifs.read(reinterpret_cast<char*>(&ImageId), sizeof(ImageId));
      ifs.read(reinterpret_cast<char*>(&Offset), sizeof(Offset));

      if (!ifs) {
        return Images;
      }

      if (ImageId >= Images.size()) {
        LogMan::Msg::EFmt("Invalid ImageId: {}", ImageId);
        return {};
      }
      Images[ImageId].EntryPoints.push_back(Offset);
      break;
    }

    default: {
      LogMan::Msg::EFmt("Unknown CodeMap item type encountered.");
      return {};
    }
    }
  }

  return Images;
}

} // namespace FEX::CodeMap