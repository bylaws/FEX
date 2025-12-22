
#include <cstdint>
#include <array>
#include <winternl.h>
#include <bcrypt.h>
#include <memoryapi.h>

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include "SteamStub.h"

namespace FEX::Windows {

#ifdef _M_ARM_64EC
static uint32_t LookupStubRVA(uint64_t BaseAddress, HMODULE Module) {
  IMAGE_NT_HEADERS* Nt = RtlImageNtHeader(Module);

  // If the image has no TLS callbacks, then the PE EP will be the stub entrypoint, otherwise it's the first TLS callback.
  uint32_t EntryPoint = Nt->OptionalHeader.AddressOfEntryPoint;
  ULONG TlsDirSize = 0;
  auto TlsDir = RtlImageDirectoryEntryToData(Module, true, IMAGE_DIRECTORY_ENTRY_TLS, &TlsDirSize);
  if (Nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && TlsDirSize >= sizeof(IMAGE_TLS_DIRECTORY64)) {
    auto TlsDir64 = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(TlsDir);
    if (!TlsDir64->AddressOfCallBacks) {
      return EntryPoint;
    }

    auto FirstCallback = reinterpret_cast<uint64_t*>(TlsDir64->AddressOfCallBacks);
    return *FirstCallback ? (*FirstCallback - BaseAddress) : EntryPoint;
  } else if (Nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && TlsDirSize >= sizeof(IMAGE_TLS_DIRECTORY32)) {
    auto TlsDir32 = reinterpret_cast<IMAGE_TLS_DIRECTORY32*>(TlsDir);
    if (!TlsDir32->AddressOfCallBacks) {
      return EntryPoint;
    }

    auto FirstCallback = reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(TlsDir32->AddressOfCallBacks));
    return *FirstCallback ? (*FirstCallback - BaseAddress) : EntryPoint;
  } else {
    return EntryPoint;
  }
}

struct FEX_PACKED StubHeader64 {
  static constexpr size_t MAGIC_EXPECTED = 0xc0dec0df;
  static constexpr uint32_t FLAG_NOT_ENCRYPTED = 1 << 2;

  uint32_t XORKey;                       // 0x00
  uint32_t Magic;                        // 0x04
  uint8_t Pad1[0x34];                    // 0x08
  uint32_t Flags;                        // 0x3c
  uint8_t Pad2[0x08];                    // 0x30
  uint64_t TextAddr;                     // 0x48
  uint64_t TextSize;                     // 0x50
  std::array<uint8_t, 0x20> TextAESKey;  // 0x58
  std::array<uint8_t, 0x10> TextAESIV;   // 0x78
  std::array<uint8_t, 0x10> TextPreCode; // 0x88
  uint8_t Pad3[0x58];                    // 0x98
};
static_assert(sizeof(StubHeader64) == 0xf0);

class ScopedBCryptAlg final {
public:
  explicit ScopedBCryptAlg(BCRYPT_ALG_HANDLE Handle = nullptr)
    : Handle(Handle) {}

  // Move-only type
  ScopedBCryptAlg(const ScopedBCryptAlg&) = delete;
  ScopedBCryptAlg& operator=(ScopedBCryptAlg&) = delete;
  ScopedBCryptAlg(ScopedBCryptAlg&& rhs)
    : Handle(rhs.Handle) {
    rhs.Handle = nullptr;
  }

  ~ScopedBCryptAlg() {
    if (Handle) {
      BCryptCloseAlgorithmProvider(Handle, 0);
    }
  }

  BCRYPT_ALG_HANDLE operator*() const {
    return Handle;
  }

  BCRYPT_ALG_HANDLE& operator*() {
    return Handle;
  }
private:
  BCRYPT_ALG_HANDLE Handle;
};

TryDecryptSteamStubResult TryDecryptSteamStubIfPresent(uint64_t BaseAddress) {
  auto Module = reinterpret_cast<HMODULE>(BaseAddress);
  IMAGE_NT_HEADERS* Nt = RtlImageNtHeader(Module);
  uint32_t StubRVA = LookupStubRVA(BaseAddress, Module);
  IMAGE_SECTION_HEADER* EntryPointSec = RtlImageRvaToSection(Nt, Module, StubRVA);
  if (!EntryPointSec || memcmp(EntryPointSec->Name, ".bind", 6)) {
    return TryDecryptSteamStubResult::NotPresent;
  }

  if (Nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  StubHeader64 HeaderCopy;
  memcpy(&HeaderCopy, reinterpret_cast<uint8_t*>(BaseAddress + StubRVA - sizeof(StubHeader64)), sizeof(StubHeader64));
  uint32_t XORKey = HeaderCopy.XORKey;
  uint32_t* XORRegionBegin = reinterpret_cast<uint32_t*>(&HeaderCopy) + 1;
  uint32_t* XORRegionEnd = reinterpret_cast<uint32_t*>(&HeaderCopy + 1);
  for (auto It = XORRegionBegin; It != XORRegionEnd; It++) {
    uint32_t NewXORKey = *It;
    *It ^= XORKey;
    XORKey = NewXORKey;
  }

  if (HeaderCopy.Magic != StubHeader64::MAGIC_EXPECTED) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  if (HeaderCopy.Flags & StubHeader64::FLAG_NOT_ENCRYPTED) {
    return TryDecryptSteamStubResult::NotPresent;
  }

  ScopedBCryptAlg AESECB;
  if (BCryptOpenAlgorithmProvider(&*AESECB, BCRYPT_AES_ALGORITHM, nullptr, 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  if (BCryptSetProperty(*AESECB, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  struct {
    BCRYPT_KEY_DATA_BLOB_HEADER Header;
    std::array<uint8_t, 0x20> Key;
  } KeyDataBlob {.Header {
                   .dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC,
                   .dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1,
                   .cbKeyData = static_cast<ULONG>(HeaderCopy.TextAESKey.size()),
                 },
                 .Key = HeaderCopy.TextAESKey};

  BCRYPT_KEY_HANDLE Key;
  if (BCryptImportKey(*AESECB, nullptr, BCRYPT_KEY_DATA_BLOB, &Key, nullptr, 0, reinterpret_cast<uint8_t*>(&KeyDataBlob), sizeof(KeyDataBlob), 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  std::array<uint8_t, 0x10> DecryptedIV;
  ULONG DecyptedSize = 0;
  bool Success = !BCryptDecrypt(Key, HeaderCopy.TextAESIV.data(), HeaderCopy.TextAESIV.size(), nullptr, nullptr, DecryptedIV.size(),
                                DecryptedIV.data(), DecryptedIV.size(), &DecyptedSize, 0) &&
                 DecyptedSize == DecryptedIV.size();
  BCryptDestroyKey(Key);
  if (!Success) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  auto TextBegin = reinterpret_cast<uint8_t*>(BaseAddress + HeaderCopy.TextAddr);
  ULONG OldProt;
  if (!VirtualProtect(TextBegin, HeaderCopy.TextSize, PAGE_EXECUTE_READWRITE, &OldProt)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  memmove(TextBegin + HeaderCopy.TextPreCode.size(), TextBegin, HeaderCopy.TextSize - HeaderCopy.TextPreCode.size());
  memcpy(TextBegin, HeaderCopy.TextPreCode.data(), HeaderCopy.TextPreCode.size());

  ScopedBCryptAlg AESCBC;
  if (BCryptOpenAlgorithmProvider(&*AESCBC, BCRYPT_AES_ALGORITHM, nullptr, 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  if (BCryptSetProperty(*AESCBC, BCRYPT_CHAINING_MODE, (UCHAR*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  if (BCryptImportKey(*AESCBC, nullptr, BCRYPT_KEY_DATA_BLOB, &Key, nullptr, 0, reinterpret_cast<uint8_t*>(&KeyDataBlob), sizeof(KeyDataBlob), 0)) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  Success = !BCryptDecrypt(Key, TextBegin, HeaderCopy.TextSize, nullptr, DecryptedIV.data(), DecryptedIV.size(), TextBegin,
                           HeaderCopy.TextSize, &DecyptedSize, 0) &&
            DecyptedSize == HeaderCopy.TextSize;
  BCryptDestroyKey(Key);
  if (!Success) {
    return TryDecryptSteamStubResult::DecryptFailure;
  }

  LogMan::Msg::IFmt("Decrypted encrypted SteamStub .text section: {:X}", reinterpret_cast<uint64_t>(TextBegin));
  return TryDecryptSteamStubResult::DecryptSuccess;
}
#else
TryDecryptSteamStubResult TryDecryptSteamStubIfPresent(uint64_t BaseAddress) {
  return TryDecryptSteamStubResult::NotPresent; // 32-bit steamstub is currently unsupported
}
#endif
} // namespace FEX::Windows
