// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/IR/IR.h>

namespace FEXCore::CPU {
enum class RelocationTypes : uint8_t {
  // 8 byte literal in memory for symbol
  // Aligned to struct RelocNamedSymbolLiteral
  RELOC_NAMED_SYMBOL_LITERAL,

  // TODO: Comment
  RELOC_GUEST_RIP_LITERAL,

  // Fixed size named thunk move
  // 4 instruction constant generation
  // Aligned to struct RelocNamedThunkMove
  RELOC_NAMED_THUNK_MOVE,

  // Fixed size guest RIP move
  // 4 instruction constant generation
  // Aligned to struct RelocGuestRIPMove
  RELOC_GUEST_RIP_MOVE,
};

struct RelocationTypeHeader final {
  RelocationTypes Type;
};

struct RelocNamedSymbolLiteral final {
  enum class NamedSymbol : uint8_t {
    ///< Thread specific relocations
    // JIT Literal pointers
    SYMBOL_LITERAL_EXITFUNCTION_LINKER,
  };

  RelocationTypeHeader Header {};

  NamedSymbol Symbol;

  char pad : 6 {};

  // Offset in to the code section to begin the relocation
  uint64_t Offset {};

  uint32_t pad2[8];
};

struct RelocGuestRIPLiteral final {
  RelocationTypeHeader Header {.Type = RelocationTypes::RELOC_GUEST_RIP_LITERAL};
  char pad : 7 {};

  // Offset in to the code section to begin the relocation
  // TODO: Move to RelocationTypeHeader
  uint64_t Offset {};

  // The offset relative to the fragment entry point
  uint64_t GuestEntryOffset;

  uint32_t pad2[6] {};
};

struct RelocNamedThunkMove final {
  RelocationTypeHeader Header {};

  // GPR index the constant is being moved to
  uint8_t RegisterIndex;

  // The thunk SHA256 hash
  IR::SHA256Sum Symbol;

  // Offset in to the code section to begin the relocation
  uint64_t Offset {};
};

struct RelocGuestRIPMove final {
  RelocationTypeHeader Header {};

  // GPR index the constant is being moved to
  uint8_t RegisterIndex;

  char pad : 6 {};
  // Offset in to the code section to begin the relocation
  uint64_t Offset {};

  // The unrelocated RIP that is being moved
  uint64_t GuestRIP;

  uint32_t pad2[6] {};
};

union Relocation {
  RelocationTypeHeader Header {};

  RelocNamedSymbolLiteral NamedSymbolLiteral;
  // This makes our union of relocations at least 48 bytes
  // It might be more efficient to not use a union
  // TODO: Make structs packed to reduce overall size?
  RelocNamedThunkMove NamedThunkMove;

  RelocGuestRIPMove GuestRIPMove;
};
} // namespace FEXCore::CPU
