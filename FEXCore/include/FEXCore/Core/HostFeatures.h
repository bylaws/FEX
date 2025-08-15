// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/vector.h>
#include <cstdint>

namespace FEXCore {
struct HostFeatures {
  /**
   * @brief Backend features that change how codegen is generated from IR
   *
   * Specifically things that affect the IR->Codegen process
   * Not the x86->IR process
   */
  uint32_t DCacheLineSize {};
  uint32_t ICacheLineSize {};

  bool SupportsCacheMaintenanceOps : 1 {};
  bool SupportsAES : 1 {};
  bool SupportsCRC : 1 {};
  bool SupportsCLZERO : 1 {};
  bool SupportsAtomics : 1 {};
  bool SupportsRCPC : 1 {};
  bool SupportsTSOImm9 : 1 {};
  bool SupportsRAND : 1 {};
  bool SupportsAVX : 1 {};
  bool SupportsSVE128 : 1 {};
  bool SupportsSVE256 : 1 {};
  bool SupportsSHA : 1 {};
  bool SupportsPMULL_128Bit : 1 {};
  bool SupportsCSSC : 1 {};
  bool SupportsFCMA : 1 {};
  bool SupportsFlagM : 1 {};
  bool SupportsFlagM2 : 1 {};
  bool SupportsRPRES : 1 {};
  bool SupportsPreserveAllABI : 1 {};
  bool SupportsAES256 : 1 {};
  bool SupportsSVEBitPerm : 1 {};
  bool SupportsCPUIndexInTPIDRRO : 1 {};
  bool SupportsFRINTTS : 1 {};
  bool SupportsECV : 1 {};
  bool SupportsWFXT : 1 {};
  bool Supports3DNow : 1 {};

  // Float exception behaviour
  bool SupportsAFP             : 1 {};
  bool SupportsFloatExceptions : 1 {};

  uint32_t Pad {};

  // Flag if this is InstCountCI
  bool IsInstCountCI {};

  // MIDR information
  // Also used for determining number of CPU cores for CPUID
  fextl::vector<uint32_t> CPUMIDRs;
};
} // namespace FEXCore
