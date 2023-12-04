// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|ARM64EC
desc: Implements the ARM64EC BT module API using FEXCore
$end_info$
*/

#include <FEXCore/fextl/fmt.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/EnumOperators.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#include <FEXHeaderUtils/TypeDefines.h>

#include "Common/Config.h"
#include "Common/InvalidationTracker.h"
#include "Common/CPUFeatures.h"
#include "DummyHandlers.h"
#include "BTInterface.h"

#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <mutex>
#include <optional>
#include <utility>
#include <ntstatus.h>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include <wine/unixlib.h>


class ECSyscallHandler;

struct ThreadCPUArea {
  static constexpr size_t TebCPUAreaOffset = 0x1788;
  CHPE_V2_CPU_AREA_INFO *Area;

  explicit ThreadCPUArea(_TEB *TEB)
      : Area(*reinterpret_cast<CHPE_V2_CPU_AREA_INFO **>(reinterpret_cast<uintptr_t>(TEB) + TebCPUAreaOffset)) {}

  FEXCore::Core::InternalThreadState *&ThreadState() const {
	  // TODO: move and use x28
    return reinterpret_cast<FEXCore::Core::InternalThreadState *&>(Area->EmulatorData[1]);
  }

  uint64_t &DispatcherLoopTop() const {
    return reinterpret_cast<uint64_t&>(Area->EmulatorData[2]);
  }
};

namespace {
  fextl::unique_ptr<FEXCore::Context::Context> CTX;
  fextl::unique_ptr<FEX::DummyHandlers::DummySignalDelegator> SignalDelegator;
  fextl::unique_ptr<ECSyscallHandler> SyscallHandler;
  FEX::Windows::InvalidationTracker InvalidationTracker;
  std::optional<FEX::Windows::CPUFeatures> CPUFeatures;


  std::pair<NTSTATUS, ThreadCPUArea> GetThreadCPUArea(HANDLE Thread) {
    THREAD_BASIC_INFORMATION Info;
    const NTSTATUS Err = NtQueryInformationThread(Thread, ThreadBasicInformation, &Info, sizeof(Info), nullptr);
    return {Err, ThreadCPUArea(reinterpret_cast<_TEB *>(Info.TebBaseAddress))};
  }

  ThreadCPUArea GetCPUArea() {
    return ThreadCPUArea(NtCurrentTeb());
  }

  bool IsAddressInJit(uint64_t Address) {
    return GetCPUArea().ThreadState()->CPUBackend->IsAddressInCodeBuffer(Address);
  }
}

namespace Context {
  void LoadStateFromECContext(FEXCore::Core::InternalThreadState *Thread, CONTEXT *Context) {
    auto &State = Thread->CurrentFrame->State;

    // General register state
    State.gregs[FEXCore::X86State::REG_RAX] = Context->Rax;
    State.gregs[FEXCore::X86State::REG_RCX] = Context->Rcx;
    State.gregs[FEXCore::X86State::REG_RDX] = Context->Rdx;
    State.gregs[FEXCore::X86State::REG_RBX] = Context->Rbx;
    State.gregs[FEXCore::X86State::REG_RSP] = Context->Rsp;
    State.gregs[FEXCore::X86State::REG_RBP] = Context->Rbp;
    State.gregs[FEXCore::X86State::REG_RSI] = Context->Rsi;
    State.gregs[FEXCore::X86State::REG_RDI] = Context->Rdi;
    State.gregs[FEXCore::X86State::REG_R8] = Context->R8;
    State.gregs[FEXCore::X86State::REG_R9] = Context->R9;
    State.gregs[FEXCore::X86State::REG_R10] = Context->R10;
    State.gregs[FEXCore::X86State::REG_R11] = Context->R11;
    State.gregs[FEXCore::X86State::REG_R12] = Context->R12;
    State.gregs[FEXCore::X86State::REG_R13] = Context->R13;
    State.gregs[FEXCore::X86State::REG_R14] = Context->R14;
    State.gregs[FEXCore::X86State::REG_R15] = Context->R15;

    State.rip = Context->Rip;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);

    State.es_idx = Context->SegEs & 0xffff;
    State.cs_idx = Context->SegCs & 0xffff;
    State.ss_idx = Context->SegSs & 0xffff;
    State.ds_idx = Context->SegDs & 0xffff;
    State.fs_idx = Context->SegFs & 0xffff;
    State.gs_idx = Context->SegGs & 0xffff;

    // The TEB is the only populated GDT entry by default
    const auto TEB = reinterpret_cast<uint64_t>(NtCurrentTeb());
    State.gdt[(Context->SegGs & 0xffff) >> 3].base = TEB;
    State.gs_cached = TEB;
    State.fs_cached = 0;
    State.es_cached = 0;
    State.cs_cached = 0;
    State.ss_cached = 0;
    State.ds_cached = 0;

    // Floating-point register state
    memcpy(State.xmm.sse.data, Context->FltSave.XmmRegisters, sizeof(State.xmm.sse.data));
    memcpy(State.mm, Context->FltSave.FloatRegisters, sizeof(State.mm));

    State.FCW = Context->FltSave.ControlWord;
    State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (Context->FltSave.StatusWord >> 8) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (Context->FltSave.StatusWord >> 9) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (Context->FltSave.StatusWord >> 10) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (Context->FltSave.StatusWord >> 14) & 1;
    State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = (Context->FltSave.StatusWord >> 11) & 0b111;
    State.AbridgedFTW = Context->FltSave.TagWord;
  }

  void StoreECContextFromState(FEXCore::Core::InternalThreadState *Thread, CONTEXT *Context) {
    auto &State = Thread->CurrentFrame->State;

    // General register state
    Context->Rax = State.gregs[FEXCore::X86State::REG_RAX];
    Context->Rcx = State.gregs[FEXCore::X86State::REG_RCX];
    Context->Rdx = State.gregs[FEXCore::X86State::REG_RDX];
    Context->Rbx = State.gregs[FEXCore::X86State::REG_RBX];
    Context->Rsp = State.gregs[FEXCore::X86State::REG_RSP];
    Context->Rbp = State.gregs[FEXCore::X86State::REG_RBP];
    Context->Rsi = State.gregs[FEXCore::X86State::REG_RSI];
    Context->Rdi = State.gregs[FEXCore::X86State::REG_RDI];
    Context->R8 = State.gregs[FEXCore::X86State::REG_R8];
    Context->R9 = State.gregs[FEXCore::X86State::REG_R9];
    Context->R10 = State.gregs[FEXCore::X86State::REG_R10];
    Context->R11 = State.gregs[FEXCore::X86State::REG_R11];
    Context->R12 = State.gregs[FEXCore::X86State::REG_R12];
    Context->R13 = State.gregs[FEXCore::X86State::REG_R13];
    Context->R14 = State.gregs[FEXCore::X86State::REG_R14];
    Context->R15 = State.gregs[FEXCore::X86State::REG_R15];

    Context->Rip = State.rip;
    Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

    Context->SegEs = State.es_idx;
    Context->SegCs = State.cs_idx;
    Context->SegSs = State.ss_idx;
    Context->SegDs = State.ds_idx;
    Context->SegFs = State.fs_idx;
    Context->SegGs = State.gs_idx;

    memcpy(Context->FltSave.XmmRegisters, State.xmm.sse.data, sizeof(State.xmm.sse.data));
    memcpy(Context->FltSave.FloatRegisters, State.mm, sizeof(State.mm));

    Context->FltSave.ControlWord = State.FCW;
    Context->FltSave.StatusWord = (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] << 8) |
                                  (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] << 9) |
                                  (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] << 10) |
                                  (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] << 14) |
                                  (State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] << 11);
    Context->FltSave.TagWord = State.AbridgedFTW;
  }

  void ReconstructThreadState(ARM64_NT_CONTEXT *Context) {
    const auto &Config = SignalDelegator->GetConfig();
    auto *Thread = GetCPUArea().ThreadState();
    auto &State = Thread->CurrentFrame->State;

    State.rip = CTX->RestoreRIPFromHostPC(Thread, Context->Pc);

    // Spill all SRA GPRs
    for (size_t i = 0; i < Config.SRAGPRCount; i++) {
      State.gregs[i] = Context->X[Config.SRAGPRMapping[i]];
    }

    // Spill all SRA FPRs
    for (size_t i = 0; i < Config.SRAFPRCount; i++) {
      memcpy(State.xmm.sse.data[i], &Context->V[Config.SRAFPRMapping[i]], sizeof(__uint128_t));
    }
  }

  CONTEXT ReconstructECContext(ARM64_NT_CONTEXT *Context) {
    ReconstructThreadState(Context);
    ARM64EC_NT_CONTEXT ECContext{};

    ECContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    ECContext.AMD64_SegCs = 0x1b;
    ECContext.AMD64_SegSs = 0x23;

    ECContext.AMD64_ControlWord = 0x27f;
    ECContext.AMD64_MxCsr_copy = ECContext.AMD64_MxCsr = 0x1f80;
    ECContext.AMD64_MxCsr_Mask = 0x2ffff;


    return ECContext.AMD64_Context;
  }

  bool HandleUnalignedAccess(ARM64_NT_CONTEXT *Context) {
    if (!GetCPUArea().ThreadState()->CPUBackend->IsAddressInCodeBuffer(Context->Pc)) {
      return false;
    }

    FEX_CONFIG_OPT(ParanoidTSO, PARANOIDTSO);
    const auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(ParanoidTSO(), Context->Pc, &Context->X0);
    if (!Result.first) {
      return false;
    }

    Context->Pc += Result.second;
    return true;
  }
}

namespace Logging {
  void MsgHandler(LogMan::DebugLevels Level, char const *Message) {
    const auto Output = fextl::fmt::format("[{}][{:X}] {}\n", LogMan::DebugLevelStr(Level), GetCurrentThreadId(), Message);
    __wine_dbg_output(Output.c_str());
  }

  void AssertHandler(char const *Message) {
    const auto Output = fextl::fmt::format("[ASSERT] {}\n", Message);
    __wine_dbg_output(Output.c_str());
  }

  void Init() {
    LogMan::Throw::InstallHandler(AssertHandler);
    LogMan::Msg::InstallHandler(MsgHandler);
  }
}

class ECSyscallHandler : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
public:
  ECSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_WIN32;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame *Frame, FEXCore::HLE::SyscallArguments *Args) override {
    return 0;
  }

  FEXCore::HLE::SyscallABI GetSyscallABI(uint64_t Syscall) override {
    return { .NumArgs = 0, .HasReturn = false, .HostSyscallNumber = -1 };
  }

  FEXCore::HLE::AOTIRCacheEntryLookupResult LookupAOTIRCacheEntry(FEXCore::Core::InternalThreadState *Thread, uint64_t GuestAddr) override {
    return {0, 0};
  }

  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState *Thread, uint64_t Start, uint64_t Length) override {
  }
};

void ProcessInit() {
  Logging::Init();
  LogMan::Msg::DFmt("aaa {}", __LINE__);
  FEX::Config::InitializeConfigs();
  FEXCore::Config::Initialize();
  FEXCore::Config::AddLayer(FEX::Config::CreateGlobalMainLayer());
  FEXCore::Config::AddLayer(FEX::Config::CreateMainLayer());
  LogMan::Msg::DFmt("aaa {}", __LINE__);
  FEXCore::Config::Load();
  FEXCore::Config::ReloadMetaLayer();

  FEXCore::Config::EraseSet(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  LogMan::Msg::DFmt("aaa {}", __LINE__);

  // Not applicable to Windows
  FEXCore::Config::EraseSet(FEXCore::Config::ConfigOption::CONFIG_TSOAUTOMIGRATION, "0");

  LogMan::Msg::DFmt("aaa {}", __LINE__);
  FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_64BIT);

  SignalDelegator = fextl::make_unique<FEX::DummyHandlers::DummySignalDelegator>();
  LogMan::Msg::DFmt("aaa {}", __LINE__);
  SyscallHandler = fextl::make_unique<ECSyscallHandler>();

  LogMan::Msg::DFmt("aaa {}", __LINE__);
  CTX = FEXCore::Context::Context::CreateNewContext();
  CTX->InitializeContext();
  LogMan::Msg::DFmt("aaa {}", __LINE__);
  CTX->SetSignalDelegator(SignalDelegator.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->InitCore(0, 0);
  LogMan::Msg::DFmt("aaa {}", __LINE__);
  CPUFeatures.emplace(*CTX);
  LogMan::Msg::DFmt("aaa {}", __LINE__);
}

extern "C" void RunJIT() {
  auto *Context = reinterpret_cast<CONTEXT *>(GetCPUArea().Area->ContextAmd64);
  if (RtlIsEcCode(Context->Rip)) {
    return;
  }
  LogMan::Msg::DFmt("Run: {:X}", Context->Rip);
  auto *Thread = GetCPUArea().ThreadState();
  Context::LoadStateFromECContext(Thread, Context);
  CTX->ExecuteThread(Thread);
  Context::StoreECContextFromState(Thread, Context);
  LogMan::Msg::DFmt("Done: {:X}", Context->Rip);
}

void ProcessTerm() {}

NTSTATUS ResetToConsistentState(EXCEPTION_POINTERS *Ptrs, ARM64_NT_CONTEXT *Context, BOOLEAN *Continue) {
  const auto *Exception = Ptrs->ExceptionRecord;
  if (Exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && Context::HandleUnalignedAccess(Context)) {
    LogMan::Msg::DFmt("Handled unaligned atomic: new pc: {:X}", Context->Pc);
    *Continue = true;
    return STATUS_SUCCESS;
  }

  if (Exception->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const auto FaultAddress = static_cast<uint64_t>(Exception->ExceptionInformation[1]);

    if (InvalidationTracker.HandleRWXAccessViolation(GetCPUArea().ThreadState(), FaultAddress)) {
      LogMan::Msg::DFmt("Handled self-modifying code: pc: {:X} fault: {:X}", Context->Pc, FaultAddress);
      *Continue = true;
      return STATUS_SUCCESS;
    }
  }

  if (!IsAddressInJit(Context->Pc)) {
    return STATUS_SUCCESS;
  }

  LogMan::Msg::DFmt("Reconstructing context");

  CONTEXT ECContext = Context::ReconstructECContext(Context);
  LogMan::Msg::DFmt("pc: {:X} rip: {:X}", Context->Pc, ECContext.Rip);

  *Ptrs->ContextRecord = ECContext;
  return STATUS_SUCCESS;
}

void NotifyMemoryAlloc(void *Address, SIZE_T Size, ULONG Type, ULONG Prot) {
  InvalidationTracker.HandleMemoryProtectionNotification(GetCPUArea().ThreadState(), reinterpret_cast<uint64_t>(Address),
                                                         static_cast<uint64_t>(Size), Prot);
}

void NotifyMemoryFree(void *Address, SIZE_T Size, ULONG FreeType) {
  if (!Size) {
    InvalidationTracker.InvalidateContainingSection(GetCPUArea().ThreadState(), reinterpret_cast<uint64_t>(Address), true);
  } else if (FreeType & MEM_DECOMMIT) {
    InvalidationTracker.InvalidateAlignedInterval(GetCPUArea().ThreadState(),
                                                  reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size), true);
  }
}

void NotifyMemoryProtect(void *Address, SIZE_T Size, ULONG NewProt) {
  InvalidationTracker.HandleMemoryProtectionNotification(GetCPUArea().ThreadState(),
                                                         reinterpret_cast<uint64_t>(Address), static_cast<uint64_t>(Size),
                                                         NewProt);
}

void NotifyUnmapViewOfSection(void *Address) {
  InvalidationTracker.InvalidateContainingSection(GetCPUArea().ThreadState(), reinterpret_cast<uint64_t>(Address), true);
}

void BTCpu64FlushInstructionCache(const void *Address, SIZE_T Size) {
  InvalidationTracker.InvalidateAlignedInterval(GetCPUArea().ThreadState(), reinterpret_cast<uint64_t>(Address),
                                                static_cast<uint64_t>(Size), false);
}

NTSTATUS ThreadInit() {
  const auto CPUArea = GetCPUArea();

  auto *Thread = CTX->CreateThread(nullptr, 0);
  CPUArea.ThreadState() = Thread;
#ifdef EC_SRA
  auto *Context = reinterpret_cast<CONTEXT *>(CPUArea.Area->ContextAmd64);
  Context::LoadStateFromECContext(Thread, Context);

  uint64_t LoopTop = SignalDelegator->GetConfig().AbsoluteLoopTopAddressFillSRA;
  CPUArea.DispatcherLoopTop() = LoopTop;

  auto *Frame = Thread->CurrentFrame;
  __asm ("mov x28, %[Frame];" :: [Frame] "r" (Frame));
#endif
  return STATUS_SUCCESS;
}

NTSTATUS ThreadTerm(HANDLE Thread) {
  const auto [Err, CPUArea] = GetThreadCPUArea(Thread);
  if (Err) {
    return Err;
  }

  CTX->DestroyThread(CPUArea.ThreadState());
  return STATUS_SUCCESS;
}

BOOLEAN BTCpu64IsProcessorFeaturePresent(UINT Feature) {
  return CPUFeatures->IsFeaturePresent(Feature) ? TRUE : FALSE;
}

BOOLEAN UpdateProcessorInformation(SYSTEM_CPU_INFORMATION *Info) {
  CPUFeatures->UpdateInformation(Info);
  return TRUE;
}

