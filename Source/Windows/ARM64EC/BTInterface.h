// SPDX-License-Identifier: MIT
#pragma once

#include <windef.h>
#include <ntstatus.h>
#include <winternl.h>

extern "C" {
void STDMETHODCALLTYPE ProcessInit();
void STDMETHODCALLTYPE ProcessTerm();
NTSTATUS STDMETHODCALLTYPE ThreadInit();
NTSTATUS STDMETHODCALLTYPE ThreadTerm(HANDLE Thread);
void DispatchJump();
NTSTATUS STDMETHODCALLTYPE ResetToConsistentState(EXCEPTION_POINTERS* Ptrs, ARM64_NT_CONTEXT* Context, BOOLEAN* Continue);
void STDMETHODCALLTYPE BTCpu64FlushInstructionCache(const void* Address, SIZE_T Size);
void STDMETHODCALLTYPE FlushInstructionCacheHeavy(/*?*/);
void STDMETHODCALLTYPE NotifyMapViewOfSection(void* Address);
void STDMETHODCALLTYPE NotifyMemoryAlloc(void* Address, SIZE_T Size, ULONG Type, ULONG Prot);
void STDMETHODCALLTYPE NotifyMemoryFree(void* Address, SIZE_T Size, ULONG FreeType);
void STDMETHODCALLTYPE NotifyMemoryProtect(void* Address, SIZE_T Size, ULONG NewProt);
void STDMETHODCALLTYPE NotifyUnmapViewOfSection(void* Address);
void STDMETHODCALLTYPE FEXAddNoTSOCodeRange(void* Address, SIZE_T Size);
BOOLEAN STDMETHODCALLTYPE BTCpu64IsProcessorFeaturePresent(UINT Feature);
void STDMETHODCALLTYPE UpdateProcessorInformation(SYSTEM_CPU_INFORMATION* Info);
}
