#include <iterator>
#include <windef.h>
#include <winternl.h>
#include <wine/debug.h>
#include "CRT.h"
#include "LibC.h"

extern "C" {
__attribute__((section(".CRT$XIA"))) void (*XIA)() = nullptr;
__attribute__((section(".CRT$XIZ"))) void (*XIZ)() = nullptr;
__attribute__((section(".CRT$XCA"))) void (*XCA)() = nullptr;
__attribute__((section(".CRT$XCZ"))) void (*XCZ)() = nullptr;
__attribute__((section(".CRT$XDA"))) void (*XDA)() = nullptr;
__attribute__((section(".CRT$XDZ"))) void (*XDZ)() = nullptr;
__attribute__((section(".CRT$XLA"))) void (*XLA)(HINSTANCE, DWORD, LPVOID *) = nullptr;
__attribute__((section(".CRT$XZA"))) void (*XLZ)(HINSTANCE, DWORD, LPVOID *) = nullptr;

extern void (*__CTOR_LIST__[])();
extern void (*__DTOR_LIST__[])();

void DllMainCRTStartup() {
	/* DISABLE CALLOUTS */
}
}
namespace {
template<typename TFuncIt, typename ...TArgs>
void RunFuncArray(TFuncIt Begin, TFuncIt End, TArgs... Args) {
  for (auto It = Begin; It != End; It++) {
    if (*It) (**It)(Args...);
  }
}
}

namespace FEX::Windows {
void InitCRTProcess() {
  __wine_dbg_output("Begin FEX process CRT init\n");
  InitLibCProcess();

  auto GNUCtorBegin = &__CTOR_LIST__[1];
  auto GNUCtorEnd = GNUCtorBegin;
  while (*GNUCtorEnd != nullptr) GNUCtorEnd++;

  __wine_dbg_output("Running GNU ctors\n");
  RunFuncArray(std::reverse_iterator(GNUCtorEnd), std::reverse_iterator(GNUCtorBegin)); 
  __wine_dbg_output("Running MS C ctors\n");
  RunFuncArray(&XIA, &XIZ);
  __wine_dbg_output("Running MS C++ ctors\n");
  RunFuncArray(&XCA, &XCZ);
  __wine_dbg_output("Running process attach TLS callbacks\n");
  RunFuncArray(&XLA, &XLZ, nullptr, DLL_PROCESS_ATTACH, nullptr);
  __wine_dbg_output("CRT init complete\n");
}

void InitCRTThread() {
  __wine_dbg_output("Running thread attach TLS callbacks\n");
  RunFuncArray(&XLA, &XLZ, nullptr, DLL_THREAD_ATTACH, nullptr);
}

void DeinitCRTThread() {
  __wine_dbg_output("Running thread detach TLS callbacks\n");
  RunFuncArray(&XLA, &XLZ, nullptr, DLL_THREAD_DETACH, nullptr);
}
}

