add_library(arm64ecfex SHARED
  Module.cpp
  ModuleSRA.S
  ModuleX86.o
  ARM64ECSymbols.S
  libarm64ecfex.def
)
patch_library_wine(arm64ecfex)

target_include_directories(arm64ecfex PRIVATE
  "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
  "${CMAKE_SOURCE_DIR}/Source/"
  "${CMAKE_SOURCE_DIR}/Source/Windows/"
)

target_link_libraries(arm64ecfex
  PRIVATE
  FEXCore
  FEXCore_Base
  Common
  CommonTools
  CommonWindows
  ntdll_ex
)

target_link_options(arm64ecfex PRIVATE -static -nostdlib -nostartfiles -nodefaultlibs -lc++ -lc++abi -lunwind -lclang_rt.builtins-arm64ec)
install(TARGETS arm64ecfex
  RUNTIME
  DESTINATION lib
  COMPONENT runtime)
