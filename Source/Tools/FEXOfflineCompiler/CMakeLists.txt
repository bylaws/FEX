add_executable(FEXOfflineCompiler Main.cpp)

# target_include_directories(FEXOfflineCompiler
#   PRIVATE
#     ${CMAKE_BINARY_DIR}/generated
# )

# TODO: Move AOTGenerator and drop this include
target_include_directories(FEXOfflineCompiler PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../FEXLoader")

target_link_libraries(FEXOfflineCompiler
  PRIVATE
    Common
    CommonTools
    cpp-optparse
    FEXCore
    JemallocLibs
    LinuxEmulation
    ${PTHREAD_LIB}
    fmt::fmt)

if (CMAKE_BUILD_TYPE MATCHES "RELEASE")
  target_link_options(FEXOfflineCompiler
    PRIVATE
      "LINKER:--gc-sections"
      "LINKER:--strip-all"
      "LINKER:--as-needed")
endif()

install(TARGETS FEXOfflineCompiler
  RUNTIME
    DESTINATION bin
    COMPONENT runtime)
