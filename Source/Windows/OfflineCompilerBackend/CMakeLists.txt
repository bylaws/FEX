if (_M_ARM_64EC)
  set(TARGET_NAME FEXOfflineCompilerBackendARM64EC)
elseif (_M_ARM_64)
  set(TARGET_NAME FEXOfflineCompilerBackendWOW64)
endif()
add_executable(${TARGET_NAME} Main.cpp $<TARGET_OBJECTS:FEXCore_object>)
patch_library_wine(${TARGET_NAME})

target_include_directories(${TARGET_NAME} PRIVATE
  "${CMAKE_SOURCE_DIR}/Source/Windows/include/"
  "${CMAKE_SOURCE_DIR}/Source/"
  "${CMAKE_SOURCE_DIR}/Source/Windows/"
)

target_link_libraries(${TARGET_NAME}
  PRIVATE
  FEXCore_Base
  Common
  CommonTools
  JemallocLibs
  CommonWindows
  ntdll_ex
)

target_link_options(${TARGET_NAME} PRIVATE -static)
target_link_options(${TARGET_NAME} PRIVATE "LINKER:--image-base,0x600000000")

install(TARGETS ${TARGET_NAME}
  RUNTIME
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  COMPONENT runtime)

