# LLVM documentation recommends always using static library linkage when
#   building with Microsoft toolchain; it's also the default on other platforms
set(VCPKG_LIBRARY_LINKAGE static)

if(VCPKG_CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
    message(FATAL_ERROR "llvm cannot currently be built for UWP")
endif()

vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO flang-compiler/llvm
  REF eb788bb5b191ad169eee91cb6ceb7b84c0d052fe
  SHA512 b7764b99a572e810932e68655d891d8fa70a01e696989e3337db3366814e6da0910199a0656e94b6d59f8cb92cf6edef1d014771917ae7b24a00dac9e949d216
  HEAD_REF release_80
)

vcpkg_find_acquire_program(PYTHON3)
get_filename_component(PYTHON3_DIR "${PYTHON3}" DIRECTORY)
set(ENV{PATH} "$ENV{PATH};${PYTHON3_DIR}")

vcpkg_configure_cmake(
    SOURCE_PATH ${SOURCE_PATH}
    PREFER_NINJA
    OPTIONS
        -DLLVM_TARGETS_TO_BUILD=X86
        -DLLVM_INCLUDE_TOOLS=ON
        -DLLVM_INCLUDE_UTILS=OFF
        -DLLVM_INCLUDE_EXAMPLES=OFF
        -DLLVM_INCLUDE_TESTS=OFF
        -DLLVM_ABI_BREAKING_CHECKS=FORCE_OFF
        -DLLVM_TOOLS_INSTALL_DIR=tools/flang-llvm
        -DLLVM_PARALLEL_LINK_JOBS=1
)

vcpkg_install_cmake()

vcpkg_fixup_cmake_targets(CONFIG_PATH share/flang-llvm)
vcpkg_copy_tool_dependencies(${CURRENT_PACKAGES_DIR}/tools/flang-llvm)

if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "release")
    file(READ ${CURRENT_PACKAGES_DIR}/share/flang-llvm/LLVMExports-release.cmake RELEASE_MODULE)
    string(REPLACE "\${_IMPORT_PREFIX}/bin" "\${_IMPORT_PREFIX}/tools/flang-llvm" RELEASE_MODULE "${RELEASE_MODULE}")
    file(WRITE ${CURRENT_PACKAGES_DIR}/share/flang-llvm/LLVMExports-release.cmake "${RELEASE_MODULE}")
endif()

if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "debug")
    file(READ ${CURRENT_PACKAGES_DIR}/share/flang-llvm/LLVMExports-debug.cmake DEBUG_MODULE)
    string(REPLACE "\${_IMPORT_PREFIX}/debug/bin" "\${_IMPORT_PREFIX}/tools/flang-llvm" DEBUG_MODULE "${DEBUG_MODULE}")
    file(WRITE ${CURRENT_PACKAGES_DIR}/share/flang-llvm/LLVMExports-debug.cmake "${DEBUG_MODULE}")
endif()

file(REMOVE_RECURSE
    ${CURRENT_PACKAGES_DIR}/debug/include
    ${CURRENT_PACKAGES_DIR}/debug/tools
    ${CURRENT_PACKAGES_DIR}/debug/share
    ${CURRENT_PACKAGES_DIR}/debug/bin
    ${CURRENT_PACKAGES_DIR}/debug/msbuild-bin
    ${CURRENT_PACKAGES_DIR}/bin
    ${CURRENT_PACKAGES_DIR}/msbuild-bin
    ${CURRENT_PACKAGES_DIR}/tools/msbuild-bin
    ${CURRENT_PACKAGES_DIR}/include/llvm/BinaryFormat/WasmRelocs
)

# Remove two empty include subdirectorys if they are indeed empty
file(GLOB MCANALYSISFILES ${CURRENT_PACKAGES_DIR}/include/llvm/MC/MCAnalysis/*)
if(NOT MCANALYSISFILES)
  file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/include/llvm/MC/MCAnalysis)
endif()

file(GLOB MACHOFILES ${CURRENT_PACKAGES_DIR}/include/llvm/TextAPI/MachO/*)
if(NOT MACHOFILES)
  file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/include/llvm/TextAPI/MachO)
endif()

# Handle copyright
file(INSTALL ${SOURCE_PATH}/LICENSE.TXT DESTINATION ${CURRENT_PACKAGES_DIR}/share/flang-llvm RENAME copyright)
