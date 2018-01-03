# Automatically generated by boost-vcpkg-helpers/generate-ports.ps1

include(vcpkg_common_functions)
include(${CURRENT_INSTALLED_DIR}/share/boost-vcpkg-helpers/boost-modular.cmake)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO boostorg/variant
    REF boost-1.66.0
    SHA512 3eb3d4070bf81033c0a342956393e2e902618dc482fd3ba7c0b4f97ac3259fff31943a9b059bc25dd6d399af6d8b56a8297b462776b14b5012c6436b00c7d491
    HEAD_REF master
)

boost_modular_headers(SOURCE_PATH ${SOURCE_PATH})
