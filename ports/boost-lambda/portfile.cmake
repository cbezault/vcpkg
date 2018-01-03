# Automatically generated by boost-vcpkg-helpers/generate-ports.ps1

include(vcpkg_common_functions)
include(${CURRENT_INSTALLED_DIR}/share/boost-vcpkg-helpers/boost-modular.cmake)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO boostorg/lambda
    REF boost-1.66.0
    SHA512 2f5fd6c55c686528971c9e021779f39217952b279e5bef46879233fb1c516895a4fcdc6eddf43cd0fb73aa7ee5f868d6f4d51fdc74c9f68515ef6735ff31a349
    HEAD_REF master
)

boost_modular_headers(SOURCE_PATH ${SOURCE_PATH})
