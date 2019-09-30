function(vcpkg_get_tags PORT VCPKG_TRIPLET_FILE)
    cmake_parse_arguments(_vgt "" ABI_SETTINGS_FILE "" ${ARGN})

    if (_vgt_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unexpected arguments: ${_vgt_UNPARSED_ARGUMENTS}")
    endif()

    if (_vgt_KEYWORDS_MISSING_VALUES)
        message(FATAL_ERROR "Arguments missing values: ${_vgt_KEYWORDS_MISSING_VALUES}")
    endif()

    include(${VCPKG_TRIPLET_FILE})

    # GUID used as a flag - "cut here line"
    message("c35112b6-d1ba-415b-aa5d-81de856ef8eb")
    message("VCPKG_TARGET_ARCHITECTURE=${VCPKG_TARGET_ARCHITECTURE}")
    message("VCPKG_CMAKE_SYSTEM_NAME=${VCPKG_CMAKE_SYSTEM_NAME}")
    message("VCPKG_CMAKE_SYSTEM_VERSION=${VCPKG_CMAKE_SYSTEM_VERSION}")
    message("VCPKG_PLATFORM_TOOLSET=${VCPKG_PLATFORM_TOOLSET}")
    message("VCPKG_VISUAL_STUDIO_PATH=${VCPKG_VISUAL_STUDIO_PATH}")
    message("VCPKG_CHAINLOAD_TOOLCHAIN_FILE=${VCPKG_CHAINLOAD_TOOLCHAIN_FILE}")
    message("VCPKG_BUILD_TYPE=${VCPKG_BUILD_TYPE}")
    message("CMAKE_HOST_SYSTEM_NAME=${CMAKE_HOST_SYSTEM_NAME}")
    message("CMAKE_HOST_SYSTEM_PROCESSOR=${CMAKE_HOST_SYSTEM_PROCESSOR}")
    message("CMAKE_HOST_SYSTEM_VERSION=${CMAKE_HOST_SYSTEM_VERSION}")
    message("CMAKE_HOST_SYSTEM=${CMAKE_HOST_SYSTEM}")
    message("e1e74b5c-18cb-4474-a6bd-5c1c8bc81f3f")

    if (_vgt_ABI_SETTINGS_FILE)
        include(${_vgt_ABI_SETTINGS_FILE} OPTIONAL RESULT_VARIABLE FOUND_ABI_SETTINGS)

        message("739b0178-d2cf-4a1b-b26c-6764c761d636")
        if(FOUND_ABI_SETTINGS)
            message("VCPKG_PUBLIC_ABI_OVERRIDE=${VCPKG_PUBLIC_ABI_OVERRIDE}")
            message("VCPKG_ENV_PASSTHROUGH=${VCPKG_ENV_PASSTHROUGH}")
        endif()
        message("ba27cd04-1df1-4237-b519-09cc0c3dfa3c")
    endif()
endfunction()
