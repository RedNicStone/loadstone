
include(ExternalProject)

set(LOADSTONE_MODULE_TOOLCHAIN "" CACHE FILEPATH "Path to toolchain file to use for module")

if (LOADSTONE_MODULE_TOOLCHAIN STREQUAL "")
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(LOADSTONE_MODULE_TOOLCHAIN ${CMAKE_TOOLCHAIN_FILE})
    else()
        message(FATAL_ERROR
                "LOADSTONE_MODULE_TOOLCHAIN is not defined and toolchain is not a Linux toolchain. "
                "If compiling for a platform platform than linux, a linux module toolchain is required. "
                "Please set LOADSTONE_MODULE_TOOLCHAIN to the path of a linux toolchain file. ")
    endif()
endif()

function(loadstone_find_toolchain toolchainFile toolchainPath)
    cmake_path(IS_RELATIVE toolchainFile RELATIVE)
    if (NOT RELATIVE)
        set(${toolchainPath} ${toolchainFile} PARENT_SCOPE)
        return()
    endif()

    if (EXISTS ${CMAKE_BINARY_DIR}/${toolchainFile})
        set(${toolchainPath} ${CMAKE_BINARY_DIR}/${toolchainFile} PARENT_SCOPE)
    else()
        set(${toolchainPath} ${CMAKE_SOURCE_DIR}/${toolchainFile} PARENT_SCOPE)
    endif()
endfunction()

function(loadstone_module_project name sourceDir binaryDir)
    loadstone_find_toolchain(${LOADSTONE_MODULE_TOOLCHAIN} TOOLCHAIN_FILE)
    ExternalProject_Add(${name}
            PREFIX ${name}
            SOURCE_DIR ${sourceDir}
            BINARY_DIR ${binaryDir}
            CMAKE_GENERATOR ${CMAKE_GENERATOR}
            CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${TOOLCHAIN_FILE}
            INSTALL_COMMAND ""
            DEPENDS ${ARGN}
    )
endfunction()
