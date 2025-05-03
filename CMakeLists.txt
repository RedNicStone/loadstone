cmake_minimum_required(VERSION 3.30)
project(loadstone C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)

set(LOADSTONE_BUILD_PEDANTIC OFF CACHE BOOL "Build loadstone with pedantic warnings")
set(EXTRA_COMPILE_FLAGS "")
if (LOADSTONE_BUILD_PEDANTIC)
    set(EXTRA_COMPILE_FLAGS
            -Wall
            -Wextra
            -Wpedantic
            -Werror

            -Wconversion          # Implicit type conversions that might change a value.
            -Wsign-conversion     # Implicit sign changes (unsigned to signed, etc).
            -Wshadow              # Variable shadowing.
            -Wstrict-prototypes   # Functions should declare parameter types.
            -Wmissing-prototypes  # Catch missing function declarations.
            -Wold-style-definition # Warn on K&R-style function definitions.
            -Wpointer-arith       # Pointer arithmetic on void* or function pointers.
            -Wcast-qual           # Discarding const/volatile qualifiers.
            -Wunused-parameter    # Parameters that are never used.
            -Wmissing-field-initializers # Struct initializations missing fields.
    )
endif ()

file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
file(GLOB_RECURSE HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(loadstone-static STATIC ${SOURCES} ${HEADERS})
target_include_directories(loadstone-static PUBLIC include)
set_target_properties(loadstone-static PROPERTIES LINKER_LANGUAGE C)
target_compile_options(loadstone-static PRIVATE ${EXTRA_COMPILE_FLAGS})

add_library(loadstone-shared SHARED ${SOURCES} ${HEADERS})
target_include_directories(loadstone-shared PUBLIC include)
set_target_properties(loadstone-shared PROPERTIES LINKER_LANGUAGE C)
target_compile_options(loadstone-shared PRIVATE ${EXTRA_COMPILE_FLAGS})

set(LOADSTONE_BUILD_TOOLS OFF CACHE BOOL "Build loadstone examples")
if (LOADSTONE_BUILD_TOOLS)
    add_subdirectory(examples/plugin)
    add_subdirectory(examples/lsload)
endif ()
