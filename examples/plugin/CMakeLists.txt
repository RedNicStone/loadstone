
loadstone_module_project(loadstone-example-plugin
        ${CMAKE_CURRENT_SOURCE_DIR}/module
        ${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(loadstone-example-host ${CMAKE_CURRENT_SOURCE_DIR}/host/host.c)
target_link_libraries(loadstone-example-host PRIVATE loadstone-static)

add_dependencies(loadstone-example-host loadstone-example-plugin)

set_target_properties(loadstone-example-host PROPERTIES LINKER_LANGUAGE C)

set(EXECUTABLE_RUNNER "")
set(EXECUTABLE_POSTFIX "")

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(EXECUTABLE_POSTFIX ".exe")
    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(EXECUTABLE_RUNNER "wine")
    endif()
endif()


add_test(
        NAME loadstone-example-host
        COMMAND ${EXECUTABLE_RUNNER} ${CMAKE_CURRENT_BINARY_DIR}/loadstone-example-host${EXECUTABLE_POSTFIX}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
