
add_library(loadstone-example-plugin-foo SHARED ${CMAKE_CURRENT_SOURCE_DIR}/plugin-foo.c)
add_library(loadstone-example-plugin-bar SHARED ${CMAKE_CURRENT_SOURCE_DIR}/plugin-bar.c)

target_link_libraries(loadstone-example-plugin-bar PRIVATE loadstone-example-plugin-foo)

set_target_properties(loadstone-example-plugin-foo PROPERTIES PREFIX "" SUFFIX ".so" OUTPUT_NAME "plugin-foo")
set_target_properties(loadstone-example-plugin-bar PROPERTIES PREFIX "" SUFFIX ".so" OUTPUT_NAME "plugin-bar")

target_link_options(loadstone-example-plugin-foo PRIVATE -nolibc -nostdlib -nodefaultlibs)
target_link_options(loadstone-example-plugin-bar PRIVATE -nolibc -nostdlib -nodefaultlibs)

add_executable(loadstone-example-host ${CMAKE_CURRENT_SOURCE_DIR}/host.c)
target_link_libraries(loadstone-example-host PRIVATE loadstone-static)

add_dependencies(loadstone-example-host loadstone-example-plugin-foo loadstone-example-plugin-bar)

set_target_properties(loadstone-example-host PROPERTIES LINKER_LANGUAGE C)
set_target_properties(loadstone-example-plugin-bar PROPERTIES LINKER_LANGUAGE C)
set_target_properties(loadstone-example-plugin-foo PROPERTIES LINKER_LANGUAGE C)
