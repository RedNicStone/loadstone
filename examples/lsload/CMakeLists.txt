
enable_language(CXX)

add_executable(lsload ${CMAKE_CURRENT_SOURCE_DIR}/lsload.cpp)

target_link_libraries(lsload PRIVATE loadstone-static)
set_target_properties(lsload PROPERTIES LINKER_LANGUAGE CXX)
