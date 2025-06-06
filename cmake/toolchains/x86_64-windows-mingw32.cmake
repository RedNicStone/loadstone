
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_TRIPLE x86_64-w64-mingw32)

set(CMAKE_C_COMPILER ${TOOLCHAIN_TRIPLE}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_TRIPLE}-g++)

set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_TRIPLE})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
