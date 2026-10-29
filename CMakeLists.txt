cmake_minimum_required(VERSION 3.28)
project(my_vault LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enable module scanning (CMake 3.28+)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

# Prefer libc++ with Clang for better C++ modules / import std support
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-stdlib=libc++)
    add_link_options(-stdlib=libc++ -lc++abi)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(my_vault)

target_sources(my_vault
    PUBLIC
    FILE_SET CXX_MODULES FILES
        src/core/types.ixx
        src/core/error.ixx
        src/core/result.ixx
        src/core/secure.ixx
        src/core/crypto.ixx
        src/core/io.ixx
		src/core/block.ixx
		src/core/vault.ixx
    PRIVATE
        src/main.cpp
        src/core/io.cpp
		src/core/block.cpp
		src/core/vault.cpp
)

target_include_directories(my_vault PRIVATE src ${SODIUM_INCLUDE_DIRS})
target_link_directories(my_vault PRIVATE ${SODIUM_LIBRARY_DIRS})
target_link_libraries(my_vault PRIVATE ${SODIUM_LIBRARIES})
target_compile_options(my_vault PRIVATE ${SODIUM_CFLAGS_OTHER})
