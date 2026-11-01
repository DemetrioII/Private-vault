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

add_library(my_vault_core STATIC)

target_sources(my_vault_core
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
        src/core/io.cpp
        src/core/block.cpp
        src/core/vault.cpp
)

target_include_directories(my_vault_core PUBLIC src ${SODIUM_INCLUDE_DIRS})
target_link_directories(my_vault_core PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(my_vault_core PUBLIC ${SODIUM_LIBRARIES})
target_compile_options(my_vault_core PUBLIC ${SODIUM_CFLAGS_OTHER})

add_executable(my_vault src/main.cpp)
target_link_libraries(my_vault PRIVATE my_vault_core)

include(CTest)
if(BUILD_TESTING)
    include(FetchContent)
    include(GoogleTest)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    set_target_properties(gtest PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )

    add_executable(my_vault_tests tests/vault_tests.cpp)
    target_link_libraries(my_vault_tests PRIVATE my_vault_core GTest::gtest)

    gtest_discover_tests(my_vault_tests)
endif()
