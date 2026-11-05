set(CMAKE_C_COMPILER /usr/bin/gcc-14)
set(CMAKE_CXX_COMPILER /usr/bin/g++-14)
cmake_minimum_required(VERSION 3.26)

project(my_vault_proj LANGUAGES CXX)
# set(CMAKE_CXX_STANDARD 26)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_library(vault_core
			src/block_allocator.cpp
			src/block_device.cpp
			src/file_table.cpp
			src/file_io.cpp
			src/securebuffer.cpp
			src/vault.cpp
			src/crypto.cpp
)

set(CMAKE_CXX_FLAGS "-std=c++26")

target_include_directories(vault_core
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
	${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(vault_core
	PUBLIC
	${SODIUM_LIBRARIES}
)

target_compile_options(vault_core
	PUBLIC
	${SODIUM_CFLAGS_OTHER}
)

if(EXISTS "${CMAKE_SOURCE_DIR}/src/app/main.cpp")

add_executable(vault
	src/app/main.cpp
)

target_link_libraries(vault
	PRIVATE
	vault_core
)

target_include_directories(vault
	PRIVATE
	$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
	${SODIUM_INCLUDE_DIRS}
)
endif()

option(ENABLE_SANITIZERS "Enable sanitizers" OFF)

if(ENABLE_SANITIZERS)
	add_compile_options(
		-fsanitize=undefined
		-fno-omit-frame-pointer
	)

	add_link_options(
		-fsanitize=address,undefined
	)
endif()

enable_testing()

include(FetchContent)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_Declare(
	googletest
	GIT_REPOSITORY https://github.com/google/googletest.git
	GIT_TAG v1.15.2
	GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(googletest)

add_subdirectory(tests)
