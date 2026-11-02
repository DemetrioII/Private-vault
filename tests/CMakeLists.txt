add_executable(vault_tests
	test_block_allocator.cpp
	test_block_device.cpp
	test_file_table.cpp
	test_vault.cpp
)

# Vault is not part of vault_core yet, so compile it into the test binary.
target_sources(vault_tests PRIVATE
	${CMAKE_SOURCE_DIR}/src/vault.cpp
)

target_include_directories(vault_tests PRIVATE
	${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(vault_tests PRIVATE
	vault_core
	GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(vault_tests)
