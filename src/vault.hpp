#pragma once
#include <block_device.hpp>
#include <file_table.hpp>
#include <filesystem>

enum class VaultError {
  NoEnoughMemory,
  FileOpenError,
  FileReadError,
  BlockDeviceWriteError
};

class Vault {
  std::size_t capacity_; // in bytes
  BlockDevice block_device_;
  FileTable file_table_;

public:
  explicit Vault(std::size_t capacity);

  std::expected<void, VaultError> add_file(std::filesystem::path &path);
};
