#include <fstream>
#include <vault.hpp>

Vault::Vault(std::size_t capacity)
    : capacity_(capacity), block_device_(capacity) {}

std::expected<void, VaultError> Vault::add_file(std::filesystem::path &path) {
  const auto fs = std::filesystem::file_size(path);

  auto file_id = file_table::generate_id(file_table_);
  auto block_idxs = block_device_.allocate(fs, file_id);
  if (!block_idxs.has_value()) {
    return std::unexpected(VaultError::NoEnoughMemory);
  }

  FileEntry entry;
  entry.file_size = fs;
  entry.blocks = std::move(*block_idxs);

  std::ifstream input(path, std::ios::binary);

  if (!input) {
    return std::unexpected(VaultError::FileOpenError);
  }

  std::vector<unsigned char> buffer(block_payload_size);

  for (std::size_t i = 0; i < entry.blocks.size(); ++i) {
    input.read(reinterpret_cast<char *>(buffer.data()),
               static_cast<std::streamsize>(block_payload_size));

    const auto bytes_read = input.gcount();

    if (bytes_read <= 0) {
      return std::unexpected(VaultError::FileReadError);
    }

    if (bytes_read < block_payload_size) {
      for (std::size_t i = bytes_read; i < block_payload_size; ++i)
        buffer[i] = 0;
    }

    auto result = block_device_.write_file_block(
        std::span(buffer.data(), block_payload_size), file_id, i + 1);

    if (!result) {
      return std::unexpected(VaultError::BlockDeviceWriteError);
    }
  }

  file_table::add_file(file_table_, file_id, std::move(entry));

  return {};
}
