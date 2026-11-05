#include <fstream>
#include <vault.hpp>

Vault::Vault(std::size_t capacity, SecureBuffer &&generated_key)
    : capacity_(capacity), block_device_(capacity), key_(std::move(generated_key)) {}

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

  std::vector<unsigned char> buffer(block_payload_size - block_tag_size);
  std::vector<unsigned char> encrypted(block_payload_size);

  std::array<unsigned char, block_nonce_size> nonce;

  for (std::size_t i = 0; i < entry.blocks.size(); ++i) {
    input.read(reinterpret_cast<char *>(buffer.data()),
               static_cast<std::streamsize>(block_payload_size - block_tag_size));

    const auto bytes_read = input.gcount();

    if (bytes_read <= 0) {
      return std::unexpected(VaultError::FileReadError);
    }

    randombytes_buf(nonce.data(), nonce.size());

    if (bytes_read < static_cast<std::streamsize>(buffer.size())) {
      for (std::size_t i = static_cast<std::size_t>(bytes_read); i < buffer.size(); ++i)
        buffer[i] = 0;
    }

    {
      auto result = CryptoEngine::encrypt(buffer, key_.span(), nonce, std::nullopt, encrypted);

      if (!result) {
        return std::unexpected(VaultError::CryptoError);
      }
    }

    auto result = block_device_.write_file_block(std::span(encrypted.data(), block_payload_size), file_id, i + 1);

    if (!result) {
      return std::unexpected(VaultError::BlockDeviceWriteError);
    }
  }

  file_table::add_file(file_table_, file_id, std::move(entry));

  return {};
}

std::expected<void, VaultError> Vault::remove_file(std::size_t file_id) {
  auto it = file_table_.file_table.find(file_id);
  if (it != file_table_.file_table.end())
    return std::unexpected(VaultError::FileNotFound);

  auto dealloc_res = block_device_.remove_file(file_id);
  if (!dealloc_res)
    return std::unexpected(VaultError::BlockDeviceDeallocError);

  file_table_.file_table.erase(file_id);
  return {};
}

std::expected<void, VaultError> Vault::init(const SecureBuffer &password) {
  SecureBuffer key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

  randombytes_buf(salt_.data(), salt_.size());
  randombytes_buf(magic_nonce_.data(), magic_nonce_.size());

  auto kdf_res = CryptoEngine::derive_key(password.span(), salt_, key.data());
  if (!kdf_res)
    return std::unexpected(VaultError::KDF_Error);

  auto enc_res = CryptoEngine::encrypt(magic_word, key.span(), magic_nonce_, std::nullopt, magic_ciphertext_);
  if (!enc_res)
    return std::unexpected(VaultError::CryptoError);

  return {};
}
