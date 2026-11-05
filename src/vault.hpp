#pragma once
#include <block_device.hpp>
#include <crypto.hpp>
#include <file_table.hpp>
#include <filesystem>
#include <securebuffer.hpp>

enum class VaultError {
  NoEnoughMemory,
  FileOpenError,
  FileReadError,
  BlockDeviceWriteError,
  CryptoError,
  KDF_Error,
  FileNotFound,
  BlockDeviceDeallocError,
};

constexpr std::array<unsigned char, 5> magic_word{};

class Vault {
  std::size_t capacity_; // in bytes
  BlockDevice block_device_;
  FileTable file_table_;
  SecureBuffer key_;

  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt_;
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> magic_nonce_;
  std::array<unsigned char, magic_word.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES> magic_ciphertext_;

public:
  explicit Vault(std::size_t capacity, SecureBuffer &&generated_key);

  std::expected<void, VaultError> init(const SecureBuffer &);

  std::expected<void, VaultError> add_file(std::filesystem::path &path);
  std::expected<void, VaultError> remove_file(std::size_t file_id);
};
