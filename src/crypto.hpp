#pragma once
#include <expected>
#include <iostream>
#include <optional>
#include <securebuffer.hpp>
#include <sodium.h>
#include <span>
#include <vector>

enum class CryptoError { EncryptError, DecryptError, KeyDerivationError };

class CryptoEngine {

public:
  static std::expected<void, CryptoError> encrypt(std::span<unsigned char const> plaintext,
                                                  std::span<unsigned char const> key,
                                                  std::span<unsigned char const> nonce,
                                                  std::optional<std::span<unsigned char const>> aad,
                                                  std::span<unsigned char> ciphertext);

  static std::expected<void, CryptoError> decrypt(std::span<unsigned char const> ciphertext,
                                                  std::span<unsigned char const> key,
                                                  std::span<unsigned char const> nonce,
                                                  std::optional<std::span<unsigned char const>> aad,
                                                  std::span<unsigned char> plaintext);

  static std::expected<void, CryptoError> derive_key(std::span<unsigned char const> password,
                                                     std::span<unsigned char const> salt,
                                                     unsigned char *key);
};
