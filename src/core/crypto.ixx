module;

#include <cstddef>
#include <expected>
#include <sodium.h>
#include <span>
#include <vector>

export module core.crypto;

import core.error;
import core.result;
import core.secure;

export namespace core::crypto {
inline VoidResult init() {
  if (sodium_init() < 0) {
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "sodium_init failed"));
  }
  return {};
}

inline std::vector<unsigned char> random_bytes(size_t n) {
  std::vector<unsigned char> buf(n);
  if (n > 0)
    randombytes_buf(buf.data(), n);
  return buf;
}

inline void fill_random(std::span<unsigned char> out) {
  if (!out.empty())
    randombytes_buf(out.data(), out.size());
}

namespace aead {
constexpr size_t key_bytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr size_t nonce_bytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr size_t mac_bytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;

inline VoidResult encrypt(std::span<const unsigned char> key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> plaintext,
                          std::vector<unsigned char> &ciphertext_out) {
  if (key.size() != key_bytes || nonce.size() != nonce_bytes)
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "bad key/nonce size"));

  ciphertext_out.resize(plaintext.size() + mac_bytes);
  unsigned long long clen = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          ciphertext_out.data(), &clen, plaintext.data(), plaintext.size(),
          nullptr, 0, nullptr, nonce.data(), key.data()) != 0) {
    secure_zero(ciphertext_out.data(), ciphertext_out.size());
    ciphertext_out.clear();
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "encrypt failed"));
  }
  ciphertext_out.resize(clen);
  return {};
}

inline VoidResult decrypt(std::span<const unsigned char> key,
                          std::span<const unsigned char> nonce,
                          std::span<const unsigned char> ciphertext,
                          std::vector<unsigned char> &plaintext_out) {
  if (key.size() != key_bytes || nonce.size() != nonce_bytes)
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "bad key/nonce size"));

  if (ciphertext.size() < mac_bytes)
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "ciphertext too short"));

  plaintext_out.resize(ciphertext.size() - mac_bytes);
  unsigned long long plen = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          plaintext_out.data(), &plen, nullptr, ciphertext.data(),
          ciphertext.size(), nullptr, 0, nonce.data(), key.data()) != 0) {
    secure_zero(plaintext_out.data(), plaintext_out.size());
    plaintext_out.clear();
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "decrypt failed (bad tag)"));
  }
  plaintext_out.resize(plen);
  return {};
}
} // namespace aead

namespace kdf {
constexpr size_t salt_bytes = crypto_pwhash_SALTBYTES;
constexpr size_t key_bytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

constexpr unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;

inline VoidResult derive_key(std::span<const unsigned char> password,
                             std::span<const unsigned char> salt,
                             std::span<unsigned char> key_out) {
  if (salt.size() != salt_bytes || key_out.size() != key_bytes)
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "bad salt/key size"));

  if (crypto_pwhash(key_out.data(), key_out.size(),
                    reinterpret_cast<const char *>(password.data()),
                    password.size(), salt.data(), opslimit, memlimit,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "pwhash failed (out of memory?)"));
  }
  return {};
}
} // namespace kdf
} // namespace core::crypto
