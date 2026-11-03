#include <crypto.hpp>

std::expected<void, CryptoError> CryptoEngine::encrypt(std::span<unsigned char const> plaintext,
                                                       std::span<unsigned char const> key,
                                                       std::span<unsigned char const> nonce,
                                                       std::optional<std::span<unsigned char const>> aad,
                                                       std::span<unsigned char> ciphertext) {
  constexpr std::size_t key_size = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  constexpr std::size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;

  if (key.size() != key_size || nonce.size() != nonce_size || plaintext.size() > SIZE_MAX - tag_size ||
      ciphertext.size() != plaintext.size() + tag_size) {
    return std::unexpected(CryptoError::EncryptError);
  }

  unsigned long long ciphertext_size = 0;

  const unsigned char *aad_data = aad ? aad->data() : nullptr;

  const unsigned long long aad_size = aad ? aad->size() : 0;

  int result = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_size, plaintext.data(),
                                                          plaintext.size(), aad_data, aad_size, nullptr, nonce.data(),
                                                          key.data());

  if (result != 0 || ciphertext_size != ciphertext.size()) {
    return std::unexpected(CryptoError::EncryptError);
  }

  return {};
}

std::expected<void, CryptoError> CryptoEngine::decrypt(std::span<unsigned char const> ciphertext,
                                                       std::span<unsigned char const> key,
                                                       std::span<unsigned char const> nonce,
                                                       std::optional<std::span<unsigned char const>> aad,
                                                       std::span<unsigned char> plaintext) {
  constexpr std::size_t key_size = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  constexpr std::size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  constexpr std::size_t tag_size = crypto_aead_xchacha20poly1305_ietf_ABYTES;

  if (key.size() != key_size || nonce.size() != nonce_size || ciphertext.size() < tag_size ||
      plaintext.size() != ciphertext.size() - tag_size) {
    return std::unexpected(CryptoError::DecryptError);
  }

  unsigned long long plaintext_size = 0;

  const unsigned char *aad_data = aad ? aad->data() : nullptr;

  const unsigned long long aad_size = aad ? aad->size() : 0;

  int result =
      crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &plaintext_size, nullptr, ciphertext.data(),
                                                 ciphertext.size(), aad_data, aad_size, nonce.data(), key.data());

  if (result != 0 || plaintext_size != plaintext.size()) {
    sodium_memzero(plaintext.data(), plaintext.size());
    return std::unexpected(CryptoError::DecryptError);
  }

  return {};
}

std::expected<void, CryptoError>
CryptoEngine::derive_key(std::span<unsigned char const> password,
                         std::span<unsigned char const> salt,
                         unsigned char *key) {
  constexpr std::size_t key_size = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

  if (key == nullptr || salt.size() != crypto_pwhash_SALTBYTES) {
    return std::unexpected(CryptoError::KeyDerivationError);
  }

  if (sodium_init() < 0) {
    return std::unexpected(CryptoError::KeyDerivationError);
  }

  const int result =
      crypto_pwhash(key, key_size,
                    reinterpret_cast<const char *>(password.data()),
                    password.size(), salt.data(), crypto_pwhash_OPSLIMIT_MODERATE,
                    crypto_pwhash_MEMLIMIT_MODERATE,
                    crypto_pwhash_ALG_ARGON2ID13);

  if (result != 0) {
    return std::unexpected(CryptoError::KeyDerivationError);
  }

  return {};
}
