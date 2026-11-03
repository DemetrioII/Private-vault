#include <gtest/gtest.h>

#include <crypto.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace {

using Key = std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>;
using Nonce = std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;
using Salt = std::array<unsigned char, crypto_pwhash_SALTBYTES>;

constexpr std::size_t kTagSize = crypto_aead_xchacha20poly1305_ietf_ABYTES;

template <typename Array>
Array make_filled(unsigned char start) {
  Array out{};
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<unsigned char>(start + i);
  }
  return out;
}

std::vector<unsigned char> make_bytes(std::size_t size, unsigned char start) {
  std::vector<unsigned char> out(size);
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<unsigned char>(start + i);
  }
  return out;
}

bool arrays_equal(const Key &lhs, const Key &rhs) {
  return std::memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

} // namespace

TEST(CryptoEngineTest, EncryptDecryptRoundtrip) {
  const auto plaintext = make_bytes(64, 0x10);
  const auto key = make_filled<Key>(1);
  const auto nonce = make_filled<Nonce>(2);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);

  auto encrypted = CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext);

  ASSERT_TRUE(encrypted.has_value());
  EXPECT_NE(ciphertext, plaintext);

  std::vector<unsigned char> decrypted(plaintext.size());
  auto decrypted_result =
      CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_TRUE(decrypted_result.has_value());
  EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoEngineTest, EncryptDecryptRoundtripWithAad) {
  const auto plaintext = make_bytes(48, 0x20);
  const auto aad = make_bytes(7, 0x30);
  const std::span<unsigned char const> aad_span(aad);
  const auto key = make_filled<Key>(3);
  const auto nonce = make_filled<Nonce>(4);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);

  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, aad_span, ciphertext).has_value());

  std::vector<unsigned char> decrypted(plaintext.size());
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, aad_span, decrypted);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoEngineTest, EmptyPlaintextRoundtrip) {
  const std::vector<unsigned char> plaintext;
  const auto key = make_filled<Key>(5);
  const auto nonce = make_filled<Nonce>(6);
  std::vector<unsigned char> ciphertext(kTagSize);

  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  std::vector<unsigned char> decrypted;
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(decrypted.empty());
}

TEST(CryptoEngineTest, TamperedCiphertextFails) {
  const auto plaintext = make_bytes(32, 0x40);
  const auto key = make_filled<Key>(7);
  const auto nonce = make_filled<Nonce>(8);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  ciphertext[ciphertext.size() / 2] ^= 0x01;

  std::vector<unsigned char> decrypted(plaintext.size());
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, TamperedDecryptZeroesPlaintextBuffer) {
  const auto plaintext = make_bytes(32, 0x41);
  const auto key = make_filled<Key>(9);
  const auto nonce = make_filled<Nonce>(10);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  ciphertext[0] ^= 0x01;

  std::vector<unsigned char> decrypted(plaintext.size(), 0xAA);
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  for (const auto byte : decrypted) {
    EXPECT_EQ(byte, 0u);
  }
}

TEST(CryptoEngineTest, WrongKeyFails) {
  const auto plaintext = make_bytes(16, 0x50);
  const auto key = make_filled<Key>(11);
  const auto wrong_key = make_filled<Key>(12);
  const auto nonce = make_filled<Nonce>(13);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  std::vector<unsigned char> decrypted(plaintext.size());
  auto result =
      CryptoEngine::decrypt(ciphertext, wrong_key, nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, WrongNonceFails) {
  const auto plaintext = make_bytes(16, 0x51);
  const auto key = make_filled<Key>(14);
  const auto nonce = make_filled<Nonce>(15);
  const auto wrong_nonce = make_filled<Nonce>(16);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  std::vector<unsigned char> decrypted(plaintext.size());
  auto result =
      CryptoEngine::decrypt(ciphertext, key, wrong_nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, WrongAadFails) {
  const auto plaintext = make_bytes(16, 0x52);
  const auto aad = make_bytes(5, 0x60);
  const auto wrong_aad = make_bytes(5, 0x70);
  const auto key = make_filled<Key>(17);
  const auto nonce = make_filled<Nonce>(18);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(CryptoEngine::encrypt(plaintext, key, nonce, std::span<unsigned char const>(aad),
                                    ciphertext)
                  .has_value());

  std::vector<unsigned char> decrypted(plaintext.size());
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce,
                                      std::span<unsigned char const>(wrong_aad), decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, EncryptRejectsWrongKeySize) {
  const auto plaintext = make_bytes(8, 0x80);
  const std::vector<unsigned char> wrong_key(Key{}.size() - 1, 0x01);
  const auto nonce = make_filled<Nonce>(19);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);

  auto result =
      CryptoEngine::encrypt(plaintext, wrong_key, nonce, std::nullopt, ciphertext);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::EncryptError);
}

TEST(CryptoEngineTest, EncryptRejectsWrongNonceSize) {
  const auto plaintext = make_bytes(8, 0x81);
  const auto key = make_filled<Key>(20);
  const std::vector<unsigned char> wrong_nonce(Nonce{}.size() - 1, 0x02);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);

  auto result =
      CryptoEngine::encrypt(plaintext, key, wrong_nonce, std::nullopt, ciphertext);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::EncryptError);
}

TEST(CryptoEngineTest, EncryptRejectsWrongCiphertextSize) {
  const auto plaintext = make_bytes(8, 0x82);
  const auto key = make_filled<Key>(21);
  const auto nonce = make_filled<Nonce>(22);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize - 1);

  auto result =
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::EncryptError);
}

TEST(CryptoEngineTest, DecryptRejectsWrongPlaintextSize) {
  const auto plaintext = make_bytes(24, 0x83);
  const auto key = make_filled<Key>(23);
  const auto nonce = make_filled<Nonce>(24);
  std::vector<unsigned char> ciphertext(plaintext.size() + kTagSize);
  ASSERT_TRUE(
      CryptoEngine::encrypt(plaintext, key, nonce, std::nullopt, ciphertext).has_value());

  std::vector<unsigned char> decrypted(plaintext.size() + 1);
  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, DecryptRejectsTooShortCiphertext) {
  const auto key = make_filled<Key>(25);
  const auto nonce = make_filled<Nonce>(26);
  std::vector<unsigned char> ciphertext(kTagSize - 1, 0x03);
  std::vector<unsigned char> decrypted;

  auto result = CryptoEngine::decrypt(ciphertext, key, nonce, std::nullopt, decrypted);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::DecryptError);
}

TEST(CryptoEngineTest, DeriveKeyIsDeterministic) {
  const std::vector<unsigned char> password{'p', 'a', 's', 's'};
  const auto salt = make_filled<Salt>(1);

  Key first{};
  Key second{};
  ASSERT_TRUE(CryptoEngine::derive_key(password, salt, first.data()).has_value());
  ASSERT_TRUE(CryptoEngine::derive_key(password, salt, second.data()).has_value());

  EXPECT_TRUE(arrays_equal(first, second));
  EXPECT_NE(std::memcmp(first.data(), Key{}.data(), first.size()), 0);
}

TEST(CryptoEngineTest, DeriveKeyDifferentInputsProduceDifferentKeys) {
  const std::vector<unsigned char> password_one{'o', 'n', 'e'};
  const std::vector<unsigned char> password_two{'t', 'w', 'o'};
  const auto salt_one = make_filled<Salt>(1);
  const auto salt_two = make_filled<Salt>(2);

  Key from_password_one{};
  Key from_password_two{};
  Key from_salt_two{};
  ASSERT_TRUE(
      CryptoEngine::derive_key(password_one, salt_one, from_password_one.data()).has_value());
  ASSERT_TRUE(
      CryptoEngine::derive_key(password_two, salt_one, from_password_two.data()).has_value());
  ASSERT_TRUE(
      CryptoEngine::derive_key(password_one, salt_two, from_salt_two.data()).has_value());

  EXPECT_NE(std::memcmp(from_password_one.data(), from_password_two.data(),
                        from_password_one.size()),
            0);
  EXPECT_NE(
      std::memcmp(from_password_one.data(), from_salt_two.data(), from_password_one.size()), 0);
}

TEST(CryptoEngineTest, DeriveKeyRejectsInvalidSaltSize) {
  const std::vector<unsigned char> password{'p', 'w'};
  const std::array<unsigned char, Salt{}.size() - 1> tiny_salt{};
  Key key{};

  auto result = CryptoEngine::derive_key(password, tiny_salt, key.data());

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::KeyDerivationError);
}

TEST(CryptoEngineTest, DeriveKeyRejectsNullKey) {
  const std::vector<unsigned char> password{'p', 'w'};
  const auto salt = make_filled<Salt>(3);

  auto result = CryptoEngine::derive_key(password, salt, nullptr);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), CryptoError::KeyDerivationError);
}

TEST(CryptoEngineTest, DeriveKeyAcceptsEmptyPassword) {
  const std::vector<unsigned char> password;
  const auto salt = make_filled<Salt>(4);
  Key key{};

  auto result = CryptoEngine::derive_key(password, salt, key.data());

  EXPECT_TRUE(result.has_value());
}
