#include <expected>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <utility>
#include <vector>

import core.crypto;
import core.secure;
import core.vault;

int main() {
  if (!core::crypto::init()) {
    std::cerr << "sodium init failed\n";
    return 1;
  }

  {
    std::string password = "test-password";

    std::vector<unsigned char> salt =
        core::crypto::random_bytes(core::crypto::kdf::salt_bytes);
    std::vector<unsigned char> key(core::crypto::kdf::key_bytes);
    std::vector<unsigned char> nonce =
        core::crypto::random_bytes(core::crypto::aead::nonce_bytes);

    auto r = core::crypto::kdf::derive_key(
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char *>(password.data()),
            password.size()),
        salt, key);
    if (!r) {
      std::cerr << "kdf failed\n";
      return 1;
    }

    std::string plaintext = "hello encrypted vault";
    std::vector<unsigned char> pt(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> ct;
    std::vector<unsigned char> out;

    if (!core::crypto::aead::encrypt(key, nonce, pt, ct)) {
      std::cerr << "encrypt failed\n";
      return 1;
    }

    if (!core::crypto::aead::decrypt(key, nonce, ct, out)) {
      std::cerr << "decrypt failed\n";
      return 1;
    }

    std::string dec(out.begin(), out.end());
    std::cout << "dec: " << dec << "\n";

    core::secure_zero(key.data(), key.size());
    core::secure_zero(salt.data(), salt.size());
    core::secure_zero(pt.data(), pt.size());
    core::secure_zero(ct.data(), ct.size());
    core::secure_zero(out.data(), out.size());
  }

  std::filesystem::remove("test.vault");

  core::SecureBuffer<16> password{};
  password.fill('t');

  auto created = core::vault::Vault::create(
      "test.vault",
      std::span<const unsigned char>(password.data(), password.size()), 4);
  if (!created) {
    std::cerr << "vault create failed: " << created.error().message << "\n";
    return 1;
  }

  core::vault::Vault vault = std::move(*created);

  auto opened = vault.open(
      "test.vault",
      std::span<const unsigned char>(password.data(), password.size()));
  if (!opened) {
    std::cerr << "vault open failed: " << opened.error().message << "\n";
    return 1;
  }

  core::SecureBuffer<16> wrong_password{};
  wrong_password.fill('x');

  core::vault::Vault wrong;
  auto wrong_open =
      wrong.open("test.vault", std::span<const unsigned char>(
                                   wrong_password.data(),
                                   wrong_password.size()));
  if (wrong_open) {
    std::cerr << "vault accepted the wrong password\n";
    return 1;
  }

  std::cout << "vault opened\n";

  return 0;
}
