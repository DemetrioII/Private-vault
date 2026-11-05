#include <gtest/gtest.h>

#include <vault.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kUsablePerBlock = block_payload_size - block_tag_size;

SecureBuffer make_key(unsigned char fill = 0x42) {
  return SecureBuffer(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, fill);
}

class VaultTest : public ::testing::Test {
protected:
  void SetUp() override {
    const auto prefix =
        fs::temp_directory_path() / "vault_test_" /
        std::to_string(reinterpret_cast<std::uintptr_t>(this)) / std::to_string(std::time(nullptr));
    fs::create_directories(prefix);
    dir_ = prefix;
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }

  fs::path make_file(const std::string &name, const std::vector<unsigned char> &data) {
    const auto path = dir_ / name;
    std::ofstream out(path, std::ios::binary);
    if (!data.empty()) {
      out.write(reinterpret_cast<const char *>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
    out.close();
    return path;
  }

  fs::path dir_;
};

TEST_F(VaultTest, AddEmptyFile) {
  Vault vault(block_size, make_key());
  auto path = make_file("empty.bin", {});

  auto result = vault.add_file(path);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, AddEmptyFileWithZeroCapacity) {
  Vault vault(0, make_key());
  auto path = make_file("empty.bin", {});

  auto result = vault.add_file(path);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, AddSmallFile) {
  Vault vault(block_size, make_key());
  std::vector<unsigned char> data{1, 2, 3, 4, 5, 6, 7, 8};
  auto path = make_file("small.bin", data);

  auto result = vault.add_file(path);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, AddFileExactlyOneBlock) {
  Vault vault(block_size, make_key());
  std::vector<unsigned char> data(kUsablePerBlock, 0x5A);
  auto path = make_file("block.bin", data);

  auto result = vault.add_file(path);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, AddFileLargerThanOneBlock) {
  Vault vault(block_size * 2, make_key());
  std::vector<unsigned char> data(kUsablePerBlock + 123, 0x33);
  auto path = make_file("multi.bin", data);

  auto result = vault.add_file(path);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, AddMultipleFiles) {
  Vault vault(block_size * 4, make_key());
  auto path1 = make_file("a.bin", std::vector<unsigned char>{1, 2, 3});
  auto path2 = make_file("b.bin", std::vector<unsigned char>(kUsablePerBlock, 0xFF));
  auto path3 = make_file("c.bin", std::vector<unsigned char>(kUsablePerBlock + 1, 0x0F));

  EXPECT_TRUE(vault.add_file(path1).has_value());
  EXPECT_TRUE(vault.add_file(path2).has_value());
  EXPECT_TRUE(vault.add_file(path3).has_value());
}

TEST_F(VaultTest, AddFileWhenNotEnoughMemory) {
  Vault vault(block_size, make_key());
  std::vector<unsigned char> data(kUsablePerBlock + 1, 0x7E);
  auto path = make_file("big.bin", data);

  auto result = vault.add_file(path);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), VaultError::NoEnoughMemory);
}

TEST_F(VaultTest, AddSameFileTwiceUsesMoreBlocks) {
  Vault vault(block_size * 2, make_key());
  std::vector<unsigned char> data(kUsablePerBlock, 0xA5);
  auto path = make_file("dup.bin", data);

  EXPECT_TRUE(vault.add_file(path).has_value());
  EXPECT_TRUE(vault.add_file(path).has_value());
}

TEST_F(VaultTest, AddFileRejectsWrongKeySize) {
  const std::array<std::size_t, 2> key_sizes{
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES - 1,
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES + 1,
  };

  for (const auto key_size : key_sizes) {
    Vault vault(block_size, SecureBuffer(key_size, 0x11));
    auto path = make_file("key_" + std::to_string(key_size) + ".bin",
                          std::vector<unsigned char>{1, 2, 3});

    auto result = vault.add_file(path);

    ASSERT_FALSE(result.has_value()) << "key size = " << key_size;
    EXPECT_EQ(result.error(), VaultError::CryptoError);
  }
}

TEST_F(VaultTest, InitSucceedsWithPassword) {
  Vault vault(block_size * 4, make_key());
  SecureBuffer password(16, 'p');

  auto result = vault.init(password);

  EXPECT_TRUE(result.has_value());
}

TEST_F(VaultTest, InitIsRepeatable) {
  Vault vault(block_size * 4, make_key());
  SecureBuffer password(16, 'q');

  EXPECT_TRUE(vault.init(password).has_value());
  EXPECT_TRUE(vault.init(password).has_value());
}

} // namespace
