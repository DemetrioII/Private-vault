#include <gtest/gtest.h>

#include <vault.hpp>

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kUsablePerBlock = block_payload_size - block_tag_size;

SecureBuffer make_password(unsigned char fill = 'p') {
  return SecureBuffer(16, fill);
}

class PersistenceTest : public ::testing::Test {
protected:
  void SetUp() override {
    const auto prefix =
        fs::temp_directory_path() / "vault_persistence_test_" /
        std::to_string(reinterpret_cast<std::uintptr_t>(this)) /
        std::to_string(std::time(nullptr));
    fs::create_directories(prefix);
    dir_ = prefix;
  }

  void TearDown() override {
    std::error_code ec;
    fs::remove_all(dir_, ec);
  }

  fs::path make_file(const std::string &name,
                     const std::vector<unsigned char> &data) {
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

TEST_F(PersistenceTest, CreateWritesVaultFile) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";

  auto created = Vault::create(path, 8 * block_size, password);

  ASSERT_TRUE(created.has_value());
  EXPECT_TRUE(fs::exists(path));
  EXPECT_GT(fs::file_size(path), 0u);
}

TEST_F(PersistenceTest, OpenWithCorrectPasswordSucceeds) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  ASSERT_TRUE(Vault::create(path, 8 * block_size, password).has_value());

  auto opened = Vault::open(path, password);

  EXPECT_TRUE(opened.has_value());
}

TEST_F(PersistenceTest, OpenWithWrongPasswordFails) {
  const auto path = dir_ / "vault.bin";
  auto password = make_password('p');
  ASSERT_TRUE(Vault::create(path, 8 * block_size, password).has_value());

  auto wrong = make_password('q');
  auto opened = Vault::open(path, wrong);

  ASSERT_FALSE(opened.has_value());
  EXPECT_EQ(opened.error(), VaultError::WrongPassword);
}

TEST_F(PersistenceTest, OpenMissingVaultFails) {
  auto password = make_password();

  auto opened = Vault::open(dir_ / "missing.bin", password);

  ASSERT_FALSE(opened.has_value());
  EXPECT_EQ(opened.error(), VaultError::FileOpenError);
}

TEST_F(PersistenceTest, OpenGarbageFileFails) {
  const auto path = dir_ / "garbage.bin";
  {
    std::ofstream out(path, std::ios::binary);
    out << "this is not a vault";
  }

  auto opened = Vault::open(path, make_password());

  ASSERT_FALSE(opened.has_value());
  EXPECT_EQ(opened.error(), VaultError::InvalidFormat);
}

TEST_F(PersistenceTest, OpenTruncatedVaultFails) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  ASSERT_TRUE(Vault::create(path, 8 * block_size, password).has_value());

  fs::resize_file(path, 10);

  auto opened = Vault::open(path, password);

  ASSERT_FALSE(opened.has_value());
  EXPECT_EQ(opened.error(), VaultError::InvalidFormat);
}

TEST_F(PersistenceTest, TamperedMagicFailsAuthentication) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  ASSERT_TRUE(Vault::create(path, 8 * block_size, password).has_value());

  constexpr std::streamoff magic_ciphertext_offset =
      8 + 8 + crypto_pwhash_SALTBYTES +
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

  {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(file.is_open());
    file.seekg(magic_ciphertext_offset);
    char byte = 0;
    file.read(&byte, 1);
    byte ^= 0x01;
    file.seekp(magic_ciphertext_offset);
    file.write(&byte, 1);
  }

  auto opened = Vault::open(path, password);

  ASSERT_FALSE(opened.has_value());
  EXPECT_EQ(opened.error(), VaultError::WrongPassword);
}

TEST_F(PersistenceTest, AddFileSurvivesReopenAndCanBeRemoved) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  const auto source = make_file(
      "payload.bin", std::vector<unsigned char>(kUsablePerBlock + 10, 0x5A));

  auto created = Vault::create(path, 4 * block_size, password);
  ASSERT_TRUE(created.has_value());

  auto added = created->add_file(source);
  ASSERT_TRUE(added.has_value());
  const auto file_id = *added;
  EXPECT_NE(file_id, 0u);
  ASSERT_TRUE(created->save(path).has_value());

  auto reopened = Vault::open(path, password);
  ASSERT_TRUE(reopened.has_value());

  auto removed = reopened->remove_file(file_id);
  EXPECT_TRUE(removed.has_value());
  ASSERT_TRUE(reopened->save(path).has_value());

  auto reopened_again = Vault::open(path, password);
  ASSERT_TRUE(reopened_again.has_value());

  auto removed_again = reopened_again->remove_file(file_id);
  ASSERT_FALSE(removed_again.has_value());
  EXPECT_EQ(removed_again.error(), VaultError::FileNotFound);
}

TEST_F(PersistenceTest, EmptyFileSurvivesReopen) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  const auto source = make_file("empty.bin", {});

  auto created = Vault::create(path, block_size, password);
  ASSERT_TRUE(created.has_value());

  auto added = created->add_file(source);
  ASSERT_TRUE(added.has_value());
  ASSERT_TRUE(created->save(path).has_value());

  auto reopened = Vault::open(path, password);
  ASSERT_TRUE(reopened.has_value());

  EXPECT_TRUE(reopened->remove_file(*added).has_value());
}

TEST_F(PersistenceTest, CapacityIsPersisted) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  const auto first =
      make_file("one.bin", std::vector<unsigned char>(kUsablePerBlock, 0x11));
  const auto second = make_file("two.bin", std::vector<unsigned char>{0x22});

  auto created = Vault::create(path, block_size, password);
  ASSERT_TRUE(created.has_value());
  ASSERT_TRUE(created->add_file(first).has_value());
  ASSERT_TRUE(created->save(path).has_value());

  auto reopened = Vault::open(path, password);
  ASSERT_TRUE(reopened.has_value());

  auto added = reopened->add_file(second);
  ASSERT_FALSE(added.has_value());
  EXPECT_EQ(added.error(), VaultError::NoEnoughMemory);
}

TEST_F(PersistenceTest, RemoveUnknownFileFails) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";

  auto created = Vault::create(path, block_size, password);
  ASSERT_TRUE(created.has_value());

  auto removed = created->remove_file(12345);

  ASSERT_FALSE(removed.has_value());
  EXPECT_EQ(removed.error(), VaultError::FileNotFound);
}

TEST_F(PersistenceTest, ZeroCapacityVaultRoundTrips) {
  auto password = make_password();
  const auto path = dir_ / "vault.bin";
  const auto source = make_file("empty.bin", {});

  auto created = Vault::create(path, 0, password);
  ASSERT_TRUE(created.has_value());

  auto added = created->add_file(source);
  ASSERT_TRUE(added.has_value());
  ASSERT_TRUE(created->save(path).has_value());

  auto reopened = Vault::open(path, password);
  ASSERT_TRUE(reopened.has_value());
  EXPECT_TRUE(reopened->remove_file(*added).has_value());
}

} // namespace
