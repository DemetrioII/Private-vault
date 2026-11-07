#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <vault.hpp>
#include <vector>

namespace {

constexpr std::array<char, 8> vault_magic{'L', 'I', 'B', 'R', 'E', 'V', '0', '1'};
constexpr std::size_t usable_block_bytes = block_payload_size - block_tag_size;

void put_u64(std::ostream &out, std::uint64_t value) {
  std::array<unsigned char, 8> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xFF);
  }
  out.write(reinterpret_cast<const char *>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

bool get_u64(std::istream &in, std::uint64_t &value) {
  std::array<unsigned char, 8> bytes{};
  if (!in.read(reinterpret_cast<char *>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()))) {
    return false;
  }

  value = 0;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    value |= static_cast<std::uint64_t>(bytes[i]) << (8 * i);
  }
  return true;
}

} // namespace

Vault::Vault(std::size_t capacity, SecureBuffer &&generated_key)
    : capacity_(capacity), block_device_(capacity), key_(std::move(generated_key)) {}

std::expected<Vault, VaultError>
Vault::create(const std::filesystem::path &path, std::size_t capacity,
              const SecureBuffer &password) {
  SecureBuffer placeholder(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  Vault vault(capacity, std::move(placeholder));

  auto init_res = vault.init(password);
  if (!init_res) {
    return std::unexpected(init_res.error());
  }

  auto save_res = vault.save(path);
  if (!save_res) {
    return std::unexpected(save_res.error());
  }

  return vault;
}

std::expected<Vault, VaultError>
Vault::open(const std::filesystem::path &path, const SecureBuffer &password) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return std::unexpected(VaultError::FileOpenError);
  }

  std::array<char, vault_magic.size()> magic{};
  if (!in.read(magic.data(), static_cast<std::streamsize>(magic.size())) ||
      magic != vault_magic) {
    return std::unexpected(VaultError::InvalidFormat);
  }

  std::uint64_t stored_capacity = 0;
  if (!get_u64(in, stored_capacity) ||
      stored_capacity > std::numeric_limits<std::size_t>::max()) {
    return std::unexpected(VaultError::InvalidFormat);
  }
  const auto capacity = static_cast<std::size_t>(stored_capacity);

  std::array<unsigned char, crypto_pwhash_SALTBYTES> salt{};
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>
      magic_nonce{};
  std::array<unsigned char, magic_word.size() +
                                 crypto_aead_xchacha20poly1305_ietf_ABYTES>
      magic_ciphertext{};

  if (!in.read(reinterpret_cast<char *>(salt.data()),
               static_cast<std::streamsize>(salt.size())) ||
      !in.read(reinterpret_cast<char *>(magic_nonce.data()),
               static_cast<std::streamsize>(magic_nonce.size())) ||
      !in.read(reinterpret_cast<char *>(magic_ciphertext.data()),
               static_cast<std::streamsize>(magic_ciphertext.size()))) {
    return std::unexpected(VaultError::InvalidFormat);
  }

  SecureBuffer key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  if (!CryptoEngine::derive_key(password.span(), salt, key.data())) {
    return std::unexpected(VaultError::KDF_Error);
  }

  std::array<unsigned char, magic_word.size()> decrypted_magic{};
  if (!CryptoEngine::decrypt(magic_ciphertext, key.span(), magic_nonce,
                             std::nullopt, decrypted_magic) ||
      decrypted_magic != magic_word) {
    return std::unexpected(VaultError::WrongPassword);
  }

  Vault vault(capacity, std::move(key));
  vault.salt_ = salt;
  vault.magic_nonce_ = magic_nonce;
  vault.magic_ciphertext_ = magic_ciphertext;

  const auto total_blocks =
      (static_cast<std::uint64_t>(capacity) + block_size - 1) / block_size;

  std::uint64_t file_count = 0;
  if (!get_u64(in, file_count)) {
    return std::unexpected(VaultError::InvalidFormat);
  }

  for (std::uint64_t i = 0; i < file_count; ++i) {
    std::uint64_t file_id = 0;
    std::uint64_t file_size = 0;
    std::uint64_t block_count = 0;

    if (!get_u64(in, file_id) || !get_u64(in, file_size) ||
        !get_u64(in, block_count)) {
      return std::unexpected(VaultError::InvalidFormat);
    }

    if (file_id > std::numeric_limits<std::size_t>::max() ||
        file_size > std::numeric_limits<std::size_t>::max() ||
        block_count > total_blocks) {
      return std::unexpected(VaultError::InvalidFormat);
    }

    const auto expected_blocks =
        (file_size + usable_block_bytes - 1) / usable_block_bytes;
    if (expected_blocks != block_count) {
      return std::unexpected(VaultError::InvalidFormat);
    }

    FileEntry entry;
    entry.file_size = static_cast<std::size_t>(file_size);
    entry.blocks.reserve(static_cast<std::size_t>(block_count));

    for (std::uint64_t block_index = 0; block_index < block_count;
         ++block_index) {
      std::uint64_t physical_index = 0;
      std::array<unsigned char, block_nonce_size> nonce{};
      std::array<unsigned char, block_payload_size> payload{};

      if (!get_u64(in, physical_index) ||
          !in.read(reinterpret_cast<char *>(nonce.data()),
                   static_cast<std::streamsize>(nonce.size())) ||
          !in.read(reinterpret_cast<char *>(payload.data()),
                   static_cast<std::streamsize>(payload.size()))) {
        return std::unexpected(VaultError::InvalidFormat);
      }

      if (physical_index > std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(VaultError::InvalidFormat);
      }

      auto restored = vault.block_device_.restore_file_block(
          static_cast<std::size_t>(physical_index),
          static_cast<std::size_t>(block_index) + 1,
          static_cast<std::size_t>(file_id), nonce, payload);
      if (!restored) {
        return std::unexpected(VaultError::InvalidFormat);
      }

      entry.blocks.push_back(static_cast<std::size_t>(physical_index));
    }

    if (vault.file_table_.file_table.contains(
            static_cast<std::size_t>(file_id))) {
      return std::unexpected(VaultError::InvalidFormat);
    }

    file_table::add_file(vault.file_table_, static_cast<std::size_t>(file_id),
                         std::move(entry));
  }

  return vault;
}

std::expected<void, VaultError>
Vault::save(const std::filesystem::path &path) const {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return std::unexpected(VaultError::FileOpenError);
  }

  out.write(vault_magic.data(),
            static_cast<std::streamsize>(vault_magic.size()));
  put_u64(out, static_cast<std::uint64_t>(capacity_));

  out.write(reinterpret_cast<const char *>(salt_.data()),
            static_cast<std::streamsize>(salt_.size()));
  out.write(reinterpret_cast<const char *>(magic_nonce_.data()),
            static_cast<std::streamsize>(magic_nonce_.size()));
  out.write(reinterpret_cast<const char *>(magic_ciphertext_.data()),
            static_cast<std::streamsize>(magic_ciphertext_.size()));

  put_u64(out, static_cast<std::uint64_t>(file_table_.file_table.size()));

  for (const auto &[file_id, entry] : file_table_.file_table) {
    put_u64(out, static_cast<std::uint64_t>(file_id));
    put_u64(out, static_cast<std::uint64_t>(entry.file_size));
    put_u64(out, static_cast<std::uint64_t>(entry.blocks.size()));

    for (const auto physical_index : entry.blocks) {
      const Block &block = block_device_.block_at(physical_index);

      put_u64(out, static_cast<std::uint64_t>(physical_index));
      out.write(reinterpret_cast<const char *>(block.nonce.data()),
                static_cast<std::streamsize>(block.nonce.size()));
      out.write(reinterpret_cast<const char *>(block.payload.data()),
                static_cast<std::streamsize>(block.payload.size()));
    }
  }

  out.flush();
  if (!out) {
    return std::unexpected(VaultError::FileWriteError);
  }

  return {};
}

std::expected<std::size_t, VaultError>
Vault::add_file(const std::filesystem::path &path) {
  std::error_code ec;
  const auto file_size = std::filesystem::file_size(path, ec);
  if (ec) {
    return std::unexpected(VaultError::FileOpenError);
  }

  std::ifstream input(path, std::ios::binary);
  if (!input) {
    return std::unexpected(VaultError::FileOpenError);
  }

  const auto file_id = file_table::generate_id(file_table_);

  auto block_idxs = block_device_.allocate(file_size, file_id);
  if (!block_idxs.has_value()) {
    return std::unexpected(VaultError::NoEnoughMemory);
  }

  auto release_blocks = [&] { (void)block_device_.remove_file(file_id); };

  FileEntry entry;

  entry.file_size = file_size;
  entry.blocks = std::move(*block_idxs);

  std::vector<unsigned char> buffer(usable_block_bytes);
  std::vector<unsigned char> encrypted(block_payload_size);

  std::array<unsigned char, block_nonce_size> nonce;

  for (std::size_t i = 0; i < entry.blocks.size(); ++i) {
    input.read(reinterpret_cast<char *>(buffer.data()),
               static_cast<std::streamsize>(usable_block_bytes));

    const auto bytes_read = input.gcount();

    if (bytes_read <= 0) {
      release_blocks();
      return std::unexpected(VaultError::FileReadError);
    }

    randombytes_buf(nonce.data(), nonce.size());

    if (bytes_read < static_cast<std::streamsize>(buffer.size())) {
      for (std::size_t j = static_cast<std::size_t>(bytes_read);
           j < buffer.size(); ++j) {
        buffer[j] = 0;
      }
    }

    {
      auto result =
          CryptoEngine::encrypt(buffer, key_.span(), nonce, std::nullopt, encrypted);

      if (!result) {
        release_blocks();
        return std::unexpected(VaultError::CryptoError);
      }
    }

    auto result = block_device_.write_file_block(
        std::span(encrypted.data(), block_payload_size), nonce, file_id, i + 1);

    if (!result) {
      release_blocks();
      return std::unexpected(VaultError::BlockDeviceWriteError);
    }
  }

  file_table::add_file(file_table_, file_id, std::move(entry));

  return file_id;
}

std::expected<void, VaultError> Vault::remove_file(std::size_t file_id) {
  auto it = file_table_.file_table.find(file_id);
  if (it == file_table_.file_table.end())
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

  key_ = std::move(key);

  return {};
}
