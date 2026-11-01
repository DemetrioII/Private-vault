module;

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

export module core.vault;

import core.error;
import core.result;
import core.io;
import core.crypto;
import core.secure;
import core.block;

export namespace core::vault {

inline constexpr std::uint8_t header_version = 1;
inline constexpr std::array<unsigned char, 5> magic_word_value{'L', 'E', 'N',
                                                               'I', 'N'};
inline constexpr std::size_t magic_word_size = magic_word_value.size();
inline constexpr std::size_t ciphertext_magic_size =
    magic_word_size + crypto::aead::mac_bytes;

struct Header {
  std::uint8_t version = header_version;
  std::array<unsigned char, crypto::kdf::salt_bytes> salt;
  std::array<unsigned char, crypto::aead::nonce_bytes> nonce;

  std::vector<unsigned char> magic_word{magic_word_value.begin(),
                                        magic_word_value.end()};
  std::vector<unsigned char> ciphertext_magic;
};

struct FileEntry {
  std::uint64_t id;
  std::string name;
  std::uint64_t size;
  std::vector<std::uint64_t> blocks;
};

struct FileTable {
  std::vector<FileEntry> files;
};

class Vault {
public:
  Vault() noexcept;
  Vault(Vault &&) noexcept;
  Vault &operator=(Vault &&) noexcept;
  Vault(const Vault &) = delete;
  Vault &operator=(const Vault &) = delete;

  static Result<Vault> create(const std::filesystem::path &path,
                              std::span<const unsigned char> password,
                              std::size_t capacity);

  Result<void> open(const std::filesystem::path &path,
                    std::span<const unsigned char> password);

  Result<void> read_block(std::uint64_t index, std::span<std::byte> out);

  Result<void> write_block(std::uint64_t index, std::span<const std::byte> in);

  Result<void> close();

  Result<std::uint64_t> add_file(std::string_view name,
                                 std::span<const std::byte> contents);

  Result<std::vector<std::byte>> read_file(std::uint64_t id);

  Result<void> remove_file(std::uint64_t id);

  Result<std::vector<FileEntry>> list_files() const;

  Result<void> serialize_header(std::span<std::byte> out);

  Result<Header> deserialize_header(std::span<std::byte const> out);

  bool is_open() const noexcept;

private:
  explicit Vault(io::FileIO &&io, std::size_t capacity) noexcept;

  Result<void> initialize_crypto(std::span<const unsigned char> password);

  Result<std::vector<unsigned char>> serialize_metadata() const;

  Result<void>
  deserialize_metadata(std::span<const unsigned char> plaintext);

  Result<void> read_metadata();
  Result<void> write_metadata();

  io::FileIO io_;
  block::BlockDevice block_device_;
  std::size_t capacity_ = 0;
  Header header;
  core::SecureBuffer<crypto::kdf::key_bytes> key_;
  FileTable file_table_;
  block::BlockAllocator block_allocator_;
  std::uint64_t next_file_id_ = 1;
};
} // namespace core::vault
