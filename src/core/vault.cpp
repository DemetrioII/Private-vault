module;

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

module core.vault;

import core.error;
import core.result;
import core.io;
import core.block;
import core.crypto;
import core.secure;

using namespace core;
using namespace core::io;
using namespace core::block;
using namespace core::vault;

namespace {

constexpr std::size_t header_block_index = 0;
constexpr std::size_t metadata_block_index = 1;
constexpr std::size_t minimum_block_count = 2;

constexpr std::uint32_t metadata_version = 1;
constexpr std::size_t metadata_nonce_size = crypto::aead::nonce_bytes;
constexpr std::size_t metadata_length_size = sizeof(std::uint32_t);
constexpr std::size_t metadata_plaintext_max =
    block_size - metadata_nonce_size - metadata_length_size -
    crypto::aead::mac_bytes;

static_assert(metadata_plaintext_max > 0);

using MetadataBytes = std::vector<unsigned char>;

void append_u32(MetadataBytes &out, std::uint32_t value) {
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
  }
}

void append_u64(MetadataBytes &out, std::uint64_t value) {
  for (std::size_t i = 0; i < sizeof(value); ++i) {
    out.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
  }
}

void append_bytes(MetadataBytes &out, const void *data, std::size_t size) {
  if (size == 0) {
    return;
  }

  const auto *bytes = static_cast<const unsigned char *>(data);
  out.insert(out.end(), bytes, bytes + size);
}

class MetadataReader {
public:
  explicit MetadataReader(std::span<const unsigned char> data) : data_(data) {}

  bool u8(std::uint8_t &value) {
    if (!require(sizeof(value))) {
      return false;
    }
    value = data_[position_++];
    return true;
  }

  bool u32(std::uint32_t &value) {
    if (!require(sizeof(value))) {
      return false;
    }
    value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
      value |= static_cast<std::uint32_t>(data_[position_++]) << (i * 8);
    }
    return true;
  }

  bool u64(std::uint64_t &value) {
    if (!require(sizeof(value))) {
      return false;
    }
    value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
      value |= static_cast<std::uint64_t>(data_[position_++]) << (i * 8);
    }
    return true;
  }

  bool bytes(std::size_t size, std::span<const unsigned char> &value) {
    if (!require(size)) {
      return false;
    }
    value = data_.subspan(position_, size);
    position_ += size;
    return true;
  }

  std::size_t remaining() const { return data_.size() - position_; }
  bool done() const { return position_ == data_.size(); }

private:
  bool require(std::size_t size) const {
    return size <= data_.size() - position_;
  }

  std::span<const unsigned char> data_;
  std::size_t position_ = 0;
};

struct ParsedMetadata {
  FileTable table;
  BlockAllocator allocator{0};
  std::uint64_t next_file_id = 1;
};

std::size_t blocks_for_size(std::uint64_t size) {
  return size == 0 ? 0 : static_cast<std::size_t>((size - 1) / block_size + 1);
}

} // namespace

Vault::Vault() noexcept : block_device_(io_), block_allocator_(0) {}

Vault::Vault(io::FileIO &&io, std::size_t capacity) noexcept
    : io_(std::move(io)), block_device_(io_), capacity_(capacity),
      block_allocator_(capacity) {}

Vault::Vault(Vault &&other) noexcept
    : io_(std::move(other.io_)), block_device_(io_), capacity_(other.capacity_),
      header(std::move(other.header)), key_(std::move(other.key_)),
      file_table_(std::move(other.file_table_)),
      block_allocator_(std::move(other.block_allocator_)),
      next_file_id_(other.next_file_id_) {
  other.capacity_ = 0;
  other.next_file_id_ = 1;
}

Vault &Vault::operator=(Vault &&other) noexcept {
  if (this == &other) {
    return *this;
  }

  io_ = std::move(other.io_);
  block_device_.rebind(io_);
  capacity_ = other.capacity_;
  header = std::move(other.header);
  key_ = std::move(other.key_);
  file_table_ = std::move(other.file_table_);
  block_allocator_ = std::move(other.block_allocator_);
  next_file_id_ = other.next_file_id_;
  other.capacity_ = 0;
  other.next_file_id_ = 1;
  return *this;
}

Result<void> Vault::initialize_crypto(std::span<const unsigned char> password) {
  crypto::fill_random(header.salt);
  crypto::fill_random(header.nonce);

  auto kdf_res =
      crypto::kdf::derive_key(password, header.salt, key_.span());
  if (!kdf_res) {
    key_.fill(0);
    return std::unexpected(kdf_res.error());
  }

  auto enc_res = crypto::aead::encrypt(key_.span(), header.nonce,
                                       header.magic_word,
                                       header.ciphertext_magic);
  if (!enc_res) {
    key_.fill(0);
    return std::unexpected(enc_res.error());
  }

  return {};
}

Result<Vault> Vault::create(const std::filesystem::path &path,
                            std::span<const unsigned char> password,
                            std::size_t capacity) {
  if (capacity < minimum_block_count) {
    return std::unexpected(make_error(
        ErrorCode::InvalidArgument, "capacity must be at least two blocks"));
  }

  constexpr std::size_t max_capacity =
      std::numeric_limits<std::size_t>::max() / block_size;
  if (capacity > max_capacity) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "capacity is too large"));
  }

  auto io_res = FileIO::open(path, OpenMode::CreateExclusive);
  if (!io_res.has_value()) {
    return std::unexpected(io_res.error());
  }

  auto io = std::move(*io_res);

  auto allocate_res =
      io.allocate(static_cast<std::uint64_t>(capacity) * block_size);

  if (!allocate_res.has_value())
    return std::unexpected(allocate_res.error());

  Vault vault(std::move(io), capacity);
  auto crypto_res = vault.initialize_crypto(password);
  if (!crypto_res.has_value())
    return std::unexpected(crypto_res.error());

  std::array<std::uint64_t, minimum_block_count> reserved_blocks{
      header_block_index, metadata_block_index};
  auto reserve_res = vault.block_allocator_.mark_used(reserved_blocks);
  if (!reserve_res.has_value()) {
    return std::unexpected(reserve_res.error());
  }

  std::array<std::byte, block_size> header_block{};

  auto serialize_res = vault.serialize_header(header_block);
  if (!serialize_res.has_value())
    return std::unexpected(serialize_res.error());

  auto write_res = vault.write_block(header_block_index, header_block);
  if (!write_res.has_value())
    return std::unexpected(write_res.error());

  auto metadata_res = vault.write_metadata();
  if (!metadata_res.has_value())
    return std::unexpected(metadata_res.error());

  return std::move(vault);
}

Result<void> Vault::serialize_header(std::span<std::byte> out) {
  if (out.size() != block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid header buffer size"));
  }

  if (header.magic_word.size() != magic_word_size ||
      header.ciphertext_magic.size() != ciphertext_magic_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid header field size"));
  }

  constexpr std::size_t version_offset = 0;
  constexpr std::size_t salt_offset = version_offset + sizeof(std::uint8_t);
  constexpr std::size_t nonce_offset = salt_offset + crypto::kdf::salt_bytes;
  constexpr std::size_t magic_word_offset =
      nonce_offset + crypto::aead::nonce_bytes;
  constexpr std::size_t ciphertext_magic_offset =
      magic_word_offset + magic_word_size;

  static_assert(ciphertext_magic_offset + ciphertext_magic_size <= block_size);

  std::memcpy(out.data() + version_offset, &header.version,
              sizeof(header.version));
  std::memcpy(out.data() + salt_offset, header.salt.data(), header.salt.size());
  std::memcpy(out.data() + nonce_offset, header.nonce.data(),
              header.nonce.size());
  std::memcpy(out.data() + magic_word_offset, header.magic_word.data(),
              header.magic_word.size());
  std::memcpy(out.data() + ciphertext_magic_offset,
              header.ciphertext_magic.data(), header.ciphertext_magic.size());

  return {};
}

Result<Header> Vault::deserialize_header(std::span<std::byte const> out) {
  if (out.size() != block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid header buffer size"));
  }

  constexpr std::size_t version_offset = 0;
  constexpr std::size_t salt_offset = version_offset + sizeof(std::uint8_t);
  constexpr std::size_t nonce_offset = salt_offset + crypto::kdf::salt_bytes;
  constexpr std::size_t magic_word_offset =
      nonce_offset + crypto::aead::nonce_bytes;
  constexpr std::size_t ciphertext_magic_offset =
      magic_word_offset + magic_word_size;

  static_assert(ciphertext_magic_offset + ciphertext_magic_size <= block_size);

  Header header;

  std::memcpy(&header.version, out.data() + version_offset,
              sizeof(header.version));
  if (header.version != header_version) {
    return std::unexpected(
        make_error(ErrorCode::Unsupported, "unsupported header version"));
  }

  std::memcpy(header.salt.data(), out.data() + salt_offset, header.salt.size());
  std::memcpy(header.nonce.data(), out.data() + nonce_offset,
              header.nonce.size());

  header.magic_word.assign(magic_word_value.begin(), magic_word_value.end());
  std::memcpy(header.magic_word.data(), out.data() + magic_word_offset,
              header.magic_word.size());

  header.ciphertext_magic.resize(ciphertext_magic_size);
  std::memcpy(header.ciphertext_magic.data(),
              out.data() + ciphertext_magic_offset,
              header.ciphertext_magic.size());

  return header;
}

Result<void> Vault::open(const std::filesystem::path &path,
                         std::span<const unsigned char> password) {
  auto io_res = FileIO::open(path, OpenMode::ReadWrite);
  if (!io_res.has_value()) {
    return std::unexpected(io_res.error());
  }

  auto io = std::move(*io_res);
  auto size_res = io.size();
  if (!size_res.has_value()) {
    return std::unexpected(size_res.error());
  }

  const std::uint64_t bytes = *size_res;
  if (bytes == 0 || bytes % block_size != 0) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid vault size"));
  }

  const std::uint64_t blocks = bytes / block_size;
  if (blocks < minimum_block_count) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is too small"));
  }

  if (blocks > std::numeric_limits<std::size_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is too large"));
  }

  std::array<std::byte, block_size> header_block{};
  BlockDevice local_block(io);
  auto read_res = local_block.read_block(header_block_index, header_block);
  if (!read_res.has_value()) {
    return std::unexpected(read_res.error());
  }

  auto potential_header = deserialize_header(header_block);
  if (!potential_header.has_value()) {
    return std::unexpected(potential_header.error());
  }

  SecureBuffer<crypto::kdf::key_bytes> key;
  auto key_res =
      crypto::kdf::derive_key(password, potential_header->salt, key.span());
  if (!key_res.has_value()) {
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "failed to derive key"));
  }

  std::vector<unsigned char> magic_plaintext;
  auto crypto_res = crypto::aead::decrypt(key.span(), potential_header->nonce,
                                          potential_header->ciphertext_magic,
                                          magic_plaintext);
  if (!crypto_res.has_value() ||
      magic_plaintext.size() != magic_word_value.size() ||
      !std::equal(magic_plaintext.begin(), magic_plaintext.end(),
                  magic_word_value.begin(), magic_word_value.end())) {
    secure_zero(magic_plaintext.data(), magic_plaintext.size());
    return std::unexpected(
        make_error(ErrorCode::PermissionDenied, "wrong password"));
  }

  io_ = std::move(io);
  block_device_.rebind(io_);
  capacity_ = static_cast<std::size_t>(blocks);
  header = std::move(*potential_header);
  key_ = std::move(key);

  auto metadata_res = read_metadata();
  if (!metadata_res.has_value()) {
    close();
    return std::unexpected(metadata_res.error());
  }

  return {};
}

Result<std::vector<unsigned char>> Vault::serialize_metadata() const {
  MetadataBytes out;
  out.reserve(128);

  append_u32(out, metadata_version);
  append_u64(out, next_file_id_);

  if (file_table_.files.size() >
      std::numeric_limits<std::uint32_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "file table is too large"));
  }
  append_u32(out, static_cast<std::uint32_t>(file_table_.files.size()));

  for (const auto &file : file_table_.files) {
    if (file.name.size() > std::numeric_limits<std::uint32_t>::max()) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "file name is too long"));
    }

    append_u64(out, file.id);
    append_u32(out, static_cast<std::uint32_t>(file.name.size()));
    append_bytes(out, file.name.data(), file.name.size());
    append_u64(out, file.size);
    append_u64(out, static_cast<std::uint64_t>(file.blocks.size()));

    for (const auto block : file.blocks) {
      append_u64(out, block);
    }

    if (out.size() > metadata_plaintext_max) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "metadata is too large"));
    }
  }

  const auto bitmap = block_allocator_.bitmap();
  if (bitmap.size() > std::numeric_limits<std::uint32_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "block bitmap is too large"));
  }
  append_u32(out, static_cast<std::uint32_t>(bitmap.size()));
  append_bytes(out, bitmap.data(), bitmap.size());

  if (out.size() > metadata_plaintext_max) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "metadata is too large"));
  }

  return out;
}

Result<void>
Vault::deserialize_metadata(std::span<const unsigned char> plaintext) {
  MetadataReader reader(plaintext);

  std::uint32_t version = 0;
  if (!reader.u32(version) || version != metadata_version) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid metadata version"));
  }

  std::uint64_t next_file_id = 1;
  if (!reader.u64(next_file_id)) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid metadata"));
  }

  std::uint32_t file_count = 0;
  if (!reader.u32(file_count) || file_count > metadata_plaintext_max) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid file table"));
  }

  FileTable table;
  table.files.reserve(file_count);
  std::unordered_set<std::uint64_t> file_ids;
  std::uint64_t max_file_id = 0;

  for (std::uint32_t i = 0; i < file_count; ++i) {
    std::uint64_t id = 0;
    std::uint32_t name_size = 0;
    if (!reader.u64(id) || !reader.u32(name_size)) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid file entry"));
    }

    if (id == 0 || !file_ids.insert(id).second) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid file id"));
    }

    std::span<const unsigned char> name_bytes;
    if (!reader.bytes(name_size, name_bytes)) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid file name"));
    }

    std::uint64_t size = 0;
    std::uint64_t block_count = 0;
    if (!reader.u64(size) || !reader.u64(block_count)) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid file size"));
    }

    if (block_count > reader.remaining() / sizeof(std::uint64_t) ||
        block_count != blocks_for_size(size) ||
        block_count > std::numeric_limits<std::size_t>::max()) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid file block count"));
    }

    std::vector<std::uint64_t> blocks;
    blocks.reserve(static_cast<std::size_t>(block_count));
    for (std::uint64_t j = 0; j < block_count; ++j) {
      std::uint64_t block = 0;
      if (!reader.u64(block)) {
        return std::unexpected(
            make_error(ErrorCode::VaultError, "invalid file blocks"));
      }
      blocks.push_back(block);
    }

    table.files.push_back(
        FileEntry{id,
                  std::string(reinterpret_cast<const char *>(name_bytes.data()),
                              name_bytes.size()),
                  size, std::move(blocks)});
    max_file_id = std::max(max_file_id, id);
  }

  std::uint32_t bitmap_size = 0;
  if (!reader.u32(bitmap_size) || bitmap_size != capacity_ ||
      bitmap_size < minimum_block_count) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid block bitmap size"));
  }

  std::span<const unsigned char> bitmap_bytes;
  if (!reader.bytes(bitmap_size, bitmap_bytes) || !reader.done()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid block bitmap"));
  }

  if (bitmap_bytes[header_block_index] == 0 ||
      bitmap_bytes[metadata_block_index] == 0) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "reserved blocks are not allocated"));
  }

  auto allocator_res = BlockAllocator::from_bitmap(bitmap_bytes);
  if (!allocator_res.has_value()) {
    return std::unexpected(allocator_res.error());
  }

  std::vector<std::uint8_t> seen(bitmap_size, 0);
  for (const auto &file : table.files) {
    for (const auto block : file.blocks) {
      if (block < minimum_block_count ||
          block >= static_cast<std::uint64_t>(bitmap_size)) {
        return std::unexpected(
            make_error(ErrorCode::VaultError, "invalid file block"));
      }

      const auto index = static_cast<std::size_t>(block);
      if (seen[index] != 0 || bitmap_bytes[index] == 0) {
        return std::unexpected(
            make_error(ErrorCode::VaultError, "invalid file block bitmap"));
      }
      seen[index] = 1;
    }
  }

  if (max_file_id == std::numeric_limits<std::uint64_t>::max()) {
    next_file_id = max_file_id;
  } else if (next_file_id <= max_file_id) {
    next_file_id = max_file_id + 1;
  }
  if (next_file_id == 0) {
    next_file_id = 1;
  }

  file_table_ = std::move(table);
  block_allocator_ = std::move(*allocator_res);
  next_file_id_ = next_file_id;
  return {};
}

Result<void> Vault::read_metadata() {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  std::array<std::byte, block_size> block{};
  auto read_res = read_block(metadata_block_index, block);
  if (!read_res.has_value()) {
    return std::unexpected(read_res.error());
  }

  const auto *bytes =
      reinterpret_cast<const unsigned char *>(block.data());
  std::uint32_t ciphertext_size = 0;
  std::memcpy(&ciphertext_size, bytes + metadata_nonce_size,
              sizeof(ciphertext_size));

  if (ciphertext_size < crypto::aead::mac_bytes ||
      ciphertext_size >
          block_size - metadata_nonce_size - metadata_length_size) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid metadata size"));
  }

  std::span<const unsigned char> nonce(bytes, metadata_nonce_size);
  std::span<const unsigned char> ciphertext(
      bytes + metadata_nonce_size + metadata_length_size, ciphertext_size);

  std::vector<unsigned char> plaintext;
  auto decrypt_res =
      crypto::aead::decrypt(key_.span(), nonce, ciphertext, plaintext);
  if (!decrypt_res.has_value()) {
    secure_zero(plaintext.data(), plaintext.size());
    return std::unexpected(
        make_error(ErrorCode::VaultError, "failed to decrypt metadata"));
  }

  auto deserialize_res = deserialize_metadata(plaintext);
  secure_zero(plaintext.data(), plaintext.size());
  return deserialize_res;
}

Result<void> Vault::write_metadata() {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  auto plaintext_res = serialize_metadata();
  if (!plaintext_res.has_value()) {
    return std::unexpected(plaintext_res.error());
  }
  auto &plaintext = *plaintext_res;

  std::array<std::byte, block_size> block{};
  auto *bytes = reinterpret_cast<unsigned char *>(block.data());
  std::span<unsigned char> nonce(bytes, metadata_nonce_size);
  crypto::fill_random(nonce);

  std::vector<unsigned char> ciphertext;
  auto encrypt_res =
      crypto::aead::encrypt(key_.span(), nonce, plaintext, ciphertext);
  secure_zero(plaintext.data(), plaintext.size());
  if (!encrypt_res.has_value()) {
    return std::unexpected(
        make_error(ErrorCode::CryptoError, "failed to encrypt metadata"));
  }

  if (ciphertext.size() >
      block_size - metadata_nonce_size - metadata_length_size) {
    secure_zero(ciphertext.data(), ciphertext.size());
    return std::unexpected(
        make_error(ErrorCode::VaultError, "encrypted metadata is too large"));
  }

  const auto ciphertext_size =
      static_cast<std::uint32_t>(ciphertext.size());
  std::memcpy(bytes + metadata_nonce_size, &ciphertext_size,
              sizeof(ciphertext_size));
  std::memcpy(bytes + metadata_nonce_size + metadata_length_size,
              ciphertext.data(), ciphertext.size());

  auto write_res = write_block(metadata_block_index, block);
  secure_zero(ciphertext.data(), ciphertext.size());
  return write_res;
}

Result<std::uint64_t> Vault::add_file(std::string_view name,
                                      std::span<const std::byte> contents) {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  if (name.empty()) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "file name is empty"));
  }

  if (name.size() > std::numeric_limits<std::uint32_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "file name is too long"));
  }

  if (next_file_id_ == 0 ||
      next_file_id_ == std::numeric_limits<std::uint64_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "file id is exhausted"));
  }

  const auto block_count = blocks_for_size(contents.size());
  std::vector<std::uint64_t> blocks;
  if (block_count > 0) {
    auto allocated_res = block_allocator_.allocate(block_count);
    if (!allocated_res.has_value()) {
      return std::unexpected(allocated_res.error());
    }
    blocks = std::move(*allocated_res);
  }

  for (std::size_t i = 0; i < blocks.size(); ++i) {
    std::array<std::byte, block_size> block{};
    const auto offset = i * block_size;
    const auto chunk = std::min(block_size, contents.size() - offset);
    std::memcpy(block.data(), contents.data() + offset, chunk);

    auto write_res = write_block(blocks[i], block);
    if (!write_res.has_value()) {
      block_allocator_.release(blocks);
      return std::unexpected(write_res.error());
    }
  }

  const auto id = next_file_id_++;
  file_table_.files.push_back(
      FileEntry{id, std::string(name), contents.size(), blocks});

  auto metadata_res = write_metadata();
  if (!metadata_res.has_value()) {
    file_table_.files.pop_back();
    block_allocator_.release(blocks);
    --next_file_id_;
    return std::unexpected(metadata_res.error());
  }

  return id;
}

Result<std::vector<std::byte>> Vault::read_file(std::uint64_t id) {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  auto file = std::find_if(file_table_.files.begin(), file_table_.files.end(),
                           [id](const FileEntry &entry) {
                             return entry.id == id;
                           });
  if (file == file_table_.files.end()) {
    return std::unexpected(
        make_error(ErrorCode::NotFound, "file not found"));
  }

  if (file->size > std::numeric_limits<std::size_t>::max() ||
      file->blocks.size() != blocks_for_size(file->size)) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid file metadata"));
  }

  std::vector<std::byte> result(static_cast<std::size_t>(file->size));
  for (std::size_t i = 0; i < file->blocks.size(); ++i) {
    std::array<std::byte, block_size> block{};
    auto read_res = read_block(file->blocks[i], block);
    if (!read_res.has_value()) {
      secure_zero(result.data(), result.size());
      return std::unexpected(read_res.error());
    }

    const auto offset = i * block_size;
    const auto chunk = std::min(block_size, result.size() - offset);
    std::memcpy(result.data() + offset, block.data(), chunk);
  }

  return result;
}

Result<void> Vault::remove_file(std::uint64_t id) {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  auto file = std::find_if(file_table_.files.begin(), file_table_.files.end(),
                           [id](const FileEntry &entry) {
                             return entry.id == id;
                           });
  if (file == file_table_.files.end()) {
    return std::unexpected(
        make_error(ErrorCode::NotFound, "file not found"));
  }

  auto release_res = block_allocator_.release(file->blocks);
  if (!release_res.has_value()) {
    return std::unexpected(release_res.error());
  }

  file_table_.files.erase(file);
  return write_metadata();
}

Result<std::vector<FileEntry>> Vault::list_files() const {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  return file_table_.files;
}

Result<void> Vault::read_block(std::uint64_t index, std::span<std::byte> out) {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  if (out.size() != block_size) {
    return std::unexpected(make_error(ErrorCode::InvalidArgument,
                                      "buffer must be exactly one block"));
  }

  if (index >= capacity_) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "block index out of range"));
  }

  return block_device_.read_block(static_cast<std::size_t>(index), out);
}

Result<void> Vault::write_block(std::uint64_t index,
                                std::span<const std::byte> in) {
  if (!is_open()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is not open"));
  }

  if (in.size() != block_size) {
    return std::unexpected(make_error(ErrorCode::InvalidArgument,
                                      "buffer must be exactly one block"));
  }

  if (index >= capacity_) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "block index out of range"));
  }

  return block_device_.write_block(static_cast<std::size_t>(index), in);
}

Result<void> Vault::close() {
  io_ = io::FileIO{};
  block_device_.rebind(io_);
  capacity_ = 0;
  header = Header{};
  key_.fill(0);
  file_table_.files.clear();
  block_allocator_ = BlockAllocator(0);
  next_file_id_ = 1;
  return {};
}

bool Vault::is_open() const noexcept { return io_.is_open(); }
