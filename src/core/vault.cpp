module;

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <utility>

module core.vault;

import core.error;
import core.result;
import core.io;
import core.block;

using namespace core;
using namespace core::io;
using namespace core::block;
using namespace core::vault;

Vault::Vault() noexcept : block_(io_) {}

Vault::Vault(io::FileIO &&io, std::size_t capacity) noexcept
    : io_(std::move(io)), block_(io_), capacity_(capacity) {}

Vault::Vault(Vault &&other) noexcept
    : io_(std::move(other.io_)), block_(io_), capacity_(other.capacity_) {
  other.capacity_ = 0;
}

Vault &Vault::operator=(Vault &&other) noexcept {
  if (this == &other) {
    return *this;
  }

  io_ = std::move(other.io_);
  block_.rebind(io_);
  capacity_ = other.capacity_;
  other.capacity_ = 0;
  return *this;
}

Result<Vault> Vault::create(const std::filesystem::path &path,
                            const std::string &password, std::size_t capacity) {
  (void)password;

  if (capacity == 0) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "capacity must be non-zero"));
  }

  constexpr std::size_t max_capacity =
      std::numeric_limits<std::size_t>::max() / block_size;
  if (capacity > max_capacity) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "capacity is too large"));
  }

  auto io_res = FileIO::open(path, OpenMode::CreateExclusive);
  if (!io_res) {
    return std::unexpected(io_res.error());
  }

  auto io = std::move(*io_res);
  auto resize_res =
      io.resize(static_cast<std::uint64_t>(capacity) * block_size);
  if (!resize_res) {
    return std::unexpected(resize_res.error());
  }

  return Vault(std::move(io), capacity);
}

Result<void> Vault::open(const std::filesystem::path &path,
                         const std::string &password) {
  (void)password;

  auto io_res = FileIO::open(path, OpenMode::ReadWrite);
  if (!io_res) {
    return std::unexpected(io_res.error());
  }

  auto io = std::move(*io_res);
  auto size_res = io.size();
  if (!size_res) {
    return std::unexpected(size_res.error());
  }

  const std::uint64_t bytes = *size_res;
  if (bytes == 0 || bytes % block_size != 0) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "invalid vault size"));
  }

  const std::uint64_t blocks = bytes / block_size;
  if (blocks > std::numeric_limits<std::size_t>::max()) {
    return std::unexpected(
        make_error(ErrorCode::VaultError, "vault is too large"));
  }

  io_ = std::move(io);
  block_.rebind(io_);
  capacity_ = static_cast<std::size_t>(blocks);
  return {};
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

  return block_.read_block(static_cast<std::size_t>(index), out);
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

  return block_.write_block(static_cast<std::size_t>(index), in);
}

Result<void> Vault::close() {
  io_ = io::FileIO{};
  block_.rebind(io_);
  capacity_ = 0;
  return {};
}

bool Vault::is_open() const noexcept { return io_.is_open(); }
