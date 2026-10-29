module;

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>

export module core.vault;

import core.error;
import core.result;
import core.io;
import core.crypto;
import core.block;

export namespace core::vault {

class Vault {
public:
  Vault() noexcept;
  Vault(Vault &&) noexcept;
  Vault &operator=(Vault &&) noexcept;
  Vault(const Vault &) = delete;
  Vault &operator=(const Vault &) = delete;

  static Result<Vault> create(const std::filesystem::path &path,
                              const std::string &password,
                              std::size_t capacity);

  Result<void> open(const std::filesystem::path &path,
                    const std::string &password);

  Result<void> read_block(std::uint64_t index, std::span<std::byte> out);

  Result<void> write_block(std::uint64_t index,
                           std::span<const std::byte> in);

  Result<void> close();

  bool is_open() const noexcept;

private:
  explicit Vault(io::FileIO &&io, std::size_t capacity) noexcept;

  io::FileIO io_;
  block::BlockDevice block_;
  std::size_t capacity_ = 0;
};
} // namespace core::vault
