module;

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

export module core.block;

import core.error;
import core.result;
import core.io;

export namespace core::block {
// Fixed for now; will become configurable later
constexpr std::size_t block_size = 4096;

// Facade over io: translates block index -> byte offset.
// Does NOT own the file; someone above assembles the layers.
class BlockDevice {
public:
  explicit BlockDevice(core::io::FileIO &io) noexcept : io_{&io} {}

  void rebind(core::io::FileIO &io) noexcept { io_ = &io; }

  core::Result<void> read_block(std::size_t index,
                                std::span<std::byte> out) const;
  core::Result<void> write_block(std::size_t index,
                                 std::span<const std::byte> in);

  core::Result<std::size_t> block_count() const;

private:
  core::io::FileIO *io_;
};

class BlockAllocator {
  std::vector<std::uint8_t> bitmap_;
  std::size_t free_blocks_;

public:
  BlockAllocator(std::size_t capacity);

  static Result<BlockAllocator>
  from_bitmap(std::span<const std::uint8_t> bitmap);

  Result<std::vector<std::uint64_t>> allocate(std::size_t count);

  Result<void> release(std::span<const std::uint64_t> blocks);

  Result<void> mark_used(std::span<const std::uint64_t> blocks);

  std::span<const std::uint8_t> bitmap() const noexcept;
  std::size_t capacity() const noexcept;
  std::size_t free_blocks() const noexcept;
};
} // namespace core::block
