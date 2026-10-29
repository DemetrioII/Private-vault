module;

#include <cstddef>
#include <span>

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
} // namespace core::block
