module;

#include <cerrno>
#include <cstddef>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

module core.block;

import core.error;
import core.result;

using namespace core;
using namespace core::io;

core::Result<void>
core::block::BlockDevice::read_block(std::size_t index,
                                     std::span<std::byte> out) const {
  if (out.size() % block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid block buffer size"));
  }
  return io_->read_at(block_size * index, out);
}

core::Result<void>
core::block::BlockDevice::write_block(std::size_t index,
                                      std::span<const std::byte> in) {
  if (in.size() % block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid block buffer size"));
  }
  return io_->write_at(block_size * index, in);
}

core::Result<std::size_t> core::block::BlockDevice::block_count() const {
  auto x = io_->size();
  if (x.has_value()) {
    return (*x) / block_size;
  }
  return std::unexpected(x.error());
}

namespace core::block {
BlockAllocator::BlockAllocator(std::size_t capacity)
    : bitmap_(capacity, 0), free_blocks_(capacity) {}

Result<BlockAllocator>
BlockAllocator::from_bitmap(std::span<const std::uint8_t> bitmap) {
  std::size_t free_blocks = 0;
  for (const auto value : bitmap) {
    if (value > 1) {
      return std::unexpected(
          make_error(ErrorCode::VaultError, "invalid block bitmap"));
    }
    if (value == 0) {
      ++free_blocks;
    }
  }

  BlockAllocator allocator(bitmap.size());
  for (std::size_t i = 0; i < bitmap.size(); ++i) {
    allocator.bitmap_[i] = bitmap[i];
  }
  allocator.free_blocks_ = free_blocks;
  return allocator;
}

Result<std::vector<std::uint64_t>> BlockAllocator::allocate(std::size_t count) {
  if (count == 0 || count > free_blocks_) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "not enough free blocks"));
  }

  std::vector<std::uint64_t> result;
  result.reserve(count);

  for (std::size_t i = 0; i < bitmap_.size() && result.size() < count; ++i) {
    if (bitmap_[i] == 0) {
      result.push_back(i);
    }
  }

  for (const auto index : result) {
    bitmap_[index] = 1;
  }

  free_blocks_ -= count;
  return result;
}

Result<void> BlockAllocator::release(std::span<const std::uint64_t> blocks) {
  for (const auto index : blocks) {
    if (index >= bitmap_.size() || bitmap_[index] == 0) {
      return std::unexpected(make_error(ErrorCode::InvalidArgument,
                                        "invalid or already free block"));
    }
  }

  for (const auto index : blocks) {
    bitmap_[index] = 0;
  }

  free_blocks_ += blocks.size();
  return {};
}

Result<void> BlockAllocator::mark_used(std::span<const std::uint64_t> blocks) {
  if (blocks.size() > free_blocks_) {
    return std::unexpected(make_error(ErrorCode::VaultError,
                                      "invalid block allocation metadata"));
  }

  for (const auto index : blocks) {
    if (index >= bitmap_.size() || bitmap_[index] != 0) {
      return std::unexpected(make_error(ErrorCode::VaultError,
                                        "invalid block allocation metadata"));
    }
  }

  for (const auto index : blocks) {
    bitmap_[index] = 1;
  }

  free_blocks_ -= blocks.size();
  return {};
}

std::span<const std::uint8_t> BlockAllocator::bitmap() const noexcept {
  return bitmap_;
}

std::size_t BlockAllocator::capacity() const noexcept {
  return bitmap_.size();
}

std::size_t BlockAllocator::free_blocks() const noexcept {
  return free_blocks_;
}

} // namespace core::block
