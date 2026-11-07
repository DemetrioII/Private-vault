#include <block.hpp>
#include <block_allocator.hpp>
#include <set>

BlockAllocator::BlockAllocator(std::size_t capacity) : free_blocks_(capacity), capacity_(capacity) {
  bitmap_.reserve((capacity + 7) / 8);
  bitmap_.resize((capacity + 7) / 8);
}

std::expected<std::vector<std::size_t>, BlockAllocatorError> BlockAllocator::allocate(std::size_t count) {
  if (free_blocks_ < count) {
    return std::unexpected(BlockAllocatorError::NoEnoughMemory);
  }

  std::vector<std::size_t> blocks;
  blocks.reserve(count);

  int k = 0;

  for (std::size_t i = 0; i < capacity_ && k < count; ++i) {
    const std::size_t byte_index = i / 8;
    const std::size_t bit_index = i % 8;

    const auto mask = static_cast<unsigned char>(1u << bit_index);

    if ((bitmap_[byte_index] & mask) == 0) {
      bitmap_[byte_index] |= mask;
      blocks.push_back(i);
      ++k;
    }
  }

  free_blocks_ -= count;

  return blocks;
}

std::expected<void, BlockAllocatorError> BlockAllocator::release(const std::vector<std::size_t> &blocks) {
  for (const auto index : blocks) {
    if (index < 0 || index >= capacity_ || !(bitmap_[index / 8] >> (index % 8) & 1)) {
      return std::unexpected(BlockAllocatorError::ReleaseError);
    }
  }

  {
    std::set<std::size_t> blocks_unique;
    for (std::size_t i = 0; i < blocks.size(); ++i) {
      blocks_unique.insert(blocks[i]);
    }

    if (blocks_unique.size() != blocks.size()) {
      return std::unexpected(BlockAllocatorError::DuplicateIndices);
    }
  }

  free_blocks_ += blocks.size();

  for (const auto index : blocks) {
    bitmap_[index / 8] &= static_cast<unsigned char>(~(1u << (index % 8)));
  }

  return {};
}

std::expected<void, BlockAllocatorError> BlockAllocator::reserve(std::size_t index) {
  if (index >= capacity_) {
    return std::unexpected(BlockAllocatorError::InvalidIndex);
  }

  const std::size_t byte_index = index / 8;
  const std::size_t bit_index = index % 8;
  const auto mask = static_cast<unsigned char>(1u << bit_index);

  if ((bitmap_[byte_index] & mask) != 0) {
    return std::unexpected(BlockAllocatorError::AlreadyAllocated);
  }

  bitmap_[byte_index] |= mask;
  --free_blocks_;

  return {};
}

bool BlockAllocator::has_enough_memory(std::size_t capacity) const {
  return free_blocks_ * (block_payload_size - block_tag_size) >= capacity;
}
