#pragma once
#include <cstddef>
#include <cstdint>
#include <expected>
#include <vector>

enum class BlockAllocatorError { NoEnoughMemory, ReleaseError, DuplicateIndices };

class BlockAllocator {
  std::vector<unsigned char> bitmap_;
  std::size_t free_blocks_;
  std::size_t capacity_;

public:
  explicit BlockAllocator(std::size_t capacity); // here capacity means the number of blocks

  std::expected<std::vector<std::size_t>, BlockAllocatorError> allocate(std::size_t count);

  std::expected<void, BlockAllocatorError> release(const std::vector<std::size_t> &blocks);

  bool has_enough_memory(std::size_t capacity) const;
};
