#pragma once
#include <block.hpp>
#include <block_allocator.hpp>
#include <cstring>
#include <expected>
#include <span>
#include <vector>

enum class BlockDeviceError {
  NoEnoughMemory,
  FreeError,
  InvalidBlockSize,
  InvalidNonceSize,
  BlockNotFound,
  BlockAlreadyAllocated
};

// Block Device doesn't owns files, it owns only blocks of bytes, meanwhile
// FileTable owns files
class BlockDevice {
  std::size_t capacity_; // in bytes
  std::vector<Block> blocks_;
  BlockAllocator allocator_;

public:
  explicit BlockDevice(std::size_t capacity);

  std::expected<std::vector<std::size_t>, BlockDeviceError>
  allocate(std::size_t file_size,
           std::size_t file_id); // bytes of our file we want to add

  std::expected<void, BlockDeviceError>
  write_file_block(std::span<unsigned char> file_block,
                   std::span<unsigned char const> nonce, std::size_t file_id,
                   std::size_t index);

  std::expected<void, BlockDeviceError>
  restore_file_block(std::size_t physical_index, std::size_t logical_index,
                     std::size_t file_id,
                     std::span<unsigned char const> nonce,
                     std::span<unsigned char const> payload);

  std::expected<void, BlockDeviceError> remove_file(std::size_t id);

  const Block &block_at(std::size_t physical_index) const;

  std::size_t block_count() const;

  bool has_enough_memory(std::size_t capacity);
};
