#include <block_device.hpp>

BlockDevice::BlockDevice(std::size_t capacity)
    : capacity_(capacity), allocator_((capacity + block_size - 1) / block_size) {
  blocks_.resize((capacity + block_size - 1) / block_size);
  for (size_t i = 0; i < blocks_.size(); ++i) {
    blocks_.at(i).physical_index = i;
  }
}

std::expected<std::vector<std::size_t>, BlockDeviceError> BlockDevice::allocate(std::size_t file_size,
                                                                                std::size_t file_id) {
  std::size_t blocks_to_need =
      (file_size + block_payload_size - block_tag_size - 1) / (block_payload_size - block_tag_size);
  const auto block_idxs = allocator_.allocate(blocks_to_need);
  if (!block_idxs.has_value()) {
    return std::unexpected(BlockDeviceError::NoEnoughMemory);
  }

  int k = 0;
  std::size_t offset = 0;

  for (const auto &idx : *block_idxs) {
    blocks_.at(idx).physical_index = idx;
    blocks_.at(idx).logical_index = ++k; // 0 means the block is free
    blocks_.at(idx).file_id = file_id;
    /*
std::memcpy(blocks_[idx].payload.data(), file.data() + offset,
            std::min(block_size, file.size() - offset));
offset += std::min(block_size, file.size() - offset); */
  }

  return *block_idxs;
}

std::expected<void, BlockDeviceError> BlockDevice::remove_file(std::size_t index) {
  if (index == 0)
    return {};
  std::vector<std::size_t> blocks_to_free;
  for (std::size_t i = 0; i < blocks_.size(); ++i) {
    if (blocks_.at(i).file_id == index) {
      blocks_.at(i).file_id = 0;
      blocks_.at(i).logical_index = 0;
      blocks_.at(i).payload.fill(0);
      blocks_to_free.push_back(i);
    }
  }

  auto res = allocator_.release(blocks_to_free);
  if (!res.has_value()) {
    return std::unexpected(BlockDeviceError::FreeError);
  }

  return {};
}

std::expected<void, BlockDeviceError> BlockDevice::write_file_block(std::span<unsigned char> file_block,
                                                                    std::size_t file_id, std::size_t index) {
  if (file_block.size() != block_payload_size) {
    return std::unexpected(BlockDeviceError::InvalidBlockSize);
  }

  for (std::size_t i = 0; i < blocks_.size(); ++i) {
    if (blocks_.at(i).file_id == file_id && blocks_.at(i).logical_index == index) {
      std::memcpy(blocks_.at(i).payload.data(), file_block.data(), file_block.size());
      return {};
    }
  }

  return std::unexpected(BlockDeviceError::BlockNotFound);
}

bool BlockDevice::has_enough_memory(std::size_t capacity) { return allocator_.has_enough_memory(capacity); }
