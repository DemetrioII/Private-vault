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

  std::size_t offset = 0, k = 0;

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
      blocks_.at(i).nonce.fill(0);
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

std::expected<void, BlockDeviceError>
BlockDevice::write_file_block(std::span<unsigned char> file_block,
                              std::span<unsigned char const> nonce,
                              std::size_t file_id, std::size_t index) {
  if (file_block.size() != block_payload_size) {
    return std::unexpected(BlockDeviceError::InvalidBlockSize);
  }

  if (nonce.size() != block_nonce_size) {
    return std::unexpected(BlockDeviceError::InvalidNonceSize);
  }

  for (std::size_t i = 0; i < blocks_.size(); ++i) {
    if (blocks_.at(i).file_id == file_id && blocks_.at(i).logical_index == index) {
      std::memcpy(blocks_.at(i).nonce.data(), nonce.data(), nonce.size());
      std::memcpy(blocks_.at(i).payload.data(), file_block.data(), file_block.size());
      return {};
    }
  }

  return std::unexpected(BlockDeviceError::BlockNotFound);
}

std::expected<void, BlockDeviceError> BlockDevice::restore_file_block(
    std::size_t physical_index, std::size_t logical_index, std::size_t file_id,
    std::span<unsigned char const> nonce,
    std::span<unsigned char const> payload) {
  if (physical_index >= blocks_.size()) {
    return std::unexpected(BlockDeviceError::BlockNotFound);
  }

  if (payload.size() != block_payload_size) {
    return std::unexpected(BlockDeviceError::InvalidBlockSize);
  }

  if (nonce.size() != block_nonce_size) {
    return std::unexpected(BlockDeviceError::InvalidNonceSize);
  }

  auto reserved = allocator_.reserve(physical_index);
  if (!reserved) {
    return std::unexpected(BlockDeviceError::BlockAlreadyAllocated);
  }

  Block &block = blocks_.at(physical_index);
  block.physical_index = physical_index;
  block.logical_index = logical_index;
  block.file_id = file_id;
  std::memcpy(block.nonce.data(), nonce.data(), nonce.size());
  std::memcpy(block.payload.data(), payload.data(), payload.size());

  return {};
}

const Block &BlockDevice::block_at(std::size_t physical_index) const {
  return blocks_.at(physical_index);
}

std::size_t BlockDevice::block_count() const { return blocks_.size(); }

bool BlockDevice::has_enough_memory(std::size_t capacity) { return allocator_.has_enough_memory(capacity); }
