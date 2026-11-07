#include <gtest/gtest.h>

#include <block.hpp>
#include <block_device.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <set>
#include <vector>

namespace {

constexpr std::size_t kUsablePerBlock = block_payload_size - block_tag_size;

using Nonce = std::array<unsigned char, block_nonce_size>;

Nonce make_nonce(unsigned char fill = 0x5A) {
  Nonce nonce{};
  nonce.fill(fill);
  return nonce;
}

class BlockDeviceTest : public ::testing::Test {
protected:
  static constexpr std::size_t kBlocks = 8;
  static constexpr std::size_t kDeviceCapacity = kBlocks * block_size;
  static constexpr std::size_t kUsableCapacity = kBlocks * kUsablePerBlock;
  BlockDevice device_{kDeviceCapacity};
};

TEST_F(BlockDeviceTest, AllocateZeroBytesReturnsEmpty) {
  auto result = device_.allocate(0, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->empty());
}

TEST_F(BlockDeviceTest, AllocateOneByteUsesOneBlock) {
  auto result = device_.allocate(1, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 1u);
}

TEST_F(BlockDeviceTest, AllocateExactlyUsablePerBlockUsesOneBlock) {
  auto result = device_.allocate(kUsablePerBlock, 1);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), 1u);
  EXPECT_LT(result->front(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateUsablePerBlockPlusOneUsesTwoBlocks) {
  auto result = device_.allocate(kUsablePerBlock + 1, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 2u);
}

TEST_F(BlockDeviceTest, AllocateReturnsUniqueIndicesInRange) {
  auto result = device_.allocate(kUsableCapacity, 1);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), kBlocks);
  const std::set<std::size_t> unique(result->begin(), result->end());
  EXPECT_EQ(unique.size(), kBlocks);
  EXPECT_EQ(*unique.begin(), 0u);
  EXPECT_LT(*unique.rbegin(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateExactlyUsableCapacitySucceeds) {
  auto result = device_.allocate(kUsableCapacity, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateBeyondUsableCapacityFails) {
  auto result = device_.allocate(kUsableCapacity + 1, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::NoEnoughMemory);
}

TEST_F(BlockDeviceTest, AllocateWhenFullFails) {
  ASSERT_TRUE(device_.allocate(kUsableCapacity, 1).has_value());

  auto result = device_.allocate(1, 2);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::NoEnoughMemory);
}

TEST_F(BlockDeviceTest, ConstructorUsesPhysicalBlockSize) {
  BlockDevice one_block(block_size);

  EXPECT_TRUE(one_block.has_enough_memory(kUsablePerBlock));
  EXPECT_FALSE(one_block.has_enough_memory(kUsablePerBlock + 1));

  BlockDevice probe(block_size);
  EXPECT_FALSE(probe.allocate(kUsablePerBlock + 1, 1).has_value());
}

TEST_F(BlockDeviceTest, ConstructorRoundsCapacityUpToWholeBlocks) {
  BlockDevice two_blocks(block_size + 1);

  EXPECT_TRUE(two_blocks.has_enough_memory(2 * kUsablePerBlock));
  EXPECT_FALSE(two_blocks.has_enough_memory(2 * kUsablePerBlock + 1));

  auto result = two_blocks.allocate(2 * kUsablePerBlock, 1);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 2u);
}

TEST_F(BlockDeviceTest, ZeroCapacityDeviceCannotAllocateBlocks) {
  BlockDevice empty(0);

  EXPECT_FALSE(empty.has_enough_memory(1));
  EXPECT_FALSE(empty.allocate(1, 1).has_value());

  auto zero = empty.allocate(0, 1);
  ASSERT_TRUE(zero.has_value());
  EXPECT_TRUE(zero->empty());
}

TEST_F(BlockDeviceTest, RemoveFileFreesItsBlocks) {
  ASSERT_TRUE(device_.allocate(kUsableCapacity, 42).has_value());

  ASSERT_TRUE(device_.remove_file(42).has_value());

  auto again = device_.allocate(kUsableCapacity, 43);
  EXPECT_TRUE(again.has_value());
}

TEST_F(BlockDeviceTest, RemoveUnknownFileIsNoop) {
  EXPECT_TRUE(device_.remove_file(12345).has_value());
}

TEST_F(BlockDeviceTest, RemoveZeroIsNoop) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 5).has_value());

  EXPECT_TRUE(device_.remove_file(0).has_value());

  auto result = device_.allocate(kUsableCapacity, 6);
  EXPECT_FALSE(result.has_value());
}

TEST_F(BlockDeviceTest, RemoveFileIsIdempotent) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 9).has_value());
  ASSERT_TRUE(device_.remove_file(9).has_value());

  EXPECT_TRUE(device_.remove_file(9).has_value());
  EXPECT_TRUE(device_.allocate(kUsableCapacity, 10).has_value());
}

TEST_F(BlockDeviceTest, WriteWithSmallerPayloadSizeFails) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size - 1, 0xAB);
  auto result = device_.write_file_block(payload, make_nonce(), 7, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::InvalidBlockSize);
}

TEST_F(BlockDeviceTest, WriteWithLargerPayloadSizeFails) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size + 1, 0xAB);
  auto result = device_.write_file_block(payload, make_nonce(), 7, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::InvalidBlockSize);
}

TEST_F(BlockDeviceTest, WriteWithCorrectPayloadSizeSucceeds) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, make_nonce(), 7, 1);

  EXPECT_TRUE(result.has_value());
}

TEST_F(BlockDeviceTest, WriteToUnknownFileFails) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, make_nonce(), 8, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::BlockNotFound);
}

TEST_F(BlockDeviceTest, WriteToUnknownLogicalIndexFails) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, make_nonce(), 7, 2);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::BlockNotFound);
}

TEST_F(BlockDeviceTest, HasEnoughMemoryUsesUsableBytes) {
  EXPECT_TRUE(device_.has_enough_memory(kUsableCapacity));
  EXPECT_FALSE(device_.has_enough_memory(kUsableCapacity + 1));
}

TEST_F(BlockDeviceTest, HasEnoughMemoryAfterFullAllocationIsFalse) {
  ASSERT_TRUE(device_.allocate(kUsableCapacity, 1).has_value());

  EXPECT_FALSE(device_.has_enough_memory(1));
}

TEST_F(BlockDeviceTest, WriteWithWrongNonceSizeFails) {
  ASSERT_TRUE(device_.allocate(kUsablePerBlock, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  std::vector<unsigned char> nonce(block_nonce_size - 1, 0x01);
  auto result = device_.write_file_block(payload, nonce, 7, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::InvalidNonceSize);
}

TEST_F(BlockDeviceTest, WriteStoresNonce) {
  auto blocks = device_.allocate(kUsablePerBlock, 7);
  ASSERT_TRUE(blocks.has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  const auto nonce = make_nonce(0x3C);
  ASSERT_TRUE(device_.write_file_block(payload, nonce, 7, 1).has_value());

  const auto &block = device_.block_at(blocks->front());
  EXPECT_EQ(block.nonce, nonce);
}

TEST_F(BlockDeviceTest, BlockAtMatchesAllocatedBlock) {
  auto blocks = device_.allocate(kUsablePerBlock, 7);
  ASSERT_TRUE(blocks.has_value());

  const auto &block = device_.block_at(blocks->front());
  EXPECT_EQ(block.physical_index, blocks->front());
  EXPECT_EQ(block.logical_index, 1u);
  EXPECT_EQ(block.file_id, 7u);
}

TEST_F(BlockDeviceTest, BlockCountMatchesCapacity) {
  EXPECT_EQ(device_.block_count(), kBlocks);
}

TEST_F(BlockDeviceTest, RestoreFileBlockPopulatesBlock) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size, 0x11);
  const auto nonce = make_nonce(0x22);

  auto restored = device.restore_file_block(3, 1, 99, nonce, payload);

  ASSERT_TRUE(restored.has_value());
  const auto &block = device.block_at(3);
  EXPECT_EQ(block.physical_index, 3u);
  EXPECT_EQ(block.logical_index, 1u);
  EXPECT_EQ(block.file_id, 99u);
  EXPECT_EQ(block.nonce, nonce);
  EXPECT_TRUE(std::equal(block.payload.begin(), block.payload.end(),
                         payload.begin()));
}

TEST_F(BlockDeviceTest, RestoreRejectsOutOfRangeIndex) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size, 0x11);

  auto restored =
      device.restore_file_block(kBlocks, 1, 99, make_nonce(), payload);

  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.error(), BlockDeviceError::BlockNotFound);
}

TEST_F(BlockDeviceTest, RestoreRejectsAlreadyAllocatedIndex) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size, 0x11);

  ASSERT_TRUE(device.restore_file_block(2, 1, 99, make_nonce(), payload)
                  .has_value());

  auto restored = device.restore_file_block(2, 1, 100, make_nonce(), payload);

  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.error(), BlockDeviceError::BlockAlreadyAllocated);
}

TEST_F(BlockDeviceTest, RestoreRejectsWrongNonceSize) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size, 0x11);
  std::vector<unsigned char> nonce(block_nonce_size - 1, 0x01);

  auto restored = device.restore_file_block(2, 1, 99, nonce, payload);

  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.error(), BlockDeviceError::InvalidNonceSize);
}

TEST_F(BlockDeviceTest, RestoreRejectsWrongPayloadSize) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size - 1, 0x11);

  auto restored = device.restore_file_block(2, 1, 99, make_nonce(), payload);

  ASSERT_FALSE(restored.has_value());
  EXPECT_EQ(restored.error(), BlockDeviceError::InvalidBlockSize);
}

TEST_F(BlockDeviceTest, RestoredBlocksAreNoLongerFree) {
  BlockDevice device(kDeviceCapacity);
  std::vector<unsigned char> payload(block_payload_size, 0x11);

  for (std::size_t i = 0; i < kBlocks; ++i) {
    ASSERT_TRUE(device.restore_file_block(i, i + 1, 1, make_nonce(), payload)
                    .has_value());
  }

  EXPECT_FALSE(device.has_enough_memory(1));
  EXPECT_FALSE(device.allocate(1, 2).has_value());
}

TEST_F(BlockDeviceTest, HasEnoughMemoryMatchesAllocateAtBoundaries) {
  const std::vector<std::size_t> sizes{
      0,
      1,
      kUsablePerBlock,
      kUsablePerBlock + 1,
      kUsableCapacity - 1,
      kUsableCapacity,
      kUsableCapacity + 1,
  };

  for (const auto size : sizes) {
    BlockDevice probe(kDeviceCapacity);
    const bool can_allocate = probe.allocate(size, 1).has_value();

    BlockDevice query(kDeviceCapacity);
    EXPECT_EQ(query.has_enough_memory(size), can_allocate) << "size = " << size;
  }
}

} // namespace
