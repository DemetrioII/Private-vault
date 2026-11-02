#include <gtest/gtest.h>

#include <block.hpp>
#include <block_device.hpp>

#include <set>
#include <vector>

namespace {

class BlockDeviceTest : public ::testing::Test {
protected:
  static constexpr std::size_t kBlocks = 8;
  static constexpr std::size_t kPhysicalCapacity = kBlocks * block_size;
  static constexpr std::size_t kPayloadCapacity = kBlocks * block_payload_size;
  BlockDevice device_{kPhysicalCapacity};
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

TEST_F(BlockDeviceTest, AllocateOnePayloadUsesOneBlock) {
  auto result = device_.allocate(block_payload_size, 1);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), 1u);
  EXPECT_LT(result->front(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateRoundsUpToWholeBlocks) {
  auto result = device_.allocate(block_payload_size + 1, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), 2u);
}

TEST_F(BlockDeviceTest, AllocateReturnsUniqueIndicesInRange) {
  auto result = device_.allocate(kPayloadCapacity, 1);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), kBlocks);
  const std::set<std::size_t> unique(result->begin(), result->end());
  EXPECT_EQ(unique.size(), kBlocks);
  EXPECT_EQ(*unique.begin(), 0u);
  EXPECT_LT(*unique.rbegin(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateExactlyCapacitySucceeds) {
  auto result = device_.allocate(kPayloadCapacity, 1);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), kBlocks);
}

TEST_F(BlockDeviceTest, AllocateBeyondCapacityFails) {
  auto result = device_.allocate(kPayloadCapacity + 1, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::NoEnoughMemory);
}

TEST_F(BlockDeviceTest, AllocateWhenFullFails) {
  ASSERT_TRUE(device_.allocate(kPayloadCapacity, 1).has_value());

  auto result = device_.allocate(1, 2);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::NoEnoughMemory);
}

TEST_F(BlockDeviceTest, RemoveFileFreesItsBlocks) {
  ASSERT_TRUE(device_.allocate(kPayloadCapacity, 42).has_value());

  ASSERT_TRUE(device_.remove_file(42).has_value());

  auto again = device_.allocate(kPayloadCapacity, 43);
  EXPECT_TRUE(again.has_value());
}

TEST_F(BlockDeviceTest, RemoveUnknownFileIsNoop) {
  EXPECT_TRUE(device_.remove_file(12345).has_value());
}

TEST_F(BlockDeviceTest, RemoveZeroIsNoop) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 5).has_value());

  EXPECT_TRUE(device_.remove_file(0).has_value());

  auto result = device_.allocate(kPayloadCapacity, 6);
  EXPECT_FALSE(result.has_value());
}

TEST_F(BlockDeviceTest, RemoveFileIsIdempotent) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 9).has_value());
  ASSERT_TRUE(device_.remove_file(9).has_value());

  EXPECT_TRUE(device_.remove_file(9).has_value());
  EXPECT_TRUE(device_.allocate(kPayloadCapacity, 10).has_value());
}

TEST_F(BlockDeviceTest, WriteWithSmallerPayloadSizeFails) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size - 1, 0xAB);
  auto result = device_.write_file_block(payload, 7, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::InvalidBlockSize);
}

TEST_F(BlockDeviceTest, WriteWithLargerPayloadSizeFails) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size + 1, 0xAB);
  auto result = device_.write_file_block(payload, 7, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::InvalidBlockSize);
}

TEST_F(BlockDeviceTest, WriteWithCorrectPayloadSizeSucceeds) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, 7, 1);

  EXPECT_TRUE(result.has_value());
}

TEST_F(BlockDeviceTest, WriteToUnknownFileFails) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, 8, 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::BlockNotFound);
}

TEST_F(BlockDeviceTest, WriteToUnknownLogicalIndexFails) {
  ASSERT_TRUE(device_.allocate(block_payload_size, 7).has_value());

  std::vector<unsigned char> payload(block_payload_size, 0xCD);
  auto result = device_.write_file_block(payload, 7, 2);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockDeviceError::BlockNotFound);
}

TEST_F(BlockDeviceTest, HasEnoughMemoryUsesPayloadBytes) {
  EXPECT_TRUE(device_.has_enough_memory(kPayloadCapacity));
  EXPECT_FALSE(device_.has_enough_memory(kPayloadCapacity + 1));
}

TEST_F(BlockDeviceTest, HasEnoughMemoryAfterFullAllocationIsFalse) {
  ASSERT_TRUE(device_.allocate(kPayloadCapacity, 1).has_value());

  EXPECT_FALSE(device_.has_enough_memory(1));
}

} // namespace
