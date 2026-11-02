#include <gtest/gtest.h>

#include <block.hpp>
#include <block_allocator.hpp>

#include <set>
#include <vector>

namespace {

std::set<std::size_t> to_set(const std::vector<std::size_t> &values) {
  return std::set<std::size_t>(values.begin(), values.end());
}

class BlockAllocatorTest : public ::testing::Test {
protected:
  static constexpr std::size_t kCapacity = 8;
  BlockAllocator allocator_{kCapacity};
};

TEST_F(BlockAllocatorTest, AllocateZeroReturnsEmpty) {
  auto result = allocator_.allocate(0);

  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->empty());
}

TEST_F(BlockAllocatorTest, AllocateReturnsUniqueIndicesInRange) {
  auto result = allocator_.allocate(5);

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result->size(), 5u);
  EXPECT_EQ(to_set(*result).size(), 5u);
  for (const auto index : *result) {
    EXPECT_LT(index, kCapacity);
  }
}

TEST_F(BlockAllocatorTest, AllocateExactlyCapacitySucceeds) {
  auto result = allocator_.allocate(kCapacity);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->size(), kCapacity);
  EXPECT_EQ(to_set(*result).size(), kCapacity);
}

TEST_F(BlockAllocatorTest, AllocateMoreThanCapacityFails) {
  auto result = allocator_.allocate(kCapacity + 1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::NoEnoughMemory);
}

TEST_F(BlockAllocatorTest, AllocateWhenFullFails) {
  ASSERT_TRUE(allocator_.allocate(kCapacity).has_value());

  auto result = allocator_.allocate(1);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::NoEnoughMemory);
}

TEST_F(BlockAllocatorTest, ReleaseMakesBlocksReusable) {
  auto first = allocator_.allocate(3);
  ASSERT_TRUE(first.has_value());

  ASSERT_TRUE(allocator_.release(*first).has_value());

  auto second = allocator_.allocate(3);
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(to_set(*second), to_set(*first));
}

TEST_F(BlockAllocatorTest, ReleaseUnallocatedBlockFails) {
  auto result = allocator_.release({0});

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::ReleaseError);
}

TEST_F(BlockAllocatorTest, ReleaseOutOfRangeBlockFails) {
  auto result = allocator_.release({kCapacity});

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::ReleaseError);
}

TEST_F(BlockAllocatorTest, DoubleReleaseFails) {
  auto allocated = allocator_.allocate(1);
  ASSERT_TRUE(allocated.has_value());
  ASSERT_TRUE(allocator_.release(*allocated).has_value());

  auto result = allocator_.release(*allocated);

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::ReleaseError);
}

TEST_F(BlockAllocatorTest, ReleaseDuplicateIndicesFails) {
  auto allocated = allocator_.allocate(1);
  ASSERT_TRUE(allocated.has_value());

  const std::size_t index = allocated->front();
  auto result = allocator_.release({index, index});

  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), BlockAllocatorError::DuplicateIndices);
}

TEST_F(BlockAllocatorTest, HasEnoughMemoryUsesPayloadBytes) {
  EXPECT_TRUE(allocator_.has_enough_memory(kCapacity * block_payload_size));
  EXPECT_FALSE(allocator_.has_enough_memory(kCapacity * block_payload_size + 1));
}

TEST_F(BlockAllocatorTest, HasEnoughMemoryTracksPartialRelease) {
  ASSERT_TRUE(allocator_.allocate(4).has_value());
  auto allocated = allocator_.allocate(2);
  ASSERT_TRUE(allocated.has_value());
  ASSERT_TRUE(allocator_.release(*allocated).has_value());

  EXPECT_TRUE(allocator_.has_enough_memory(4 * block_payload_size));
  EXPECT_FALSE(allocator_.has_enough_memory(5 * block_payload_size));
}

TEST_F(BlockAllocatorTest, HasEnoughMemoryAfterFullAllocationIsFalse) {
  ASSERT_TRUE(allocator_.allocate(kCapacity).has_value());

  EXPECT_FALSE(allocator_.has_enough_memory(1));
}

TEST(BlockAllocatorCapacityTest, NonMultipleOfEightIsExact) {
  BlockAllocator allocator(5);

  auto all = allocator.allocate(5);
  ASSERT_TRUE(all.has_value());

  auto extra = allocator.allocate(1);
  EXPECT_FALSE(extra.has_value());
  if (!extra.has_value()) {
    EXPECT_EQ(extra.error(), BlockAllocatorError::NoEnoughMemory);
  }
}

} // namespace
