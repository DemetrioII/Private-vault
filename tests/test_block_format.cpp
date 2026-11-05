#include <gtest/gtest.h>

#include <block.hpp>

#include <cstddef>
#include <type_traits>

static_assert(std::is_standard_layout_v<Block>);
static_assert(sizeof(Block) == block_size);

TEST(BlockFormatTest, ConstantsMatchLibsodium) {
  EXPECT_EQ(block_nonce_size, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  EXPECT_EQ(block_tag_size, crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

TEST(BlockFormatTest, PayloadAccountsForHeaderAndNonce) {
  EXPECT_EQ(block_payload_size,
            block_size - 3 * sizeof(std::size_t) - block_nonce_size);
  EXPECT_GT(block_payload_size, block_tag_size);
}

TEST(BlockFormatTest, FieldsArePackedInExpectedOrder) {
  EXPECT_EQ(offsetof(Block, physical_index), 0u);
  EXPECT_EQ(offsetof(Block, logical_index), sizeof(std::size_t));
  EXPECT_EQ(offsetof(Block, file_id), 2 * sizeof(std::size_t));
  EXPECT_EQ(offsetof(Block, nonce), 3 * sizeof(std::size_t));
  EXPECT_EQ(offsetof(Block, payload),
            3 * sizeof(std::size_t) + block_nonce_size);
}

TEST(BlockFormatTest, ArraysHaveExpectedSizes) {
  const Block block{};

  EXPECT_EQ(block.nonce.size(), block_nonce_size);
  EXPECT_EQ(block.payload.size(), block_payload_size);
}

TEST(BlockFormatTest, ValueInitializedBlockIsZeroed) {
  const Block block{};

  EXPECT_EQ(block.physical_index, 0u);
  EXPECT_EQ(block.logical_index, 0u);
  EXPECT_EQ(block.file_id, 0u);
  for (const auto byte : block.nonce) {
    EXPECT_EQ(byte, 0u);
  }
  for (const auto byte : block.payload) {
    EXPECT_EQ(byte, 0u);
  }
}
