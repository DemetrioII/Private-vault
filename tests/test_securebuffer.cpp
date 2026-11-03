#include <gtest/gtest.h>

#include <securebuffer.hpp>

#include <cstddef>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

static_assert(!std::is_copy_constructible_v<SecureBuffer>);
static_assert(!std::is_copy_assignable_v<SecureBuffer>);
static_assert(std::is_move_constructible_v<SecureBuffer>);
static_assert(std::is_move_assignable_v<SecureBuffer>);

namespace {

void expect_all_bytes(const SecureBuffer &buffer, unsigned char expected) {
  for (std::size_t i = 0; i < buffer.size(); ++i) {
    EXPECT_EQ(buffer.data()[i], expected) << "at index " << i;
  }
}

void expect_prefix(const SecureBuffer &buffer, const std::string &expected) {
  for (std::size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(buffer.data()[i], static_cast<unsigned char>(expected[i])) << "at index " << i;
  }
}

void expect_zero_from(const SecureBuffer &buffer, std::size_t offset) {
  for (std::size_t i = offset; i < buffer.size(); ++i) {
    EXPECT_EQ(buffer.data()[i], 0u) << "at index " << i;
  }
}

} // namespace

TEST(SecureBufferTest, ConstructorFillsWithGivenByte) {
  SecureBuffer buffer(8, 0xAB);

  EXPECT_EQ(buffer.size(), 8u);
  EXPECT_EQ(buffer.span().size(), 8u);
  EXPECT_EQ(buffer.span().data(), buffer.data());
  expect_all_bytes(buffer, 0xAB);
}

TEST(SecureBufferTest, ConstructorZeroFillsByDefault) {
  SecureBuffer buffer(16);

  EXPECT_EQ(buffer.size(), 16u);
  expect_all_bytes(buffer, 0u);
}

TEST(SecureBufferTest, MoveConstructorTransfersOwnership) {
  SecureBuffer source(8, 0x5A);
  const auto *original_data = source.data();

  SecureBuffer moved(std::move(source));

  EXPECT_EQ(moved.size(), 8u);
  EXPECT_EQ(moved.data(), original_data);
  expect_all_bytes(moved, 0x5A);
  EXPECT_EQ(source.size(), 0u);
  EXPECT_EQ(source.data(), nullptr);
}

TEST(SecureBufferTest, MoveAssignmentTransfersOwnership) {
  SecureBuffer source(8, 0x6B);
  const auto *original_data = source.data();
  SecureBuffer target(4, 0xFF);

  target = std::move(source);

  EXPECT_EQ(target.size(), 8u);
  EXPECT_EQ(target.data(), original_data);
  expect_all_bytes(target, 0x6B);
  EXPECT_EQ(source.size(), 0u);
  EXPECT_EQ(source.data(), nullptr);
}

TEST(SecureBufferTest, ReadsWholeLineIncludingSpaces) {
  SecureBuffer buffer(16, 0xCC);
  std::istringstream input("hunter two\n");

  input >> buffer;

  EXPECT_FALSE(input.fail());
  expect_prefix(buffer, "hunter two");
  expect_zero_from(buffer, 10);
}

TEST(SecureBufferTest, ReadStopsAtNewline) {
  SecureBuffer buffer(16);
  std::istringstream input("abc\ndef");

  input >> buffer;

  expect_prefix(buffer, "abc");
  expect_zero_from(buffer, 3);
  EXPECT_EQ(input.get(), 'd');
}

TEST(SecureBufferTest, ReadTruncatesToCapacityAndConsumesLine) {
  SecureBuffer buffer(3);
  std::istringstream input("abcdef\n");

  input >> buffer;

  expect_prefix(buffer, "abc");
  EXPECT_EQ(input.get(), std::char_traits<char>::eof());
}

TEST(SecureBufferTest, ReadZeroesTailOfShorterInput) {
  SecureBuffer buffer(8, 0x58);
  std::istringstream input("ab\n");

  input >> buffer;

  expect_prefix(buffer, "ab");
  expect_zero_from(buffer, 2);
}

TEST(SecureBufferTest, ReadHandlesCrLf) {
  SecureBuffer buffer(8, 0x59);
  std::istringstream input("secret\r\n");

  input >> buffer;

  expect_prefix(buffer, "secret");
  expect_zero_from(buffer, 6);
}

TEST(SecureBufferTest, ReadEmptyLineLeavesBufferZeroed) {
  SecureBuffer buffer(4, 0x5A);
  std::istringstream input("\n");

  input >> buffer;

  EXPECT_FALSE(input.fail());
  expect_all_bytes(buffer, 0u);
}

TEST(SecureBufferTest, ReadFromEmptyStreamSetsFailbit) {
  SecureBuffer buffer(4, 0x5B);
  std::istringstream input;

  input >> buffer;

  EXPECT_TRUE(input.fail());
  expect_all_bytes(buffer, 0u);
}

TEST(SecureBufferTest, ReadKeepsLeadingSpaces) {
  SecureBuffer buffer(8);
  std::istringstream input("  x\n");

  input >> buffer;

  expect_prefix(buffer, "  x");
  expect_zero_from(buffer, 3);
}
