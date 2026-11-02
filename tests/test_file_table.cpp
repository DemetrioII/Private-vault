#include <gtest/gtest.h>

#include <file_table.hpp>

#include <unordered_set>
#include <vector>

namespace {

FileEntry make_entry(std::size_t size, std::vector<std::size_t> blocks) {
  return FileEntry{size, std::move(blocks)};
}

TEST(FileTableTest, GenerateIdNeverReturnsZero) {
  FileTable table;

  for (int i = 0; i < 1000; ++i) {
    EXPECT_NE(file_table::generate_id(table), 0u);
  }
}

TEST(FileTableTest, GenerateIdDoesNotModifyTable) {
  FileTable table;
  const auto size_before = table.file_table.size();

  (void)file_table::generate_id(table);

  EXPECT_EQ(table.file_table.size(), size_before);
}

TEST(FileTableTest, GenerateIdIsUniqueForEveryStoredId) {
  FileTable table;
  std::unordered_set<std::size_t> ids;

  for (int i = 0; i < 1000; ++i) {
    const auto id = file_table::generate_id(table);
    ASSERT_TRUE(ids.insert(id).second);
    file_table::add_file(table, id, make_entry(static_cast<std::size_t>(i), {}));
  }

  EXPECT_EQ(table.file_table.size(), ids.size());
}

TEST(FileTableTest, GenerateIdSkipsExistingIds) {
  FileTable table;
  for (std::size_t id = 1; id <= 1000; ++id) {
    file_table::add_file(table, id, make_entry(id, {}));
  }

  for (int i = 0; i < 1000; ++i) {
    const auto id = file_table::generate_id(table);
    EXPECT_EQ(table.file_table.count(id), 0u);
  }
}

TEST(FileTableTest, AddFileStoresEntryUnderGivenId) {
  FileTable table;
  const auto id = file_table::generate_id(table);

  file_table::add_file(table, id, make_entry(10, {0, 1}));

  ASSERT_EQ(table.file_table.size(), 1u);
  const auto it = table.file_table.find(id);
  ASSERT_NE(it, table.file_table.end());
  EXPECT_EQ(it->second.file_size, 10u);
  EXPECT_EQ(it->second.blocks, (std::vector<std::size_t>{0, 1}));
}

TEST(FileTableTest, AddMultipleFilesStoresAllOfThem) {
  FileTable table;

  const auto first = file_table::generate_id(table);
  file_table::add_file(table, first, make_entry(1, {0}));
  const auto second = file_table::generate_id(table);
  file_table::add_file(table, second, make_entry(2, {1}));

  EXPECT_NE(first, second);
  EXPECT_EQ(table.file_table.size(), 2u);
  EXPECT_EQ(table.file_table.at(first).file_size, 1u);
  EXPECT_EQ(table.file_table.at(second).file_size, 2u);
}

TEST(FileTableTest, RemoveFileDeletesEntry) {
  FileTable table;
  const auto id = file_table::generate_id(table);
  file_table::add_file(table, id, make_entry(1, {0}));

  file_table::remove_file(table, id);

  EXPECT_EQ(table.file_table.size(), 0u);
  EXPECT_EQ(table.file_table.count(id), 0u);
}

TEST(FileTableTest, RemoveNonexistentFileIsNoop) {
  FileTable table;
  const auto id = file_table::generate_id(table);
  file_table::add_file(table, id, make_entry(1, {0}));

  file_table::remove_file(table, id + 1);

  EXPECT_EQ(table.file_table.size(), 1u);
  EXPECT_EQ(table.file_table.count(id), 1u);
}

TEST(FileTableTest, RemoveFirstFileKeepsRemainingAndNewIdDoesNotCollide) {
  FileTable table;
  const auto first = file_table::generate_id(table);
  file_table::add_file(table, first, make_entry(1, {0}));
  const auto second = file_table::generate_id(table);
  file_table::add_file(table, second, make_entry(2, {1}));

  file_table::remove_file(table, first);
  const auto third = file_table::generate_id(table);

  EXPECT_EQ(table.file_table.size(), 1u);
  EXPECT_EQ(table.file_table.count(first), 0u);
  ASSERT_EQ(table.file_table.count(second), 1u);
  EXPECT_EQ(table.file_table.at(second).file_size, 2u);
  EXPECT_EQ(table.file_table.count(third), 0u);
  EXPECT_NE(third, second);
}

} // namespace
