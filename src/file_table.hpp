#pragma once

#include <block.hpp>
#include <cstddef>
#include <memory>
#include <unordered_map>
#include <vector>

struct FileEntry {
  std::size_t file_size;           // in bytes
  std::vector<std::size_t> blocks; // array of block indexes
};

struct FileTable {
  std::unordered_map<std::size_t, FileEntry> file_table;
};

namespace file_table {
void add_file(FileTable &table, std::size_t file_id,
              FileEntry &&entry); // returns file_id of new file

void remove_file(FileTable &table, std::size_t index);

std::size_t generate_id(FileTable &table);
} // namespace file_table
