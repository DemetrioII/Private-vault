#include <file_table.hpp>

#include <limits>
#include <random>
#include <utility>

namespace file_table {
namespace {

std::mt19937_64 &random_engine() {
  thread_local std::mt19937_64 engine = [] {
    std::random_device device;
    std::seed_seq seed{device(), device(), device(), device()};
    return std::mt19937_64(seed);
  }();
  return engine;
}

} // namespace

std::size_t generate_id(FileTable &table) {
  std::uniform_int_distribution<std::size_t> distribution(
      1, std::numeric_limits<std::size_t>::max());

  std::size_t id = 0;
  do {
    id = distribution(random_engine());
  } while (table.file_table.contains(id));

  return id;
}

void add_file(FileTable &table, std::size_t file_id, FileEntry &&entry) {
  table.file_table[file_id] = std::move(entry);
}

void remove_file(FileTable &table, std::size_t index) {
  table.file_table.erase(index);
}
} // namespace file_table
