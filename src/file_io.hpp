#pragma once
#include <cstddef>
#include <expected>
#include <span>

struct FileEntry;

enum class FileEntryError {

};

class FileIO {
  int fd_{-1};
  FileEntry &file_entry_;

public:
  FileIO(int fd, FileEntry &file_entry);

  // это на будущее, пока что не трогаем
  std::expected<unsigned char, FileEntryError>
  read(std::size_t offset, std::span<unsigned char> out);

  std::expected<unsigned char, FileEntryError>
  write(std::size_t offset, std::span<unsigned char> in);

  ~FileIO();
};
