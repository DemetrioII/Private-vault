module;

#include <cstddef>
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <sys/stat.h>
#include <unistd.h>

export module core.io;

import core.error;
import core.result;

export namespace core::io {
enum class OpenMode { ReadOnly, ReadWrite, CreateReadWrite, CreateExclusive };

class FileIO {
public:
  FileIO() noexcept : fd_{-1} {}
  ~FileIO() noexcept;

  FileIO(const FileIO &) = delete;
  FileIO &operator=(const FileIO &) = delete;

  FileIO(FileIO &&other) noexcept;
  FileIO &operator=(FileIO &&other) noexcept;

  static core::Result<FileIO> open(const std::filesystem::path &path,
                                   OpenMode mode = OpenMode::ReadWrite);

  core::Result<void> read_at(std::uint64_t offset, std::span<std::byte> out);
  core::Result<void> write_at(std::uint64_t offset,
                              std::span<const std::byte> in);
  core::Result<std::uint64_t> size() const;
  core::Result<void> resize(std::uint64_t);
  core::Result<void> allocate(std::uint64_t);

  bool is_open() const noexcept { return fd_ >= 0; }

private:
  explicit FileIO(int fd) noexcept : fd_{fd} {}
  int fd_;
};
} // namespace core::io
