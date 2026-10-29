module;

#include <cerrno>
#include <cstddef>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <span>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

module core.io;

import core.error;
import core.result;

using namespace core;
using namespace core::io;

FileIO::~FileIO() noexcept {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

FileIO::FileIO(FileIO &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

FileIO &FileIO::operator=(FileIO &&other) noexcept {
  if (this == &other)
    return *this;
  if (fd_ >= 0)
    ::close(fd_);
  fd_ = other.fd_;
  other.fd_ = -1;
  return *this;
}

core::Result<FileIO> FileIO::open(const std::filesystem::path &path,
                                  OpenMode mode) {
  int flags = 0;
  mode_t perms = 0644;

  switch (mode) {
  case OpenMode::ReadOnly:
    flags = O_RDONLY;
    break;
  case OpenMode::ReadWrite:
    flags = O_RDWR;
    break;
  case OpenMode::CreateReadWrite:
    flags = O_RDWR | O_CREAT;
    break;
  case OpenMode::CreateExclusive:
    flags = O_RDWR | O_CREAT | O_EXCL;
    break;
  }

  int fd = ::open(path.c_str(), flags, perms);
  if (fd < 0) {
    if (errno == EACCES || errno == EPERM)
      return std::unexpected(
          make_error(ErrorCode::PermissionDenied, "permission denied"));
    if (errno == ENOENT)
      return std::unexpected(make_error(ErrorCode::NotFound, "file not found"));
    return std::unexpected(make_error(ErrorCode::IoError, "open failed"));
  }

  return FileIO{fd};
}

core::Result<void> FileIO::read_at(std::uint64_t offset,
                                   std::span<std::byte> out) {
  if (!is_open())
    return std::unexpected(make_error(ErrorCode::IoError, "file not open"));
  if (out.empty())
    return {};

  std::size_t total = 0;
  while (total < out.size()) {
    ssize_t r = ::pread(fd_, out.data() + total, out.size() - total,
                        static_cast<off_t>(offset + total));
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return std::unexpected(make_error(ErrorCode::IoError, "pread failed"));
    }
    if (r == 0)
      return std::unexpected(make_error(ErrorCode::IoError, "unexpected eof"));
    total += static_cast<std::size_t>(r);
  }
  return {};
}

core::Result<void> FileIO::write_at(std::uint64_t offset,
                                    std::span<const std::byte> in) {
  if (!is_open())
    return std::unexpected(make_error(ErrorCode::IoError, "file not open"));
  if (in.empty())
    return {};

  std::size_t total = 0;
  while (total < in.size()) {
    ssize_t w = ::pwrite(fd_, in.data() + total, in.size() - total,
                         static_cast<off_t>(offset + total));
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return std::unexpected(make_error(ErrorCode::IoError, "pwrite failed"));
    }
    total += static_cast<std::size_t>(w);
  }
  return {};
}

core::Result<std::uint64_t> FileIO::size() const {
  if (!is_open())
    return std::unexpected(make_error(ErrorCode::IoError, "file not open"));

  struct stat st{};
  if (::fstat(fd_, &st) != 0)
    return std::unexpected(make_error(ErrorCode::IoError, "fstat failed"));
  if (st.st_size < 0)
    return std::unexpected(make_error(ErrorCode::IoError, "invalid size"));

  return static_cast<std::uint64_t>(st.st_size);
}

core::Result<void> FileIO::resize(uint64_t new_size) {
  if (!is_open())
    return std::unexpected(make_error(ErrorCode::IoError, "file not open"));

  if (new_size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "file size is too large"));

  if (::ftruncate(fd_, static_cast<off_t>(new_size)) != 0)
    return std::unexpected(make_error(ErrorCode::IoError, "ftruncate failed"));

  return {};
}
