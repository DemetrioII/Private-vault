module;

#include <cerrno>
#include <cstddef>
#include <expected>
#include <fcntl.h>
#include <filesystem>
#include <span>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

module core.block;

import core.error;
import core.result;

using namespace core;
using namespace core::io;

core::Result<void>
core::block::BlockDevice::read_block(std::size_t index,
                                     std::span<std::byte> out) const {
  if (out.size() % block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid block buffer size"));
  }
  return io_->read_at(block_size * index, out);
}

core::Result<void>
core::block::BlockDevice::write_block(std::size_t index,
                                      std::span<const std::byte> in) {
  if (in.size() % block_size) {
    return std::unexpected(
        make_error(ErrorCode::InvalidArgument, "invalid block buffer size"));
  }
  return io_->write_at(block_size * index, in);
}

core::Result<std::size_t> core::block::BlockDevice::block_count() const {
  auto x = io_->size();
  if (x.has_value()) {
    return (*x) / block_size;
  }
  return std::unexpected(x.error());
}
