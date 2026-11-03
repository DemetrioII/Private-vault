#include <cstdio>
#include <cstring>
#include <iostream>
#include <securebuffer.hpp>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>
#include <utility>

namespace {

class TerminalEchoGuard {
 public:
  explicit TerminalEchoGuard(int fd) : fd_(fd) {
    if (fd_ < 0 || ::isatty(fd_) == 0) {
      return;
    }
    if (::tcgetattr(fd_, &saved_) != 0) {
      return;
    }

    termios hidden = saved_;
    hidden.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    hidden.c_lflag |= static_cast<tcflag_t>(ECHONL);

    if (::tcsetattr(fd_, TCSAFLUSH, &hidden) == 0) {
      active_ = true;
    }
  }

  TerminalEchoGuard(const TerminalEchoGuard &) = delete;
  TerminalEchoGuard &operator=(const TerminalEchoGuard &) = delete;

  ~TerminalEchoGuard() {
    if (active_) {
      ::tcsetattr(fd_, TCSANOW, &saved_);
    }
  }

 private:
  int fd_;
  termios saved_{};
  bool active_ = false;
};

} // namespace

SecureBuffer::SecureBuffer(std::size_t capacity, unsigned char c) : capacity_(capacity) {
  if (sodium_init() < 0) {
    throw std::runtime_error("sodium_init error");
  }

  data_ = (unsigned char *)sodium_malloc(capacity);
  if (data_ != nullptr) {
    std::memset(data_, c, capacity_);
  } else {
    throw std::runtime_error("sodium_malloc error");
  }

  sodium_mlock(data_, capacity_);
}

std::span<unsigned char const> SecureBuffer::span() const { return std::span(data_, data_ + capacity_); }

unsigned char *SecureBuffer::data() { return data_; }

const unsigned char *SecureBuffer::data() const { return data_; }

std::size_t SecureBuffer::size() const { return capacity_; }

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : data_(std::exchange(other.data_, nullptr)), capacity_(std::exchange(other.capacity_, 0)) {}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
  if (this == &other) {
    return *this;
  }

  // Освобождаем собственные ресурсы.
  if (data_) {
    sodium_memzero(data_, capacity_);
    sodium_free(data_);
  }

  // Передаём владение.
  data_ = std::exchange(other.data_, nullptr);
  capacity_ = std::exchange(other.capacity_, 0);

  return *this;
}

SecureBuffer::~SecureBuffer() {
  if (data_ != nullptr) {
    sodium_memzero(data_, capacity_);
    sodium_munlock(data_, capacity_);
    sodium_free(data_);
  }
}

std::istream &operator>>(std::istream &input, SecureBuffer &buffer) {
  if (buffer.data() == nullptr || buffer.size() == 0) {
    input.setstate(std::ios::failbit);
    return input;
  }

  sodium_memzero(buffer.data(), buffer.size());

  const int fd = (&input == &std::cin) ? ::fileno(stdin) : -1;
  TerminalEchoGuard echo_guard(fd);

  std::size_t length = 0;
  bool read_anything = false;
  char ch = 0;

  while (input.get(ch)) {
    read_anything = true;

    if (ch == '\n') {
      break;
    }
    if (ch == '\r') {
      continue;
    }

    if (length < buffer.size()) {
      buffer.data()[length++] = static_cast<unsigned char>(ch);
    }
  }

  sodium_memzero(&ch, sizeof(ch));

  if (!read_anything) {
    input.setstate(std::ios::failbit);
  }

  return input;
}
