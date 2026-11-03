#pragma once
#include <expected>
#include <iosfwd>
#include <sodium.h>
#include <span>
#include <vector>

class SecureBuffer {
  unsigned char *data_;
  std::size_t capacity_;

public:
  SecureBuffer(std::size_t capacity, unsigned char c = 0);

  // Нужно добавить сюда operator >> для возможности ввода паролей

  std::span<unsigned char const> span() const;

  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;

  SecureBuffer(SecureBuffer &&) noexcept;
  SecureBuffer &operator=(SecureBuffer &&) noexcept;

  const unsigned char *data() const;
  unsigned char *data();

  std::size_t size() const;

  ~SecureBuffer();
};

// Reads a whole line (spaces included) without echoing it when reading from a
// terminal. The buffer is zeroed first, and the tail is left zero-filled.
std::istream &operator>>(std::istream &input, SecureBuffer &buffer);
