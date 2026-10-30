module;

#include <array>
#include <cstddef>
#include <cstring>
#include <sodium.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

export module core.secure;

export namespace core {
// Securely zero memory - attempt to prevent compiler optimizations
inline void secure_zero(void *ptr, size_t len) noexcept {
  if (ptr == nullptr || len == 0)
    return;

#if defined(__STDC_LIB_EXT1__)
  memset_s(ptr, len, 0, len);
#elif defined(_MSC_VER)
  SecureZeroMemory(ptr, len);
#else
  volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
  for (size_t i = 0; i < len; ++i)
    p[i] = 0;
#endif
}

template <typename T> inline void secure_zero(T &obj) noexcept {
  secure_zero(&obj, sizeof(T));
}

template <typename T, size_t N>
inline void secure_zero_array(T (&arr)[N]) noexcept {
  secure_zero(arr, sizeof(arr));
}

inline void secure_lock(void *ptr, size_t size) noexcept {
  sodium_mlock(ptr, size);
}

inline void secure_unlock(void *ptr, size_t size) noexcept {
  sodium_munlock(ptr, size);
}

template <std::size_t N> class SecureBuffer {
  std::array<unsigned char, N> buffer;

public:
  SecureBuffer() {
    secure_zero(buffer);
    secure_lock(buffer.data(), N);
  }

  ~SecureBuffer() {
    secure_zero(buffer);
    secure_unlock(buffer.data(), N);
  }

  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;

  SecureBuffer(SecureBuffer &&other) noexcept {
    std::memcpy(buffer.data(), other.buffer.data(), N);
    secure_zero(other.buffer.data(), N);
    secure_lock(buffer.data(), N);
  }

  SecureBuffer &operator=(SecureBuffer &&other) noexcept {
    if (this != &other) {
      std::memcpy(buffer.data(), other.buffer.data(), N);
      secure_zero(other.buffer.data(), N);
    }

    return *this;
  }

  unsigned char *data() { return buffer.data(); }
  const unsigned char *data() const { return buffer.data(); }

  static constexpr std::size_t size() { return N; }

  void fill(unsigned char value) { std::memset(buffer.data(), value, N); }

  void write(const unsigned char *src, std::size_t len) {
    if (len > N) {
      throw std::out_of_range("Data too large");
    }

    if (src) {
      std::memcpy(buffer.data(), src, len);
    }
  }
};

} // namespace core
