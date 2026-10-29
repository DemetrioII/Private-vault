module;

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

} // namespace core
