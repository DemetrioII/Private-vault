module;

#include <string_view>

export module core.error;

export namespace core {
enum class ErrorCode {
  None = 0,
  Unknown,
  InvalidArgument,
  NotFound,
  PermissionDenied,
  IoError,
  CryptoError,
  VaultError,
  Unsupported
};

struct Error {
  ErrorCode code = ErrorCode::Unknown;
  std::string_view message = {};
};

constexpr bool is_ok(const Error &e) noexcept {
  return e.code == ErrorCode::None;
}
} // namespace core
