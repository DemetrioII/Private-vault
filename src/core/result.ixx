module;

#include <expected>
#include <string_view>
#include <type_traits>
#include <utility>

export module core.result;

import core.error;

export namespace core
{
    template<typename T, typename E = Error>
    using Result = std::expected<T, E>;

    using VoidResult = std::expected<void, Error>;

    inline Error make_error(ErrorCode code, std::string_view msg) noexcept
    {
        return Error{code, msg};
    }

    template<typename T>
    constexpr bool is_ok_result(const Result<T>& r) noexcept
    {
        return r.has_value();
    }
}
