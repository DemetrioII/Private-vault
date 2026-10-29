module;

#include <cstddef>
#include <type_traits>

export module core.types;

export namespace core
{
    using byte = unsigned char;
    using size_type = std::size_t;

    template<typename T>
    concept Trivial = std::is_trivial_v<T>;
}
