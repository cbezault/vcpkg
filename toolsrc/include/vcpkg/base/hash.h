#pragma once

#include <vcpkg/base/files.h>

#include <string>

namespace vcpkg::Hash
{
    struct Algorithm
    {
        enum Tag
        {
            Sha1,
            Sha256,
            Sha512,
        } tag;

        StringLiteral to_string() const;
        static Optional<Algorithm> from_string(StringView sv);

        constexpr Algorithm(Tag tag) : tag(tag) {}
    };

    constexpr bool operator==(Algorithm lhs, Algorithm rhs) noexcept { return lhs.tag == rhs.tag; }
    constexpr bool operator==(Algorithm lhs, Algorithm::Tag rhs) noexcept { return lhs.tag == rhs; }
    constexpr bool operator==(Algorithm::Tag lhs, Algorithm rhs) noexcept { return lhs == rhs.tag; }
    constexpr bool operator!=(Algorithm lhs, Algorithm rhs) noexcept { return lhs.tag != rhs.tag; }
    constexpr bool operator!=(Algorithm lhs, Algorithm::Tag rhs) noexcept { return lhs.tag != rhs; }
    constexpr bool operator!=(Algorithm::Tag lhs, Algorithm rhs) noexcept { return lhs != rhs.tag; }

    struct Hasher
    {
        virtual void add_bytes(const void* start, const void* end) noexcept = 0;

        // one may only call this once before calling `clear()` or the dtor
        virtual std::string get_hash() noexcept = 0;
        virtual void clear() noexcept = 0;
        virtual ~Hasher() = default;
    };

    std::unique_ptr<Hasher> get_hasher_for(Algorithm algo);

    std::string get_bytes_hash(const void* first, const void* last, Algorithm algo);
    std::string get_string_hash(StringView s, Algorithm algo);
    std::string get_file_hash(const Files::Filesystem& fs, const fs::path& path, Algorithm algo);
}
