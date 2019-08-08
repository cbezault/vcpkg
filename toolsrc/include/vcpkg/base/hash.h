#pragma once

#include <vcpkg/base/files.h>

#include <string>

namespace vcpkg::Hash
{
    struct Algorithm {
        enum Tag {
            Sha1,
            Sha256,
            Sha512,
        } tag;

        StringLiteral to_string() const;
        static Optional<Algorithm> from_string(StringView sv);

        constexpr Algorithm(Tag tag) : tag(tag) {}
    };

    constexpr bool operator==(Algorithm lhs, Algorithm rhs) noexcept {
        return lhs.tag == rhs.tag;
    }
    constexpr bool operator==(Algorithm lhs, Algorithm::Tag rhs) noexcept {
        return lhs.tag == rhs;
    }
    constexpr bool operator==(Algorithm::Tag lhs, Algorithm rhs) noexcept {
        return lhs == rhs.tag;
    }
    constexpr bool operator!=(Algorithm lhs, Algorithm rhs) noexcept {
        return lhs.tag != rhs.tag;
    }
    constexpr bool operator!=(Algorithm lhs, Algorithm::Tag rhs) noexcept {
        return lhs.tag != rhs;
    }
    constexpr bool operator!=(Algorithm::Tag lhs, Algorithm rhs) noexcept {
        return lhs != rhs.tag;
    }

    std::string get_string_hash(const std::string& s, Algorithm algo);
    std::string get_file_hash(const Files::Filesystem& fs, const fs::path& path, Algorithm algo);
}
