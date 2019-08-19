#pragma once

#include <vcpkg/base/files.h>

#include <string>

namespace vcpkg::Hash
{
    enum class Algorithm
    {
        Sha1,
        Sha256,
        Sha512,
    };

    const char* to_string(Algorithm algo);
    Optional<Algorithm> algorithm_from_string(StringView sv);

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
