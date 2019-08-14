#include "pch.h"

#include <vcpkg/base/hash.h>

#include <vcpkg/base/checks.h>
#include <vcpkg/base/strings.h>
#include <vcpkg/base/system.process.h>
#include <vcpkg/base/util.h>

#if defined(_WIN32)
#include <bcrypt.h>
#pragma comment(lib, "bcrypt")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

namespace vcpkg::Hash
{
    Optional<Algorithm> Algorithm::from_string(StringView sv) {
        if (Strings::case_insensitive_ascii_equals(sv, "SHA1")) {
            return {Algorithm::Sha1};
        }
        if (Strings::case_insensitive_ascii_equals(sv, "SHA256")) {
            return {Algorithm::Sha256};
        }
        if (Strings::case_insensitive_ascii_equals(sv, "SHA512")) {
            return {Algorithm::Sha512};
        }

        return {};
    }

    StringLiteral Algorithm::to_string() const {
        switch (tag) {
            case Algorithm::Sha1: return "Sha1";
            case Algorithm::Sha256: return "Sha256";
            case Algorithm::Sha512: return "Sha512";
            default: vcpkg::Checks::exit_fail(VCPKG_LINE_INFO);
        }
    }

    static void verify_has_only_allowed_chars(const std::string& s)
    {
        static const std::regex ALLOWED_CHARS{"^[a-zA-Z0-9-]*$"};
        Checks::check_exit(VCPKG_LINE_INFO,
                           std::regex_match(s, ALLOWED_CHARS),
                           "Only alphanumeric chars and dashes are currently allowed. String was:\n"
                           "    % s",
                           s);
    }

    using uchar = unsigned char;

    template <class T>
    static constexpr uchar top_bits(T x)
    {
        return (x >> ((sizeof(T) - 1) * 8)) & 0xFF;
    }

    // treats UIntTy as big endian for the purpose of this mapping
    template <class UIntTy>
    static std::string to_hex(const UIntTy* start, const UIntTy* end)
    {
        static constexpr char HEX_MAP[] = "0123456789abcdef";

        std::string output;
        output.resize(2 * sizeof(UIntTy) * (end - start));

        constexpr UIntTy high_order_mask = 0xFF << (sizeof(UIntTy) - 1);

        std::size_t output_index = 0;
        for (const UIntTy* it = start; it != end; ++it)
        {
            // holds *it in a big-endian buffer, for copying into output
            uchar buff[sizeof(UIntTy)];
            UIntTy tmp = *it;
            for (uchar& ch : buff) {
                ch = top_bits(tmp);
                tmp <<= 8;
            }

            for (const auto byte : buff) {
                // high
                output[output_index] = HEX_MAP[(byte & 0xF0) >> 4];
                ++output_index;
                // low
                output[output_index] = HEX_MAP[byte & 0x0F];
                ++output_index;
            }
        }

        return output;
    }

    static std::uint32_t shr32(std::uint32_t value, int by) noexcept {
        return value >> by;
    }
    static std::uint32_t rol32(std::uint32_t value, int by) noexcept {
        return (value << by) | (value >> (32 - by));
    }

    static std::uint64_t shr64(std::uint64_t value, int by) noexcept {
        return value >> by;
    }
    static std::uint64_t rol64(std::uint64_t value, int by) noexcept {
        return (value << by) | (value >> (64 - by));
    }

    struct Hasher {
        virtual void add_bytes(const void* start, const void* end) = 0;
        virtual std::string get_hash() = 0;
        virtual ~Hasher() = default;
    };

    template <class ShaAlgorithm>
    struct ShaHasher final : Hasher {
        ShaHasher() = default;

        virtual void add_bytes(const void* start, const void* end) override {
            for (;;) {
                start = add_to_unprocessed(start, end);
                if (!start) {
                    break; // done
                }

                m_impl.process_full_chunk(m_chunk);
                m_current_chunk_size = 0;
            }
        }

        virtual std::string get_hash() override {
            process_last_chunk();
            return to_hex(m_impl.begin(), m_impl.end());
        }

    private:
        // if unprocessed gets filled,
        // returns a pointer to the remainder of the block (which might be end)
        // else, returns nullptr
        const void* add_to_unprocessed(const void* start_, const void* end_) {
            const uchar* start = static_cast<const uchar*>(start_);
            const uchar* end = static_cast<const uchar*>(end_);

            const auto remaining = chunk_size - m_current_chunk_size;

            const std::size_t message_length = end - start;
            if (message_length >= remaining) {
                std::copy(start, start + remaining, m_chunk.begin() + m_current_chunk_size);
                m_current_chunk_size += remaining;
                m_message_length += remaining * 8;
                return start + remaining;
            } else {
                std::copy(start, end, m_chunk.begin() + m_current_chunk_size);
                m_current_chunk_size += message_length;
                m_message_length += message_length * 8;
                return nullptr;
            }
        }

        // called before `get_hash`
        void process_last_chunk() {
            auto message_length = m_message_length;

            // append the bit '1' to the message
            {
                const uchar temp = 0x80;
                add_to_unprocessed(&temp, &temp + 1);
            }

            // append 0 to the message so that the resulting length is just enough
            // to add the message length
            if (chunk_size - m_current_chunk_size < sizeof(m_message_length)) {
                // not enough space to add the message length
                // just resize and process full chunk
                std::fill(m_chunk.begin() + m_current_chunk_size, m_chunk.end(), 0);
                m_impl.process_full_chunk(m_chunk);
                m_current_chunk_size = 0;
            }

            std::fill(m_chunk.begin(), m_chunk.end() - sizeof(m_message_length), 0);
            for (int i = 0; i < sizeof(message_length); ++i) {
                m_chunk[i + chunk_size - sizeof(m_message_length)] = top_bits(message_length);
                message_length <<= 8;
            }

            m_impl.process_full_chunk(m_chunk);
        }

        using type = typename ShaAlgorithm::type;
        constexpr static std::size_t chunk_size = ShaAlgorithm::chunk_size;

        ShaAlgorithm m_impl{};

        std::array<uchar, chunk_size> m_chunk{};
        std::size_t m_current_chunk_size = 0;
        std::uint64_t m_message_length = 0;
    };

    struct Sha1Algorithm {
        using type = std::uint32_t;
        constexpr static std::size_t chunk_size = 64; // = 512 / 8

        void process_full_chunk(const std::array<uchar, chunk_size>& chunk) {
            std::uint32_t words[80];

            // break chunk into 16 32-bit words
            for (std::size_t i = 0; i < chunk_size / 4; ++i) {
                // big-endian -- so the earliest i becomes the most significant
                words[i]  = shr32(chunk[i * 4 + 0], 24);
                words[i] |= shr32(chunk[i * 4 + 1], 16);
                words[i] |= shr32(chunk[i * 4 + 2], 8);
                words[i] |= shr32(chunk[i * 4 + 3], 0);
            }

            for (std::size_t i = 16; i < 80; ++i) {
                words[i] = rol32(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            }

            std::uint32_t a = m_digest[0];
            std::uint32_t b = m_digest[1];
            std::uint32_t c = m_digest[2];
            std::uint32_t d = m_digest[3];
            std::uint32_t e = m_digest[4];

            for (std::size_t i = 0; i < 80; ++i) {
                std::uint32_t f;
                std::uint32_t k;

                if (0 <= i && i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (20 <= i && i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (40 <= i && i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                auto tmp = rol32(a, 5) + f + e + k + words[i];
                e = d;
                d = c;
                c = rol32(b, 30);
                b = a;
                a = tmp;
            }

            m_digest[0] += a;
            m_digest[1] += b;
            m_digest[2] += c;
            m_digest[3] += d;
            m_digest[4] += e;
        }

        const std::uint32_t* begin() const {
            return &m_digest[0];
        }
        const std::uint32_t* end() const {
            return &m_digest[5];
        }

        std::uint32_t m_digest[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    };

    template <class UIntType>
    struct Sha2Constants;
    template <>
    struct Sha2Constants<std::uint32_t> {
        constexpr static std::size_t number_of_rounds = 64;
        constexpr static std::array<std::uint32_t, number_of_rounds> round_constants = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
    };
    template <>
    struct Sha2Constants<std::uint64_t> {
        constexpr static std::size_t number_of_rounds = 80;

        constexpr static std::array<std::uint64_t, number_of_rounds> round_constants = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };
    };

    template <class F>
    static std::string do_hash(Algorithm algo, const F& f) {
        switch (algo.tag)
        {
            case Algorithm::Sha1: {
                auto hasher = ShaHasher<Sha1Algorithm>();
                return f(hasher);
            }
            case Algorithm::Sha256:
                //auto hasher = Sha2Hasher<std::uint32_t>();
                //return f(hasher);
            case Algorithm::Sha512:
                //auto hasher = Sha2Hasher<std::uint64_t>();
                //return f(hasher);
            default: vcpkg::Checks::exit_with_message(VCPKG_LINE_INFO, "Unknown hashing algorithm: %s", algo);
        }
    }

    std::string get_string_hash(StringView sv, Algorithm algo)
    {
        return do_hash(algo, [sv](Hasher& hasher) {
            hasher.add_bytes(sv.data(), sv.data() + sv.size());
            return hasher.get_hash();
        });
    }

    std::string get_file_hash(const Files::Filesystem& fs, const fs::path& path, Algorithm algo) {
        vcpkg::Checks::exit_with_message(VCPKG_LINE_INFO, "aww");
    }

#if 0
#if defined(_WIN32)
    namespace
    {
        std::string to_hex(const unsigned char* string, const size_t bytes)
        {
            static constexpr char HEX_MAP[] = "0123456789abcdef";

            std::string output;
            output.resize(2 * bytes);

            size_t current_char = 0;
            for (size_t i = 0; i < bytes; i++)
            {
                // high
                output[current_char] = HEX_MAP[(string[i] & 0xF0) >> 4];
                ++current_char;
                // low
                output[current_char] = HEX_MAP[(string[i] & 0x0F)];
                ++current_char;
            }

            return output;
        }

        class BCryptHasher
        {
            struct BCryptAlgorithmHandle : Util::ResourceBase
            {
                BCRYPT_ALG_HANDLE handle = nullptr;

                ~BCryptAlgorithmHandle()
                {
                    if (handle) BCryptCloseAlgorithmProvider(handle, 0);
                }
            };

            struct BCryptHashHandle : Util::ResourceBase
            {
                BCRYPT_HASH_HANDLE handle = nullptr;

                ~BCryptHashHandle()
                {
                    if (handle) BCryptDestroyHash(handle);
                }
            };

            static void initialize_hash_handle(BCryptHashHandle& hash_handle,
                                               const BCryptAlgorithmHandle& algorithm_handle)
            {
                const NTSTATUS error_code =
                    BCryptCreateHash(algorithm_handle.handle, &hash_handle.handle, nullptr, 0, nullptr, 0, 0);
                Checks::check_exit(VCPKG_LINE_INFO, NT_SUCCESS(error_code), "Failed to initialize the hasher");
            }

            static void hash_data(BCryptHashHandle& hash_handle, const unsigned char* buffer, const size_t& data_size)
            {
                const NTSTATUS error_code = BCryptHashData(
                    hash_handle.handle, const_cast<unsigned char*>(buffer), static_cast<ULONG>(data_size), 0);
                Checks::check_exit(VCPKG_LINE_INFO, NT_SUCCESS(error_code), "Failed to hash data");
            }

            static std::string finalize_hash_handle(const BCryptHashHandle& hash_handle, const ULONG length_in_bytes)
            {
                std::unique_ptr<unsigned char[]> hash_buffer = std::make_unique<UCHAR[]>(length_in_bytes);
                const NTSTATUS error_code = BCryptFinishHash(hash_handle.handle, hash_buffer.get(), length_in_bytes, 0);
                Checks::check_exit(VCPKG_LINE_INFO, NT_SUCCESS(error_code), "Failed to finalize the hash");
                return to_hex(hash_buffer.get(), length_in_bytes);
            }

        public:
            explicit BCryptHasher(std::string hash_type)
            {
                NTSTATUS error_code = BCryptOpenAlgorithmProvider(
                    &this->algorithm_handle.handle,
                    Strings::to_utf16(Strings::ascii_to_uppercase(std::move(hash_type))).c_str(),
                    nullptr,
                    0);
                Checks::check_exit(VCPKG_LINE_INFO, NT_SUCCESS(error_code), "Failed to open the algorithm provider");

                DWORD hash_buffer_bytes;
                DWORD cb_data;
                error_code = BCryptGetProperty(this->algorithm_handle.handle,
                                               BCRYPT_HASH_LENGTH,
                                               reinterpret_cast<PUCHAR>(&hash_buffer_bytes),
                                               sizeof(DWORD),
                                               &cb_data,
                                               0);
                Checks::check_exit(VCPKG_LINE_INFO, NT_SUCCESS(error_code), "Failed to get hash length");
                this->length_in_bytes = hash_buffer_bytes;
            }

            std::string hash_file(const fs::path& path) const
            {
                BCryptHashHandle hash_handle;
                initialize_hash_handle(hash_handle, this->algorithm_handle);

                FILE* file = nullptr;
                const auto ec = _wfopen_s(&file, path.c_str(), L"rb");
                Checks::check_exit(VCPKG_LINE_INFO, ec == 0, "Failed to open file: %s", path.u8string());
                if (file != nullptr)
                {
                    unsigned char buffer[4096];
                    while (const auto actual_size = fread(buffer, 1, sizeof(buffer), file))
                    {
                        hash_data(hash_handle, buffer, actual_size);
                    }
                    fclose(file);
                }

                return finalize_hash_handle(hash_handle, length_in_bytes);
            }

            std::string hash_string(const std::string& s) const
            {
                BCryptHashHandle hash_handle;
                initialize_hash_handle(hash_handle, this->algorithm_handle);
                hash_data(hash_handle, reinterpret_cast<const unsigned char*>(s.c_str()), s.size());
                return finalize_hash_handle(hash_handle, length_in_bytes);
            }

        private:
            BCryptAlgorithmHandle algorithm_handle;
            ULONG length_in_bytes;
        };
    }

    std::string get_file_hash(const Files::Filesystem& fs, const fs::path& path, const std::string& hash_type)
    {
        Checks::check_exit(VCPKG_LINE_INFO, fs.exists(path), "File %s does not exist", path.u8string());
        return BCryptHasher{hash_type}.hash_file(path);
    }

    std::string get_string_hash(const std::string& s, const std::string& hash_type)
    {
        verify_has_only_allowed_chars(s);
        return BCryptHasher{hash_type}.hash_string(s);
    }

#else
    static std::string get_digest_size(const std::string& hash_type)
    {
        if (!Strings::case_insensitive_ascii_starts_with(hash_type, "SHA"))
        {
            Checks::exit_with_message(
                VCPKG_LINE_INFO, "shasum only supports SHA hashes, but %s was provided", hash_type);
        }

        return hash_type.substr(3, hash_type.length() - 3);
    }

    static std::string parse_shasum_output(const std::string& shasum_output)
    {
        std::vector<std::string> split = Strings::split(shasum_output, " ");
        // Checking if >= 3 because filenames with spaces will show up as multiple tokens.
        // The hash is the first token so we don't need to parse the filename anyway.
        Checks::check_exit(VCPKG_LINE_INFO,
                           split.size() >= 3,
                           "Expected output of the form [hash filename\n] (3+ tokens), but got\n"
                           "[%s] (%s tokens)",
                           shasum_output,
                           std::to_string(split.size()));

        return split[0];
    }

    std::string get_file_hash(const Files::Filesystem& fs, const fs::path& path, const std::string& hash_type)
    {
        const std::string digest_size = get_digest_size(hash_type);
        Checks::check_exit(VCPKG_LINE_INFO, fs.exists(path), "File %s does not exist", path.u8string());

        // Try hash-specific tools, like sha512sum
        {
            const auto ec_data = System::cmd_execute_and_capture_output(
                Strings::format(R"(sha%ssum "%s")", digest_size, path.u8string()));
            if (ec_data.exit_code == 0)
            {
                return parse_shasum_output(ec_data.output);
            }
        }

        // Try shasum
        {
            const auto ec_data = System::cmd_execute_and_capture_output(
                Strings::format(R"(shasum -a %s "%s")", digest_size, path.u8string()));
            if (ec_data.exit_code == 0)
            {
                return parse_shasum_output(ec_data.output);
            }
        }

        Checks::exit_with_message(VCPKG_LINE_INFO, "Could not hash file %s with %s", path.u8string(), hash_type);
    }

    std::string get_string_hash(const std::string& s, const std::string& hash_type)
    {
        const std::string digest_size = get_digest_size(hash_type);
        verify_has_only_allowed_chars(s);

        // Try hash-specific tools, like sha512sum
        {
            const auto ec_data =
                System::cmd_execute_and_capture_output(Strings::format(R"(echo -n "%s" | sha%ssum)", s, digest_size));
            if (ec_data.exit_code == 0)
            {
                return parse_shasum_output(ec_data.output);
            }
        }

        // Try shasum
        {
            const auto ec_data = System::cmd_execute_and_capture_output(
                Strings::format(R"(echo -n "%s" | shasum -a %s)", s, digest_size));
            if (ec_data.exit_code == 0)
            {
                return parse_shasum_output(ec_data.output);
            }
        }

        Checks::exit_with_message(VCPKG_LINE_INFO, "Could not hash input string with %s", hash_type);
    }
#endif
#endif
}
