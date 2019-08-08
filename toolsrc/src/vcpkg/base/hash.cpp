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

    struct Hasher {
        virtual void add_bytes(const void* start, const void* end) = 0;
        virtual std::string get_hash() = 0;
        virtual ~Hasher() = default;
    };

    struct Sha1Hasher final : Hasher {
        Sha1Hasher() {
            m_unprocessed.reserve(chunk_size);
        }

        virtual void add_bytes(const void* start, const void* end) override {
            for (;;) {
                start = add_to_unprocessed(start, end);
                if (!start) {
                    break; // done
                }

                process_full_chunk();
            }
        }

        virtual std::string get_hash() override {
            process_last_chunk();
            return to_hex(&m_digest[0], &m_digest[5]);
        }

    private:
        // if unprocessed gets filled,
        // returns a pointer to the remainder of the block (which might be end)
        // else, returns nullptr
        const void* add_to_unprocessed(const void* start_, const void* end_) {
            const uchar* start = static_cast<const uchar*>(start_);
            const uchar* end = static_cast<const uchar*>(end_);

            const auto original_length = m_unprocessed.size();
            const auto remaining = chunk_size - original_length;

            const std::size_t message_length = end - start;
            if (message_length >= remaining) {
                std::copy(start, start + remaining, std::back_inserter(m_unprocessed));
                m_message_length += remaining * 8;
                return start + remaining;
            } else {
                std::copy(start, end, std::back_inserter(m_unprocessed));
                m_message_length += message_length * 8;
                return nullptr;
            }
        }

        static constexpr std::uint32_t shr(std::uint32_t value, int by) noexcept {
            return value << by;
        }
        // requires: 0 < by < 32
        static constexpr std::uint32_t rol(std::uint32_t value, int by) noexcept {
            return (value << by) | (value >> (32 - by));
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
            const auto length = m_unprocessed.size();
            if (chunk_size - length < sizeof(message_length)) {
                // not enough space to add the message length
                // just resize and process full chunk
                m_unprocessed.resize(chunk_size);
                process_full_chunk();
            }

            m_unprocessed.resize(chunk_size - sizeof(m_message_length));

            for (int i = 0; i < sizeof(message_length); ++i) {
                m_unprocessed.push_back(top_bits(message_length));
                message_length <<= 8;
            }

            process_full_chunk();
        }

        // requires: m_unprocessed.size() == chunk_size
        void process_full_chunk() {
            vcpkg::Checks::check_exit(VCPKG_LINE_INFO, m_unprocessed.size() == chunk_size);
            std::uint32_t words[80];

            // break chunk into 16 32-bit words
            for (std::size_t i = 0; i < chunk_size / 4; ++i) {
                // big-endian -- so the earliest i becomes the most significant
                words[i]  = shr(m_unprocessed[i * 4 + 0], 24);
                words[i] |= shr(m_unprocessed[i * 4 + 1], 16);
                words[i] |= shr(m_unprocessed[i * 4 + 2], 8);
                words[i] |= shr(m_unprocessed[i * 4 + 3], 0);
            }
            m_unprocessed.clear();

            for (std::size_t i = 16; i < 80; ++i) {
                words[i] = rol(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
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

                auto tmp = rol(a, 5) + f + e + k + words[i];
                e = d;
                d = c;
                c = rol(b, 30);
                b = a;
                a = tmp;
            }

            m_digest[0] += a;
            m_digest[1] += b;
            m_digest[2] += c;
            m_digest[3] += d;
            m_digest[4] += e;
        }

        constexpr static std::size_t chunk_size = 64;

        std::uint64_t m_message_length = 0;
        std::vector<unsigned char> m_unprocessed; // has length up to 512 bits / 8 = 64 (chunk_size) chars
        std::uint32_t m_digest[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    };

    // always returns non-null
    static std::unique_ptr<Hasher> get_hasher(Algorithm algo) {
        switch (algo.tag)
        {
            case Algorithm::Sha1: return std::make_unique<Sha1Hasher>();
            default: vcpkg::Checks::exit_with_message(VCPKG_LINE_INFO, "unimplemented");
        }
    }

    std::string get_string_hash(const std::string& s, Algorithm algo)
    {
        auto hasher = get_hasher(algo);
        hasher->add_bytes(s.data(), s.data() + s.size());
        return hasher->get_hash();
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
