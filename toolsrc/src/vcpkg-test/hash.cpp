#include <vcpkg-test/catch.h>

#include <vcpkg/base/hash.h>

#include <algorithm>
#include <iterator>
#include <iostream>
#include <map>

namespace Hash = vcpkg::Hash;
using vcpkg::StringView;

#define CHECK_HASH(size, value, real_hash) do { \
  std::uint8_t data[size]; \
  std::fill(std::begin(data), std::end(data), value); \
  const auto hash = Hash::get_bytes_hash(data, data + size, algorithm); \
  REQUIRE(hash == real_hash); \
} while (0)

#define CHECK_HASH_OF(data, real_hash) do { \
  const auto hash = Hash::get_bytes_hash(std::begin(data), std::end(data), algorithm); \
  REQUIRE(hash == real_hash); \
} while (0)

#define CHECK_HASH_STRING(data, real_hash) do { \
  const auto hash = Hash::get_string_hash(data, algorithm); \
  REQUIRE(hash == real_hash); \
} while (0)


TEST_CASE("sha1 implementation is correct", "[hash]") {
  const auto algorithm = Hash::Algorithm::Sha1;

  CHECK_HASH_STRING("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  CHECK_HASH_STRING(";", "2d14ab97cc3dc294c51c0d6814f4ea45f4b4e312");
  CHECK_HASH_STRING("asdifasdfnas", "b77eb8a1b4c2ef6716d7d302647e4511b1a638a6");
  CHECK_HASH_STRING(
    "asdfanvoinaoifawenflawenfiwnofvnasfjvnaslkdfjlkasjdfanm,werflawoienfowanevoinwai32910u2740918741o;j;wejfqwioaher9283hrpf;asd",
    "c69bcd30c196c7050906d212722dd7a7659aad04");
}

TEST_CASE("sha256 implementation is correct", "[hash]") {
  const auto algorithm = Hash::Algorithm::Sha256;

  CHECK_HASH_STRING("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  CHECK_HASH_STRING(";", "41b805ea7ac014e23556e98bb374702a08344268f92489a02f0880849394a1e4");
  CHECK_HASH_STRING("asdifasdfnas", "2bb1fb910831fdc11d5a3996425a84ace27aeb81c9c20ace9f60ac1b3218b291");
  CHECK_HASH_STRING(
    "asdfanvoinaoifawenflawenfiwnofvnasfjvnaslkdfjlkasjdfanm,werflawoienfowanevoinwai32910u2740918741o;j;wejfqwioaher9283hrpf;asd",
    "10c98034b424d4e40ca933bc524ea38b4e53290d76e8b38edc4ea2fec7f529aa");
}

TEST_CASE("NIST test data (small): SHA256", "[hash]") {
  const auto algorithm = Hash::Algorithm::Sha256;

  CHECK_HASH(1, 0xbd, "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b");
  {
    const std::uint8_t data[] = {0xc9, 0x8c, 0x8e, 0x55};
    CHECK_HASH_OF(data, "7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504");
  }
  CHECK_HASH(55, 0, "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7");
  CHECK_HASH(56, 0, "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb");
  CHECK_HASH(57, 0, "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785");
  CHECK_HASH(64, 0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
  CHECK_HASH(1000, 0, "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53");
  CHECK_HASH(1000, 'A', "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4");
  CHECK_HASH(1005, 'U', "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0");
}

#if 0
TEST_CASE("NIST test data (large): SHA256", "[hash]") {
  const auto algorithm = Hash::Algorithm::Sha256;

  CHECK_HASH(1'000'000, 0, "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025");
  CHECK_HASH(0x2000'0000, 'Z', "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd");
  CHECK_HASH(0x4100'0000, 0, "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53");
  CHECK_HASH(0x6000'003e, 'B', "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea");
}
#endif
