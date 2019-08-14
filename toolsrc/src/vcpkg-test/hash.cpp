#include <vcpkg-test/catch.h>

#include <vcpkg/base/hash.h>

#include <iostream>

namespace Hash = vcpkg::Hash;
using vcpkg::StringView;

TEST_CASE("sha1 implementation is correct", "[hash]") {
  const auto check_hash = [] (StringView data, const char* real_hash) {
    const auto algorithm = vcpkg::Hash::Algorithm::Sha1;
    const auto hash = Hash::get_string_hash(data, algorithm);

    REQUIRE(hash == real_hash);
  };

  check_hash("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  check_hash(";", "2d14ab97cc3dc294c51c0d6814f4ea45f4b4e312");
  check_hash("asdifasdfnas", "2a333739416c2746198b36852f61cd1a63f861a6");
  check_hash(
    "asdfanvoinaoifawenflawenfiwnofvnasfjvnaslkdfjlkasjdfanm,werflawoienfowanevoinwai32910u2740918741o;j;wejfqwioaher9283hrpf;asd",
    "c69bcd30c196c7050906d212722dd7a7659aad04");
}
