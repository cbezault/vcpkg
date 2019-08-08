#include <vcpkg-test/catch.h>

#include <vcpkg/base/hash.h>

#include <iostream>

TEST_CASE("foobar", "[hash]") {
  const auto hash = vcpkg::Hash::get_string_hash(
    ";",
    vcpkg::Hash::Algorithm::Sha1
  );

  FAIL(hash);
}
