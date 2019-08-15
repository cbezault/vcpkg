#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include <vcpkg/base/system.debug.h>

int main(int argc, char** argv)
{
    vcpkg::Debug::g_debugging = true;

    if (argc < 2) {
        const char* my_argv[] = {".\\vcpkg.exe", "[sha256]"};
        return Catch::Session().run(2, my_argv);
    } else {
        return Catch::Session().run(argc, argv);
    }
}
