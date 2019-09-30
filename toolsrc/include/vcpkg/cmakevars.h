#pragma once

#include <vcpkg/base/system.process.h>
#include <vcpkg/base/util.h>
#include <vcpkg/portfileprovider.h>
#include <vcpkg/vcpkgpaths.h>

namespace vcpkg::CMakeVars
{
    struct CMakeVarProvider : Util::ResourceBase
    {
    private:
        fs::path create_extraction_file(const Span<const PackageSpec> specs) {}
        std::vector<std::pair<std::string, std::string>> launch_and_split(const fs::path& script_path) const
        {
            static constexpr CStringView FLAG_GUID1 = "c35112b6-d1ba-415b-aa5d-81de856ef8eb";
            static constexpr CStringView FLAG_GUID2 = "e1e74b5c-18cb-4474-a6bd-5c1c8bc81f3f";
            static constexpr CStringView FLAG_GUID3 = "739b0178-d2cf-4a1b-b26c-6764c761d636";
            static constexpr CStringView FLAG_GUID4 = "ba27cd04-1df1-4237-b519-09cc0c3dfa3c";

            const auto cmd_launch_cmake = System::make_cmake_cmd(cmake_exe_path, script_path, {});
            const auto ec_data = System::cmd_execute_and_capture_output(cmd_launch_cmake);
            Checks::check_exit(VCPKG_LINE_INFO, ec_data.exit_code == 0, ec_data.output);

            const std::vector<std::string> lines = Strings::split(ec_data.output, "\n");

            std::vector<std::pair<std::string, std::string>> vars;

            auto parse_vars = [&vars](decltype(lines)::const_iterator& cur,
                                      const decltype(lines)::const_iterator& end) {
                if (cur != end) ++cur;
                for (; cur != end; ++cur)
                {
                    auto&& line = *cur;

                    std::vector<std::string> s = Strings::split(line, "=");
                    Checks::check_exit(VCPKG_LINE_INFO,
                                       s.size() == 1 || s.size() == 2,
                                       "Expected format is [VARIABLE_NAME=VARIABLE_VALUE], but was [%s]",
                                       line);

                    vars.emplace_back(std::move(s[0]), s.size() == 1 ? "" : std::move(s[1]));
                }
            };

            const auto end = lines.cend();
            auto triplet_start = std::find(lines.cbegin(), end, FLAG_GUID1);
            auto triplet_end = std::find(triplet_start, end, FLAG_GUID2);
            auto abi_settings_start = std::find(triplet_end, end, FLAG_GUID3);
            auto abi_settings_end = std::find(abi_settings_start, end, FLAG_GUID4);

            while (triplet_start != end)
            {
                parse_vars(triplet_start, triplet_end);
                parse_vars(abi_settings_start, abi_settings_end);

                triplet_start = std::find(abi_settings_end, end, FLAG_GUID1);
                triplet_end = std::find(triplet_start, end, FLAG_GUID2);
                abi_settings_start = std::find(triplet_end, end, FLAG_GUID3);
                abi_settings_end = std::find(abi_settings_start, end, FLAG_GUID4);
            }

            return vars;
        }

    public:
        explicit CMakeVarProvider(const vcpkg::VcpkgPaths& paths, const PortFileProvider::PortFileProvider& provider)
            : paths(paths), port_provider(provider)
        {
        }

        const std::unordered_map<std::string, std::string>& get_cmake_vars(const Triplet& triplet) const
        {
            auto find_itr = base_cmake_variables.find(triplet);
            if (find_itr == base_cmake_variables.end())
            {
                const fs::path triplet_file_path = paths.get_triplet_file_path(triplet);

                auto vars = launch_and_split(triplet_file_path, get_triplet_script_path);

                return base_cmake_variables
                    .emplace(std::make_move_iterator(vars.begin()), std::make_move_iterator(vars.end()))
                    .first->second;
            }

            return find_itr->second;
        }

        const std::unordered_map<std::string, std::string>& get_cmake_vars(const PackageSpec& spec) const
        {
            auto find_itr = final_cmake_variables.find(spec);
            if (find_itr != final_cmake_variables.end())
            {
                Optional<const SourceControlFileLocation&> maybe_scfl = port_provider.get_control_file(spec.name());
                if (maybe_scfl)
                {
                    const SourceControlFileLocation& scfl = maybe_scfl.value_or_exit(VCPKG_LINE_INFO);
                    const fs::path override_path = scfl.source_location / "environment-overrides.cmake";

                    const std::unordered_map<std::string, std::string>& base = get_cmake_vars(spec.triplet());

                    if (paths.get_filesystem().is_regular_file(override_path))
                    {
                        auto vars = launch_and_split(override_path, get_overrides_script_path);
                        std::unordered_map<std::string, std::string>& kv =
                            overriden_cmake_vars
                                .emplace(
                                    spec, std::make_move_iterator(vars.begin()), std::make_move_iterator(vars.end()))
                                .first->second;

                        kv.insert(base.begin(), base.end());

                        return *final_cmake_variables.emplace(spec, &kv).first->second;
                    }
                    else
                    {
                        return *final_cmake_variables.emplace(spec, &base).first->second;
                    }
                }
                else
                {
                    Checks::exit_fail(VCPKG_LINE_INFO);
                }
            }

            return *find_itr->second;
        }

    private:
        const VcpkgPaths& paths;
        const fs::path& cmake_exe_path = paths.get_tool_exe(Tools::CMAKE);
        const fs::path get_triplet_script_path = paths.scripts / "get_triplet_environment.cmake";
        const fs::path get_overrides_script_path = paths.scripts / "get_triplet_overrides.cmake";
        const PortFileProvider::PortFileProvider& port_provider;
        mutable std::unordered_map<PackageSpec, std::unordered_map<std::string, std::string>> overriden_cmake_vars;
        mutable std::unordered_map<Triplet, std::unordered_map<std::string, std::string>> base_cmake_variables;
        mutable std::unordered_map<PackageSpec, std::unordered_map<std::string, std::string>*> final_cmake_variables;
    };
}
