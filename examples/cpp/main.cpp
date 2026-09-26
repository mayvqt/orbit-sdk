#include <orbit_sdk.hpp>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    const bool smoke = argc == 2 && std::string_view(argv[1]) == "--smoke";
    if (!smoke && argc != 1) {
        std::cerr << "Usage: orbit-cpp-licensed-export [--smoke]\n";
        return 2;
    }

    std::string app_key;
    orbit::Options options;
    std::filesystem::path smoke_path;
    if (smoke) {
        app_key = "orbit_app_test_aHR0cHM6Ly9leGFtcGxlLmludmFsaWQ.cpp_smoke_app.cpp_smoke_env";
        auto temporary_root = std::filesystem::temp_directory_path();
#if defined(__APPLE__)
        // macOS commonly exposes /tmp through a symlink; resolve the fixture
        // root so the SDK can keep rejecting symlinked state-directory paths.
        temporary_root = std::filesystem::canonical(temporary_root);
#endif
        smoke_path = temporary_root /
            ("orbit-cpp-smoke-" + orbit::new_installation_id());
        options.state_directory = smoke_path.string();
    } else {
        const char* selected = std::getenv("ORBIT_APP_KEY");
        if (selected == nullptr || *selected == '\0') {
            std::cerr << "Set ORBIT_APP_KEY to the public key from Orbit Integration.\n";
            return 2;
        }
        app_key = selected;
    }

    try {
        auto client = orbit::Client::open(app_key, options);
        if (smoke) {
            const auto state = client.snapshot();
            std::cout << "Initial access state: " << static_cast<unsigned>(state.access) << '\n';
            client.close();
            std::filesystem::remove_all(smoke_path);
            std::cout << "Smoke check complete; no network request was made.\n";
            return 0;
        }
        try {
            const auto access = client.ensure_access("export", []() -> std::optional<std::string> {
                std::cout << "Licence key: ";
                std::string key;
                std::getline(std::cin, key);
                if (key.empty()) return std::nullopt;
                return key;
            });
            if (access.has_feature("export"))
                std::cout << "Licensed export is ready.\n";
            client.close();
        } catch (const orbit::Error&) {
            client.close();
            throw;
        }
        return 0;
    } catch (const orbit::Error& error) {
        std::cerr << error.what() << " (kind=" << static_cast<std::uint32_t>(error.kind())
                  << ", code=" << error.code();
        if (!error.request_id().empty()) std::cerr << ", request_id=" << error.request_id();
        std::cerr << ")\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Example failed: " << error.what() << '\n';
        return 1;
    }
}
