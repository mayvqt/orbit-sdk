#include <orbit_sdk.hpp>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

int main(int argc, char** argv) {
    const bool smoke = argc == 2 && std::string_view(argv[1]) == "--smoke";
    if (!smoke && (argc < 5 || argc > 6)) {
        std::cerr << "Usage: orbit-cpp-licensed-export API_ORIGIN APP_ID ENV_ID ISSUER [STATE_DIRECTORY]\n"
                     "       orbit-cpp-licensed-export --smoke\n";
        return 2;
    }

    try {
        orbit::AppConfig config;
        std::optional<std::string> state_directory;
        if (smoke) {
            config.api_origin = "https://example.invalid";
            config.application_id = "cpp_smoke_app";
            config.environment_id = "cpp_smoke_env";
            config.issuer = "https://issuer.example.invalid";
        } else {
            config.api_origin = argv[1];
            config.application_id = argv[2];
            config.environment_id = argv[3];
            config.issuer = argv[4];
            if (argc == 6) {
                state_directory = argv[5];
            }
        }

        if (smoke) {
            const auto path = std::filesystem::temp_directory_path() /
                ("orbit-cpp-smoke-" + orbit::new_installation_id());
            // open() creates its dedicated private directory before any request.
            auto client = orbit::Client::open(std::move(config), path.string());
            std::cout << "Snapshot JSON: " << client.snapshot() << '\n';
            client.close();
            std::filesystem::remove_all(path);
            std::cout << "No network request was made.\n";
            return 0;
        }

        auto client = orbit::Client::open(std::move(config), std::move(state_directory));
        try {
            std::cout << "Access JSON: " << client.require_access("export") << '\n';
        } catch (const orbit::Error& failure) {
            if (failure.code() != "access_unavailable") throw;
            std::cout << "Licence key: ";
            std::string licence_key;
            std::getline(std::cin, licence_key);
            client.activate(licence_key);
            std::cout << "Access JSON: " << client.require_access("export") << '\n';
        }
        client.close();
        return 0;
    } catch (const orbit::Error& error) {
        std::cerr << error.what() << " (kind=" << static_cast<std::uint32_t>(error.kind())
                  << ", code=" << error.code();
        if (!error.request_id().empty()) {
            std::cerr << ", request_id=" << error.request_id();
        }
        std::cerr << ")\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Example failed: " << error.what() << '\n';
        return 1;
    }
}
