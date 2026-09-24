#include <orbit_sdk.hpp>

#include <iostream>
#include <string>
#include <string_view>
#include <utility>

int main(int argc, char** argv) {
    const bool smoke = argc == 2 && std::string_view(argv[1]) == "--smoke";
    if (!smoke && (argc < 5 || argc > 6)) {
        std::cerr << "Usage: orbit-cpp-licensed-export API_ORIGIN APP_ID ENV_ID ISSUER [INSTALLATION_ID]\n"
                     "       orbit-cpp-licensed-export --smoke\n";
        return 2;
    }

    try {
        orbit::Config config;
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
                config.installation_id = argv[5];
            }
        }

        auto client = orbit::Client::connect(std::move(config));
        std::cout << "Installation ID (public; persist and reuse): "
                  << client.installation_id() << '\n';
        std::cout << "Snapshot JSON: " << client.snapshot() << '\n';
        if (smoke) {
            std::cout << "No network request was made.\n";
            return 0;
        }

        std::cout << "Licence key: ";
        std::string licence_key;
        std::getline(std::cin, licence_key);
        const auto operation_id = orbit::new_installation_id();
        std::cout << "Activation JSON: "
                  << client.activate(licence_key, operation_id) << '\n';
        std::cout << "Access JSON: " << client.require_access("export") << '\n';
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
