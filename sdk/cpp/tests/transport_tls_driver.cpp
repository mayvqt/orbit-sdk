#include "error.hpp"
#include "transport.hpp"
#include "online.hpp"
#include <filesystem>
#include <fstream>

#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using orbit::Error;
using orbit::ErrorKind;
using orbit::detail::Transport;

void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

template <class Call>
void expect_error(Call&& call, ErrorKind expected) {
    try {
        call();
    } catch (const Error& error) {
        require(error.kind() == expected, "request returned an unexpected Orbit error kind");
        return;
    }
    throw std::runtime_error("request unexpectedly succeeded");
}

void expect_route_rejections(std::string_view origin) {
    const Transport transport(origin);
    const std::atomic_bool not_cancelled{false};
    const std::vector<std::string> bad_routes = {
        "/api/client/v1/../admin",
        "/api/client/v1/%2e%2e/admin",
        "/api/client/v1/status/./child",
        "/api/client/v1/status/",
        "/api/client/v1/licences",
        "/api/client/v1/sessions/current",
        "/api/client/v1/licences?environment_id=test&application_id=app",
        "/api/client/v1/sessions/current?application_id=app",
        "/api/client/v1/sessions/current?application_id=app&environment_id=test&after=cursor",
        "/api/client/v1/licences?application_id=app&environment_id=test&after=bad%2Fcursor",
    };
    for (const auto& route : bad_routes) {
        expect_error([&] { (void)transport.get(route, not_cancelled); },
                     ErrorKind::configuration);
    }
}

void test_downloads(std::string_view origin, std::string_view ca_file) {
    using namespace orbit;
    const auto directory = std::filesystem::temp_directory_path() / ("orbit-stream-" + new_installation_id());
    std::filesystem::create_directory(directory);
    const auto path = (directory / "artifact.bin").string();
    const std::atomic_bool ready{false};
    auto authorization = [&](std::string_view route, bool protect = false) {
        DownloadAuthorization result;
        result.artifact = {"artifact",
                           "release",
                           {"linux", "x64"},
                           "ignored.bin",
                           3,
                           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                           protect ? DeliveryMode::protected_endpoint : DeliveryMode::public_url,
                           std::string(origin) + std::string(route),
                           std::nullopt};
        if (protect) {
            result.ticket = "e30.e30.c2ln";
            result.expires_at =
                std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now()) +
                std::chrono::seconds(120);
        }
        return result;
    };
    auto read = [&] {
        std::ifstream input(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), {});
    };
    auto intact = [&] {
        require(read() == "abc", "failed download changed existing destination");
        require(std::distance(std::filesystem::directory_iterator(directory),
                              std::filesystem::directory_iterator{}) == 1,
                "download left a temporary file");
    };
    auto failure = [&](std::string_view route) {
        try {
            detail::download_stream(authorization(route), path, 3, true, ready, ca_file);
        } catch (const Error &) {
            intact();
            return;
        }
        throw std::runtime_error("invalid download was accepted");
    };
    try {
        expect_error(
            [&] { detail::download_stream(authorization("/download/bytes"), path, 3, false, ready); },
            ErrorKind::transport_security);
        require(!std::filesystem::exists(path), "untrusted TLS exposed an artifact");
        detail::download_stream(authorization("/download/redirect/5", true), path, 3, false, ready, ca_file);
        intact();
        expect_error(
            [&] {
                detail::download_stream(authorization("/download/bytes"), path, 3, false, ready, ca_file);
            },
            ErrorKind::storage);
        for (const auto route :
             {"/download/redirect/6", "/download/downgrade", "/download/encoded", "/download/length",
              "/download/oversize", "/download/short", "/download/wrong"})
            failure(route);
        std::atomic_bool cancelled{false};
        std::thread cancel([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            cancelled = true;
        });
        try {
            expect_error(
                [&] {
                    detail::download_stream(authorization("/download/slow"), path, 3, true, cancelled,
                                            ca_file);
                },
                ErrorKind::cancelled);
        } catch (...) {
            cancel.join();
            throw;
        }
        cancel.join();
        intact();
        detail::download_stream(authorization("/download/chunked"), path, 3, true, ready, ca_file);
        intact();
    } catch (...) {
        std::filesystem::remove_all(directory);
        throw;
    }
    std::filesystem::remove_all(directory);
}

void run(std::string_view scenario, std::string_view origin, std::string_view ca_file) {
    const std::atomic_bool not_cancelled{false};
    if (scenario == "downloads") {
        test_downloads(origin, ca_file);
        return;
    }
    if (scenario == "routes") {
        expect_route_rejections(origin);
        return;
    }
    if (scenario == "refused") {
        const Transport transport(origin);
        expect_error([&] { (void)transport.get("/api/client/v1/status", not_cancelled); },
                     ErrorKind::transient);
        return;
    }
    if (scenario == "untrusted") {
        const Transport transport(origin);
        expect_error([&] { (void)transport.get("/api/client/v1/status/success", not_cancelled); },
                     ErrorKind::transport_security);
        return;
    }

    const Transport transport{std::string(origin), std::string(ca_file)};
    if (scenario == "success") {
        const auto response = transport.get("/api/client/v1/status/success", not_cancelled);
        require(response && response->isObject() && (*response)["ok"].asBool(),
                "trusted test CA did not return the expected JSON response");
    } else if (scenario == "hostname") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/success", not_cancelled);
        }, ErrorKind::transport_security);
    } else if (scenario == "redirect") {
        expect_error([&] {
            (void)transport.get_bearer(
                "/api/client/v1/sessions/current?application_id=app&environment_id=test",
                "synthetic_bearer_123", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "body-limit") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/body-limit", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "header-limit") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/header-limit", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "cancel" || scenario == "owner-cancel") {
        std::atomic_bool cancelled{false};
        auto owner = std::make_shared<std::atomic_bool>(false);
        auto cancellable = transport;
        if (scenario == "owner-cancel") cancellable.bind_owner_cancellation(owner);
        const auto started = std::chrono::steady_clock::now();
        std::thread cancel_after_request([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (scenario == "owner-cancel") owner->store(true, std::memory_order_relaxed);
            else cancelled.store(true, std::memory_order_relaxed);
        });
        try {
            expect_error([&] {
                (void)cancellable.get("/api/client/v1/status/stall", cancelled);
            }, ErrorKind::cancelled);
        } catch (...) {
            cancel_after_request.join();
            throw;
        }
        cancel_after_request.join();
        require(std::chrono::steady_clock::now() - started < std::chrono::seconds(2),
                "in-flight TLS cancellation did not settle promptly");
    } else if (scenario == "deadline" || scenario == "stalled-deadline") {
        Json::Value body(Json::objectValue);
        body["idempotency_key"] = "synthetic_tls_deadline_1";
        const auto started = std::chrono::steady_clock::now();
        expect_error([&] {
            const auto route = scenario == "deadline"
                                   ? "/api/client/v1/activations/deadline"
                                   : "/api/client/v1/activations/stalled-deadline";
            (void)transport.post(route, body,
                                 false, not_cancelled);
        }, ErrorKind::transient);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        require(elapsed >= std::chrono::seconds(9) && elapsed < std::chrono::seconds(13),
                "stalled or trickled response did not obey the transfer deadline");
    } else if (scenario == "duplicate-field" || scenario == "duplicate-member") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/" + std::string(scenario),
                                not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "proxy-html") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/proxy-html", not_cancelled);
        }, ErrorKind::transient);
    } else if (scenario == "valid-bounds") {
        try {
            (void)transport.get("/api/client/v1/status/valid-bounds", not_cancelled);
        } catch (const Error& error) {
            require(error.kind() == ErrorKind::denied && error.code().size() == 128 &&
                        error.request_id().size() == 64,
                    "maximum valid diagnostic lengths were rejected or truncated");
            return;
        }
        throw std::runtime_error("valid diagnostic error envelope unexpectedly succeeded");
    } else if (scenario == "code-too-long") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/code-too-long", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "request-id-too-long") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/request-id-too-long", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "nonfinite") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/nonfinite", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "surrogate-value") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/surrogate-value", not_cancelled);
        }, ErrorKind::invalid_response);
    } else if (scenario == "surrogate-key") {
        expect_error([&] {
            (void)transport.get("/api/client/v1/status/surrogate-key", not_cancelled);
        }, ErrorKind::invalid_response);
    } else {
        throw std::runtime_error("unknown transport TLS scenario");
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        require(argc == 4, "expected scenario, origin, and test CA path");
        run(argv[1], argv[2], argv[3]);
        return 0;
    } catch (const orbit::Error& error) {
        std::cerr << "transport_tls_driver: kind=" << static_cast<int>(error.kind()) << " code=" << error.code() << '\n';
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "transport_tls_driver: " << error.what() << '\n';
        return 1;
    }
}
