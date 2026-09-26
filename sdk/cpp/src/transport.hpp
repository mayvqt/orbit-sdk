#pragma once

#include "json.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail {

struct HttpResponse {
    long status = 0;
    std::string body;
    std::string retry_after;
};

class Transport {
public:
    using TestHandler = std::function<HttpResponse(
        std::string_view method, std::string_view url,
        std::string_view authorization, std::string_view body,
        const std::atomic_bool& cancelled)>;

    explicit Transport(std::string_view origin);
    std::optional<Json::Value> get(std::string_view path,
                                   const std::atomic_bool& cancelled) const;
    std::optional<Json::Value> get_bearer(std::string_view path,
                                          std::string_view bearer,
                                          const std::atomic_bool& cancelled) const;
    std::optional<Json::Value> delete_bearer(std::string_view path,
                                             std::string_view bearer,
                                             const std::atomic_bool& cancelled) const;
    std::optional<Json::Value> post(std::string_view path, const Json::Value& body,
                                    bool retry_safe,
                                    const std::atomic_bool& cancelled) const;

#ifdef ORBIT_SDK_TESTING
    Transport(std::string origin, TestHandler handler);
    Transport(std::string origin, std::string trusted_test_ca_file);
#endif

private:
    std::optional<Json::Value> request(std::string_view method, std::string_view path,
                                       std::string_view body, std::string_view bearer,
                                       bool retry_safe,
                                       const std::atomic_bool& cancelled) const;
    std::string endpoint(std::string_view path) const;
    HttpResponse attempt(std::string_view method, std::string_view url,
                         std::string_view body, std::string_view bearer,
                         const std::atomic_bool& cancelled, long timeout_ms) const;

    std::string origin_;
#ifdef ORBIT_SDK_TESTING
    TestHandler test_handler_;
    std::string trusted_test_ca_file_;
#endif
};

} // namespace orbit::detail
