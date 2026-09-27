#include "app_version.hpp"

#include "error.hpp"

#include <algorithm>

#ifndef ORBIT_SDK_VERSION
#error "ORBIT_SDK_VERSION must come from the CMake project version"
#endif

namespace orbit::detail {
namespace {

bool digit(char c) { return c >= '0' && c <= '9'; }
bool lower(char c) { return c >= 'a' && c <= 'z'; }

bool number(std::string_view part) {
    return !part.empty() && std::all_of(part.begin(), part.end(), digit) &&
           (part == "0" || part.front() != '0');
}

bool identifier(std::string_view part) {
    return !part.empty() && std::all_of(part.begin(), part.end(), [](char c) {
        return digit(c) || lower(c) || (c >= 'A' && c <= 'Z') || c == '-';
    });
}

template <typename Check>
bool all_parts(std::string_view value, Check check, std::size_t max_parts = 0) {
    std::size_t count = 0;
    while (true) {
        const auto dot = value.find('.');
        if (!check(value.substr(0, dot))) return false;
        ++count;
        if (max_parts != 0 && count > max_parts) return false;
        if (dot == std::string_view::npos) return true;
        value.remove_prefix(dot + 1);
    }
}

std::string platform() {
#if defined(_WIN32)
    std::string os = "windows";
#elif defined(__APPLE__)
    std::string os = "macos";
#elif defined(__linux__)
    std::string os = "linux";
#elif defined(__FreeBSD__)
    std::string os = "freebsd";
#else
    std::string os = "unknown";
#endif
#if defined(__x86_64__) || defined(_M_X64)
    const char* arch = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    const char* arch = "aarch64";
#elif defined(__i386__) || defined(_M_IX86)
    const char* arch = "x86";
#elif defined(__arm__) || defined(_M_ARM)
    const char* arch = "arm";
#else
    const char* arch = "unknown";
#endif
    return os + "-" + arch;
}

} // namespace

bool valid_app_version(std::string_view value) {
    if (value.empty() || value.size() > 32) return false;
    const auto plus = value.find('+');
    const auto rest = value.substr(0, plus);
    const auto dash = rest.find('-');
    if (!all_parts(rest.substr(0, dash), number, 4)) return false;
    if (dash != std::string_view::npos &&
        !all_parts(rest.substr(dash + 1), [](std::string_view part) {
            return identifier(part) &&
                   (!std::all_of(part.begin(), part.end(), digit) || number(part));
        }))
        return false;
    return plus == std::string_view::npos || all_parts(value.substr(plus + 1), identifier);
}

std::optional<std::string> format_client_header(std::string_view language,
                                                std::string_view sdk_version,
                                                std::string_view platform_value) {
    const bool language_valid =
        !language.empty() && language.size() <= 16 && lower(language.front()) &&
        std::all_of(language.begin(), language.end(),
                    [](char c) { return lower(c) || digit(c) || c == '-'; });
    const bool platform_valid =
        !platform_value.empty() && platform_value.size() <= 32 &&
        (lower(platform_value.front()) || digit(platform_value.front())) &&
        std::all_of(platform_value.begin(), platform_value.end(), [](char c) {
            return lower(c) || digit(c) || c == '_' || c == '.' || c == '-';
        });
    if (!language_valid || !platform_valid || !valid_app_version(sdk_version)) return std::nullopt;
    std::string header;
    header.append(language).append("/").append(sdk_version).append(" (")
        .append(platform_value).append(")");
    if (header.size() > 128) return std::nullopt;
    return header;
}

const std::string& client_header() {
    static const std::string value = [] {
        auto header = format_client_header("cpp", ORBIT_SDK_VERSION, platform());
        if (!header) header = format_client_header("cpp", ORBIT_SDK_VERSION, "unknown");
        return header.value_or("cpp/0 (unknown)");
    }();
    return value;
}

std::optional<std::string> update_hint(const Json::Value& reply) {
    if (!reply.isObject() || !reply.isMember("update_available")) return std::nullopt;
    const auto& hint = reply["update_available"];
    if (!hint.isObject() || !hint.isMember("version") || !hint["version"].isString() ||
        !valid_app_version(hint["version"].asString()))
        raise(ErrorKind::invalid_response, "invalid_response");
    return hint["version"].asString();
}

} // namespace orbit::detail
