#include "orbit_sdk.hpp"
#include "error.hpp"
#include "grants.hpp"
#include "transport.hpp"

#include <algorithm>
#include <array>

namespace orbit {
namespace {
constexpr std::int64_t maximum_time = 253402300799;
constexpr std::int64_t maximum_length = 9007199254740991;

[[noreturn]] void invalid() { detail::raise(ErrorKind::denied, "invalid_download_ticket"); }
[[noreturn]] void invalid_keys() { detail::raise(ErrorKind::configuration, "invalid_download_keys"); }
[[noreturn]] void invalid_endpoint() { detail::raise(ErrorKind::configuration, "invalid_download_endpoint"); }

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-';
        });
}

bool hex(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

void validate_port(std::string_view port) {
    if (port.empty()) invalid_endpoint();
    unsigned value = 0;
    for (const auto c : port) {
        if (c < '0' || c > '9') invalid_endpoint();
        value = value * 10 + static_cast<unsigned>(c - '0');
        if (value > 65535) invalid_endpoint();
    }
    if (value == 0) invalid_endpoint();
}

void validate_endpoint(std::string_view endpoint, bool allow_query = false) {
    try {
        if (endpoint.empty() || endpoint.size() > 2048 || endpoint.substr(0, 8) != "https://" ||
            std::any_of(endpoint.begin(), endpoint.end(), [allow_query](unsigned char c) {
                return c <= 32 || c >= 127 || std::string_view("\\#<>\"{}|^`").find(c) != std::string_view::npos || (!allow_query && c == '?');
            })) invalid_endpoint();
        for (std::size_t i = 0; i < endpoint.size(); ++i) {
            if (endpoint[i] != '%') continue;
            if (i + 2 >= endpoint.size() || !hex(endpoint[i + 1]) || !hex(endpoint[i + 2])) invalid_endpoint();
            i += 2;
        }
        const auto path_start = endpoint.find_first_of("/?", 8);
        const auto authority = endpoint.substr(8, path_start == std::string_view::npos
            ? endpoint.size() - 8 : path_start - 8);
        if (authority.empty() || authority.find('@') != std::string_view::npos ||
            authority.find('%') != std::string_view::npos) invalid_endpoint();
        if (authority.front() == '[') {
            const auto close = authority.find(']');
            if (close == std::string_view::npos || close < 2) invalid_endpoint();
            const auto suffix = authority.substr(close + 1);
            if (!suffix.empty()) {
                if (suffix.front() != ':') invalid_endpoint();
                validate_port(suffix.substr(1));
            }
        } else {
            if (authority.find_first_of("[]") != std::string_view::npos) invalid_endpoint();
            const auto colon = authority.find(':');
            if (colon != std::string_view::npos) {
                if (colon != authority.rfind(':')) invalid_endpoint();
                validate_port(authority.substr(colon + 1));
                if (colon == 0) invalid_endpoint();
            }
        }
        const auto origin = endpoint.substr(0, path_start);
        const detail::Transport parsed(origin);
    } catch (const Error&) { invalid_endpoint(); }
}

detail::GrantKeys parse_keys(std::string_view bytes, std::string_view environment) {
    try {
        auto value = detail::parse_json(bytes, 16384);
        auto keys = detail::GrantKeys::parse(value);
        const auto prefix = std::string(environment) + "-";
        for (const auto& entry : value["keys"]) {
            const auto kid = entry["kid"].asString();
            if (!opaque(kid) || kid.compare(0, prefix.size(), prefix) != 0 || kid.size() == prefix.size()) invalid_keys();
        }
        return keys;
    } catch (const Error&) { invalid_keys(); }
}

std::string text(const Json::Value& value, const char* name) {
    if (!value[name].isString()) invalid();
    return value[name].asString();
}
} // namespace

namespace detail {
void validate_delivery_url(std::string_view url, bool allow_query) { validate_endpoint(url, allow_query); }
}

struct DownloadTicketVerifier::State {
    AppKey app;
    std::string endpoint;
    detail::GrantKeys keys;
};

DownloadTicketVerifier::DownloadTicketVerifier(std::string_view app_key, std::string_view endpoint,
                                             std::string_view public_keys) {
    auto app = AppKey::parse(app_key);
    validate_endpoint(endpoint);
    auto keys = parse_keys(public_keys, app.environment());
    state_ = std::make_shared<const State>(State{std::move(app), std::string(endpoint), std::move(keys)});
}

DownloadTicket DownloadTicketVerifier::verify(std::string_view token, std::optional<Timestamp> now) const {
    try {
        const auto trusted_now = now ? *now : std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::system_clock::now());
        const auto seconds = trusted_now.time_since_epoch().count();
        if (seconds < 0 || seconds > maximum_time) invalid();
        const auto claims = state_->keys.verify_download_signature(token);
        constexpr std::array<const char*, 14> fields = {"ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp",
            "application_id", "environment_id", "release_id", "artifact_id", "sha256", "byte_length"};
        if (!claims.isObject() || claims.size() != fields.size()) invalid();
        for (const auto* name : fields) if (!claims.isMember(name)) invalid();
        for (const auto* name : {"sub", "jti", "application_id", "environment_id", "release_id", "artifact_id"})
            if (!opaque(text(claims, name))) invalid();
        const auto issued = detail::json_int64(claims["iat"]);
        const auto expires = detail::json_int64(claims["exp"]);
        const auto length = detail::json_int64(claims["byte_length"]);
        const auto digest = text(claims, "sha256");
        if (detail::json_int64(claims["ver"]) != 1 || text(claims, "iss") != state_->app.issuer() ||
            text(claims, "aud") != state_->endpoint ||
            text(claims, "application_id") != state_->app.application_id() ||
            text(claims, "environment_id") != state_->app.environment_id() || issued < 0 || issued > maximum_time ||
            detail::json_int64(claims["nbf"]) != issued || issued > seconds + 30 ||
            expires <= seconds || expires > maximum_time || expires <= issued || expires - issued > 120 ||
            length < 1 || length > maximum_length || digest.size() != 64 ||
            !std::all_of(digest.begin(), digest.end(), [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            })) invalid();
        return {text(claims, "sub"), text(claims, "release_id"), text(claims, "artifact_id"), digest,
            length, text(claims, "jti"), Timestamp(std::chrono::seconds(issued)), Timestamp(std::chrono::seconds(expires))};
    } catch (const Error&) { invalid(); }
}
} // namespace orbit
