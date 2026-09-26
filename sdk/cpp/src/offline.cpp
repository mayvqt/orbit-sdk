#include "offline.hpp"
#include "error.hpp"

#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <limits>
#include <set>

namespace orbit::detail {
namespace {
constexpr std::int64_t maximum_time = 253402300799;
constexpr std::int64_t maximum_sequence = 9007199254740991;
constexpr std::int64_t maximum_lifetime = 366LL * 86400;
[[noreturn]] void invalid() { raise(ErrorKind::invalid_response, "invalid_offline_file"); }

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-';
        });
}

std::string text(const Json::Value& value, const char* name) {
    if (!value.isObject() || !value.isMember(name) || !value[name].isString()) invalid();
    return value[name].asString();
}

bool feature(std::string_view name) {
    return !name.empty() && name.size() <= 64 && name[0] >= 'a' && name[0] <= 'z' &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        });
}

bool valid_fingerprint(const Fingerprint& fingerprint) {
    const auto& value = fingerprint.value;
    const auto& provider = fingerprint.provider;
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }) && (provider == "machine_v1" || (provider.size() > 7 && provider.size() <= 55 &&
        provider.compare(0, 7, "custom:") == 0 &&
        std::all_of(provider.begin() + 7, provider.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        })));
}

std::string digest(const Json::Value& claims) {
    // JsonCpp object members are ordered by name; integer-only accepted claims
    // and UTF-8 output match the shared canonical renewal representation.
    const auto canonical = encode_json(claims);
    std::array<unsigned char, SHA256_DIGEST_LENGTH> bytes{};
    if (!SHA256(reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(), bytes.data())) invalid();
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto value : bytes) { result.push_back(hex[value >> 4]); result.push_back(hex[value & 15]); }
    return result;
}
} // namespace

OfflineKeys OfflineKeys::parse_jwks(std::string_view jwks, std::string_view environment) {
    return parse(parse_json(jwks, 16384), environment);
}

OfflineKeys OfflineKeys::parse(const Json::Value& jwks, std::string_view environment) {
    if ((environment != "test" && environment != "live") || encode_json(jwks).size() > 16384) invalid();
    auto keys = GrantKeys::parse(jwks);
    const auto prefix = "offline-" + std::string(environment) + "-";
    for (const auto& entry : jwks["keys"]) {
        const auto kid = text(entry, "kid");
        if (!opaque(kid) || kid.compare(0, prefix.size(), prefix) != 0 || kid.size() == prefix.size()) invalid();
    }
    return OfflineKeys(std::move(keys), std::string(environment));
}

OfflineFile OfflineKeys::verify(std::string_view token, const OfflineExpected& expected) const {
    if (token.size() > 16384 || std::any_of(token.begin(), token.end(), [](unsigned char c) { return c > 127; }) ||
        expected.app_key.environment() != environment_ || !opaque(expected.installation_id) ||
        expected.installation_id.size() < 16 || expected.now < 0 || expected.now > maximum_time ||
        expected.minimum_sequence < 1 || expected.minimum_sequence > maximum_sequence ||
        (expected.fingerprint && !valid_fingerprint(*expected.fingerprint))) invalid();
    constexpr std::string_view whitespace = " \t\r\n\v\f";
    const auto first = token.find_first_not_of(whitespace);
    if (first == std::string_view::npos) invalid();
    token = token.substr(first, token.find_last_not_of(whitespace) - first + 1);
    auto verified = keys_.verify_offline_signature(token);
    const auto& claims = verified.claims;
    const auto binding = text(claims, "binding_mode");
    std::set<std::string> fields = {"ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp",
        "application_id", "environment_id", "activation_id", "installation_id", "sequence",
        "binding_mode", "policy_version", "entitlements"};
    if (claims.isMember("licence_expires_at")) fields.emplace("licence_expires_at");
    if (binding == "hwid") { fields.emplace("fingerprint"); fields.emplace("fingerprint_provider"); }
    for (const auto& name : claims.getMemberNames()) if (fields.erase(name) != 1) invalid();
    if (!fields.empty()) invalid();
    for (const auto* name : {"sub", "jti", "application_id", "environment_id", "activation_id", "installation_id"})
        if (!opaque(text(claims, name))) invalid();
    const auto issued = json_int64(claims["iat"]);
    const auto expires = json_int64(claims["exp"]);
    const auto sequence = json_int64(claims["sequence"]);
    const auto policy = json_int64(claims["policy_version"]);
    std::optional<std::int64_t> licence_expiry;
    if (claims.isMember("licence_expires_at")) licence_expiry = json_int64(claims["licence_expires_at"]);
    if (json_int64(claims["ver"]) != 1 || text(claims, "iss") != expected.app_key.issuer() ||
        text(claims, "aud") != "orbit-offline:" + expected.app_key.application_id() + ":" + expected.app_key.environment_id() ||
        text(claims, "application_id") != expected.app_key.application_id() ||
        text(claims, "environment_id") != expected.app_key.environment_id() ||
        text(claims, "installation_id") != expected.installation_id || sequence < expected.minimum_sequence ||
        sequence > maximum_sequence || policy < 1 || policy > std::numeric_limits<std::int32_t>::max() ||
        issued < 0 || issued > maximum_time || json_int64(claims["nbf"]) != issued || issued > expected.now + 30 ||
        expires <= expected.now || expires > maximum_time || expires <= issued || expires - issued > maximum_lifetime ||
        (licence_expiry && (*licence_expiry < expires || *licence_expiry > maximum_time))) invalid();
    if (binding == "hwid") {
        if (!expected.fingerprint || text(claims, "fingerprint") != expected.fingerprint->value ||
            text(claims, "fingerprint_provider") != expected.fingerprint->provider) invalid();
    } else if (binding != "none") invalid();
    const auto& values = claims["entitlements"];
    if (!values.isObject() || values.size() > 64) invalid();
    std::map<std::string, bool> entitlements;
    for (const auto& name : values.getMemberNames()) {
        if (!feature(name) || !values[name].isBool()) invalid();
        entitlements.emplace(name, values[name].asBool());
    }
    return {std::string(token), std::move(verified.key_id), text(claims, "sub"), text(claims, "activation_id"),
        expected.installation_id, text(claims, "jti"), issued, expires, licence_expiry, sequence,
        static_cast<std::int32_t>(policy), std::move(entitlements), digest(claims)};
}
} // namespace orbit::detail
