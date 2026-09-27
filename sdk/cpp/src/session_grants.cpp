#include "session_grants.hpp"

#include "error.hpp"

#include <algorithm>
#include <limits>
#include <set>

namespace orbit::detail {
namespace {

constexpr std::int64_t max_time = 253402300799LL;
constexpr std::int64_t max_sequence = 9007199254740991LL;

[[noreturn]] void invalid(std::string_view code = "invalid_session_grant") {
    raise(ErrorKind::invalid_response, std::string(code));
}

const Json::Value &required(const Json::Value &value, const char *name) {
    if (!value.isObject() || !value.isMember(name))
        invalid();
    return value[name];
}

std::string string_value(const Json::Value &value) {
    if (!value.isString())
        invalid();
    return value.asString();
}

std::int64_t integer_value(const Json::Value &value) {
    if ((value.type() != Json::intValue && value.type() != Json::uintValue) || !value.isInt64())
        invalid();
    return value.asInt64();
}

std::optional<std::int64_t> optional_integer(const Json::Value &value, const char *name) {
    if (!value.isObject())
        invalid();
    if (!value.isMember(name) || value[name].isNull())
        return std::nullopt;
    return integer_value(value[name]);
}

std::optional<std::string> optional_string(const Json::Value &value, const char *name) {
    if (!value.isObject())
        invalid();
    if (!value.isMember(name))
        return std::nullopt;
    return string_value(value[name]);
}

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
           });
}

bool lower_hex(std::string_view value, std::size_t size) {
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

bool valid_provider(std::string_view value) {
    if (value == "machine_v1")
        return true;
    constexpr std::string_view prefix = "custom:";
    if (value.size() < 8 || value.size() > 55 || value.substr(0, prefix.size()) != prefix)
        return false;
    return std::all_of(
        value.begin() + static_cast<std::ptrdiff_t>(prefix.size()), value.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        });
}

bool feature(std::string_view name) {
    return !name.empty() && name.size() <= 64 && name.front() >= 'a' && name.front() <= 'z' &&
           std::all_of(name.begin(), name.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
           });
}

std::int64_t add_saturated(std::int64_t value, std::int64_t delta) {
    if (delta > 0 && value > std::numeric_limits<std::int64_t>::max() - delta)
        return std::numeric_limits<std::int64_t>::max();
    return value + delta;
}

} // namespace

SessionKeys SessionKeys::parse_jwks(std::string_view input, std::string_view environment) {
    if (input.size() > 16384)
        invalid("invalid_session_keys");
    return parse(parse_json(input, 16384), environment);
}

SessionKeys SessionKeys::parse(const Json::Value &jwks, std::string_view environment) {
    if (environment != "test" && environment != "live")
        invalid("invalid_session_keys");
    try {
        auto keys = GrantKeys::parse(jwks);
        const auto prefix = std::string(environment) + "-";
        for (const auto &key : jwks["keys"]) {
            const auto kid = string_value(required(key, "kid"));
            if (!opaque(kid) || kid.size() == prefix.size() || kid.substr(0, prefix.size()) != prefix)
                invalid("invalid_session_keys");
        }
        return SessionKeys(std::move(keys), std::string(environment));
    } catch (const Error &error) {
        if (error.code() == "invalid_session_keys")
            throw;
        invalid("invalid_session_keys");
    }
}

bool SessionKeys::contains(std::string_view token) const {
    try {
        return keys_.contains_session(token);
    } catch (...) {
        return false;
    }
}

SessionGrant SessionKeys::verify(std::string_view token, const SessionExpected &expected) const {
    try {
        constexpr std::string_view known[] = {"iss",
                                              "aud",
                                              "sub",
                                              "jti",
                                              "iat",
                                              "nbf",
                                              "exp",
                                              "application_id",
                                              "environment_id",
                                              "activation_id",
                                              "installation_id",
                                              "binding_mode",
                                              "fingerprint",
                                              "fingerprint_provider",
                                              "policy_version",
                                              "entitlements",
                                              "refresh_after",
                                              "offline_allowed",
                                              "licence_expires_at",
                                              "session_id",
                                              "session_sequence"};
        const auto claims = keys_.verify_session_signature(token);
        if (!claims.isObject())
            invalid();
        for (const auto &name : claims.getMemberNames()) {
            const auto match = std::find_if(std::begin(known), std::end(known),
                                            [&name](auto field) { return field == name; });
            if (match == std::end(known)) {
                auto lowered = name;
                std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
                    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
                });
                if (std::any_of(std::begin(known), std::end(known),
                                [&lowered](auto field) { return lowered == field; }))
                    invalid();
            }
        }
        SessionGrant output;
        output.session_id = string_value(required(claims, "session_id"));
        output.sequence = integer_value(required(claims, "session_sequence"));
        output.licence_id = string_value(required(claims, "sub"));
        output.token_id = string_value(required(claims, "jti"));
        output.issued_at = integer_value(required(claims, "iat"));
        const auto nbf = integer_value(required(claims, "nbf"));
        output.expires_at = integer_value(required(claims, "exp"));
        output.refresh_after = integer_value(required(claims, "refresh_after"));
        const auto policy = integer_value(required(claims, "policy_version"));
        if (policy < 1 || policy > INT32_MAX)
            invalid();
        output.policy_version = static_cast<std::int32_t>(policy);
        output.licence_expires_at = optional_integer(claims, "licence_expires_at");
        output.activation_id = string_value(required(claims, "activation_id"));
        output.installation_id = string_value(required(claims, "installation_id"));
        output.binding_mode = string_value(required(claims, "binding_mode"));
        const auto fingerprint_present = claims.isMember("fingerprint");
        const auto provider_present = claims.isMember("fingerprint_provider");
        output.entitlements.clear();
        const auto &entitlements = required(claims, "entitlements");
        if (!entitlements.isObject() || entitlements.size() > 64)
            invalid();
        for (const auto &name : entitlements.getMemberNames()) {
            if (!feature(name) || !entitlements[name].isBool())
                invalid();
            output.entitlements.emplace(name, entitlements[name].asBool());
        }
        const auto &expected_grant = expected.grant;
        const auto configured_pair = expected_grant.fingerprint && expected_grant.fingerprint_provider;
        const auto expected_unbound = !expected_grant.fingerprint && !expected_grant.fingerprint_provider;
        bool binding_ok = output.binding_mode == "none" && !fingerprint_present && !provider_present &&
                          (expected_unbound || (expected_grant.allow_unbound_fingerprint && configured_pair));
        if (output.binding_mode == "hwid") {
            const auto fingerprint = optional_string(claims, "fingerprint");
            const auto provider = optional_string(claims, "fingerprint_provider");
            binding_ok = fingerprint && provider && lower_hex(*fingerprint, 64) &&
                         valid_provider(*provider) && expected_grant.fingerprint &&
                         expected_grant.fingerprint_provider && *fingerprint == *expected_grant.fingerprint &&
                         *provider == *expected_grant.fingerprint_provider;
        }
        const auto &offline_value = required(claims, "offline_allowed");
        if (!offline_value.isBool())
            invalid();
        const bool offline_allowed = offline_value.asBool();
        const auto licence_expiry = output.licence_expires_at;
        if (!opaque(output.session_id) || output.session_id.size() < 16 ||
            output.session_id != expected.session_id || output.sequence < 1 ||
            output.sequence > max_sequence || output.sequence != expected.sequence || offline_allowed ||
            output.licence_id.empty() || output.licence_id.size() > 128 || output.token_id.empty() ||
            output.token_id.size() > 128 || output.activation_id.empty() ||
            output.activation_id.size() > 128 || output.installation_id.empty() ||
            output.installation_id.size() > 128 ||
            string_value(required(claims, "iss")) != expected_grant.issuer ||
            string_value(required(claims, "aud")) !=
                "orbit-session:" + std::string(expected_grant.application) + ":" +
                    std::string(expected_grant.environment) ||
            (expected_grant.licence && output.licence_id != *expected_grant.licence) ||
            string_value(required(claims, "application_id")) != expected_grant.application ||
            string_value(required(claims, "environment_id")) != expected_grant.environment ||
            output.activation_id != expected_grant.activation ||
            output.installation_id != expected_grant.installation || !binding_ok || nbf != output.issued_at ||
            output.issued_at < 0 || output.issued_at > max_time || expected_grant.now < 0 ||
            expected_grant.now > max_time || output.issued_at > add_saturated(expected_grant.now, 30) ||
            output.expires_at <= expected_grant.now || output.expires_at <= output.issued_at ||
            output.expires_at - output.issued_at > 120 ||
            (expected_grant.credential_expires_at &&
             output.expires_at > *expected_grant.credential_expires_at) ||
            (licence_expiry && (*licence_expiry < 0 || *licence_expiry > max_time)) ||
            licence_expiry != expected_grant.licence_expires_at ||
            (licence_expiry && output.expires_at > *licence_expiry) ||
            output.refresh_after <= output.issued_at || output.refresh_after > output.expires_at ||
            output.refresh_after > add_saturated(output.issued_at, 75) ||
            (output.refresh_after < add_saturated(output.issued_at, 45) &&
             output.refresh_after != output.expires_at))
            invalid();
        return output;
    } catch (const Error &error) {
        if (error.code() == "invalid_session_grant")
            throw;
        invalid();
    } catch (...) {
        invalid();
    }
}

} // namespace orbit::detail
