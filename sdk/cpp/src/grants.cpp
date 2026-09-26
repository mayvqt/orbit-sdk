#include "grants.hpp"

#include "error.hpp"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <vector>

namespace orbit::detail {
namespace {

[[noreturn]] void invalid() { raise(ErrorKind::invalid_response, "invalid_response"); }

void only_fields(const Json::Value& value,
                 std::initializer_list<std::string_view> allowed) {
    if (!value.isObject()) invalid();
    for (const auto& key : value.getMemberNames()) {
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) invalid();
    }
}

const Json::Value& required(const Json::Value& value, const char* key) {
    if (!value.isMember(key)) invalid();
    return value[key];
}

std::string string_value(const Json::Value& value) {
    if (!value.isString()) invalid();
    return value.asString();
}

std::int64_t integer_value(const Json::Value& value) {
    return json_int64(value);
}

bool bool_value(const Json::Value& value) {
    if (!value.isBool()) invalid();
    return value.asBool();
}

std::string base64url_encode(const unsigned char* data, std::size_t size) {
    if (size > static_cast<std::size_t>(INT_MAX)) invalid();
    std::string encoded(4 * ((size + 2) / 3), '\0');
    const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()), data,
                                        static_cast<int>(size));
    if (length < 0) invalid();
    encoded.resize(static_cast<std::size_t>(length));
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    for (auto& c : encoded) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return encoded;
}

std::vector<unsigned char> base64url_decode(std::string_view input,
                                            std::size_t maximum = 16384) {
    if (input.empty() || input.size() > maximum || input.size() % 4 == 1 ||
        !std::all_of(input.begin(), input.end(), [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        })) invalid();
    std::string padded(input);
    for (auto& c : padded) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    const auto padding = (4 - (padded.size() % 4)) % 4;
    padded.append(padding, '=');
    std::vector<unsigned char> decoded(3 * (padded.size() / 4));
    const auto length = EVP_DecodeBlock(decoded.data(),
                                        reinterpret_cast<const unsigned char*>(padded.data()),
                                        static_cast<int>(padded.size()));
    if (length < 0 || static_cast<std::size_t>(length) < padding) invalid();
    decoded.resize(static_cast<std::size_t>(length) - padding);
    if (base64url_encode(decoded.data(), decoded.size()) != input) invalid();
    return decoded;
}

struct ParsedToken {
    std::string_view signing_input;
    std::string kid;
    Json::Value claims;
    std::vector<unsigned char> signature;
};

ParsedToken parse_token(std::string_view token) {
    if (token.empty() || token.size() > 16384) invalid();
    const auto first = token.find('.');
    if (first == std::string_view::npos) invalid();
    const auto second = token.find('.', first + 1);
    if (second == std::string_view::npos || token.find('.', second + 1) != std::string_view::npos) invalid();
    const auto header_bytes = base64url_decode(token.substr(0, first));
    const auto claim_bytes = base64url_decode(token.substr(first + 1, second - first - 1));
    auto signature = base64url_decode(token.substr(second + 1));
    if (signature.size() != 64) invalid();
    const std::string_view header_text(reinterpret_cast<const char*>(header_bytes.data()), header_bytes.size());
    const std::string_view claims_text(reinterpret_cast<const char*>(claim_bytes.data()), claim_bytes.size());
    const auto header = parse_json(header_text, 8192);
    only_fields(header, {"alg", "typ", "kid"});
    const auto alg = string_value(required(header, "alg"));
    const auto typ = string_value(required(header, "typ"));
    const auto kid = string_value(required(header, "kid"));
    if (alg != "ES256" || typ != "orbit-access+jwt" || kid.empty() || kid.size() > 128 ||
        std::any_of(kid.begin(), kid.end(), [](unsigned char c) { return c > 0x7f; })) invalid();
    return {token.substr(0, second), kid, parse_json(claims_text, 32768), std::move(signature)};
}

std::shared_ptr<EVP_PKEY> p256_key(std::string_view x, std::string_view y) {
    const auto x_bytes = base64url_decode(x, 256);
    const auto y_bytes = base64url_decode(y, 256);
    if (x_bytes.size() != 32 || y_bytes.size() != 32) invalid();
    std::array<unsigned char, 65> point{};
    point[0] = 0x04;
    std::copy(x_bytes.begin(), x_bytes.end(), point.begin() + 1);
    std::copy(y_bytes.begin(), y_bytes.end(), point.begin() + 33);

    EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!raw_context) invalid();
    const auto context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(raw_context, EVP_PKEY_CTX_free);
    if (EVP_PKEY_fromdata_init(raw_context) <= 0) invalid();
    char group[] = "prime256v1";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_fromdata(raw_context, &raw_key, EVP_PKEY_PUBLIC_KEY, parameters) <= 0 || !raw_key) invalid();
    auto key = std::shared_ptr<EVP_PKEY>(raw_key, EVP_PKEY_free);
    EVP_PKEY_CTX* raw_check = EVP_PKEY_CTX_new_from_pkey(nullptr, raw_key, nullptr);
    if (!raw_check) invalid();
    const auto check = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(raw_check, EVP_PKEY_CTX_free);
    if (EVP_PKEY_public_check(raw_check) <= 0) invalid();
    return key;
}

bool verify_signature(EVP_PKEY* key, std::string_view signing_input,
                      const std::vector<unsigned char>& raw_signature) {
    ECDSA_SIG* raw_ecdsa = ECDSA_SIG_new();
    if (!raw_ecdsa) invalid();
    const auto ecdsa = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>(raw_ecdsa, ECDSA_SIG_free);
    BIGNUM* r = BN_bin2bn(raw_signature.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw_signature.data() + 32, 32, nullptr);
    if (!r || !s || ECDSA_SIG_set0(raw_ecdsa, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        invalid();
    }
    const int der_size = i2d_ECDSA_SIG(raw_ecdsa, nullptr);
    if (der_size <= 0 || der_size > 128) invalid();
    std::vector<unsigned char> der(static_cast<std::size_t>(der_size));
    auto* output = der.data();
    if (i2d_ECDSA_SIG(raw_ecdsa, &output) != der_size) invalid();
    EVP_MD_CTX* raw_digest = EVP_MD_CTX_new();
    if (!raw_digest) invalid();
    const auto digest = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(raw_digest, EVP_MD_CTX_free);
    if (EVP_DigestVerifyInit(raw_digest, nullptr, EVP_sha256(), nullptr, key) != 1) invalid();
    const auto verified = EVP_DigestVerify(raw_digest, der.data(), der.size(),
        reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size());
    return verified == 1;
}

std::optional<std::string> optional_string(const Json::Value& value, const char* key) {
    if (!value.isMember(key) || value[key].isNull()) return std::nullopt;
    return string_value(value[key]);
}

std::optional<std::int64_t> optional_integer(const Json::Value& value, const char* key) {
    if (!value.isMember(key) || value[key].isNull()) return std::nullopt;
    return integer_value(value[key]);
}

GrantClaims parse_claims(const Json::Value& value) {
    if (!value.isObject()) invalid();
    GrantClaims claims;
    claims.issuer = string_value(required(value, "iss"));
    claims.audience = string_value(required(value, "aud"));
    claims.subject = string_value(required(value, "sub"));
    claims.token_id = string_value(required(value, "jti"));
    claims.issued_at = integer_value(required(value, "iat"));
    claims.not_before = integer_value(required(value, "nbf"));
    claims.expires_at = integer_value(required(value, "exp"));
    claims.application_id = string_value(required(value, "application_id"));
    claims.environment_id = string_value(required(value, "environment_id"));
    claims.activation_id = string_value(required(value, "activation_id"));
    claims.installation_id = string_value(required(value, "installation_id"));
    claims.binding_mode = string_value(required(value, "binding_mode"));
    claims.fingerprint = optional_string(value, "fingerprint");
    claims.fingerprint_provider = optional_string(value, "fingerprint_provider");
    const auto policy_version = integer_value(required(value, "policy_version"));
    if (policy_version < 1 ||
        policy_version > std::numeric_limits<std::int32_t>::max()) invalid();
    claims.policy_version = static_cast<std::int32_t>(policy_version);
    const auto& entitlements = required(value, "entitlements");
    if (!entitlements.isObject() || entitlements.size() > 64) invalid();
    for (const auto& name : entitlements.getMemberNames()) {
        if (name.empty() || name.size() > 64 || name.front() < 'a' || name.front() > 'z' ||
            !std::all_of(name.begin(), name.end(), [](unsigned char c) {
                return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            }) || !entitlements[name].isBool()) invalid();
        claims.entitlements.emplace(name, entitlements[name].asBool());
    }
    claims.refresh_after = integer_value(required(value, "refresh_after"));
    claims.offline_allowed = bool_value(required(value, "offline_allowed"));
    claims.licence_expires_at = optional_integer(value, "licence_expires_at");
    return claims;
}

} // namespace

GrantKeys GrantKeys::parse(const Json::Value& jwks) {
    only_fields(jwks, {"keys"});
    if (!jwks["keys"].isArray() || jwks["keys"].empty() || jwks["keys"].size() > 8) invalid();
    GrantKeys result;
    for (const auto& jwk : jwks["keys"]) {
        only_fields(jwk, {"kty", "crv", "alg", "use", "kid", "x", "y"});
        const auto kty = string_value(required(jwk, "kty"));
        const auto crv = string_value(required(jwk, "crv"));
        const auto alg = string_value(required(jwk, "alg"));
        const auto use = string_value(required(jwk, "use"));
        const auto kid = string_value(required(jwk, "kid"));
        const auto x = string_value(required(jwk, "x"));
        const auto y = string_value(required(jwk, "y"));
        if (kty != "EC" || crv != "P-256" || alg != "ES256" || use != "sig" ||
            kid.empty() || kid.size() > 128 ||
            std::any_of(kid.begin(), kid.end(), [](unsigned char c) { return c > 0x7f; })) invalid();
        if (!result.keys_.emplace(kid, p256_key(x, y)).second) invalid();
        result.public_keys_.emplace(kid, jwk);
    }
    return result;
}

std::string grant_kid(std::string_view token) {
    return parse_token(token).kid;
}

bool GrantKeys::contains(std::string_view token) const {
    const auto parsed = parse_token(token);
    return keys_.find(std::string(parsed.kid)) != keys_.end();
}

Json::Value GrantKeys::jwks_for(std::string_view token) const {
    const auto parsed = parse_token(token);
    const auto found = public_keys_.find(std::string(parsed.kid));
    if (found == public_keys_.end()) invalid();
    Json::Value result(Json::objectValue);
    result["keys"] = Json::Value(Json::arrayValue);
    result["keys"].append(found->second);
    return result;
}

GrantClaims GrantKeys::verify(std::string_view token, const GrantExpected& expected) const {
    const auto parsed = parse_token(token);
    const auto key = keys_.find(std::string(parsed.kid));
    if (key == keys_.end() || !verify_signature(key->second.get(), parsed.signing_input, parsed.signature)) invalid();
    auto claims = parse_claims(parsed.claims);
    const auto audience = "orbit:" + std::string(expected.application) + ":" + std::string(expected.environment);
    const bool bound = [&] {
        if (!expected.fingerprint && !expected.fingerprint_provider) {
            return claims.binding_mode == "none" && !claims.fingerprint && !claims.fingerprint_provider;
        }
        return expected.fingerprint && expected.fingerprint_provider && claims.binding_mode == "hwid" &&
               claims.fingerprint && *claims.fingerprint == *expected.fingerprint &&
               claims.fingerprint_provider && *claims.fingerprint_provider == *expected.fingerprint_provider;
    }();
    const auto allowance = claims.offline_allowed ? std::int64_t{86400} : std::int64_t{300};
    const auto add_saturated = [](std::int64_t value, std::int64_t delta) {
        if (delta > 0 && value > std::numeric_limits<std::int64_t>::max() - delta)
            return std::numeric_limits<std::int64_t>::max();
        if (delta < 0 && value < std::numeric_limits<std::int64_t>::min() - delta)
            return std::numeric_limits<std::int64_t>::min();
        return value + delta;
    };
    const bool persistent_offline = !expected.credential_expires_at && claims.offline_allowed;
    const auto refresh_minimum = persistent_offline ? 675 : 45;
    const auto refresh_maximum = persistent_offline ? 1125 : 75;
    if (claims.issuer != expected.issuer || claims.audience != audience ||
        claims.subject.empty() || claims.subject.size() > 128 ||
        (expected.licence && claims.subject != *expected.licence) ||
        claims.token_id.empty() || claims.token_id.size() > 128 ||
        claims.application_id != expected.application || claims.environment_id != expected.environment ||
        claims.activation_id != expected.activation || claims.installation_id != expected.installation ||
        !bound || claims.policy_version < 1 || claims.issued_at < 0 ||
        claims.not_before != claims.issued_at || add_saturated(claims.issued_at, 30) < expected.now ||
        add_saturated(claims.issued_at, -30) > expected.now || claims.expires_at <= expected.now ||
        claims.expires_at <= claims.issued_at ||
        claims.expires_at > add_saturated(claims.issued_at, allowance) ||
        (expected.credential_expires_at && claims.expires_at > *expected.credential_expires_at) ||
        claims.licence_expires_at != expected.licence_expires_at ||
        (claims.licence_expires_at && claims.expires_at > *claims.licence_expires_at) ||
        claims.refresh_after <= claims.issued_at || claims.refresh_after > claims.expires_at ||
        claims.refresh_after > add_saturated(claims.issued_at, refresh_maximum) ||
        (claims.refresh_after < add_saturated(claims.issued_at, refresh_minimum) && claims.refresh_after != claims.expires_at)) {
        invalid();
    }
    return claims;
}

} // namespace orbit::detail
