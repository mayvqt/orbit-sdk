#pragma once

#include "grants.hpp"
#include "orbit_sdk.hpp"
#include <utility>

namespace orbit::detail {

struct OfflineExpected {
    AppKey app_key;
    std::string installation_id;
    std::optional<Fingerprint> fingerprint;
    std::int64_t now;
    std::int64_t minimum_sequence = 1;
};

struct OfflineFile {
    std::string token, key_id, licence_id, activation_id, installation_id, issuance_id;
    std::int64_t issued_at, expires_at;
    std::optional<std::int64_t> licence_expires_at;
    std::int64_t sequence;
    std::int32_t policy_version;
    std::map<std::string, bool> entitlements;
    std::string content_digest;
};

// Verifier foundation; installed storage must commit the file, sequence and
// clock evidence before making any resulting access available.
class OfflineKeys {
public:
    static OfflineKeys parse_jwks(std::string_view jwks, std::string_view environment);
    static OfflineKeys parse(const Json::Value& jwks, std::string_view environment);
    OfflineFile verify(std::string_view token, const OfflineExpected& expected) const;

private:
    OfflineKeys(GrantKeys keys, std::string environment)
        : keys_(std::move(keys)), environment_(std::move(environment)) {}
    GrantKeys keys_;
    std::string environment_;
};

} // namespace orbit::detail
