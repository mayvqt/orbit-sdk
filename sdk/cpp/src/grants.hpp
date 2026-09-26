#pragma once

#include "json.hpp"

#include <map>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <openssl/evp.h>

namespace orbit::detail {

struct GrantClaims {
    std::string issuer;
    std::string audience;
    std::string subject;
    std::string token_id;
    std::int64_t issued_at = 0;
    std::int64_t not_before = 0;
    std::int64_t expires_at = 0;
    std::string application_id;
    std::string environment_id;
    std::string activation_id;
    std::string installation_id;
    std::string binding_mode;
    std::optional<std::string> fingerprint;
    std::optional<std::string> fingerprint_provider;
    std::int32_t policy_version = 0;
    std::map<std::string, bool> entitlements;
    std::int64_t refresh_after = 0;
    bool offline_allowed = false;
    std::optional<std::int64_t> licence_expires_at;
};

struct GrantExpected {
    std::string_view issuer;
    std::string_view application;
    std::string_view environment;
    std::optional<std::string_view> licence;
    std::string_view activation;
    std::string_view installation;
    std::optional<std::string_view> fingerprint;
    std::optional<std::string_view> fingerprint_provider;
    std::optional<std::int64_t> credential_expires_at;
    std::optional<std::int64_t> licence_expires_at;
    std::int64_t now = 0;
};

class GrantKeys {
public:
    static GrantKeys parse(const Json::Value& jwks);
    bool contains(std::string_view token) const;
    std::size_t size() const noexcept { return keys_.size(); }
    Json::Value jwks_for(std::string_view token) const;
    GrantClaims verify(std::string_view token, const GrantExpected& expected) const;

private:
    std::map<std::string, std::shared_ptr<EVP_PKEY>> keys_;
    std::map<std::string, Json::Value> public_keys_;
};

std::string grant_kid(std::string_view token);

} // namespace orbit::detail
