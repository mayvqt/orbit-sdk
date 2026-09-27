#pragma once

#include "grants.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail {

struct SessionGrant {
    std::string session_id;
    std::int64_t sequence = 0;
    std::string licence_id;
    std::string activation_id;
    std::string installation_id;
    std::string binding_mode;
    std::string token_id;
    std::int64_t issued_at = 0;
    std::int64_t expires_at = 0;
    std::int64_t refresh_after = 0;
    std::optional<std::int64_t> licence_expires_at;
    std::int32_t policy_version = 0;
    std::map<std::string, bool> entitlements;
};

struct SessionExpected {
    GrantExpected grant;
    std::string_view session_id;
    std::int64_t sequence = 0;
};

class SessionKeys {
  public:
    static SessionKeys parse_jwks(std::string_view jwks, std::string_view environment);
    static SessionKeys parse(const Json::Value &jwks, std::string_view environment);
    bool contains(std::string_view token) const;
    SessionGrant verify(std::string_view token, const SessionExpected &expected) const;

  private:
    SessionKeys(GrantKeys keys, std::string environment)
        : keys_(std::move(keys)), environment_(std::move(environment)) {}
    GrantKeys keys_;
    std::string environment_;
};

} // namespace orbit::detail
