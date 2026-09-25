#pragma once

#include "orbit_sdk.hpp"
#include <json/json.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace orbit::detail {

// Nanoseconds of suspend-inclusive elapsed time, and current Unix seconds.
std::int64_t elapsed_nanoseconds();
std::int64_t wall_seconds();

// Credential JSON is the existing private Rust codec credential object:
// activation_id, licence_id, bearer, expires_at. Never expose it as public metadata.
class CredentialStorage {
public:
    virtual ~CredentialStorage() = default;
    virtual std::uint64_t version() = 0;
    virtual std::pair<std::uint64_t, std::optional<Json::Value>> load() = 0;
    virtual void save(std::uint64_t expected_version, const Json::Value& credential) = 0;
    virtual std::uint64_t invalidate() = 0;
};

std::shared_ptr<CredentialStorage> open_storage(const Config& config);

} // namespace orbit::detail
