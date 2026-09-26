#include "persistent_codec.hpp"

#include "error.hpp"
#include "grants.hpp"
#include "json.hpp"

#include <algorithm>
#include <limits>

namespace orbit::detail::persistent_codec {
namespace {

[[noreturn]] void corrupt() {
    throw Error(1, ErrorKind::corrupt_state, "installation_state_corrupt", {});
}

bool exact(const Json::Value& value,
           std::initializer_list<std::string_view> names) {
    if (!value.isObject() || value.getMemberNames().size() != names.size()) return false;
    for (const auto name : names) {
        if (!value.isMember(std::string(name))) return false;
    }
    return true;
}

bool opaque(std::string_view value, std::size_t maximum = 128,
            std::size_t minimum = 1) {
    return value.size() >= minimum && value.size() <= maximum &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                   (c >= '0' && c <= '9') || c == '_' || c == '-';
        });
}

bool lower_hex(std::string_view value) {
    return value.size() == 64 &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

bool signed_integer(const Json::Value& value, std::int64_t& output) {
    if (value.type() != Json::intValue && value.type() != Json::uintValue) return false;
    if (!value.isInt64()) return false;
    output = value.asInt64();
    return output >= 0;
}

bool bounded_time(const Json::Value& value, bool nullable) {
    if (nullable && value.isNull()) return true;
    std::int64_t number = 0;
    return signed_integer(value, number) && number > 0 &&
           number <= 253402300799LL;
}

bool fingerprint_provider(std::string_view value) {
    if (value == "machine_v1") return true;
    if (value.size() < 8 || value.size() > 55 || value.substr(0, 7) != "custom:") return false;
    value.remove_prefix(7);
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-' || c == '.';
    });
}

void validate_credential(const Json::Value& value) {
    if (value.isNull()) return;
    if (!exact(value, {"activation_id", "licence_id", "bearer", "expires_at"}) ||
        !value["activation_id"].isString() || !value["licence_id"].isString() ||
        !value["bearer"].isString() ||
        !opaque(value["activation_id"].asString()) ||
        !opaque(value["licence_id"].asString()) ||
        !opaque(value["bearer"].asString(), 128, 43) ||
        value["bearer"].asString().size() != 43 ||
        !bounded_time(value["expires_at"], true)) corrupt();
}

void validate_pending(const Json::Value& value) {
    if (value.isNull()) return;
    std::int64_t created = 0;
    if (!exact(value, {"operation_id", "principal_kind", "input_digest", "created_at"}) ||
        !value["operation_id"].isString() ||
        !opaque(value["operation_id"].asString(), 128, 16) ||
        !value["principal_kind"].isString() ||
        (value["principal_kind"] != "key" && value["principal_kind"] != "account") ||
        !value["input_digest"].isString() ||
        !lower_hex(value["input_digest"].asString()) ||
        !signed_integer(value["created_at"], created)) corrupt();
}

void validate_access(const Json::Value& value, const Json::Value& credential) {
    if (value.isNull()) return;
    std::int64_t received_server = 0, received_wall = 0, server_high = 0, wall_high = 0;
    if (credential.isNull() ||
        !exact(value, {"jws", "jwks", "licence_expires_at", "received_server_time",
                       "received_wall_time", "server_high_water", "wall_high_water"}) ||
        !value["jws"].isString() || value["jws"].asString().empty() ||
        value["jws"].asString().size() > max_jws ||
        !value["jwks"].isObject() || value["jwks"].getMemberNames().size() != 1 ||
        !value["jwks"].isMember("keys") || !value["jwks"]["keys"].isArray() ||
        value["jwks"]["keys"].size() != 1 ||
        !bounded_time(value["licence_expires_at"], true) ||
        !signed_integer(value["received_server_time"], received_server) ||
        !signed_integer(value["received_wall_time"], received_wall) ||
        !signed_integer(value["server_high_water"], server_high) ||
        !signed_integer(value["wall_high_water"], wall_high)) corrupt();
    try {
        (void)GrantKeys::parse(value["jwks"]);
    } catch (...) {
        corrupt();
    }
}

std::uint64_t generation_value(const Json::Value& value) {
    std::uint64_t output = 0;
    if (value.type() == Json::intValue) {
        const auto number = value.asInt64();
        if (number < 0) corrupt();
        output = static_cast<std::uint64_t>(number);
    } else if (value.type() == Json::uintValue) {
        output = value.asUInt64();
    } else {
        corrupt();
    }
    if (output > max_generation) corrupt();
    return output;
}

} // namespace

Json::Value empty_record(const Config& config, std::string_view provider) {
    if (!config.installation_id || !opaque(*config.installation_id, 128, 16) ||
        (provider != "private_file" && provider != "windows_dpapi")) corrupt();
    Json::Value record(Json::objectValue);
    record["sdk"] = "orbit.installed-client";
    record["format"] = 2;
    record["provider"] = std::string(provider);
    Json::Value scope(Json::objectValue);
    scope["api_origin"] = config.api_origin;
    scope["issuer"] = config.issuer;
    scope["application_id"] = config.application_id;
    scope["environment_id"] = config.environment_id;
    record["scope"] = std::move(scope);
    Json::Value installation(Json::objectValue);
    installation["id"] = *config.installation_id;
    installation["fingerprint"] = config.fingerprint
        ? Json::Value(config.fingerprint->value) : Json::Value(Json::nullValue);
    installation["fingerprint_provider"] = config.fingerprint
        ? Json::Value(config.fingerprint->provider) : Json::Value(Json::nullValue);
    record["installation"] = std::move(installation);
    record["generation"] = 0;
    record["credential"] = Json::nullValue;
    record["pending_activation"] = Json::nullValue;
    record["access"] = Json::nullValue;
    return record;
}

Json::Value decode(const Config& config, std::string_view provider,
                   std::string_view bytes) {
    if (bytes.empty() || bytes.size() > max_plaintext) corrupt();
    Json::Value record;
    try {
        record = parse_json(bytes, max_plaintext);
    } catch (...) {
        corrupt();
    }
    if (!exact(record, {"sdk", "format", "provider", "scope", "installation",
                        "generation", "credential", "pending_activation", "access"}) ||
        !record["sdk"].isString() || record["sdk"] != "orbit.installed-client" ||
        record["format"].type() != Json::intValue || record["format"].asInt() != 2 ||
        !record["provider"].isString() || record["provider"].asString() != provider ||
        !exact(record["scope"], {"api_origin", "issuer", "application_id", "environment_id"}) ||
        !record["scope"]["api_origin"].isString() ||
        record["scope"]["api_origin"].asString() != config.api_origin ||
        !record["scope"]["issuer"].isString() ||
        record["scope"]["issuer"].asString() != config.issuer ||
        !record["scope"]["application_id"].isString() ||
        record["scope"]["application_id"].asString() != config.application_id ||
        !record["scope"]["environment_id"].isString() ||
        record["scope"]["environment_id"].asString() != config.environment_id ||
        !exact(record["installation"], {"id", "fingerprint", "fingerprint_provider"}) ||
        !record["installation"]["id"].isString() ||
        !opaque(record["installation"]["id"].asString(), 128, 16) ||
        (config.installation_id && record["installation"]["id"].asString() != *config.installation_id) ||
        generation_value(record["generation"]) > max_generation) corrupt();

    const auto& fingerprint = record["installation"]["fingerprint"];
    const auto& fingerprint_provider_value = record["installation"]["fingerprint_provider"];
    const bool no_binding = fingerprint.isNull() && fingerprint_provider_value.isNull();
    const bool valid_binding = fingerprint.isString() && fingerprint_provider_value.isString() &&
        lower_hex(fingerprint.asString()) &&
        fingerprint_provider(fingerprint_provider_value.asString());
    if ((!no_binding && !valid_binding) ||
        (config.fingerprint
            ? (!fingerprint.isString() || fingerprint.asString() != config.fingerprint->value ||
               !fingerprint_provider_value.isString() ||
               fingerprint_provider_value.asString() != config.fingerprint->provider)
            : !no_binding)) corrupt();

    validate_credential(record["credential"]);
    validate_pending(record["pending_activation"]);
    validate_access(record["access"], record["credential"]);
    return record;
}

std::string encode(const Config& config, std::string_view provider,
                   const Json::Value& record) {
    try {
        const auto bytes = encode_json(record);
        (void)decode(config, provider, bytes);
        return bytes;
    } catch (const Error&) {
        throw;
    } catch (...) {
        throw Error(1, ErrorKind::storage, "installation_state_write_failed", {});
    }
}

} // namespace orbit::detail::persistent_codec
