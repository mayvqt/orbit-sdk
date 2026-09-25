#include "storage_codec.hpp"

#include "json.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace orbit::detail::storage_codec {
namespace {

[[noreturn]] void storage_failure() {
    throw Error(1, ErrorKind::storage, "storage", {});
}

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

bool lowercase_hex(std::string_view value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

bool valid_provider(std::string_view value) {
    if (value == "machine_v1") {
        return true;
    }
    if (value.size() < 8 || value.size() > 55 ||
        value.substr(0, 7) != "custom:") {
        return false;
    }
    const auto suffix = value.substr(7);
    return std::all_of(suffix.begin(), suffix.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-' || c == '.';
    });
}

bool signed_i64(const Json::Value& value) {
    if (value.type() == Json::intValue) {
        return true;
    }
    return value.type() == Json::uintValue &&
           value.asUInt64() <= static_cast<Json::UInt64>(
               std::numeric_limits<std::int64_t>::max());
}

bool nonnegative_integer(const Json::Value& value, std::uint64_t maximum,
                         std::uint64_t& output) {
    if (value.type() == Json::intValue) {
        const auto number = value.asInt64();
        if (number < 0) {
            return false;
        }
        output = static_cast<std::uint64_t>(number);
    } else if (value.type() == Json::uintValue) {
        output = value.asUInt64();
    } else {
        return false;
    }
    return output <= maximum;
}

void validate_scope(const Config& config) {
    if (!opaque(config.application_id) || !opaque(config.environment_id) ||
        config.issuer.empty() || config.issuer.size() > max_plaintext ||
        !config.installation_id || !opaque(*config.installation_id) ||
        config.installation_id->size() < 16 ||
        (config.fingerprint &&
         (!lowercase_hex(config.fingerprint->value) ||
          !valid_provider(config.fingerprint->provider)))) {
        throw Error(1, ErrorKind::configuration, "configuration", {});
    }
}

void digest_update(EVP_MD_CTX* context, const void* data, std::size_t length) {
    if (EVP_DigestUpdate(context, data, length) != 1) {
        storage_failure();
    }
}

void append_u32(std::string& output, std::uint32_t value) {
    output.push_back(static_cast<char>((value >> 24) & 0xff));
    output.push_back(static_cast<char>((value >> 16) & 0xff));
    output.push_back(static_cast<char>((value >> 8) & 0xff));
    output.push_back(static_cast<char>(value & 0xff));
}

void append_scope_value(std::string& output, std::string_view value) {
    if (value.size() > max_plaintext || value.size() > UINT32_MAX) {
        storage_failure();
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.append(value);
}

void append_json_string(std::string& output, std::string_view value) {
    try {
        output.append(encode_json(Json::Value(std::string(value))));
    } catch (...) {
        storage_failure();
    }
}

bool valid_credential(const Json::Value& credential) {
    if (!credential.isObject() || credential.getMemberNames().size() != 4 ||
        !credential.isMember("activation_id") ||
        !credential.isMember("licence_id") ||
        !credential.isMember("bearer") ||
        !credential.isMember("expires_at")) {
        return false;
    }
    const auto& activation = credential["activation_id"];
    const auto& licence = credential["licence_id"];
    const auto& bearer = credential["bearer"];
    const auto& expiry = credential["expires_at"];
    if (!activation.isString() || !licence.isString() || !bearer.isString() ||
        !signed_i64(expiry) || !opaque(activation.asString()) ||
        !opaque(licence.asString())) {
        return false;
    }
    const auto token = bearer.asString();
    return token.size() == 43 &&
           std::all_of(token.begin(), token.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

bool exact_members(const Json::Value& object,
                   std::initializer_list<const char*> expected) {
    if (!object.isObject() || object.getMemberNames().size() != expected.size()) {
        return false;
    }
    for (const auto* member : expected) {
        if (!object.isMember(member)) {
            return false;
        }
    }
    return true;
}

bool nullable_string_matches(const Json::Value& value,
                             const std::optional<std::string>& expected) {
    if (!expected) {
        return value.isNull();
    }
    return value.isString() && value.asString() == *expected;
}

std::uint64_t validate_record(const Config& config, const Json::Value& record) {
    std::uint64_t format = 0;
    std::uint64_t generation = 0;
    if (!exact_members(record, {"sdk", "format", "generation", "issuer",
                                "application_id", "environment_id",
                                "installation_id", "fingerprint",
                                "fingerprint_provider", "credential"}) ||
        !record["sdk"].isString() ||
        record["sdk"].asString() != "orbit.rust.storage" ||
        !nonnegative_integer(record["format"], UINT32_MAX, format) || format != 1 ||
        !nonnegative_integer(record["generation"], max_generation, generation) ||
        !record["issuer"].isString() || record["issuer"].asString() != config.issuer ||
        !record["application_id"].isString() ||
        record["application_id"].asString() != config.application_id ||
        !record["environment_id"].isString() ||
        record["environment_id"].asString() != config.environment_id ||
        !record["installation_id"].isString() ||
        record["installation_id"].asString() != *config.installation_id ||
        !nullable_string_matches(record["fingerprint"],
            config.fingerprint ? std::optional<std::string>(config.fingerprint->value)
                               : std::nullopt) ||
        !nullable_string_matches(record["fingerprint_provider"],
            config.fingerprint ? std::optional<std::string>(config.fingerprint->provider)
                               : std::nullopt)) {
        storage_failure();
    }
    if (!record["credential"].isNull() &&
        !valid_credential(record["credential"])) {
        storage_failure();
    }
    return generation;
}

} // namespace

std::array<unsigned char, 32> entropy(const Config& config) {
    validate_scope(config);
    EVP_MD_CTX* raw = EVP_MD_CTX_new();
    if (raw == nullptr) {
        storage_failure();
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw,
                                                                   EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        storage_failure();
    }
    static constexpr char domain[] = "orbit.sdk.storage.v1\0";
    digest_update(context.get(), domain, sizeof(domain) - 1);
    std::string framed;
    framed.reserve(4 * 4 + config.issuer.size() + config.application_id.size() +
                   config.environment_id.size() + config.installation_id->size());
    append_scope_value(framed, config.issuer);
    append_scope_value(framed, config.application_id);
    append_scope_value(framed, config.environment_id);
    append_scope_value(framed, *config.installation_id);
    digest_update(context.get(), framed.data(), framed.size());
    std::array<unsigned char, 32> output{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), output.data(), &length) != 1 ||
        length != output.size()) {
        storage_failure();
    }
    return output;
}

std::string encode(const Config& config, std::uint64_t generation,
                   const std::optional<Json::Value>& credential) {
    (void)entropy(config);
    if (generation > max_generation ||
        (credential && !valid_credential(*credential))) {
        storage_failure();
    }
    // Keep the established serde struct field order and compact JSON bytes so
    // the native adapter writes the same private record shape as Rust.
    std::string bytes = "{\"sdk\":\"orbit.rust.storage\",\"format\":1,\"generation\":";
    bytes.append(std::to_string(generation));
    bytes.append(",\"issuer\":");
    append_json_string(bytes, config.issuer);
    bytes.append(",\"application_id\":");
    append_json_string(bytes, config.application_id);
    bytes.append(",\"environment_id\":");
    append_json_string(bytes, config.environment_id);
    bytes.append(",\"installation_id\":");
    append_json_string(bytes, *config.installation_id);
    bytes.append(",\"fingerprint\":");
    if (config.fingerprint) {
        append_json_string(bytes, config.fingerprint->value);
    } else {
        bytes.append("null");
    }
    bytes.append(",\"fingerprint_provider\":");
    if (config.fingerprint) {
        append_json_string(bytes, config.fingerprint->provider);
    } else {
        bytes.append("null");
    }
    bytes.append(",\"credential\":");
    if (credential) {
        const auto& activation = (*credential)["activation_id"];
        const auto& licence = (*credential)["licence_id"];
        const auto& bearer = (*credential)["bearer"];
        bytes.append("{\"activation_id\":");
        append_json_string(bytes, activation.asString());
        bytes.append(",\"licence_id\":");
        append_json_string(bytes, licence.asString());
        bytes.append(",\"bearer\":");
        append_json_string(bytes, bearer.asString());
        bytes.append(",\"expires_at\":");
        bytes.append(std::to_string((*credential)["expires_at"].asInt64()));
        bytes.push_back('}');
    } else {
        bytes.append("null");
    }
    bytes.push_back('}');
    try {
        if (bytes.empty() || bytes.size() > max_plaintext) {
            storage_failure();
        }
        return bytes;
    } catch (const Error&) {
        throw;
    } catch (...) {
        storage_failure();
    }
}

std::pair<std::uint64_t, std::optional<Json::Value>> decode(
    const Config& config, std::string_view bytes) {
    (void)entropy(config);
    if (bytes.empty() || bytes.size() > max_plaintext) {
        storage_failure();
    }
    Json::Value record;
    try {
        record = parse_json(bytes, max_plaintext);
    } catch (...) {
        storage_failure();
    }
    const auto generation = validate_record(config, record);
    std::optional<Json::Value> credential;
    if (!record["credential"].isNull()) {
        credential = record["credential"];
    }
    return {generation, std::move(credential)};
}

} // namespace orbit::detail::storage_codec
