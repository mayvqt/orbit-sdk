#include "core.hpp"

#include "error.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <functional>
#include <mutex>
#include <thread>

#include <openssl/rand.h>
#include <openssl/evp.h>

namespace orbit::detail {
namespace {

#ifdef ORBIT_SDK_TESTING
std::mutex test_clock_mutex;
TestClock test_clock;
#endif

std::pair<std::int64_t, std::int64_t> current_clock() {
#ifdef ORBIT_SDK_TESTING
    TestClock provider;
    {
        std::lock_guard<std::mutex> lock(test_clock_mutex);
        provider = test_clock;
    }
    if (provider) return provider();
#endif
    return {elapsed_nanoseconds(), wall_seconds()};
}

[[noreturn]] void invalid_response() { raise(ErrorKind::invalid_response, "invalid_response"); }

bool opaque(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
           });
}

bool bearer(std::string_view value) { return value.size() == 43 && opaque(value); }

bool valid_provider(std::string_view value) {
    if (value == "machine_v1") return true;
    if (value.substr(0, 7) != "custom:") return false;
    value.remove_prefix(7);
    return !value.empty() && value.size() <= 48 &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-' || c == '.';
           });
}

bool valid_lower_hex(std::string_view value, std::size_t length) {
    return value.size() == length && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool valid_utf8(std::string_view text) {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c <= 0x7f) { ++i; continue; }
        std::size_t count;
        std::uint32_t code;
        if ((c & 0xe0) == 0xc0) { count = 2; code = c & 0x1f; if (code < 2) return false; }
        else if ((c & 0xf0) == 0xe0) { count = 3; code = c & 0x0f; }
        else if ((c & 0xf8) == 0xf0) { count = 4; code = c & 0x07; if (code > 4) return false; }
        else return false;
        if (i + count > text.size()) return false;
        for (std::size_t j = 1; j < count; ++j) {
            const auto continuation = static_cast<unsigned char>(text[i + j]);
            if ((continuation & 0xc0) != 0x80) return false;
            code = (code << 6) | (continuation & 0x3f);
        }
        if ((count == 3 && code < 0x800) || (count == 4 && code < 0x10000) || code > 0x10ffff ||
            (code >= 0xd800 && code <= 0xdfff)) return false;
        i += count;
    }
    return true;
}

std::size_t utf8_characters(std::string_view value) {
    if (!valid_utf8(value)) raise(ErrorKind::configuration, "configuration");
    return static_cast<std::size_t>(std::count_if(value.begin(), value.end(), [](unsigned char c) {
        return (c & 0xc0) != 0x80;
    }));
}

bool is_digits(std::string_view value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}

int number(std::string_view value) {
    if (!is_digits(value)) invalid_response();
    int result = 0;
    for (const auto c : value) result = result * 10 + (c - '0');
    return result;
}

std::int64_t days_from_civil(int year, unsigned month, unsigned day) {
    year -= month <= 2;
    const auto era = (year >= 0 ? year : year - 399) / 400;
    const auto yoe = static_cast<unsigned>(year - era * 400);
    const auto adjusted_month = static_cast<int>(month) + (month > 2 ? -3 : 9);
    const auto doy = static_cast<unsigned>((153 * adjusted_month + 2) / 5) + day - 1;
    const auto doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

std::int64_t timestamp(std::string_view value) {
    if (value.size() < 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
        value[13] != ':' || value[16] != ':') invalid_response();
    const int year = number(value.substr(0, 4));
    const int month = number(value.substr(5, 2));
    const int day = number(value.substr(8, 2));
    const int hour = number(value.substr(11, 2));
    const int minute = number(value.substr(14, 2));
    const int second = number(value.substr(17, 2));
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) invalid_response();
    static constexpr int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const auto maximum_day = month_days[month - 1] + (month == 2 && leap ? 1 : 0);
    if (day > maximum_day) invalid_response();
    std::size_t suffix = 19;
    if (suffix < value.size() && value[suffix] == '.') {
        const auto fractional_start = ++suffix;
        while (suffix < value.size() && value[suffix] >= '0' && value[suffix] <= '9') {
            if (value[suffix] != '0') invalid_response();
            ++suffix;
        }
        if (suffix == fractional_start || suffix - fractional_start > 9) invalid_response();
    }
    int offset_seconds = 0;
    if (suffix < value.size() && value[suffix] == 'Z') {
        ++suffix;
    } else if (suffix + 6 == value.size() && (value[suffix] == '+' || value[suffix] == '-') && value[suffix + 3] == ':') {
        const int offset_hour = number(value.substr(suffix + 1, 2));
        const int offset_minute = number(value.substr(suffix + 4, 2));
        if (offset_hour > 23 || offset_minute > 59) invalid_response();
        offset_seconds = (offset_hour * 60 + offset_minute) * 60;
        if (value[suffix] == '-') offset_seconds = -offset_seconds;
        suffix += 6;
    } else {
        invalid_response();
    }
    if (suffix != value.size()) invalid_response();
    const auto days = days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
    return days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds;
}

std::optional<std::string> optional_string(const Json::Value& value, const char* key) {
    if (!value.isMember(key) || value[key].isNull()) return std::nullopt;
    if (!value[key].isString()) invalid_response();
    return value[key].asString();
}

std::optional<std::int64_t> optional_integer(const Json::Value& value, const char* key) {
    if (!value.isMember(key) || value[key].isNull()) return std::nullopt;
    return json_int64(value[key]);
}

const Json::Value& required(const Json::Value& value, const char* key) {
    if (!value.isObject() || !value.isMember(key)) invalid_response();
    return value[key];
}

std::string text(const Json::Value& value) {
    if (!value.isString()) invalid_response();
    return value.asString();
}

bool boolean(const Json::Value& value) {
    if (!value.isBool()) invalid_response();
    return value.asBool();
}

std::int64_t integer(const Json::Value& value) {
    return json_int64(value);
}

Json::Value null_value() { return Json::Value(Json::nullValue); }

std::string sha256_hex(std::string_view input) {
    std::array<unsigned char, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(input.data(), input.size(), digest.data(), &length,
                   EVP_sha256(), nullptr) != 1 || length != digest.size()) {
        raise(ErrorKind::internal, "digest_failed");
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2);
    for (const auto value : digest) {
        output.push_back(digits[value >> 4]);
        output.push_back(digits[value & 15]);
    }
    return output;
}

std::string activation_input_digest(const Config& config, std::string_view key,
                                    std::optional<std::string_view> previous,
                                    std::string_view principal,
                                    std::optional<std::string_view> account_licence) {
    Json::Value input(Json::objectValue);
    Json::Value scope(Json::objectValue);
    scope["api_origin"] = config.api_origin;
    scope["application_id"] = config.application_id;
    scope["environment_id"] = config.environment_id;
    scope["issuer"] = config.issuer;
    input["scope"] = std::move(scope);
    input["installation_id"] = config.installation_id.value_or("");
    input["fingerprint"] = config.fingerprint
        ? Json::Value(config.fingerprint->value) : null_value();
    input["fingerprint_provider"] = config.fingerprint
        ? Json::Value(config.fingerprint->provider) : null_value();
    input["principal_kind"] = std::string(principal);
    input["credential_mode"] = "persistent";
    if (account_licence) input["licence_id"] = std::string(*account_licence);
    else input["licence_key"] = std::string(key);
    input["previous_credential_digest"] = previous
        ? Json::Value(sha256_hex(*previous)) : null_value();
    return sha256_hex(encode_json(input));
}

Json::Value persistent_access_cache(const Json::Value& reply,
                                   const GrantClaims& claims,
                                   const GrantKeys& keys, ClockStart start) {
    const auto grant = text(required(reply, "grant"));
    const auto received_server = timestamp(text(required(reply, "server_time")));
    if (grant.size() > persistent_codec::max_jws || received_server <= 0 ||
        start.wall_seconds <= 0) {
        invalid_response();
    }
    Json::Value access(Json::objectValue);
    access["jws"] = grant;
    access["jwks"] = keys.jwks_for(grant);
    access["licence_expires_at"] = claims.licence_expires_at
        ? Json::Value(static_cast<Json::Int64>(*claims.licence_expires_at)) : null_value();
    access["received_server_time"] = static_cast<Json::Int64>(received_server);
    access["received_wall_time"] = static_cast<Json::Int64>(start.wall_seconds);
    access["server_high_water"] = static_cast<Json::Int64>(received_server);
    access["wall_high_water"] = static_cast<Json::Int64>(start.wall_seconds);
    return access;
}

Json::Value customer_json(const Json::Value& input) {
    const auto& customer = required(input, "customer");
    if (!customer.isObject()) invalid_response();
    const auto id = text(required(customer, "id"));
    const auto username = text(required(customer, "username"));
    const auto email = text(required(customer, "email"));
    const auto suspended = boolean(required(customer, "suspended"));
    const auto created = text(required(customer, "created_at"));
    (void)timestamp(created);
    if (!opaque(id) || suspended || username.size() < 3 || username.size() > 32 ||
        !std::all_of(username.begin(), username.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        }) || email.empty() || email.size() > 254) invalid_response();
    Json::Value safe(Json::objectValue);
    safe["id"] = id;
    safe["username"] = username;
    safe["email"] = email;
    safe["suspended"] = suspended;
    safe["created_at"] = created;
    return safe;
}

Json::Value account_safe_json(const Json::Value& account) {
    Json::Value result(Json::objectValue);
    result["customer"] = account["customer"];
    result["expires_at"] = account["expires_at"];
    return result;
}

Json::Value owned_licence(const Json::Value& input) {
    if (!input.isObject()) invalid_response();
    const auto id = text(required(input, "id"));
    const auto policy = text(required(input, "policy_name"));
    const auto state = text(required(input, "state"));
    const auto expiry_mode = text(required(input, "expiry_mode"));
    const auto first_used = optional_string(input, "first_used_at");
    const auto expires = optional_string(input, "expires_at");
    const auto duration = optional_integer(input, "duration_seconds");
    const auto device_limit = integer(required(input, "device_limit"));
    const auto hwid_locked = boolean(required(input, "hwid_locked"));
    const auto offline_allowed = boolean(required(input, "offline_allowed"));
    const auto offline_seconds = integer(required(input, "offline_seconds"));
    const auto& entitlements = required(input, "entitlements");
    if (!opaque(id) || device_limit < 1 || device_limit > 100 || entitlements.size() > 64 ||
        utf8_characters(policy) > 80 || offline_seconds < INT32_MIN || offline_seconds > INT32_MAX ||
        device_limit > INT32_MAX) invalid_response();
    if (first_used) (void)timestamp(*first_used);
    if (expires) (void)timestamp(*expires);
    if (!entitlements.isObject()) invalid_response();
    Json::Value entitlement_output(Json::objectValue);
    for (const auto& key : entitlements.getMemberNames()) {
        if (!entitlements[key].isBool()) invalid_response();
        entitlement_output[key] = entitlements[key].asBool();
    }
    Json::Value output(Json::objectValue);
    output["id"] = id;
    output["policy_name"] = policy;
    output["state"] = state;
    output["expiry_mode"] = expiry_mode;
    output["first_used_at"] = first_used ? Json::Value(*first_used) : null_value();
    output["expires_at"] = expires ? Json::Value(*expires) : null_value();
    output["duration_seconds"] = duration ? Json::Value(static_cast<Json::Int64>(*duration)) : null_value();
    output["device_limit"] = static_cast<Json::Int64>(device_limit);
    output["hwid_locked"] = hwid_locked;
    output["offline_allowed"] = offline_allowed;
    output["offline_seconds"] = static_cast<Json::Int64>(offline_seconds);
    output["entitlements"] = std::move(entitlement_output);
    return output;
}

} // namespace

ClockStart capture_clock() {
    const auto value = current_clock();
    if (value.first < 0 || value.second < 0) raise(ErrorKind::clock_uncertain, "clock_uncertain");
    return {value.first, value.second};
}

std::int64_t ClockAnchor::now() const {
    const auto [elapsed, wall] = current_clock();
    if (server_seconds < 0 || elapsed_nanoseconds < 0 || wall_seconds < 0 ||
        elapsed < 0 || wall < 0 || elapsed < elapsed_nanoseconds) {
        raise(ErrorKind::clock_uncertain, "clock_uncertain");
    }
    const auto passed = (elapsed - elapsed_nanoseconds) / 1000000000;
    if (passed > std::numeric_limits<std::int64_t>::max() - wall_seconds ||
        passed > std::numeric_limits<std::int64_t>::max() - server_seconds) {
        raise(ErrorKind::clock_uncertain, "clock_uncertain");
    }
    const auto expected_wall = wall_seconds + passed;
    const auto drift = wall >= expected_wall ? wall - expected_wall : expected_wall - wall;
    if (drift > 30) raise(ErrorKind::clock_uncertain, "clock_uncertain");
    return server_seconds + passed;
}

ClientState::ClientState(Config setup, Transport http,
                         std::shared_ptr<CredentialStorage> protected_storage,
                         std::uint64_t version,
                         std::optional<Credential> saved, bool installed)
    : config(std::move(setup)), transport(std::move(http)), storage(std::move(protected_storage)),
      current_generation(installed ? version : 0), storage_version(version),
      credential(std::move(saved)), persistent(installed) {
    if (persistent) transport.bind_owner_cancellation(owner_cancelled);
}

void ClientState::throw_if_cancelled(const std::atomic_bool& cancelled) const {
    check_cancelled(cancelled.load(std::memory_order_relaxed) ||
        (persistent && owner_cancelled->load(std::memory_order_relaxed)));
    if (persistence_failed.load(std::memory_order_relaxed)) {
        raise(ErrorKind::storage, "installation_state_write_failed");
    }
}

std::unique_lock<std::timed_mutex> ClientState::lock_serial(const std::atomic_bool& cancelled) {
    std::unique_lock<std::timed_mutex> lock(serial, std::defer_lock);
    while (!lock.try_lock_for(std::chrono::milliseconds(20))) throw_if_cancelled(cancelled);
    throw_if_cancelled(cancelled);
    return lock;
}

void ClientState::advance_generation_locked() {
    if (current_generation >= persistent_codec::max_generation) {
        raise(ErrorKind::storage, "installation_generation_exhausted");
    }
    ++current_generation;
}

void ClientState::clear_access_locked() {
    advance_generation_locked();
    credential.reset();
    claims.reset();
    anchor.reset();
    transient = false;
    retry_deadline.reset();
}

void ClientState::clear_all_locked() {
    clear_access_locked();
    customer.reset();
}

void ClientState::invalidate_locked() {
    if (persistent) {
        persistent_record["generation"] = static_cast<Json::UInt64>(current_generation);
        persistent_record["credential"] = null_value();
        persistent_record["pending_activation"] = null_value();
        persistent_record["access"] = null_value();
        persist_record_locked();
        return;
    }
    storage_version = storage->invalidate();
}

void ClientState::sync_storage_locked() {
    if (persistent) return;
    const auto observed = storage->version();
    if (observed != storage_version) {
        clear_all_locked();
        storage_version = observed;
    }
}

std::uint64_t ClientState::request_generation_locked() {
    sync_storage_locked();
    return current_generation;
}

std::uint64_t ClientState::generation() {
    std::lock_guard<std::mutex> lock(mutex);
    return request_generation_locked();
}

void ClientState::check_generation(std::uint64_t request_generation,
                                  const std::atomic_bool& cancelled) {
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (current_generation != request_generation) raise(ErrorKind::stale_response, "stale_response");
    throw_if_cancelled(cancelled);
}

Credential ClientState::stored_credential(const Json::Value& value) const {
    if (!value.isObject()) raise(ErrorKind::storage, "storage");
    const auto names = value.getMemberNames();
    if (names.size() != 4 || !value.isMember("activation_id") || !value.isMember("licence_id") ||
        !value.isMember("bearer") || !value.isMember("expires_at") ||
        !value["activation_id"].isString() || !value["licence_id"].isString() ||
        !value["bearer"].isString() ||
        (!value["expires_at"].isNull() &&
         ((value["expires_at"].type() != Json::intValue && value["expires_at"].type() != Json::uintValue) ||
          !value["expires_at"].isInt64()))) {
        raise(ErrorKind::storage, "storage");
    }
    Credential saved{value["activation_id"].asString(), value["licence_id"].asString(),
                     value["bearer"].asString(), value["expires_at"].isNull()
                         ? std::nullopt
                         : std::optional<std::int64_t>(value["expires_at"].asInt64())};
    if (!opaque(saved.activation_id) || !opaque(saved.licence_id) || !bearer(saved.bearer)) {
        raise(ErrorKind::storage, "storage");
    }
    return saved;
}

Json::Value ClientState::credential_json(const Credential& value) const {
    Json::Value result(Json::objectValue);
    result["activation_id"] = value.activation_id;
    result["licence_id"] = value.licence_id;
    result["bearer"] = value.bearer;
    result["expires_at"] = value.expires_at
        ? Json::Value(static_cast<Json::Int64>(*value.expires_at)) : null_value();
    return result;
}

Json::Value ClientState::credential_body(const Credential& value) const {
    Json::Value result(Json::objectValue);
    result["application_id"] = config.application_id;
    result["environment_id"] = config.environment_id;
    result["credential"] = value.bearer;
    result["installation_id"] = *config.installation_id;
    result["fingerprint"] = config.fingerprint ? Json::Value(config.fingerprint->value) : null_value();
    result["fingerprint_provider"] = config.fingerprint ? Json::Value(config.fingerprint->provider) : null_value();
    return result;
}

Json::Value ClientState::account_body(Json::Value value) const {
    if (!value.isObject()) raise(ErrorKind::internal, "invalid_request");
    value["application_id"] = config.application_id;
    value["environment_id"] = config.environment_id;
    return value;
}

std::string ClientState::account_path(std::string_view path,
                                      std::optional<std::string_view> cursor) const {
    std::string result(path);
    result += "?application_id=" + config.application_id + "&environment_id=" + config.environment_id;
    if (cursor) result += "&after=" + std::string(*cursor);
    return result;
}

Json::Value ClientState::snapshot_locked(bool tolerate_clock_error) {
    const auto credential_expiry = credential && credential->expires_at
        ? Json::Value(static_cast<Json::Int64>(*credential->expires_at)) : null_value();
    Json::Value result(Json::objectValue);
    result["access"] = credential ? "refresh_required" : "denied";
    result["entitlements"] = Json::Value(Json::objectValue);
    result["expires_at"] = null_value();
    result["next_check_at"] = null_value();
    result["credential_expires_at"] = credential_expiry;
    result["reauthentication_required"] = !credential.has_value() ||
        (credential->expires_at && *credential->expires_at <= capture_clock().wall_seconds + 86400);
    result["offline_allowed"] = false;
    result["remaining_offline_seconds"] = Json::UInt64(0);
    if (!claims || !anchor) return result;
    std::int64_t now = 0;
    try {
        now = anchor->now();
    } catch (const Error& error) {
        if (!tolerate_clock_error || error.kind() != ErrorKind::clock_uncertain) throw;
        claims.reset();
        anchor.reset();
        advance_generation_locked();
        if (persistent && !persistent_record.isNull()) {
            persistent_record["generation"] = static_cast<Json::UInt64>(current_generation);
            persistent_record["access"] = null_value();
            persist_record_locked();
        }
        return result;
    }
    result["expires_at"] = static_cast<Json::Int64>(claims->expires_at);
    result["next_check_at"] = static_cast<Json::Int64>(claims->refresh_after);
    result["reauthentication_required"] = !credential ||
        (credential->expires_at && *credential->expires_at <= now + 86400);
    result["offline_allowed"] = claims->offline_allowed;
    std::string access;
    if (claims->expires_at <= now) access = "expired";
    else if (transient) access = claims->offline_allowed ? "offline" : "refresh_required";
    else if (claims->refresh_after <= now) access = "refresh_required";
    else access = "online";
    result["access"] = access;
    if (access == "online" || access == "offline") {
        Json::Value entitlements(Json::objectValue);
        for (const auto& item : claims->entitlements) entitlements[item.first] = item.second;
        result["entitlements"] = std::move(entitlements);
        if (claims->offline_allowed) {
            result["remaining_offline_seconds"] = static_cast<Json::UInt64>(claims->expires_at - now);
        }
    }
    return result;
}

Json::Value ClientState::snapshot() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    return snapshot_locked(true);
}

std::pair<Credential, GrantClaims> ClientState::verify_reply(
    const Json::Value& reply, const std::optional<Credential>& previous,
    std::optional<std::string_view> expected_licence, ClockStart start,
    const std::atomic_bool& cancelled, ClockAnchor& out_anchor) {
    const auto activation_id = text(required(reply, "activation_id"));
    const auto installation_id = text(required(reply, "installation_id"));
    const auto credential_value = optional_string(reply, "credential");
    const auto& expiry_value = required(reply, "credential_expires_at");
    std::optional<std::int64_t> expiry;
    if (!expiry_value.isNull()) {
        if (!expiry_value.isString()) invalid_response();
        expiry = timestamp(expiry_value.asString());
    }
    const auto grant = optional_string(reply, "grant");
    const auto server_text = text(required(reply, "server_time"));
    const auto binding = text(required(reply, "binding_mode"));
    const auto fingerprint_provider = optional_string(reply, "fingerprint_provider");
    const auto licence_expiry_text = optional_string(reply, "licence_expires_at");
    const auto secret_replay_expired = boolean(required(reply, "secret_replay_expired"));
    if (secret_replay_expired) raise(ErrorKind::reauthentication_required, "reauthentication_required");
    const auto configured_fingerprint = config.fingerprint
        ? std::optional<std::string_view>(config.fingerprint->value) : std::nullopt;
    const auto configured_provider = config.fingerprint
        ? std::optional<std::string_view>(config.fingerprint->provider) : std::nullopt;
    if (!opaque(activation_id) || installation_id != *config.installation_id ||
        fingerprint_provider != (configured_provider ? std::optional<std::string>(*configured_provider) : std::nullopt) ||
        binding != (configured_fingerprint ? "hwid" : "none")) invalid_response();

    const auto server_time = timestamp(server_text);
    out_anchor = ClockAnchor{server_time, start.elapsed_nanoseconds, start.wall_seconds};
    auto now = out_anchor.now();
    if ((!persistent && !expiry) || (persistent && !previous && expiry)) invalid_response();
    if (expiry && (*expiry <= now || *expiry > now + 30 * 86400)) invalid_response();
    if (previous && (activation_id != previous->activation_id || expiry != previous->expires_at || credential_value)) {
        invalid_response();
    }
    if (!grant) invalid_response();
    const auto kid = grant_kid(*grant);
    bool known = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        known = keys.contains(*grant);
    }
    if (!known) {
        throw_if_cancelled(cancelled);
        const auto path = "/.well-known/orbit-jwks.json?application_id=" + config.application_id +
                          "&environment_id=" + config.environment_id;
        auto jwks = transport.get(path, cancelled);
        if (!jwks) invalid_response();
        auto refreshed = GrantKeys::parse(*jwks);
        {
            std::lock_guard<std::mutex> lock(mutex);
            keys = std::move(refreshed);
            known = keys.contains(*grant);
        }
    }
    if (!known) invalid_response();
    auto licence_expiry = licence_expiry_text
        ? std::optional<std::int64_t>(timestamp(*licence_expiry_text)) : std::nullopt;
    now = out_anchor.now();
    GrantExpected expected{
        config.issuer,
        config.application_id,
        config.environment_id,
        expected_licence ? expected_licence : (previous ? std::optional<std::string_view>(previous->licence_id) : std::nullopt),
        activation_id,
        *config.installation_id,
        configured_fingerprint,
        configured_provider,
        expiry,
        licence_expiry,
        now,
    };
    GrantClaims verified;
    {
        std::lock_guard<std::mutex> lock(mutex);
        verified = keys.verify(*grant, expected);
    }
    auto bearer_value = credential_value ? *credential_value : (previous ? previous->bearer : std::string{});
    if (!bearer(bearer_value)) invalid_response();
    Credential saved{activation_id, verified.subject, std::move(bearer_value), expiry};
    (void)kid;
    return {std::move(saved), std::move(verified)};
}

Json::Value ClientState::accept_reply(
    const std::optional<Json::Value>& reply, const Error* response_error,
    std::uint64_t request_generation,
    const std::optional<Credential>& previous, std::optional<std::string_view> expected_licence,
    ClockStart start, const std::atomic_bool& cancelled, bool mutation) {
    std::optional<std::pair<Credential, GrantClaims>> accepted;
    std::optional<ClockAnchor> accepted_anchor;
    std::optional<Error> failure;
    const bool verifying = reply.has_value();
    if (response_error) {
        failure.emplace(*response_error);
    } else if (reply) {
        try {
            ClockAnchor request_anchor;
            accepted.emplace(verify_reply(*reply, previous, expected_licence, start, cancelled, request_anchor));
            accepted_anchor = request_anchor;
        } catch (const Error& error) {
            failure.emplace(error);
        }
    } else {
        failure.emplace(1, ErrorKind::invalid_response, "invalid_response", std::string{});
    }

    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (current_generation != request_generation) raise(ErrorKind::stale_response, "stale_response");
    throw_if_cancelled(cancelled);
    if (accepted && accepted_anchor) {
        if (persistent) {
            auto candidate = persistent_record;
            candidate["generation"] = static_cast<Json::UInt64>(current_generation);
            candidate["credential"] = credential_json(accepted->first);
            candidate["access"] = persistent_access_cache(
                *reply, accepted->second, keys, start);
            if (mutation) candidate["pending_activation"] = null_value();
            commit_persistent_locked(std::move(candidate));
        } else {
            try {
                storage->save(storage_version, credential_json(accepted->first));
            } catch (...) {
                clear_all_locked();
                throw;
            }
        }
        credential = accepted->first;
        claims = accepted->second;
        anchor = accepted_anchor;
        transient = false;
        retry_deadline.reset();
        if (persistent) last_checkpoint = std::chrono::steady_clock::now();
        wake_worker();
        return snapshot_locked(true);
    }
    if (!failure) raise(ErrorKind::internal, "internal");
    if (failure->kind() == ErrorKind::cancelled) throw *failure;

    if (persistent && mutation &&
        failure->kind() != ErrorKind::denied &&
        failure->kind() != ErrorKind::reauthentication_required) {
        // The server may have committed an activation whose reply was lost or
        // could not be verified. Keep its durable retry identity, but do not
        // let the old cached grant authorize while that mutation is unresolved.
        auto candidate = persistent_record;
        candidate["access"] = null_value();
        candidate["generation"] = static_cast<Json::UInt64>(current_generation);
        commit_persistent_locked(std::move(candidate));
        claims.reset();
        anchor.reset();
        transient = true;
        if (failure->kind() == ErrorKind::transient) {
            std::uint8_t entropy = 0;
            const auto delay = RAND_bytes(&entropy, sizeof(entropy)) == 1
                ? std::chrono::seconds(15 + (entropy % 30)) : std::chrono::seconds(15);
            retry_deadline = std::chrono::steady_clock::now() + delay;
        }
        wake_worker();
        throw *failure;
    }

    if (failure->kind() == ErrorKind::transient) {
        if (verifying) {
            advance_generation_locked();
            claims.reset();
            anchor.reset();
            credential = previous;
            if (persistent) {
                persistent_record["generation"] = static_cast<Json::UInt64>(current_generation);
                persistent_record["credential"] = credential
                    ? credential_json(*credential) : null_value();
                persistent_record["access"] = null_value();
                persist_record_locked();
            }
        }
        transient = true;
        std::uint8_t entropy = 0;
        const auto delay = RAND_bytes(&entropy, sizeof(entropy)) == 1
            ? std::chrono::seconds(15 + (entropy % 30)) : std::chrono::seconds(15);
        retry_deadline = std::chrono::steady_clock::now() + delay;
        auto current = snapshot_locked(true);
        if (current["access"] == "offline") return current;
        throw *failure;
    }

    clear_all_locked();
    invalidate_locked();
    wake_worker();
    throw *failure;
}

Json::Value ClientState::activate(std::string_view key, std::string_view idempotency_key,
                                  std::optional<std::string_view> previous,
                                  const std::atomic_bool& cancelled,
                                  std::optional<std::string_view> account_licence) {
    ClientOperation call(*this);
    const bool automatic = idempotency_key.empty();
    if ((account_licence ? !opaque(*account_licence) : (key.empty() || key.size() > 256)) ||
        (!automatic && (idempotency_key.size() < 16 || idempotency_key.size() > 128)) ||
        (automatic && (!persistent || account_licence)) || !valid_utf8(key) ||
        !valid_utf8(idempotency_key) || (previous && !valid_utf8(*previous))) {
        raise(ErrorKind::configuration, "configuration");
    }
    const auto before_serial = generation();
    auto serial_lock = lock_serial(cancelled);
    std::string account_token;
    std::string operation_id(idempotency_key);
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != before_serial) raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        if (persistent && account_licence) {
            if (!persistent_record["pending_activation"].isNull()) {
                raise(ErrorKind::configuration, "activation_pending_resolution_required");
            }
            if (!customer) raise(ErrorKind::reauthentication_required, "reauthentication_required");
            account_token = customer->bearer;
            clear_access_locked();
            invalidate_locked();
        } else if (persistent) {
            const auto digest = activation_input_digest(
                config, key, previous, "key", std::nullopt);
            const auto now = capture_clock().wall_seconds;
            if (now <= 0) raise(ErrorKind::clock_uncertain, "clock_uncertain");
            auto candidate = persistent_record;
            const auto& pending = candidate["pending_activation"];
            if (!pending.isNull()) {
                if (!pending.isObject() || !pending["operation_id"].isString() ||
                    pending["principal_kind"] != "key" ||
                    pending["input_digest"].asString() != digest) {
                    raise(ErrorKind::configuration, "activation_pending_input_mismatch");
                }
                const auto created = json_int64(pending["created_at"]);
                if (now < created || now - created > 24 * 60 * 60) {
                    raise(ErrorKind::reauthentication_required,
                          "activation_pending_resolution_required");
                }
                operation_id = pending["operation_id"].asString();
                if (!automatic && operation_id != idempotency_key) {
                    raise(ErrorKind::configuration, "activation_pending_input_mismatch");
                }
            } else {
                if (automatic) operation_id = new_installation_id();
                candidate["pending_activation"] = Json::Value(Json::objectValue);
                candidate["pending_activation"]["operation_id"] = operation_id;
                candidate["pending_activation"]["principal_kind"] = "key";
                candidate["pending_activation"]["input_digest"] = digest;
                candidate["pending_activation"]["created_at"] = static_cast<Json::Int64>(now);
                advance_generation_locked();
                candidate["generation"] = static_cast<Json::UInt64>(current_generation);
            }
            // The retry identity and invalidation precede the network side
            // effect in one durable transaction; unchanged retries need no write.
            credential.reset();
            claims.reset();
            anchor.reset();
            transient = false;
            retry_deadline.reset();
            candidate["credential"] = null_value();
            candidate["access"] = null_value();
            if (candidate != persistent_record) {
                commit_persistent_locked(std::move(candidate));
            }
        } else {
            if (account_licence) {
                if (!customer) raise(ErrorKind::reauthentication_required, "reauthentication_required");
                account_token = customer->bearer;
                clear_access_locked();
            } else {
                clear_all_locked();
            }
            invalidate_locked();
        }
        request_generation = current_generation;
    }
    Json::Value input(Json::objectValue);
    input["application_id"] = config.application_id;
    input["environment_id"] = config.environment_id;
    input["installation_id"] = *config.installation_id;
    input["fingerprint"] = config.fingerprint ? Json::Value(config.fingerprint->value) : null_value();
    input["fingerprint_provider"] = config.fingerprint ? Json::Value(config.fingerprint->provider) : null_value();
    input["previous_credential"] = previous ? Json::Value(std::string(*previous)) : null_value();
    input["idempotency_key"] = operation_id;
    if (persistent) input["credential_mode"] = "persistent";
    if (account_licence) {
        input["customer_session"] = account_token;
        input["licence_id"] = std::string(*account_licence);
    } else {
        input["licence_key"] = std::string(key);
    }
    const ClockStart start = capture_clock();
    std::optional<Json::Value> response;
    try {
        response = transport.post("/api/client/v1/activations", input, true, cancelled);
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        return accept_reply(std::nullopt, &error, request_generation,
                            std::nullopt, account_licence, start, cancelled, true);
    }
    return accept_reply(response, nullptr, request_generation, std::nullopt,
                        account_licence, start, cancelled, true);
}

Json::Value ClientState::refresh(const std::atomic_bool& cancelled, bool if_needed) {
    ClientOperation call(*this);
    const auto before_serial = generation();
    auto serial_lock = lock_serial(cancelled);
    Credential saved;
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != before_serial) raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        if (if_needed) {
            const auto current = snapshot_locked(true);
            const auto access = current["access"].asString();
            const bool due = !retry_deadline || std::chrono::steady_clock::now() >= *retry_deadline;
            if ((access != "refresh_required" && access != "expired" && access != "offline") || !due) return current;
        }
        if (!credential) raise(ErrorKind::reauthentication_required, "reauthentication_required");
        saved = *credential;
        request_generation = current_generation;
    }
    const auto input = credential_body(saved);
    const auto path = "/api/client/v1/activations/" + saved.activation_id + "/validate";
    const ClockStart start = capture_clock();
    std::optional<Json::Value> response;
    try {
        response = transport.post(path, input, true, cancelled);
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        return accept_reply(std::nullopt, &error, request_generation, saved,
                            std::nullopt, start, cancelled);
    }
    return accept_reply(response, nullptr, request_generation, saved,
                        std::nullopt, start, cancelled);
}

Json::Value ClientState::require_access(std::string_view feature, const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    throw_if_cancelled(cancelled);
    if (!valid_utf8(feature)) raise(ErrorKind::configuration, "configuration");
    auto current = snapshot();
    const auto access = current["access"].asString();
    if (access == "refresh_required" || access == "expired" || access == "offline") {
        try {
            current = refresh(cancelled, true);
        } catch (const Error& error) {
            if (error.kind() != ErrorKind::transient) throw;
            current = snapshot();
        }
    }
    const auto current_access = current["access"].asString();
    if (current_access != "online" && current_access != "offline") {
        std::lock_guard<std::mutex> lock(mutex);
        if (persistent && credential && transient) raise(ErrorKind::transient, "network_unavailable");
        raise(ErrorKind::denied, "access_unavailable");
    }
    if (!current["entitlements"].isMember(std::string(feature)) || !current["entitlements"][std::string(feature)].asBool()) {
        raise(ErrorKind::denied, "feature_unavailable");
    }
    throw_if_cancelled(cancelled);
    return current;
}

void ClientState::deactivate(std::string_view idempotency_key, const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (idempotency_key.size() < 16 || idempotency_key.size() > 128 || !valid_utf8(idempotency_key)) {
        raise(ErrorKind::configuration, "configuration");
    }
    Credential saved;
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (!credential) raise(ErrorKind::reauthentication_required, "reauthentication_required");
        saved = *credential;
        clear_access_locked();
        invalidate_locked();
        request_generation = current_generation;
    }
    auto input = credential_body(saved);
    input["idempotency_key"] = std::string(idempotency_key);
    const auto path = "/api/client/v1/activations/" + saved.activation_id + "/deactivate";
    try {
        if (transport.post(path, input, true, cancelled)) invalid_response();
        check_generation(request_generation, cancelled);
    } catch (const Error&) {
        check_generation(request_generation, cancelled);
        throw;
    }
}

void ClientState::local_logout() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    clear_all_locked();
    invalidate_locked();
}

void ClientState::finish_account_error(std::uint64_t request_generation,
                                       const std::optional<ErrorKind>& error_kind,
                                       std::string_view error_code,
                                       const std::atomic_bool& cancelled) {
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (current_generation != request_generation) raise(ErrorKind::stale_response, "stale_response");
    throw_if_cancelled(cancelled);
    if (error_kind && *error_kind != ErrorKind::transient && *error_kind != ErrorKind::cancelled &&
        !(*error_kind == ErrorKind::denied && error_code == "session_expired")) {
        clear_all_locked();
        invalidate_locked();
    }
}

AccountSession ClientState::customer_session(std::uint64_t request_generation) {
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (current_generation != request_generation) raise(ErrorKind::stale_response, "stale_response");
    if (!customer) raise(ErrorKind::reauthentication_required, "reauthentication_required");
    return *customer;
}

Json::Value ClientState::account_post(std::string_view path, Json::Value body,
                                      bool retry_safe, const std::atomic_bool& cancelled,
                                      std::uint64_t& request_generation) {
    request_generation = generation();
    auto serial_lock = lock_serial(cancelled);
    const auto session = customer_session(request_generation);
    if (!body.isObject()) raise(ErrorKind::configuration, "configuration");
    body["customer_session"] = session.bearer;
    try {
        auto response = transport.post(path, account_body(std::move(body)), retry_safe, cancelled);
        finish_account_error(request_generation, std::nullopt, {}, cancelled);
        return response ? *response : null_value();
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
}

void ClientState::accepted(const Json::Value& value) {
    if (!value.isObject() || !value.isMember("accepted") || !value["accepted"].isBool() ||
        !value["accepted"].asBool()) invalid_response();
}

std::pair<Json::Value, std::shared_ptr<PendingRegistrationState>> ClientState::register_customer(
    std::string_view licence_key, std::string_view username, std::string_view email,
    std::string_view password, const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (licence_key.empty() || licence_key.size() > 256 || username.size() > 128 ||
        email.size() > 254 || password.size() > 256 || !valid_utf8(licence_key) ||
        !valid_utf8(username) || !valid_utf8(email) || utf8_characters(password) < 8) {
        raise(ErrorKind::configuration, "configuration");
    }
    Json::Value input(Json::objectValue);
    input["licence_key"] = std::string(licence_key);
    input["username"] = std::string(username);
    input["email"] = std::string(email);
    input["password"] = std::string(password);
    const auto request_generation = generation();
    try {
        const auto response = transport.post("/api/client/v1/registrations",
            account_body(std::move(input)), false, cancelled);
        check_generation(request_generation, cancelled);
        if (!response || !response->isObject()) invalid_response();
        accepted(*response);
        const auto resend = text(required(*response, "resend_credential"));
        const auto expires = text(required(*response, "expires_at"));
        if (!bearer(resend)) invalid_response();
        (void)timestamp(expires);
        auto pending = std::make_shared<PendingRegistrationState>();
        pending->resend_credential = resend;
        pending->application_id = config.application_id;
        pending->environment_id = config.environment_id;
        Json::Value metadata(Json::objectValue);
        metadata["accepted"] = true;
        metadata["expires_at"] = expires;
        check_generation(request_generation, cancelled);
        return {std::move(metadata), std::move(pending)};
    } catch (const Error&) {
        check_generation(request_generation, cancelled);
        throw;
    }
}

void ClientState::resend_registration(const PendingRegistrationState& pending,
                                      const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (pending.application_id != config.application_id || pending.environment_id != config.environment_id) {
        raise(ErrorKind::configuration, "configuration");
    }
    Json::Value input(Json::objectValue);
    input["resend_credential"] = pending.resend_credential;
    const auto request_generation = generation();
    try {
        const auto response = transport.post("/api/client/v1/registrations/resend",
            account_body(std::move(input)), false, cancelled);
        check_generation(request_generation, cancelled);
        if (!response) invalid_response();
        accepted(*response);
        check_generation(request_generation, cancelled);
    } catch (const Error&) {
        check_generation(request_generation, cancelled);
        throw;
    }
}

Json::Value ClientState::login(std::string_view username, std::string_view password,
                               const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (username.empty() || username.size() > 128 || password.size() > 256 ||
        !valid_utf8(username) || !valid_utf8(password)) raise(ErrorKind::configuration, "configuration");
    const auto before_serial = generation();
    auto serial_lock = lock_serial(cancelled);
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != before_serial) raise(ErrorKind::stale_response, "stale_response");
        clear_all_locked();
        invalidate_locked();
        request_generation = current_generation;
    }
    Json::Value input(Json::objectValue);
    input["username"] = std::string(username);
    input["password"] = std::string(password);
    std::optional<Json::Value> response;
    try {
        response = transport.post("/api/client/v1/sessions", account_body(std::move(input)), false, cancelled);
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
    Json::Value safe_account;
    std::string session_token;
    try {
        if (!response || !response->isObject()) invalid_response();
        safe_account["customer"] = customer_json(*response);
        session_token = text(required(*response, "session"));
        const auto expires = text(required(*response, "expires_at"));
        if (!bearer(session_token)) invalid_response();
        (void)timestamp(expires);
        safe_account["expires_at"] = expires;
    } catch (const Error& error) {
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != request_generation) raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        customer = AccountSession{std::move(session_token), safe_account};
    }
    return safe_account;
}

Json::Value ClientState::account() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (!customer) return null_value();
    return account_safe_json(customer->account);
}

Json::Value ClientState::owned_licences(std::optional<std::string_view> cursor,
                                        const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (cursor && !opaque(*cursor)) raise(ErrorKind::configuration, "configuration");
    const auto request_generation = generation();
    auto serial_lock = lock_serial(cancelled);
    const auto session = customer_session(request_generation);
    std::optional<Json::Value> response;
    try {
        response = transport.get_bearer(account_path("/api/client/v1/licences", cursor), session.bearer, cancelled);
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
    try {
        if (!response || !response->isObject()) invalid_response();
        const auto& items = required(*response, "items");
        if (!items.isArray() || items.size() > 100) invalid_response();
        const auto next_cursor = optional_string(*response, "next_cursor");
        if (next_cursor && !opaque(*next_cursor)) invalid_response();
        Json::Value output(Json::objectValue);
        Json::Value safe_items(Json::arrayValue);
        for (const auto& item : items) safe_items.append(owned_licence(item));
        output["items"] = std::move(safe_items);
        output["next_cursor"] = next_cursor ? Json::Value(*next_cursor) : null_value();
        finish_account_error(request_generation, std::nullopt, {}, cancelled);
        return output;
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
}

Json::Value ClientState::claim_licence(std::string_view key, std::string_view idempotency_key,
                                       const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (key.empty() || key.size() > 256 || idempotency_key.size() < 16 || idempotency_key.size() > 128 ||
        !valid_utf8(key) || !valid_utf8(idempotency_key)) raise(ErrorKind::configuration, "configuration");
    Json::Value body(Json::objectValue);
    body["licence_key"] = std::string(key);
    body["idempotency_key"] = std::string(idempotency_key);
    std::uint64_t request_generation = 0;
    auto response = account_post("/api/client/v1/licence-claims", std::move(body), true,
                                 cancelled, request_generation);
    try {
        auto safe = owned_licence(response);
        finish_account_error(request_generation, std::nullopt, {}, cancelled);
        return safe;
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
}

void ClientState::account_logout(const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    std::optional<AccountSession> session;
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        session = customer;
        clear_all_locked();
        invalidate_locked();
        request_generation = current_generation;
    }
    if (!session) {
        throw_if_cancelled(cancelled);
        return;
    }
    try {
        const auto response = transport.delete_bearer(account_path("/api/client/v1/sessions/current"),
                                                       session->bearer, cancelled);
        if (response) invalid_response();
        check_generation(request_generation, cancelled);
    } catch (const Error&) {
        check_generation(request_generation, cancelled);
        throw;
    }
}

void ClientState::request_email_change(std::string_view password, std::string_view email,
                                       const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (password.size() > 256 || email.size() > 254 || !valid_utf8(password) || !valid_utf8(email)) {
        raise(ErrorKind::configuration, "configuration");
    }
    Json::Value body(Json::objectValue);
    body["password"] = std::string(password);
    body["email"] = std::string(email);
    std::uint64_t request_generation = 0;
    const auto response = account_post("/api/client/v1/email-changes", std::move(body), false,
                                       cancelled, request_generation);
    try {
        accepted(response);
        finish_account_error(request_generation, std::nullopt, {}, cancelled);
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled) throw;
        finish_account_error(request_generation, error.kind(), error.code(), cancelled);
        throw;
    }
}

void ClientState::request_password_recovery(std::string_view email,
                                            const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (email.size() > 254 || !valid_utf8(email)) raise(ErrorKind::configuration, "configuration");
    Json::Value body(Json::objectValue);
    body["email"] = std::string(email);
    const auto request_generation = generation();
    try {
        const auto response = transport.post("/api/client/v1/password-recovery",
            account_body(std::move(body)), false, cancelled);
        check_generation(request_generation, cancelled);
        if (!response) invalid_response();
        accepted(*response);
        check_generation(request_generation, cancelled);
    } catch (const Error&) {
        check_generation(request_generation, cancelled);
        throw;
    }
}

std::string ClientState::customer_session_authorization() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (!customer) raise(ErrorKind::reauthentication_required, "reauthentication_required");
    return "Bearer " + customer->bearer;
}

std::shared_ptr<ClientState> connect_state(Config config) {
    if (!config.installation_id || config.installation_id->empty()) config.installation_id = new_installation_id();
    if (!opaque(config.application_id) || !opaque(config.environment_id) || config.issuer.empty() ||
        config.issuer.size() > 2048 || !valid_utf8(config.issuer) ||
        config.installation_id->size() < 16 || !opaque(*config.installation_id)) {
        raise(ErrorKind::configuration, "configuration");
    }
    if (config.fingerprint && (!valid_lower_hex(config.fingerprint->value, 64) ||
                               !valid_provider(config.fingerprint->provider))) {
        raise(ErrorKind::configuration, "configuration");
    }
    const auto now = current_clock();
    if (now.first < 0 || now.second < 0) raise(ErrorKind::clock_uncertain, "clock_uncertain");
    Transport transport(config.api_origin);
    auto protected_storage = open_storage(config);
    const auto loaded = protected_storage->load();
    std::optional<Credential> credential;
    if (loaded.second) {
        ClientState temporary(config, Transport(config.api_origin), protected_storage,
                              loaded.first, std::nullopt);
        credential = temporary.stored_credential(*loaded.second);
    }
    return std::make_shared<ClientState>(std::move(config), std::move(transport),
                                         std::move(protected_storage), loaded.first,
                                         std::move(credential));
}

std::shared_ptr<ClientState> open_installed_state(
    Config config, Transport transport, std::shared_ptr<InstalledStorage> installed) {
    auto raw_record = installed->load();
    Json::Value record;
    if (installed->initialization_needed()) {
        config.installation_id = new_installation_id();
        record = persistent_codec::empty_record(config, installed->provider());
        const auto bytes = persistent_codec::encode(config, installed->provider(), record);
        installed->initialize(bytes);
    } else {
        if (!raw_record) raise(ErrorKind::corrupt_state, "installation_state_corrupt");
        record = persistent_codec::decode(config, installed->provider(), *raw_record);
        config.installation_id = record["installation"]["id"].asString();
        record = persistent_codec::decode(config, installed->provider(), *raw_record);
    }
    const auto generation_value = json_int64(record["generation"]);
    std::optional<Credential> credential;
    if (!record["credential"].isNull()) {
        const auto& saved = record["credential"];
        std::optional<std::int64_t> expiry;
        if (!saved["expires_at"].isNull()) expiry = json_int64(saved["expires_at"]);
        credential = Credential{saved["activation_id"].asString(),
                                saved["licence_id"].asString(),
                                saved["bearer"].asString(), expiry};
    }
    auto state = std::make_shared<ClientState>(
        std::move(config), std::move(transport), nullptr,
        static_cast<std::uint64_t>(generation_value), std::move(credential), true);
    state->installed_storage = std::move(installed);
    state->persistent_record = std::move(record);

    if (state->credential && state->persistent_record["pending_activation"].isNull()) {
        std::atomic_bool cancelled{false};
        try {
            (void)state->refresh(cancelled, false);
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::transient) {
                (void)state->restore_persistent_cache(true);
            } else if (error.kind() == ErrorKind::storage ||
                       error.kind() == ErrorKind::corrupt_state ||
                       error.kind() == ErrorKind::internal ||
                       error.kind() == ErrorKind::configuration) {
                throw;
            }
        }
    }
    state->start_worker();
    return state;
}

#ifdef ORBIT_SDK_TESTING
void set_test_clock(TestClock clock) {
    std::lock_guard<std::mutex> lock(test_clock_mutex);
    test_clock = std::move(clock);
}

::orbit::Client make_test_client(Config config, Transport transport,
                                 std::shared_ptr<CredentialStorage> storage) {
    if (!config.installation_id || !opaque(*config.installation_id) || config.installation_id->size() < 16 ||
        !opaque(config.application_id) || !opaque(config.environment_id) || config.issuer.empty() ||
        config.issuer.size() > 2048 || !valid_utf8(config.issuer)) {
        raise(ErrorKind::configuration, "configuration");
    }
    if (config.fingerprint && (!valid_lower_hex(config.fingerprint->value, 64) ||
                               !valid_provider(config.fingerprint->provider))) {
        raise(ErrorKind::configuration, "configuration");
    }
    const auto loaded = storage->load();
    std::optional<Credential> credential;
    if (loaded.second) {
        ClientState temporary(config, Transport(config.api_origin), storage, loaded.first, std::nullopt);
        credential = temporary.stored_credential(*loaded.second);
    }
    auto state = std::make_shared<ClientState>(std::move(config), std::move(transport),
                                               std::move(storage), loaded.first,
                                               std::move(credential));
    return ::orbit::Client(std::move(state));
}

::orbit::Client make_test_installed_client(
    Config config, Transport transport, std::shared_ptr<InstalledStorage> installed) {
    config.installation_id.reset();
    config.api_origin = transport.origin();
    auto state = open_installed_state(std::move(config), std::move(transport),
                                      std::move(installed));
    return ::orbit::Client(std::move(state));
}
#endif

const std::atomic_bool& cancellation_flag(const ::orbit::Cancellation* cancellation,
                                          const std::atomic_bool& fallback) {
    if (cancellation && cancellation->state_) return cancellation->state_->cancelled;
    return fallback;
}

} // namespace orbit::detail

namespace orbit {

Error::Error(std::uint32_t status, ErrorKind kind, std::string code,
             std::string request_id)
    : std::runtime_error("Orbit SDK operation failed"), status_(status), kind_(kind),
      code_(std::move(code)), request_id_(std::move(request_id)) {}

Cancellation::Cancellation() : state_(std::make_shared<detail::CancellationState>()) {}

void Cancellation::cancel() const noexcept {
    if (state_) state_->cancelled.store(true, std::memory_order_relaxed);
}

PendingRegistration::PendingRegistration(
    std::shared_ptr<detail::ClientState> owner,
    std::shared_ptr<detail::PendingRegistrationState> value) noexcept
    : owner_(std::move(owner)), value_(std::move(value)) {}

PendingRegistration::~PendingRegistration() { reset(); }

PendingRegistration::PendingRegistration(PendingRegistration&& other) noexcept
    : owner_(std::move(other.owner_)), value_(std::move(other.value_)) {}

PendingRegistration& PendingRegistration::operator=(PendingRegistration&& other) noexcept {
    if (this != &other) {
        reset();
        owner_ = std::move(other.owner_);
        value_ = std::move(other.value_);
    }
    return *this;
}

void PendingRegistration::reset() noexcept {
    value_.reset();
    owner_.reset();
}

Client::Client(std::shared_ptr<detail::ClientState> state) noexcept : state_(std::move(state)) {}
Client::Client(Client&& other) noexcept : state_(std::move(other.state_)) {}
Client& Client::operator=(Client&& other) noexcept {
    if (this != &other) state_ = std::move(other.state_);
    return *this;
}

Client Client::connect(Config config) { return Client(detail::connect_state(std::move(config))); }

Client Client::open(AppConfig app,
                    std::optional<std::string> state_directory) {
    Config config;
    config.api_origin = std::move(app.api_origin);
    config.application_id = std::move(app.application_id);
    config.environment_id = std::move(app.environment_id);
    config.issuer = std::move(app.issuer);
    config.fingerprint = std::move(app.fingerprint);
    if (!detail::opaque(config.application_id) || !detail::opaque(config.environment_id) ||
        config.issuer.empty() || config.issuer.size() > 2048 || !detail::valid_utf8(config.issuer) ||
        std::any_of(config.issuer.begin(), config.issuer.end(), [](unsigned char c) {
            return c < 0x20 || c == 0x7f;
        }) || (config.fingerprint &&
            (!detail::valid_lower_hex(config.fingerprint->value, 64) ||
             !detail::valid_provider(config.fingerprint->provider)))) {
        detail::raise(ErrorKind::configuration, "configuration");
    }
    (void)detail::capture_clock();
    detail::Transport transport(config.api_origin);
    config.api_origin = transport.origin();
    auto installed = detail::open_installed_storage(config, std::move(state_directory));
    auto state = detail::open_installed_state(
        std::move(config), std::move(transport), std::move(installed));
    return Client(std::move(state));
}

const Config& Client::config() const noexcept {
    static const Config empty;
    return state_ ? state_->config : empty;
}

const std::string& Client::installation_id() const noexcept {
    static const std::string empty;
    if (!state_ || !state_->config.installation_id) return empty;
    return *state_->config.installation_id;
}

namespace {
detail::ClientState& require_state(const std::shared_ptr<detail::ClientState>& state) {
    if (!state) detail::raise(ErrorKind::configuration, "configuration");
    return *state;
}
} // namespace

std::string Client::snapshot(const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    if (detail::cancellation_flag(cancellation, inactive).load(std::memory_order_relaxed)) {
        detail::raise(ErrorKind::cancelled, "cancelled");
    }
    return detail::encode_json(require_state(state_).snapshot());
}

std::string Client::activate(std::string_view licence_key, std::string_view idempotency_key,
                             const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).activate(licence_key, idempotency_key,
        std::nullopt, detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::activate(std::string_view licence_key,
                             const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).activate(licence_key, {},
        std::nullopt, detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::activate_previous(std::string_view licence_key,
                                      std::optional<std::string_view> previous_credential,
                                      std::string_view idempotency_key,
                                      const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).activate(licence_key, idempotency_key,
        previous_credential, detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::refresh(const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).refresh(detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::require_access(std::string_view feature, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).require_access(feature, detail::cancellation_flag(cancellation, inactive)));
}

void Client::deactivate(std::string_view idempotency_key, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    require_state(state_).deactivate(idempotency_key, detail::cancellation_flag(cancellation, inactive));
}

void Client::local_logout() const { require_state(state_).local_logout(); }

void Client::close() const { require_state(state_).close(); }

RegistrationResult Client::register_customer(
    std::string_view licence_key, std::string_view username, std::string_view email,
    std::string_view password, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    auto result = require_state(state_).register_customer(licence_key, username, email, password,
                                                          detail::cancellation_flag(cancellation, inactive));
    return RegistrationResult{detail::encode_json(result.first),
                              PendingRegistration(state_, std::move(result.second))};
}

void Client::resend_registration(const PendingRegistration& pending,
                                 const Cancellation* cancellation) const {
    if (!state_ || !pending.value_ || pending.owner_.get() != state_.get()) {
        detail::raise(ErrorKind::configuration, "configuration");
    }
    std::atomic_bool inactive{false};
    state_->resend_registration(*pending.value_, detail::cancellation_flag(cancellation, inactive));
}

std::string Client::login(std::string_view username, std::string_view password,
                          const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).login(username, password, detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::account() const { return detail::encode_json(require_state(state_).account()); }

std::string Client::owned_licences(std::optional<std::string_view> cursor,
                                   const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).owned_licences(cursor, detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::claim_licence(std::string_view licence_key, std::string_view idempotency_key,
                                  const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).claim_licence(licence_key, idempotency_key,
        detail::cancellation_flag(cancellation, inactive)));
}

std::string Client::activate_account(std::string_view licence_id, std::string_view idempotency_key,
                                     const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).activate({}, idempotency_key, std::nullopt,
        detail::cancellation_flag(cancellation, inactive), licence_id));
}

std::string Client::activate_account_previous(
    std::string_view licence_id, std::optional<std::string_view> previous_credential,
    std::string_view idempotency_key, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::encode_json(require_state(state_).activate({}, idempotency_key, previous_credential,
        detail::cancellation_flag(cancellation, inactive), licence_id));
}

void Client::account_logout(const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    require_state(state_).account_logout(detail::cancellation_flag(cancellation, inactive));
}

void Client::request_email_change(std::string_view password, std::string_view new_email,
                                  const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    require_state(state_).request_email_change(password, new_email, detail::cancellation_flag(cancellation, inactive));
}

void Client::request_password_recovery(std::string_view email,
                                       const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    require_state(state_).request_password_recovery(email, detail::cancellation_flag(cancellation, inactive));
}

std::string Client::customer_session_authorization() const {
    return require_state(state_).customer_session_authorization();
}

} // namespace orbit
