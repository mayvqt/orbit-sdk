#include "core.hpp"
#include "online.hpp"

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

bool same_credential(const Credential &left, const Credential &right) {
    return left.activation_id == right.activation_id && left.licence_id == right.licence_id &&
           left.bearer == right.bearer && left.expires_at == right.expires_at;
}

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
                                    std::optional<std::string_view> account_licence,
                                    std::optional<std::string_view> principal_identity = std::nullopt) {
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
    input["principal_identity"] = principal_identity
        ? Json::Value(std::string(*principal_identity)) : null_value();
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
    const auto offline_file_seconds = integer(required(input, "offline_file_seconds"));
    const auto& entitlements = required(input, "entitlements");
    if (!opaque(id) || device_limit < 1 || device_limit > 100 || entitlements.size() > 64 ||
        utf8_characters(policy) > 80 || offline_seconds < INT32_MIN || offline_seconds > INT32_MAX ||
        (offline_file_seconds != 0 && (offline_file_seconds < 86400 || offline_file_seconds > 31622400)) ||
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
    output["offline_file_seconds"] = static_cast<Json::Int64>(offline_file_seconds);
    output["entitlements"] = std::move(entitlement_output);
    for (const auto *field : {"usage_limits", "resource_limits", "concurrent_session_limit"})
        if (input.isMember(field))
            output[field] = input[field];
    return output;
}

} // namespace

ClockStart capture_clock() {
    const auto value = current_clock();
    if (value.first < 0 || value.second < 0) raise(ErrorKind::clock_uncertain, "clock_uncertain");
    return {value.first, value.second};
}

std::optional<Fingerprint> resolve_fingerprint(const ::orbit::AppKey& app_key,
                                                const ::orbit::Options& options) {
    if (options.disable_machine_binding && options.fingerprint) {
        raise(ErrorKind::configuration, "configuration");
    }
    if (options.fingerprint) {
        if (!valid_lower_hex(options.fingerprint->value, 64) ||
            !valid_provider(options.fingerprint->provider)) {
            raise(ErrorKind::configuration, "configuration");
        }
        return options.fingerprint;
    }
    if (options.disable_machine_binding) return std::nullopt;
    try {
        return Fingerprint{::orbit::native_fingerprint(app_key.application_id(), app_key.environment_id()),
                           "machine_v1"};
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::denied && error.code() == "device_identity_unavailable") {
            return std::nullopt;
        }
        throw;
    }
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
    offline.reset();
    session_required = false;
    session_profile_known = false;
    session_disabled = false;
    session_grant.reset();
    session_anchor.reset();
    pending_session_id.reset();
    pending_renewal_sequence.reset();
    session_retry_deadline.reset();
    session_licence_expiry.reset();
    session_binding_mode.clear();
    transient = false;
    retry_deadline.reset();
}

void ClientState::clear_all_locked() {
    clear_access_locked();
    customer.reset();
}

void ClientState::invalidate_locked(bool clear_pending) {
    if (persistent) {
        persistent_record["generation"] = static_cast<Json::UInt64>(current_generation);
        persistent_record["credential"] = null_value();
        if (clear_pending) persistent_record["pending_activation"] = null_value();
        persistent_record["access"] = null_value();
        if (persistent_record.isMember("offline") && persistent_record["offline"].isObject())
            persistent_record["offline"]["jws"] = null_value();
        persist_record_locked();
        return;
    }
    storage_version = storage->invalidate();
}

void ClientState::sync_storage_locked() {
    if (persistent) {
        if (persistence_failed.load(std::memory_order_relaxed)) {
            credential.reset();
            claims.reset();
            anchor.reset();
            offline.reset();
            customer.reset();
            transient = false;
            retry_deadline.reset();
            raise(ErrorKind::storage, "installation_storage_unavailable");
        }
        try {
            if (!installed_storage) raise(ErrorKind::storage, "installation_storage_unavailable");
            installed_storage->verify();
        } catch (...) {
            if (!persistence_failed.exchange(true, std::memory_order_relaxed) &&
                current_generation < persistent_codec::max_generation) {
                ++current_generation;
            }
            credential.reset();
            claims.reset();
            anchor.reset();
            offline.reset();
            customer.reset();
            transient = false;
            retry_deadline.reset();
            worker_cancelled.store(true, std::memory_order_relaxed);
            wake_worker();
            raise(ErrorKind::storage, "installation_storage_unavailable");
        }
#ifdef ORBIT_SDK_TESTING
        note_access_benchmark_invalidation_check();
#endif
        return;
    }
    const auto observed = storage->version();
#ifdef ORBIT_SDK_TESTING
    note_access_benchmark_invalidation_check();
#endif
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

::orbit::Snapshot ClientState::snapshot_locked(bool tolerate_clock_error) {
    if (offline) return offline_snapshot_locked();
    ::orbit::Snapshot result;
    result.access = credential ? ::orbit::Access::refresh_required : ::orbit::Access::denied;
    result.reauthentication_required = !credential.has_value();
    if (credential && credential->expires_at) {
        result.credential_expires_at = ::orbit::Timestamp(std::chrono::seconds(*credential->expires_at));
    }
    if (session_required) {
        result.offline_allowed = false;
        result.reauthentication_required =
            credential && credential->expires_at &&
            *credential->expires_at <= capture_clock().wall_seconds + 86400;
        if (!session_grant || !session_anchor)
            return result;
        std::int64_t now = 0;
        try {
            now = session_anchor->now();
        } catch (const Error &error) {
            if (!tolerate_clock_error || error.kind() != ErrorKind::clock_uncertain)
                throw;
            session_grant.reset();
            session_anchor.reset();
            pending_renewal_sequence.reset();
            advance_generation_locked();
            return result;
        }
        result.expires_at = ::orbit::Timestamp(std::chrono::seconds(session_grant->expires_at));
        result.next_check_at =
            ::orbit::Timestamp(std::chrono::seconds(session_grant->refresh_after));
        result.session =
            ::orbit::Snapshot::Session{session_grant->session_id, session_grant->sequence};
        result.access =
            session_grant->expires_at <= now ? ::orbit::Access::expired : ::orbit::Access::online;
        if (result.access == ::orbit::Access::online)
            result.entitlements = session_grant->entitlements;
        return result;
    }
    if (!claims || !anchor) {
        if (credential && credential->expires_at) {
            result.reauthentication_required =
                *credential->expires_at <= capture_clock().wall_seconds + 86400;
        }
        return result;
    }
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
        if (credential && credential->expires_at) {
            result.reauthentication_required =
                *credential->expires_at <= capture_clock().wall_seconds + 86400;
        }
        return result;
    }
    result.expires_at = ::orbit::Timestamp(std::chrono::seconds(claims->expires_at));
    result.next_check_at = ::orbit::Timestamp(std::chrono::seconds(claims->refresh_after));
    result.reauthentication_required = !credential ||
        (credential->expires_at && *credential->expires_at <= now + 86400);
    result.offline_allowed = claims->offline_allowed;
    result.policy_version = claims->policy_version;
    if (claims->expires_at <= now) result.access = ::orbit::Access::expired;
    else if (transient) result.access = claims->offline_allowed
        ? ::orbit::Access::offline : ::orbit::Access::refresh_required;
    else if (claims->refresh_after <= now) result.access = ::orbit::Access::refresh_required;
    else result.access = ::orbit::Access::online;
    if (result.access == ::orbit::Access::online || result.access == ::orbit::Access::offline) {
        result.entitlements = claims->entitlements;
        if (claims->offline_allowed)
            result.remaining_offline = std::chrono::seconds(claims->expires_at - now);
    }
    return result;
}

::orbit::Snapshot ClientState::offline_snapshot_locked() {
    if (!offline) raise(ErrorKind::storage, "offline_state_unavailable");
    auto& current = *offline;
    if (!offline_clock) {
        offline_clock = OfflineClockState{current.anchor, current.time_high_water,
            current.wall_high_water, current.uncertain, current.last_checkpoint};
    }
    std::int64_t now = 0;
    try {
        now = offline_clock->anchor.now();
        const auto wall = capture_clock().wall_seconds;
        if (wall < offline_clock->wall_high_water - 30 || now < offline_clock->time_high_water)
            raise(ErrorKind::clock_uncertain, "clock_uncertain");
        offline_clock->time_high_water = std::max(offline_clock->time_high_water, now);
        offline_clock->wall_high_water = std::max(offline_clock->wall_high_water, wall);
        offline_clock->uncertain = false;
        current.anchor = offline_clock->anchor;
        current.time_high_water = offline_clock->time_high_water;
        current.wall_high_water = offline_clock->wall_high_water;
        current.uncertain = false;
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::clock_uncertain) {
            offline_clock->uncertain = true;
            current.uncertain = true;
        }
        throw;
    }
    ::orbit::Snapshot result;
    const bool expired = now >= current.file.expires_at;
    result.access = expired ? ::orbit::Access::expired : ::orbit::Access::offline;
    result.expires_at = ::orbit::Timestamp(std::chrono::seconds(current.file.expires_at));
    result.offline_allowed = true;
    result.offline_file_mode = true;
    result.policy_version = current.file.policy_version;
    result.remaining_offline = std::chrono::seconds(expired ? 0 : current.file.expires_at - now);
    if (!expired) result.entitlements = current.file.entitlements;
    return result;
}

::orbit::Snapshot ClientState::snapshot() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    return snapshot_locked(true);
}

::orbit::OfflineRequest ClientState::offline_request() {
    ClientOperation call(*this);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (!persistent || !config.public_app_key || !config.installation_id)
        raise(ErrorKind::configuration, "configuration");
    return {*config.public_app_key, *config.installation_id,
            config.fingerprint ? std::optional<std::string>(config.fingerprint->value) : std::nullopt,
            config.fingerprint ? std::optional<std::string>(config.fingerprint->provider) : std::nullopt};
}

void ClientState::restore_offline() {
    std::lock_guard<std::mutex> lock(mutex);
    if (!persistent_record.isObject() || !persistent_record.isMember("offline") ||
        persistent_record["offline"].isNull()) return;
    const auto& saved = persistent_record["offline"];
    const auto time_high = json_int64(saved["time_high_water"]);
    const auto wall_high = json_int64(saved["wall_high_water"]);
    const auto start = capture_clock();
    const auto trusted = std::max(time_high, start.wall_seconds);
    const bool uncertain = start.wall_seconds + 30 < wall_high || time_high < json_int64(saved["verified_at"]);
    ClockAnchor restored_anchor{trusted, start.elapsed_nanoseconds, start.wall_seconds};
    offline_clock = OfflineClockState{restored_anchor, time_high, wall_high, uncertain,
        std::chrono::steady_clock::now()};
    if (saved["jws"].isNull()) return;
    if (!config.offline_keys || !config.public_app_key || !config.installation_id)
        raise(ErrorKind::configuration, "offline_keys_required");
    try {
        const auto token = saved["jws"].asString();
        const auto verified_at = json_int64(saved["verified_at"]);
        const auto sequence = json_int64(saved["sequence"]);
        const auto app_key = ::orbit::AppKey::parse(*config.public_app_key);
        auto verified = config.offline_keys->verify(token,
            OfflineExpected{app_key, *config.installation_id, config.fingerprint, verified_at, sequence});
        if (verified.sequence != sequence || verified.issuance_id != saved["issuance_id"].asString() ||
            verified.content_digest != saved["content_digest"].asString() ||
            verified_at < verified.issued_at - 30 || verified_at >= verified.expires_at)
            raise(ErrorKind::corrupt_state, "offline_state_invalid");
        offline = OfflineRuntime{std::move(verified), restored_anchor,
            time_high, wall_high, uncertain, offline_clock->last_checkpoint};
    } catch (const Error& error) {
        if (error.kind() == ErrorKind::configuration) throw;
        if (error.kind() == ErrorKind::clock_uncertain) throw;
        raise(ErrorKind::corrupt_state, "offline_state_invalid");
    } catch (...) {
        raise(ErrorKind::corrupt_state, "offline_state_invalid");
    }
}

::orbit::Snapshot ClientState::import_offline_file(
    std::string_view input, const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    if (!persistent || !config.offline_keys || !config.public_app_key || !config.installation_id)
        raise(ErrorKind::configuration, "offline_keys_required");
    if (input.empty() || input.size() > 16384 ||
        std::any_of(input.begin(), input.end(), [](unsigned char c) { return c > 127; }))
        raise(ErrorKind::invalid_response, "invalid_offline_file");
    throw_if_cancelled(cancelled);
    const auto expected_generation = generation();
    auto serial_lock = lock_serial(cancelled);
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    if (current_generation != expected_generation)
        raise(ErrorKind::stale_response, "stale_response");
    throw_if_cancelled(cancelled);

    const Json::Value previous = persistent_record.isMember("offline")
        ? persistent_record["offline"] : Json::Value(Json::nullValue);
    std::int64_t minimum = 1, old_time = 0, old_wall = 0;
    if (previous.isObject()) {
        minimum = json_int64(previous["sequence"]);
        old_time = json_int64(previous["time_high_water"]);
        old_wall = json_int64(previous["wall_high_water"]);
    }
    if (offline_clock) {
        old_time = std::max(old_time, offline_clock->time_high_water);
        old_wall = std::max(old_wall, offline_clock->wall_high_water);
    }
    const auto start = capture_clock();
    if (start.wall_seconds < 0 || start.wall_seconds > 253402300799LL ||
        start.wall_seconds + 30 < old_wall)
        raise(ErrorKind::clock_uncertain, "clock_uncertain");
    auto now = std::max(start.wall_seconds, old_time);
    if (offline_clock) {
        try {
            const auto current = offline_clock->anchor.now();
            if (current < old_time || start.wall_seconds + 30 < old_wall) {
                offline_clock->uncertain = true;
                if (offline) offline->uncertain = true;
                raise(ErrorKind::clock_uncertain, "clock_uncertain");
            }
            now = std::max(now, current);
        } catch (const Error& error) {
            if (error.kind() == ErrorKind::clock_uncertain) {
                offline_clock->uncertain = true;
                if (offline) offline->uncertain = true;
            }
            throw;
        }
    }
    const auto app_key = ::orbit::AppKey::parse(*config.public_app_key);
    const auto verified = config.offline_keys->verify(input,
        OfflineExpected{app_key, *config.installation_id, config.fingerprint, now, minimum});
    if (previous.isObject() && verified.sequence == minimum &&
        (verified.issuance_id != previous["issuance_id"].asString() ||
         verified.content_digest != previous["content_digest"].asString()))
        raise(ErrorKind::denied, "offline_sequence");
    throw_if_cancelled(cancelled);

    const auto trusted = std::max(now, verified.issued_at);
    ClockAnchor import_anchor = offline_clock
        ? offline_clock->anchor : ClockAnchor{trusted, start.elapsed_nanoseconds, start.wall_seconds};
    const auto anchored_now = import_anchor.now();
    if (trusted > anchored_now) {
        const auto advance = trusted - anchored_now;
        if (advance > std::numeric_limits<std::int64_t>::max() - import_anchor.server_seconds)
            raise(ErrorKind::clock_uncertain, "clock_uncertain");
        import_anchor.server_seconds += advance;
    }

    if (current_generation >= persistent_codec::max_generation)
        raise(ErrorKind::storage, "installation_generation_exhausted");
    ++current_generation;
    Json::Value saved(Json::objectValue);
    saved["jws"] = verified.token;
    saved["sequence"] = static_cast<Json::Int64>(verified.sequence);
    saved["issuance_id"] = verified.issuance_id;
    saved["content_digest"] = verified.content_digest;
    saved["verified_at"] = static_cast<Json::Int64>(now);
    saved["time_high_water"] = static_cast<Json::Int64>(std::max(now, verified.issued_at));
    saved["wall_high_water"] = static_cast<Json::Int64>(std::max(old_wall, start.wall_seconds));
    Json::Value candidate = persistent_record;
    candidate["format"] = 3;
    candidate["generation"] = static_cast<Json::UInt64>(current_generation);
    candidate["credential"] = null_value();
    candidate["pending_activation"] = null_value();
    candidate["access"] = null_value();
    candidate["offline"] = saved;
    commit_persistent_locked(std::move(candidate));
    offline_clock = OfflineClockState{import_anchor,
        json_int64(persistent_record["offline"]["time_high_water"]),
        json_int64(persistent_record["offline"]["wall_high_water"]), false,
        std::chrono::steady_clock::now()};
    credential.reset();
    claims.reset();
    anchor.reset();
    customer.reset();
    transient = false;
    retry_deadline.reset();
    offline.reset();

    OfflineRuntime runtime{verified, import_anchor,
        json_int64(persistent_record["offline"]["time_high_water"]),
        json_int64(persistent_record["offline"]["wall_high_water"]), false,
        offline_clock->last_checkpoint};
    bool durable_cleared = false;
    auto abandon = [&](ErrorKind reason, std::string code) -> void {
        offline.reset();
        if (persistence_failed.load(std::memory_order_relaxed))
            raise(ErrorKind::storage, "installation_state_write_failed");
        if (current_generation >= persistent_codec::max_generation)
            raise(ErrorKind::storage, "installation_generation_exhausted");
        ++current_generation;
        auto cleared = persistent_record;
        cleared["generation"] = static_cast<Json::UInt64>(current_generation);
        cleared["credential"] = null_value();
        cleared["access"] = null_value();
        cleared["pending_activation"] = null_value();
        const auto time_floor = std::max(runtime.time_high_water,
            offline_clock ? offline_clock->time_high_water : std::int64_t{0});
        const auto wall_floor = std::max(runtime.wall_high_water,
            offline_clock ? offline_clock->wall_high_water : std::int64_t{0});
        cleared["offline"]["time_high_water"] = static_cast<Json::Int64>(time_floor);
        cleared["offline"]["wall_high_water"] = static_cast<Json::Int64>(wall_floor);
        cleared["offline"]["jws"] = null_value();
        try { commit_persistent_locked(std::move(cleared)); }
        catch (...) { raise(ErrorKind::storage, "installation_state_write_failed"); }
        if (offline_clock) {
            offline_clock->time_high_water = time_floor;
            offline_clock->wall_high_water = wall_floor;
            if (reason == ErrorKind::clock_uncertain) offline_clock->uncertain = true;
        }
        durable_cleared = true;
        raise(reason, std::move(code));
    };
    try {
        throw_if_cancelled(cancelled);
        const auto sampled_now = runtime.anchor.now();
        const auto sampled_wall = capture_clock().wall_seconds;
        if (sampled_wall + 30 < runtime.wall_high_water || sampled_now < runtime.time_high_water)
            abandon(ErrorKind::clock_uncertain, "clock_uncertain");
        runtime.time_high_water = std::max(runtime.time_high_water, sampled_now);
        runtime.wall_high_water = std::max(runtime.wall_high_water, sampled_wall);
        if (sampled_now >= runtime.file.expires_at)
            abandon(ErrorKind::denied, "offline_file_expired");
        auto checkpoint = persistent_record;
        checkpoint["offline"]["time_high_water"] = static_cast<Json::Int64>(runtime.time_high_water);
        checkpoint["offline"]["wall_high_water"] = static_cast<Json::Int64>(runtime.wall_high_water);
        if (checkpoint != persistent_record) commit_persistent_locked(std::move(checkpoint));
        offline_clock->time_high_water = runtime.time_high_water;
        offline_clock->wall_high_water = runtime.wall_high_water;
        throw_if_cancelled(cancelled);
        const auto after_write = runtime.anchor.now();
        const auto after_wall = capture_clock().wall_seconds;
        if (after_wall + 30 < runtime.wall_high_water || after_write < runtime.time_high_water)
            abandon(ErrorKind::clock_uncertain, "clock_uncertain");
        runtime.time_high_water = std::max(runtime.time_high_water, after_write);
        runtime.wall_high_water = std::max(runtime.wall_high_water, after_wall);
        if (after_write >= runtime.file.expires_at)
            abandon(ErrorKind::denied, "offline_file_expired");
        throw_if_cancelled(cancelled);
        offline = std::move(runtime);
        const auto snapshot = offline_snapshot_locked();
        throw_if_cancelled(cancelled);
        return snapshot;
    } catch (const Error& error) {
        if (durable_cleared || persistence_failed.load(std::memory_order_relaxed)) throw;
        abandon(error.kind(), error.code());
    } catch (...) {
        if (durable_cleared || persistence_failed.load(std::memory_order_relaxed)) throw;
        abandon(ErrorKind::storage, "installation_state_write_failed");
    }
    raise(ErrorKind::internal, "offline_import_failed");
}

ClientState::VerifiedActivation
ClientState::verify_reply(const Json::Value &reply, const std::optional<Credential> &previous,
                          std::optional<std::string_view> expected_licence, ClockStart start,
                          const std::atomic_bool &cancelled, ClockAnchor &out_anchor) {
    const auto activation_id = text(required(reply, "activation_id"));
    const auto installation_id = text(required(reply, "installation_id"));
    const auto credential_value = optional_string(reply, "credential");
    const auto &expiry_value = required(reply, "credential_expires_at");
    std::optional<std::int64_t> expiry;
    if (!expiry_value.isNull()) {
        if (!expiry_value.isString())
            invalid_response();
        expiry = timestamp(expiry_value.asString());
    }
    const auto session_flag = reply.isMember("session_required");
    if (session_flag &&
        (!reply["session_required"].isBool() || !reply["session_required"].asBool()))
        invalid_response();
    const bool requires_session = session_flag;
    const auto &grant_value = required(reply, "grant");
    std::optional<std::string> grant;
    if (requires_session) {
        if (!grant_value.isNull())
            invalid_response();
    } else {
        if (!grant_value.isString())
            invalid_response();
        grant = grant_value.asString();
    }
    const auto reply_licence = optional_string(reply, "licence_id");
    const auto server_text = text(required(reply, "server_time"));
    const auto binding = text(required(reply, "binding_mode"));
    const auto fingerprint_provider = optional_string(reply, "fingerprint_provider");
    const auto licence_expiry_text = optional_string(reply, "licence_expires_at");
    const auto secret_replay_expired = boolean(required(reply, "secret_replay_expired"));
    if (secret_replay_expired)
        raise(ErrorKind::reauthentication_required, "reauthentication_required");
    const auto configured_fingerprint =
        config.fingerprint ? std::optional<std::string_view>(config.fingerprint->value)
                           : std::nullopt;
    const auto configured_provider =
        config.fingerprint ? std::optional<std::string_view>(config.fingerprint->provider)
                           : std::nullopt;
    if (!opaque(activation_id) || installation_id != *config.installation_id ||
        fingerprint_provider != (configured_provider
                                     ? std::optional<std::string>(*configured_provider)
                                     : std::nullopt) ||
        (configured_fingerprint ? (binding != "none" && binding != "hwid") : binding != "none"))
        invalid_response();

    const auto server_time = timestamp(server_text);
    out_anchor = ClockAnchor{server_time, start.elapsed_nanoseconds, start.wall_seconds};
    auto now = out_anchor.now();
    if ((!persistent && !expiry) || (persistent && !previous && expiry))
        invalid_response();
    if (expiry && (*expiry <= now || *expiry > now + 30 * 86400))
        invalid_response();
    if (previous && (activation_id != previous->activation_id || expiry != previous->expires_at ||
                     credential_value)) {
        invalid_response();
    }
    auto licence_expiry = licence_expiry_text
                              ? std::optional<std::int64_t>(timestamp(*licence_expiry_text))
                              : std::nullopt;
    auto bearer_value =
        credential_value ? *credential_value : (previous ? previous->bearer : std::string{});
    if (!bearer(bearer_value))
        invalid_response();
    if (requires_session) {
        if (!reply_licence || !opaque(*reply_licence) ||
            (expected_licence && *reply_licence != *expected_licence) ||
            (previous && *reply_licence != previous->licence_id))
            invalid_response();
        Credential saved{activation_id, *reply_licence, std::move(bearer_value), expiry};
        return {std::move(saved), std::nullopt, out_anchor, true, licence_expiry, binding};
    }
    if (!grant)
        invalid_response();
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
        if (!jwks)
            invalid_response();
        auto refreshed = GrantKeys::parse(*jwks);
        {
            std::lock_guard<std::mutex> lock(mutex);
            keys = std::move(refreshed);
            known = keys.contains(*grant);
        }
    }
    if (!known)
        invalid_response();
    now = out_anchor.now();
    GrantExpected expected{
        config.issuer,
        config.application_id,
        config.environment_id,
        expected_licence
            ? expected_licence
            : (previous ? std::optional<std::string_view>(previous->licence_id) : std::nullopt),
        activation_id,
        *config.installation_id,
        configured_fingerprint,
        configured_provider,
        expiry,
        licence_expiry,
        now,
        true,
        binding,
    };
    GrantClaims verified;
    {
        std::lock_guard<std::mutex> lock(mutex);
        verified = keys.verify(*grant, expected);
    }
    Credential saved{activation_id, verified.subject, std::move(bearer_value), expiry};
    (void)kid;
    return {std::move(saved), std::move(verified), out_anchor, false, licence_expiry, binding};
}

::orbit::Snapshot ClientState::accept_reply(
    const std::optional<Json::Value>& reply, const Error* response_error,
    std::uint64_t request_generation,
    const std::optional<Credential>& previous, std::optional<std::string_view> expected_licence,
    ClockStart start, const std::atomic_bool& cancelled, bool mutation) {
    std::optional<VerifiedActivation> accepted;
    std::optional<ClockAnchor> accepted_anchor;
    std::optional<Error> failure;
    const bool verifying = reply.has_value();
    if (response_error) {
        failure.emplace(*response_error);
    } else if (reply) {
        try {
            ClockAnchor request_anchor;
            accepted.emplace(
                verify_reply(*reply, previous, expected_licence, start, cancelled, request_anchor));
            accepted_anchor = request_anchor;
        } catch (const Error &error) {
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
            candidate["credential"] = credential_json(accepted->credential);
            candidate["access"] =
                accepted->session_required
                    ? Json::Value(Json::nullValue)
                    : persistent_access_cache(*reply, *accepted->claims, keys, start);
            if (mutation) candidate["pending_activation"] = null_value();
            commit_persistent_locked(std::move(candidate));
        } else {
            try {
                storage->save(storage_version, credential_json(accepted->credential));
            } catch (...) {
                clear_all_locked();
                throw;
            }
        }
        credential = accepted->credential;
        claims = accepted->claims;
        anchor = accepted_anchor;
        const bool profile_changed = session_required != accepted->session_required ||
                                     (session_required && accepted->session_required &&
                                      (session_licence_expiry != accepted->licence_expires_at ||
                                       session_binding_mode != accepted->binding_mode));
        if (!accepted->session_required || profile_changed) {
            session_grant.reset();
            session_anchor.reset();
            pending_session_id.reset();
            pending_renewal_sequence.reset();
            session_retry_deadline.reset();
            if (!accepted->session_required)
                session_disabled = false;
        }
        session_required = accepted->session_required;
        session_profile_known = true;
        session_licence_expiry =
            accepted->session_required ? accepted->licence_expires_at : std::nullopt;
        session_binding_mode = accepted->session_required ? accepted->binding_mode : std::string{};
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
        if (current.access == ::orbit::Access::offline) return current;
        throw *failure;
    }

    clear_all_locked();
    invalidate_locked();
    wake_worker();
    throw *failure;
}

::orbit::Snapshot ClientState::activate(std::string_view key, std::string_view idempotency_key,
                                        std::optional<std::string_view> previous,
                                        const std::atomic_bool& cancelled,
                                        std::optional<std::string_view> account_licence) {
    ClientOperation call(*this);
    const bool automatic = idempotency_key.empty();
    if ((account_licence ? !opaque(*account_licence) : (key.empty() || key.size() > 256)) ||
        (!automatic && (idempotency_key.size() < 16 || idempotency_key.size() > 128)) ||
        (automatic && !persistent) || !valid_utf8(key) ||
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
        checkpoint_offline_before_transition_locked();
        if (persistent) {
            std::optional<std::string> customer_identity;
            if (account_licence) {
                if (!customer) raise(ErrorKind::reauthentication_required, "reauthentication_required");
                account_token = customer->bearer;
                customer_identity = text(required(required(customer->account, "customer"), "id"));
            }
            const auto digest = activation_input_digest(
                config, key, previous, account_licence ? "account" : "key",
                account_licence, customer_identity
                    ? std::optional<std::string_view>(*customer_identity) : std::nullopt);
            const auto now = capture_clock().wall_seconds;
            if (now <= 0) raise(ErrorKind::clock_uncertain, "clock_uncertain");
            auto candidate = persistent_record;
            const auto& pending = candidate["pending_activation"];
            if (!pending.isNull()) {
                if (!pending.isObject() || !pending["operation_id"].isString() ||
                    pending["principal_kind"] != (account_licence ? "account" : "key") ||
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
                candidate["pending_activation"]["principal_kind"] = account_licence ? "account" : "key";
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
            if (candidate.isMember("offline") && candidate["offline"].isObject())
                candidate["offline"]["jws"] = null_value();
            offline.reset();
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
        session_grant.reset();
        session_anchor.reset();
        pending_session_id.reset();
        pending_renewal_sequence.reset();
        session_retry_deadline.reset();
        session_profile_known = false;
        session_required = false;
        session_disabled = false;
        session_licence_expiry.reset();
        session_binding_mode.clear();
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
    auto accepted_snapshot = accept_reply(response, nullptr, request_generation, std::nullopt,
                                          account_licence, start, cancelled, true);
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (session_required && !session_disabled) {
            // The activation credential was durably committed by accept_reply
            // before the first seat request is allowed to leave this process.
        } else
            return accepted_snapshot;
    }
    return start_session_serialized(cancelled, false);
}

SessionGrant ClientState::verify_session_reply(const Json::Value &reply,
                                               std::string_view session_id, std::int64_t sequence,
                                               const Credential &saved, ClockStart start,
                                               ClockAnchor &out_anchor,
                                               const std::atomic_bool &cancelled) {
    std::optional<std::int64_t> licence_expiry;
    std::string binding_mode;
    {
        std::lock_guard<std::mutex> lock(mutex);
        licence_expiry = session_licence_expiry;
        binding_mode = session_binding_mode;
    }
    if (!reply.isObject() || reply.size() != 5 || !reply.isMember("session_id") ||
        !reply.isMember("sequence") || !reply.isMember("expires_at") ||
        !reply.isMember("server_time") || !reply.isMember("grant"))
        invalid_response();
    const auto response_session = text(required(reply, "session_id"));
    const auto response_sequence = integer(required(reply, "sequence"));
    const auto expires = timestamp(text(required(reply, "expires_at")));
    out_anchor = ClockAnchor{timestamp(text(required(reply, "server_time"))),
                             start.elapsed_nanoseconds, start.wall_seconds};
    const auto grant_token = text(required(reply, "grant"));
    if (response_session != session_id || response_sequence != sequence ||
        !opaque(response_session) || response_session.size() < 16 || sequence < 1 ||
        sequence > 9007199254740991LL)
        invalid_response();

    auto trusted = config.session_keys;
    bool known = false;
    if (trusted)
        known = trusted->contains(grant_token);
    if (!known) {
        throw_if_cancelled(cancelled);
        const auto path = "/.well-known/orbit-jwks.json?application_id=" + config.application_id +
                          "&environment_id=" + config.environment_id;
        auto jwks = transport.get(path, cancelled);
        if (!jwks)
            invalid_response();
        auto refreshed = SessionKeys::parse(*jwks, config.environment);
        known = refreshed.contains(grant_token);
        if (!known)
            invalid_response();
        config.session_keys = std::make_shared<const SessionKeys>(std::move(refreshed));
        trusted = config.session_keys;
    }
    if (!trusted)
        invalid_response();
    const auto configured_fingerprint =
        config.fingerprint ? std::optional<std::string_view>(config.fingerprint->value)
                           : std::nullopt;
    const auto configured_provider =
        config.fingerprint ? std::optional<std::string_view>(config.fingerprint->provider)
                           : std::nullopt;
    GrantExpected expected{
        config.issuer,          config.application_id,
        config.environment_id,  std::string_view(saved.licence_id),
        saved.activation_id,    *config.installation_id,
        configured_fingerprint, configured_provider,
        saved.expires_at,       licence_expiry,
        out_anchor.now(),       true,
        binding_mode,
    };
    SessionExpected session_expected{expected, session_id, sequence};
    auto verified = trusted->verify(grant_token, session_expected);
    if (verified.expires_at != expires || verified.binding_mode != binding_mode)
        invalid_response();
    return verified;
}

::orbit::Snapshot ClientState::start_session_serialized(const std::atomic_bool &cancelled,
                                                        bool explicit_start) {
    Credential saved;
    std::uint64_t request_generation = 0;
    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        throw_if_cancelled(cancelled);
        if (offline)
            return snapshot_locked(true);
        if (!session_required)
            return snapshot_locked(true);
        if (session_disabled && !explicit_start)
            raise(ErrorKind::denied, "session_explicitly_ended");
        if (explicit_start)
            session_disabled = false;
        if (!credential)
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        if (session_grant && session_anchor) {
            const auto now = session_anchor->now();
            if (now < session_grant->expires_at)
                return snapshot_locked(true);
            session_grant.reset();
            session_anchor.reset();
            pending_renewal_sequence.reset();
        }
        if (!pending_session_id)
            pending_session_id = new_installation_id();
        session_id = *pending_session_id;
        saved = *credential;
        request_generation = current_generation;
    }
    Json::Value input = credential_body(saved);
    input["session_id"] = session_id;
    const auto path = "/api/client/v1/activations/" + saved.activation_id + "/sessions";
    const auto start = capture_clock();
    bool sent = false;
    try {
        sent = true;
        const auto response = transport.post(path, input, true, cancelled);
        if (!response)
            invalid_response();
        ClockAnchor response_anchor;
        auto verified = verify_session_reply(*response, session_id, 1, saved, start,
                                             response_anchor, cancelled);
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != request_generation || !credential ||
            !same_credential(*credential, saved) || !session_required || session_disabled ||
            !pending_session_id || *pending_session_id != session_id)
            raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        session_grant = std::move(verified);
        session_anchor = response_anchor;
        pending_session_id.reset();
        pending_renewal_sequence.reset();
        session_retry_deadline.reset();
        wake_worker();
        return snapshot_locked(true);
    } catch (const Error &error) {
        if (sent &&
            (error.kind() == ErrorKind::cancelled || error.kind() == ErrorKind::stale_response)) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (pending_session_id && *pending_session_id == session_id)
                    pending_session_id.reset();
            }
            std::atomic_bool cleanup_cancelled{false};
            try {
                const auto path = "/api/client/v1/activations/" + saved.activation_id +
                                  "/sessions/" + session_id + "/end";
                (void)transport.post(path, credential_body(saved), false, cleanup_cancelled);
            } catch (...) {
            }
        } else {
            std::lock_guard<std::mutex> lock(mutex);
            if (current_generation != request_generation || !credential ||
                !same_credential(*credential, saved) || !session_required || !pending_session_id ||
                *pending_session_id != session_id)
                raise(ErrorKind::stale_response, "stale_response");
            if (error.kind() == ErrorKind::transient ||
                (error.kind() == ErrorKind::denied &&
                 error.code() == "concurrent_session_limit_reached")) {
                session_retry_deadline =
                    std::chrono::steady_clock::now() + std::chrono::seconds(15 + std::rand() % 30);
                wake_worker();
            } else if (error.kind() == ErrorKind::denied) {
                // A definite denial such as an expired ID or sequence conflict
                // makes that unacknowledged start key unusable. Capacity denial
                // above remains safely retryable with the same key.
                pending_session_id.reset();
            } else if (error.kind() == ErrorKind::invalid_response) {
                session_grant.reset();
                session_anchor.reset();
                pending_renewal_sequence.reset();
            }
        }
        throw;
    }
}

::orbit::Snapshot ClientState::advance_session_serialized(const std::atomic_bool &cancelled) {
    bool start_new = false;
    Credential saved;
    SessionGrant current;
    ClockAnchor current_anchor;
    std::int64_t sequence = 0;
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        throw_if_cancelled(cancelled);
        if (offline || !session_required || session_disabled)
            return snapshot_locked(true);
        if (!credential)
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        if (session_retry_deadline && std::chrono::steady_clock::now() < *session_retry_deadline)
            return snapshot_locked(true);
        saved = *credential;
        request_generation = current_generation;
        if (!session_grant || !session_anchor)
            start_new = true;
        else {
            current = *session_grant;
            current_anchor = *session_anchor;
            const auto now = current_anchor.now();
            if (now >= current.expires_at) {
                session_grant.reset();
                session_anchor.reset();
                pending_renewal_sequence.reset();
                pending_session_id.reset();
                start_new = true;
            } else if (now < current.refresh_after) {
                return snapshot_locked(true);
            } else {
                if (!pending_renewal_sequence) {
                    if (current.sequence >= 9007199254740991LL)
                        raise(ErrorKind::denied, "session_sequence_exhausted");
                    pending_renewal_sequence = current.sequence + 1;
                }
                sequence = *pending_renewal_sequence;
            }
        }
    }
    if (start_new)
        return start_session_serialized(cancelled, false);
    Json::Value input = credential_body(saved);
    input["sequence"] = static_cast<Json::Int64>(sequence);
    const auto path = "/api/client/v1/activations/" + saved.activation_id + "/sessions/" +
                      current.session_id + "/renew";
    const auto start = capture_clock();
    try {
        const auto response = transport.post(path, input, true, cancelled);
        if (!response)
            invalid_response();
        ClockAnchor response_anchor;
        auto verified = verify_session_reply(*response, current.session_id, sequence, saved, start,
                                             response_anchor, cancelled);
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != request_generation || !credential ||
            !same_credential(*credential, saved) || !session_required || session_disabled ||
            !session_grant || session_grant->session_id != current.session_id ||
            session_grant->sequence != current.sequence)
            raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        session_grant = std::move(verified);
        session_anchor = response_anchor;
        pending_renewal_sequence.reset();
        session_retry_deadline.reset();
        wake_worker();
        return snapshot_locked(true);
    } catch (const Error &error) {
        std::lock_guard<std::mutex> lock(mutex);
        if (current_generation != request_generation || !credential ||
            !same_credential(*credential, saved) || !session_required || session_disabled ||
            !session_grant || session_grant->session_id != current.session_id ||
            session_grant->sequence != current.sequence)
            raise(ErrorKind::stale_response, "stale_response");
        if (error.kind() == ErrorKind::transient) {
            session_retry_deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(15 + std::rand() % 30);
            wake_worker();
            const auto current_snapshot = snapshot_locked(true);
            if (current_snapshot.access == ::orbit::Access::online)
                return current_snapshot;
        } else if (error.kind() == ErrorKind::denied ||
                   error.kind() == ErrorKind::invalid_response) {
            session_grant.reset();
            session_anchor.reset();
            pending_renewal_sequence.reset();
        }
        throw;
    }
}

::orbit::Snapshot ClientState::start_session(const std::atomic_bool &cancelled) {
    ClientOperation call(*this);
    bool known = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (offline)
            return snapshot_locked(true);
        if (!credential)
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        known = session_profile_known;
    }
    if (!known)
        (void)refresh(cancelled, false);
    auto serial_lock = lock_serial(cancelled);
    return start_session_serialized(cancelled, true);
}

::orbit::Snapshot ClientState::end_session(const std::atomic_bool &cancelled) {
    ClientOperation call(*this);
    bool known = false;
    Credential saved;
    std::string session_id;
    std::uint64_t request_generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (offline || (session_profile_known && !session_required))
            return snapshot_locked(true);
        throw_if_cancelled(cancelled);
        if (!credential) {
            session_disabled = true;
            advance_generation_locked();
            return snapshot_locked(true);
        }
        known = session_profile_known;
        saved = *credential;
        session_disabled = true;
        if (session_grant)
            session_id = session_grant->session_id;
        else if (pending_session_id)
            session_id = *pending_session_id;
        session_grant.reset();
        session_anchor.reset();
        pending_session_id.reset();
        pending_renewal_sequence.reset();
        session_retry_deadline.reset();
        advance_generation_locked();
        request_generation = current_generation;
    }
    if (!known) {
        (void)refresh(cancelled, false, false);
        std::lock_guard<std::mutex> lock(mutex);
        request_generation = current_generation;
    }
    auto serial_lock = lock_serial(cancelled);
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != request_generation)
            raise(ErrorKind::stale_response, "stale_response");
        if (offline || !session_required)
            return snapshot_locked(true);
    }
    if (!session_id.empty()) {
        const auto path = "/api/client/v1/activations/" + saved.activation_id + "/sessions/" +
                          session_id + "/end";
        try {
            const auto response = transport.post(path, credential_body(saved), false, cancelled);
            if (response)
                invalid_response();
            std::lock_guard<std::mutex> lock(mutex);
            if (current_generation != request_generation)
                raise(ErrorKind::stale_response, "stale_response");
            throw_if_cancelled(cancelled);
        } catch (...) {
            // The local snapshot stays cleared even when release is uncertain.
            throw;
        }
    }
    std::lock_guard<std::mutex> lock(mutex);
    return snapshot_locked(true);
}

::orbit::Snapshot ClientState::refresh(const std::atomic_bool &cancelled, bool if_needed,
                                       bool acquire_session) {
    ClientOperation call(*this);
    const auto before_serial = generation();
    auto serial_lock = lock_serial(cancelled);
    Credential saved;
    std::uint64_t request_generation = 0;
    bool floating_profile = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        if (current_generation != before_serial)
            raise(ErrorKind::stale_response, "stale_response");
        throw_if_cancelled(cancelled);
        if (if_needed) {
            const auto current = snapshot_locked(true);
            if (current.offline_file_mode)
                return current;
            if (session_required) {
                if (session_disabled)
                    return current;
                const bool due = !session_retry_deadline ||
                                 std::chrono::steady_clock::now() >= *session_retry_deadline;
                if (!due)
                    return current;
                if (session_grant && session_anchor &&
                    session_anchor->now() < session_grant->refresh_after)
                    return current;
                floating_profile = true;
            }
            const bool refreshable = current.access == ::orbit::Access::refresh_required ||
                                     current.access == ::orbit::Access::expired ||
                                     current.access == ::orbit::Access::offline;
            const bool due = !retry_deadline || std::chrono::steady_clock::now() >= *retry_deadline;
            if (!session_required && (!refreshable || !due))
                return current;
        }
        if (offline)
            return snapshot_locked(true);
        if (!credential)
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        if (session_profile_known && session_required)
            floating_profile = true;
        if (floating_profile) {
            // The serialized session transition below never validates the
            // activation credential on every access check.
        } else {
            saved = *credential;
            request_generation = current_generation;
        }
    }
    if (floating_profile)
        return advance_session_serialized(cancelled);
    const auto input = credential_body(saved);
    const auto path = "/api/client/v1/activations/" + saved.activation_id + "/validate";
    const ClockStart start = capture_clock();
    std::optional<Json::Value> response;
    try {
        response = transport.post(path, input, true, cancelled);
    } catch (const Error &error) {
        if (error.kind() == ErrorKind::stale_response || error.kind() == ErrorKind::cancelled)
            throw;
        return accept_reply(std::nullopt, &error, request_generation, saved, std::nullopt, start,
                            cancelled);
    }
    auto accepted_snapshot =
        accept_reply(response, nullptr, request_generation, saved, std::nullopt, start, cancelled);
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!session_required || session_disabled)
            return accepted_snapshot;
    }
    if (!acquire_session)
        return accepted_snapshot;
    return start_session_serialized(cancelled, false);
}

::orbit::Snapshot ClientState::require_access(std::string_view feature, const std::atomic_bool& cancelled) {
    ClientOperation call(*this);
    throw_if_cancelled(cancelled);
    if (!valid_utf8(feature)) raise(ErrorKind::configuration, "configuration");
    bool refreshable = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        sync_storage_locked();
        throw_if_cancelled(cancelled);
        auto current = snapshot_locked(true);
        if (current.offline_file_mode) {
            if (current.access == ::orbit::Access::expired)
                raise(ErrorKind::denied, "offline_file_expired");
            if (current.access != ::orbit::Access::offline)
                raise(ErrorKind::not_activated, "access_unavailable");
            if (!current.has_feature(feature)) raise(ErrorKind::feature_unavailable, "feature_unavailable");
            return current;
        }
        if (current.access == ::orbit::Access::online) {
            throw_if_cancelled(cancelled);
            current = snapshot_locked(true);
            throw_if_cancelled(cancelled);
            if (current.access == ::orbit::Access::online && !current.has_feature(feature)) {
                raise(ErrorKind::feature_unavailable, "feature_unavailable");
            }
            if (current.access == ::orbit::Access::online)
                return current;
        }
        if (session_required && session_disabled)
            raise(ErrorKind::denied, "session_explicitly_ended");
        refreshable = current.access == ::orbit::Access::refresh_required ||
            current.access == ::orbit::Access::expired || current.access == ::orbit::Access::offline;
    }
    if (refreshable) {
        try {
            (void)refresh(cancelled, true);
        } catch (const Error& error) {
            if (error.kind() != ErrorKind::transient) throw;
        }
    }
    std::lock_guard<std::mutex> lock(mutex);
    sync_storage_locked();
    throw_if_cancelled(cancelled);
    const auto current = snapshot_locked(true);
    if (current.access != ::orbit::Access::online && current.access != ::orbit::Access::offline) {
        if (session_required) {
            if (session_disabled)
                raise(ErrorKind::denied, "session_explicitly_ended");
            if (transient)
                raise(ErrorKind::transient, "session_unavailable");
            raise(ErrorKind::denied, "session_access_unavailable");
        }
        if (credential && transient) raise(ErrorKind::transient, "network_unavailable");
        raise(ErrorKind::not_activated, "access_unavailable");
    }
    if (!current.has_feature(feature)) {
        raise(ErrorKind::feature_unavailable, "feature_unavailable");
    }
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
        checkpoint_offline_before_transition_locked();
        if (!credential) {
            if (offline) {
                clear_access_locked();
                invalidate_locked();
            }
            raise(ErrorKind::reauthentication_required, "reauthentication_required");
        }
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
    sync_storage_locked();
    checkpoint_offline_before_transition_locked();
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
        // An unrelated account failure cannot resolve an uncertain activation.
        invalidate_locked(false);
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
        const bool preserve_pending = persistent && !persistent_record["pending_activation"].isNull();
        checkpoint_offline_before_transition_locked();
        clear_all_locked();
        invalidate_locked(!preserve_pending);
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
        checkpoint_offline_before_transition_locked();
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
        record = persistent_codec::decode(config, installed->provider(), *raw_record, true);
        const auto& saved_fingerprint = record["installation"]["fingerprint"];
        const auto& saved_provider = record["installation"]["fingerprint_provider"];
        const bool identity_matches = config.fingerprint
            ? saved_fingerprint.isString() && saved_fingerprint.asString() == config.fingerprint->value &&
              saved_provider.isString() && saved_provider.asString() == config.fingerprint->provider
            : saved_fingerprint.isNull() && saved_provider.isNull();
        if (!identity_matches) {
            config.installation_id = new_installation_id();
            record = persistent_codec::empty_record(config, installed->provider());
            installed->save(persistent_codec::encode(config, installed->provider(), record));
        } else {
            config.installation_id = record["installation"]["id"].asString();
        }
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

    state->restore_offline();

    if (state->credential && state->persistent_record["pending_activation"].isNull() && !state->offline) {
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

::orbit::Client make_test_client_from_state(std::shared_ptr<ClientState> state) {
    return ::orbit::Client(std::move(state));
}
#endif

std::int64_t online_timestamp(std::string_view value) { return timestamp(value); }

const std::atomic_bool& cancellation_flag(const ::orbit::Cancellation* cancellation,
                                          const std::atomic_bool& fallback) {
    if (cancellation && cancellation->state_) return cancellation->state_->cancelled;
    return fallback;
}

namespace {

::orbit::Timestamp public_time(std::int64_t seconds) {
    return ::orbit::Timestamp(std::chrono::seconds(seconds));
}

::orbit::Customer public_customer(const Json::Value& value) {
    ::orbit::Customer output;
    output.id = text(required(value, "id"));
    output.username = text(required(value, "username"));
    output.email = text(required(value, "email"));
    output.suspended = boolean(required(value, "suspended"));
    output.created_at = public_time(timestamp(text(required(value, "created_at"))));
    return output;
}

::orbit::Account public_account(const Json::Value& value) {
    ::orbit::Account output;
    output.customer = public_customer(required(value, "customer"));
    output.expires_at = public_time(timestamp(text(required(value, "expires_at"))));
    return output;
}

::orbit::OwnedLicence public_licence(const Json::Value& value) {
    ::orbit::OwnedLicence output;
    output.id = text(required(value, "id"));
    output.policy_name = text(required(value, "policy_name"));
    output.state = text(required(value, "state"));
    output.expiry_mode = text(required(value, "expiry_mode"));
    const auto first_used = optional_string(value, "first_used_at");
    const auto expires = optional_string(value, "expires_at");
    const auto duration = optional_integer(value, "duration_seconds");
    if (first_used) output.first_used_at = public_time(timestamp(*first_used));
    if (expires) output.expires_at = public_time(timestamp(*expires));
    if (duration) output.duration = std::chrono::seconds(*duration);
    const auto device_limit = integer(required(value, "device_limit"));
    const auto offline_seconds = integer(required(value, "offline_seconds"));
    const auto offline_file_seconds = integer(required(value, "offline_file_seconds"));
    if (device_limit < 0 || device_limit > INT32_MAX || offline_seconds < 0 ||
        (offline_file_seconds != 0 && (offline_file_seconds < 86400 || offline_file_seconds > 31622400))) invalid_response();
    output.device_limit = static_cast<std::int32_t>(device_limit);
    output.hwid_locked = boolean(required(value, "hwid_locked"));
    output.offline_allowed = boolean(required(value, "offline_allowed"));
    output.offline_duration = std::chrono::seconds(offline_seconds);
    output.offline_file_duration = std::chrono::seconds(offline_file_seconds);
    output.usage_limits = usage_definitions(value);
    output.resource_limits = resource_definitions(value);
    if (value.isMember("concurrent_session_limit")) {
        const auto concurrent = json_int64(value["concurrent_session_limit"]);
        if (concurrent < 0 || concurrent > 65535)
            invalid_response();
        output.concurrent_session_limit = static_cast<std::int32_t>(concurrent);
    }
    const auto& entitlements = required(value, "entitlements");
    if (!entitlements.isObject() || entitlements.size() > 64) invalid_response();
    for (const auto& name : entitlements.getMemberNames()) {
        if (!entitlements[name].isBool()) invalid_response();
        output.entitlements.emplace(name, entitlements[name].asBool());
    }
    return output;
}

} // namespace

} // namespace orbit::detail

namespace orbit {

namespace {

[[noreturn]] void invalid_app_key() {
    detail::raise(ErrorKind::configuration, "invalid_app_key");
}

int app_key_base64_value(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

std::string encode_app_key_origin(std::string_view value) {
    std::string encoded(4 * ((value.size() + 2) / 3), '\0');
    const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(encoded.data()),
        reinterpret_cast<const unsigned char*>(value.data()), static_cast<int>(value.size()));
    if (length < 0) invalid_app_key();
    encoded.resize(static_cast<std::size_t>(length));
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    for (auto& character : encoded) {
        if (character == '+') character = '-';
        else if (character == '/') character = '_';
    }
    return encoded;
}

std::string decode_app_key_origin(std::string_view encoded) {
    if (encoded.empty() || encoded.size() % 4 == 1) invalid_app_key();
    std::string decoded;
    decoded.reserve(encoded.size() * 3 / 4);
    std::uint32_t accumulator = 0;
    unsigned bits = 0;
    for (const auto character : encoded) {
        const auto value = app_key_base64_value(character);
        if (value < 0) invalid_app_key();
        accumulator = (accumulator << 6) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> bits) & 0xff));
        }
    }
    if ((bits && (accumulator & ((1u << bits) - 1u)) != 0) || !detail::valid_utf8(decoded)) {
        invalid_app_key();
    }
    return decoded;
}

bool app_key_id(std::string_view value) {
    return !value.empty() && value.size() <= 128 &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return (character >= 'A' && character <= 'Z') ||
                   (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9') || character == '_' || character == '-';
        });
}

std::string required_operation_id(std::optional<std::string_view> value) {
    return value ? std::string(*value) : new_installation_id();
}

void validate_optional_activation_operation_id(std::optional<std::string_view> value) {
    if (value && (value->size() < 16 || value->size() > 128 || !detail::valid_utf8(*value))) {
        detail::raise(ErrorKind::configuration, "configuration");
    }
}

} // namespace

AppKey::AppKey(std::string api_origin, std::string application_id,
               std::string environment_id, std::string environment)
    : api_origin_(std::move(api_origin)), issuer_(api_origin_),
      application_id_(std::move(application_id)), environment_id_(std::move(environment_id)),
      environment_(std::move(environment)) {}

AppKey AppKey::parse(std::string_view input) {
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.front()))) input.remove_prefix(1);
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.back()))) input.remove_suffix(1);
    if (input.empty() || input.size() > 512) invalid_app_key();
    std::string_view environment;
    std::string_view rest;
    constexpr std::string_view test_prefix = "orbit_app_test_";
    constexpr std::string_view live_prefix = "orbit_app_live_";
    if (input.substr(0, test_prefix.size()) == test_prefix) {
        environment = "test";
        rest = input.substr(test_prefix.size());
    } else if (input.substr(0, live_prefix.size()) == live_prefix) {
        environment = "live";
        rest = input.substr(live_prefix.size());
    } else {
        invalid_app_key();
    }
    const auto first_dot = rest.find('.');
    const auto second_dot = first_dot == std::string_view::npos
        ? std::string_view::npos : rest.find('.', first_dot + 1);
    if (first_dot == std::string_view::npos || first_dot == 0 ||
        second_dot == std::string_view::npos || second_dot == first_dot + 1 ||
        rest.find('.', second_dot + 1) != std::string_view::npos) invalid_app_key();
    const auto encoded_origin = rest.substr(0, first_dot);
    const auto application = rest.substr(first_dot + 1, second_dot - first_dot - 1);
    const auto environment_id = rest.substr(second_dot + 1);
    if (!app_key_id(application) || !app_key_id(environment_id)) invalid_app_key();
    auto origin = decode_app_key_origin(encoded_origin);
    if (origin.empty() || origin.back() == '/') invalid_app_key();
    try {
        detail::Transport transport(origin);
        origin = transport.origin();
    } catch (const Error&) {
        invalid_app_key();
    }
    return AppKey(std::move(origin), std::string(application), std::string(environment_id),
                  std::string(environment));
}

std::string AppKey::public_key() const {
    return "orbit_app_" + environment_ + "_" + encode_app_key_origin(api_origin_) +
        "." + application_id_ + "." + environment_id_;
}

OfflineKeys OfflineKeys::parse(std::string_view jwks_json, std::string_view environment) {
    auto keys = detail::OfflineKeys::parse_jwks(jwks_json, environment);
    return OfflineKeys(std::make_shared<const detail::OfflineKeys>(std::move(keys)),
                       std::string(environment));
}

SessionKeys SessionKeys::parse(std::string_view jwks_json, std::string_view environment) {
    auto keys = detail::SessionKeys::parse_jwks(jwks_json, environment);
    return SessionKeys(std::make_shared<const detail::SessionKeys>(std::move(keys)),
                       std::string(environment));
}

std::string OfflineRequest::to_json() const {
    Json::Value value(Json::objectValue);
    value["format"] = "orbit-offline-request";
    value["version"] = 1;
    value["app_key"] = app_key;
    value["installation_id"] = installation_id;
    value["fingerprint"] = fingerprint ? Json::Value(*fingerprint) : Json::Value(Json::nullValue);
    value["fingerprint_provider"] = fingerprint_provider
        ? Json::Value(*fingerprint_provider) : Json::Value(Json::nullValue);
    return detail::encode_json(value);
}

Error::Error(std::uint32_t status, ErrorKind kind, std::string code,
             std::string request_id)
    : std::runtime_error("Orbit SDK operation failed"), status_(status), kind_(kind),
      code_(std::move(code)), request_id_(std::move(request_id)) {}

Cancellation::Cancellation() : state_(std::make_shared<detail::CancellationState>()) {}

void Cancellation::cancel() const noexcept {
    if (state_) state_->cancelled.store(true, std::memory_order_relaxed);
}

bool Snapshot::has_feature(std::string_view feature) const {
    const auto found = entitlements.find(std::string(feature));
    return found != entitlements.end() && found->second;
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

Client Client::open(std::string_view app_key, Options options) {
    return open(AppKey::parse(app_key), std::move(options));
}

Client Client::open(const AppKey& app_key, Options options) {
    detail::Config config;
    config.api_origin = app_key.api_origin();
    config.application_id = app_key.application_id();
    config.environment_id = app_key.environment_id();
    config.environment = app_key.environment();
    config.issuer = app_key.issuer();
    config.public_app_key = app_key.public_key();
    if (options.offline_keys) {
        if (options.offline_keys->environment() != app_key.environment())
            detail::raise(ErrorKind::configuration, "invalid_offline_keys");
        config.offline_keys = options.offline_keys->keys_;
    }
    if (options.session_keys) {
        if (options.session_keys->environment() != app_key.environment())
            detail::raise(ErrorKind::configuration, "invalid_session_keys");
        config.session_keys = options.session_keys->keys_;
    }
    config.fingerprint = detail::resolve_fingerprint(app_key, options);
    (void)detail::capture_clock();
    detail::Transport transport(config.api_origin);
    config.api_origin = transport.origin();
    auto installed = detail::open_installed_storage(config, std::move(options.state_directory));
    auto state = detail::open_installed_state(std::move(config), std::move(transport), std::move(installed));
    return Client(std::move(state));
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

Snapshot Client::snapshot(const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    if (detail::cancellation_flag(cancellation, inactive).load(std::memory_order_relaxed)) {
        detail::raise(ErrorKind::cancelled, "cancelled");
    }
    return require_state(state_).snapshot();
}

OfflineRequest Client::offline_request() const {
    return require_state(state_).offline_request();
}

Snapshot Client::import_offline_file(std::string_view file,
                                      const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return require_state(state_).import_offline_file(
        file, detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::activate(std::string_view licence_key,
                          std::optional<std::string_view> idempotency_key,
                          const Cancellation* cancellation) const {
    validate_optional_activation_operation_id(idempotency_key);
    std::atomic_bool inactive{false};
    auto& state = require_state(state_);
    const auto operation = idempotency_key ? std::string(*idempotency_key)
        : (state.persistent ? std::string{} : new_installation_id());
    return state.activate(licence_key, operation,
        std::nullopt, detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::activate(std::string_view licence_key, const Cancellation* cancellation) const {
    return activate(licence_key, std::nullopt, cancellation);
}

Snapshot Client::activate_previous(std::string_view licence_key,
                                   std::optional<std::string_view> previous_credential,
                                   std::optional<std::string_view> idempotency_key,
                                   const Cancellation* cancellation) const {
    validate_optional_activation_operation_id(idempotency_key);
    std::atomic_bool inactive{false};
    auto& state = require_state(state_);
    const auto operation = idempotency_key ? std::string(*idempotency_key)
        : (state.persistent ? std::string{} : new_installation_id());
    return state.activate(licence_key, operation,
        previous_credential, detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::refresh(const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return require_state(state_).refresh(detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::start_session(const Cancellation *cancellation) const {
    std::atomic_bool inactive{false};
    return require_state(state_).start_session(detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::end_session(const Cancellation *cancellation) const {
    std::atomic_bool inactive{false};
    return require_state(state_).end_session(detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::require_access(std::string_view feature, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return require_state(state_).require_access(feature, detail::cancellation_flag(cancellation, inactive));
}

Snapshot Client::ensure_access(std::string_view feature,
                               const std::function<std::optional<std::string>()>& ask_for_key,
                               const Cancellation* cancellation) const {
    try {
        return require_access(feature, cancellation);
    } catch (const Error& error) {
        if (error.kind() != ErrorKind::not_activated) throw;
    }
    if (!ask_for_key) detail::raise(ErrorKind::not_activated, "access_unavailable");
    const auto key = ask_for_key();
    if (!key || key->empty()) detail::raise(ErrorKind::not_activated, "access_unavailable");
    (void)activate(*key, std::nullopt, cancellation);
    return require_access(feature, cancellation);
}

void Client::deactivate(std::optional<std::string_view> idempotency_key,
                        const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    const auto operation = required_operation_id(idempotency_key);
    require_state(state_).deactivate(operation, detail::cancellation_flag(cancellation, inactive));
}

void Client::logout() const { require_state(state_).local_logout(); }

void Client::close() const { require_state(state_).close(); }

RegistrationResult Client::register_customer(
    std::string_view licence_key, std::string_view username, std::string_view email,
    std::string_view password, const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    auto result = require_state(state_).register_customer(licence_key, username, email, password,
                                                          detail::cancellation_flag(cancellation, inactive));
    RegistrationResult output;
    output.accepted = detail::boolean(detail::required(result.first, "accepted"));
    output.expires_at = detail::public_time(detail::timestamp(
        detail::text(detail::required(result.first, "expires_at"))));
    output.pending = PendingRegistration(state_, std::move(result.second));
    return output;
}

void Client::resend_registration(const PendingRegistration& pending,
                                 const Cancellation* cancellation) const {
    if (!state_ || !pending.value_ || pending.owner_.get() != state_.get()) {
        detail::raise(ErrorKind::configuration, "configuration");
    }
    std::atomic_bool inactive{false};
    state_->resend_registration(*pending.value_, detail::cancellation_flag(cancellation, inactive));
}

Account Client::login(std::string_view username, std::string_view password,
                      const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    return detail::public_account(require_state(state_).login(username, password, detail::cancellation_flag(cancellation, inactive)));
}

std::optional<Account> Client::account() const {
    const auto value = require_state(state_).account();
    if (value.isNull()) return std::nullopt;
    return detail::public_account(value);
}

OwnedLicencePage Client::owned_licences(std::optional<std::string_view> cursor,
                                        const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    const auto page = require_state(state_).owned_licences(cursor, detail::cancellation_flag(cancellation, inactive));
    OwnedLicencePage output;
    const auto& items = detail::required(page, "items");
    output.items.reserve(items.size());
    for (const auto& item : items) output.items.push_back(detail::public_licence(item));
    output.next_cursor = detail::optional_string(page, "next_cursor");
    return output;
}

OwnedLicence Client::claim_licence(std::string_view licence_key,
                                   std::optional<std::string_view> idempotency_key,
                                   const Cancellation* cancellation) const {
    std::atomic_bool inactive{false};
    const auto operation = required_operation_id(idempotency_key);
    return detail::public_licence(require_state(state_).claim_licence(licence_key, operation,
        detail::cancellation_flag(cancellation, inactive)));
}

Snapshot Client::activate_account(std::string_view licence_id,
                                  std::optional<std::string_view> idempotency_key,
                                  const Cancellation* cancellation) const {
    validate_optional_activation_operation_id(idempotency_key);
    std::atomic_bool inactive{false};
    auto& state = require_state(state_);
    const auto operation = idempotency_key ? std::string(*idempotency_key)
        : (state.persistent ? std::string{} : new_installation_id());
    return state.activate({}, operation, std::nullopt,
        detail::cancellation_flag(cancellation, inactive), licence_id);
}

Snapshot Client::activate_account_previous(
    std::string_view licence_id, std::optional<std::string_view> previous_credential,
    std::optional<std::string_view> idempotency_key, const Cancellation* cancellation) const {
    validate_optional_activation_operation_id(idempotency_key);
    std::atomic_bool inactive{false};
    auto& state = require_state(state_);
    const auto operation = idempotency_key ? std::string(*idempotency_key)
        : (state.persistent ? std::string{} : new_installation_id());
    return state.activate({}, operation, previous_credential,
        detail::cancellation_flag(cancellation, inactive), licence_id);
}

void Client::logout_account(const Cancellation* cancellation) const {
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
