#pragma once

#include "grants.hpp"
#include "platform.hpp"
#include "transport.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace orbit::detail {

struct CancellationState {
    std::atomic_bool cancelled{false};
};

struct PendingRegistrationState {
    std::string resend_credential;
    std::string application_id;
    std::string environment_id;
};

struct Credential {
    std::string activation_id;
    std::string licence_id;
    std::string bearer;
    std::int64_t expires_at = 0;
};

struct ClockStart {
    std::int64_t elapsed_nanoseconds = 0;
    std::int64_t wall_seconds = 0;
};

struct ClockAnchor {
    std::int64_t server_seconds = 0;
    std::int64_t elapsed_nanoseconds = 0;
    std::int64_t wall_seconds = 0;
    std::int64_t now() const;
};

struct AccountSession {
    std::string bearer;
    Json::Value account;
};

class ClientState {
public:
    ClientState(Config config, Transport transport,
                std::shared_ptr<CredentialStorage> storage,
                std::uint64_t storage_version,
                std::optional<Credential> credential);

    Json::Value snapshot();
    Json::Value activate(std::string_view key, std::string_view idempotency_key,
                         std::optional<std::string_view> previous,
                         const std::atomic_bool& cancelled,
                         std::optional<std::string_view> account_licence = std::nullopt);
    Json::Value refresh(const std::atomic_bool& cancelled, bool if_needed = false);
    Json::Value require_access(std::string_view feature, const std::atomic_bool& cancelled);
    void deactivate(std::string_view idempotency_key, const std::atomic_bool& cancelled);
    void local_logout();
    std::pair<Json::Value, std::shared_ptr<PendingRegistrationState>> register_customer(
        std::string_view licence_key, std::string_view username, std::string_view email,
        std::string_view password, const std::atomic_bool& cancelled);
    void resend_registration(const PendingRegistrationState& pending,
                             const std::atomic_bool& cancelled);
    Json::Value login(std::string_view username, std::string_view password,
                      const std::atomic_bool& cancelled);
    Json::Value account();
    Json::Value owned_licences(std::optional<std::string_view> cursor,
                               const std::atomic_bool& cancelled);
    Json::Value claim_licence(std::string_view key, std::string_view idempotency_key,
                              const std::atomic_bool& cancelled);
    void account_logout(const std::atomic_bool& cancelled);
    void request_email_change(std::string_view password, std::string_view email,
                              const std::atomic_bool& cancelled);
    void request_password_recovery(std::string_view email,
                                   const std::atomic_bool& cancelled);
    std::string customer_session_authorization();

    std::uint64_t generation();
    void sync_storage_locked();
    std::string account_path(std::string_view path,
                             std::optional<std::string_view> cursor = std::nullopt) const;
    Json::Value account_body(Json::Value value) const;
    void finish_account_error(std::uint64_t request_generation,
                              const std::optional<ErrorKind>& error_kind,
                              std::string_view error_code,
                              const std::atomic_bool& cancelled);

    Config config;
    Transport transport;
    std::shared_ptr<CredentialStorage> storage;
    mutable std::mutex mutex;
    std::timed_mutex serial;
    std::uint64_t current_generation = 0;
    std::uint64_t storage_version = 0;
    std::optional<Credential> credential;
    std::optional<GrantClaims> claims;
    std::optional<ClockAnchor> anchor;
    std::optional<AccountSession> customer;
    bool transient = false;
    std::optional<std::chrono::steady_clock::time_point> retry_deadline;
    GrantKeys keys;

private:
    friend std::shared_ptr<ClientState> connect_state(Config);
#ifdef ORBIT_SDK_TESTING
    friend ::orbit::Client make_test_client(Config, Transport,
                                             std::shared_ptr<CredentialStorage>);
#endif
    void check_generation(std::uint64_t request_generation,
                          const std::atomic_bool& cancelled);
    std::unique_lock<std::timed_mutex> lock_serial(const std::atomic_bool& cancelled);
    Json::Value snapshot_locked(bool tolerate_clock_error);
    std::pair<Credential, GrantClaims> verify_reply(
        const Json::Value& reply, const std::optional<Credential>& previous,
        std::optional<std::string_view> expected_licence, ClockStart start,
        const std::atomic_bool& cancelled, ClockAnchor& out_anchor);
    Json::Value accept_reply(const std::optional<Json::Value>& reply,
                             const Error* response_error,
                             std::uint64_t request_generation,
                             const std::optional<Credential>& previous,
                             std::optional<std::string_view> expected_licence,
                             ClockStart start,
                             const std::atomic_bool& cancelled);
    void clear_access_locked();
    void clear_all_locked();
    void invalidate_locked();
    std::uint64_t request_generation_locked();
    Credential stored_credential(const Json::Value& value) const;
    Json::Value credential_json(const Credential& value) const;
    Json::Value credential_body(const Credential& value) const;
    Json::Value account_post(std::string_view path, Json::Value body,
                             bool retry_safe,
                             const std::atomic_bool& cancelled,
                             std::uint64_t& request_generation);
    AccountSession customer_session(std::uint64_t request_generation);
    static void accepted(const Json::Value& value);
};

std::shared_ptr<ClientState> connect_state(Config config);

#ifdef ORBIT_SDK_TESTING
using TestClock = std::function<std::pair<std::int64_t, std::int64_t>()>;
void set_test_clock(TestClock clock);
::orbit::Client make_test_client(Config config, Transport transport,
                                 std::shared_ptr<CredentialStorage> storage);
#endif

} // namespace orbit::detail
