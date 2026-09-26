#ifndef ORBIT_SDK_HPP
#define ORBIT_SDK_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace orbit {

class Cancellation;
class Client;
namespace detail {
struct Config;
class ClientState;
struct PendingRegistrationState;
}

enum class ErrorKind : std::uint32_t {
    none = 0,
    configuration = 1,
    cancelled = 2,
    transient = 3,
    denied = 4,
    not_activated = 5,
    feature_unavailable = 6,
    invalid_response = 7,
    transport_security = 8,
    reauthentication_required = 9,
    stale_response = 10,
    storage = 11,
    clock_uncertain = 12,
    internal = 13,
    installation_in_use = 14,
    corrupt_state = 15,
};

class Error : public std::runtime_error {
public:
    Error(std::uint32_t status, ErrorKind kind, std::string code,
          std::string request_id);

    std::uint32_t status() const noexcept { return status_; }
    ErrorKind kind() const noexcept { return kind_; }
    const std::string& code() const noexcept { return code_; }
    const std::string& request_id() const noexcept { return request_id_; }

private:
    std::uint32_t status_;
    ErrorKind kind_;
    std::string code_;
    std::string request_id_;
};

struct Fingerprint {
    std::string value;
    std::string provider;
};

class AppKey {
public:
    static AppKey parse(std::string_view value);
    const std::string& api_origin() const noexcept { return api_origin_; }
    const std::string& issuer() const noexcept { return issuer_; }
    const std::string& application_id() const noexcept { return application_id_; }
    const std::string& environment_id() const noexcept { return environment_id_; }
    const std::string& environment() const noexcept { return environment_; }

private:
    AppKey(std::string api_origin, std::string application_id,
           std::string environment_id, std::string environment);
    std::string api_origin_;
    std::string issuer_;
    std::string application_id_;
    std::string environment_id_;
    std::string environment_;
};

struct Options {
    std::optional<std::string> state_directory;
    bool disable_machine_binding = false;
    std::optional<Fingerprint> fingerprint;
};

enum class Access : std::uint32_t { denied, online, offline, refresh_required, expired };

using Timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds>;

// Verified metadata. Match it to the seller's artifact registry before delivery.
struct DownloadTicket {
    std::string licence_id;
    std::string release_id;
    std::string artifact_id;
    std::string sha256;
    std::int64_t byte_length = 0;
    std::string ticket_id;
    Timestamp issued_at;
    Timestamp expires_at;
};

class DownloadTicketVerifier {
public:
    // Configure the exact HTTPS endpoint and trusted connected-purpose JWKS JSON.
    // Construction copies configuration; verification never fetches keys or files.
    DownloadTicketVerifier(std::string_view app_key, std::string_view endpoint,
                           std::string_view public_keys);
    DownloadTicketVerifier(const DownloadTicketVerifier&) noexcept = default;
    DownloadTicketVerifier& operator=(const DownloadTicketVerifier&) noexcept = default;

    // now is an optional trusted application clock, never a request parameter.
    DownloadTicket verify(std::string_view token,
                          std::optional<Timestamp> now = std::nullopt) const;

private:
    struct State;
    std::shared_ptr<const State> state_;
};

struct Snapshot {
    Access access = Access::denied;
    std::map<std::string, bool> entitlements;
    std::optional<Timestamp> expires_at;
    std::optional<Timestamp> next_check_at;
    std::optional<Timestamp> credential_expires_at;
    bool reauthentication_required = false;
    bool offline_allowed = false;
    std::chrono::seconds remaining_offline{0};
    std::int32_t policy_version = 0;

    bool has_feature(std::string_view feature) const;
};

struct Customer {
    std::string id;
    std::string username;
    std::string email;
    bool suspended = false;
    Timestamp created_at;
};

struct Account {
    Customer customer;
    Timestamp expires_at;
};

struct OwnedLicence {
    std::string id;
    std::string policy_name;
    std::string state;
    std::string expiry_mode;
    std::optional<Timestamp> first_used_at;
    std::optional<Timestamp> expires_at;
    std::optional<std::chrono::seconds> duration;
    std::int32_t device_limit = 0;
    bool hwid_locked = false;
    bool offline_allowed = false;
    std::chrono::seconds offline_duration{0};
    std::map<std::string, bool> entitlements;
};

struct OwnedLicencePage {
    std::vector<OwnedLicence> items;
    std::optional<std::string> next_cursor;
};

class PendingRegistration {
public:
    PendingRegistration() noexcept = default;
    ~PendingRegistration();
    PendingRegistration(PendingRegistration&& other) noexcept;
    PendingRegistration& operator=(PendingRegistration&& other) noexcept;
    PendingRegistration(const PendingRegistration&) = delete;
    PendingRegistration& operator=(const PendingRegistration&) = delete;

    explicit operator bool() const noexcept { return value_ != nullptr; }

private:
    PendingRegistration(std::shared_ptr<detail::ClientState> owner,
                        std::shared_ptr<detail::PendingRegistrationState> value) noexcept;
    void reset() noexcept;

    std::shared_ptr<detail::ClientState> owner_;
    std::shared_ptr<detail::PendingRegistrationState> value_;
    friend class Client;
};

struct RegistrationResult {
    bool accepted = false;
    Timestamp expires_at;
    PendingRegistration pending;
};

namespace detail {
struct Config;
class ClientState;
struct CancellationState;
struct PendingRegistrationState;
class Transport;
class CredentialStorage;
class InstalledStorage;
const std::atomic_bool& cancellation_flag(const ::orbit::Cancellation*,
                                          const std::atomic_bool& fallback);
#ifdef ORBIT_SDK_TESTING
::orbit::Client make_test_installed_client(Config, Transport, std::shared_ptr<InstalledStorage>);
::orbit::Client make_test_client(Config, Transport, std::shared_ptr<CredentialStorage>);
#endif
}

class Cancellation {
public:
    Cancellation();
    void cancel() const noexcept;

private:
    std::shared_ptr<detail::CancellationState> state_;
    friend class Client;
    friend const std::atomic_bool& detail::cancellation_flag(
        const Cancellation*, const std::atomic_bool&);
};

class Client {
public:
    Client(const Client&) noexcept = default;
    Client& operator=(const Client&) noexcept = default;
    Client(Client&& other) noexcept;
    Client& operator=(Client&& other) noexcept;

    static Client open(std::string_view app_key, Options options = {});
    static Client open(const AppKey& app_key, Options options = {});

    const std::string& installation_id() const noexcept;

    Snapshot snapshot(const Cancellation* cancellation = nullptr) const;
    Snapshot activate(std::string_view licence_key,
                      std::optional<std::string_view> idempotency_key = std::nullopt,
                      const Cancellation* cancellation = nullptr) const;
    Snapshot activate(std::string_view licence_key, const Cancellation* cancellation) const;
    Snapshot activate_previous(
        std::string_view licence_key,
        std::optional<std::string_view> previous_credential,
        std::optional<std::string_view> idempotency_key = std::nullopt,
        const Cancellation* cancellation = nullptr) const;
    Snapshot refresh(const Cancellation* cancellation = nullptr) const;
    Snapshot require_access(std::string_view feature,
                            const Cancellation* cancellation = nullptr) const;
    Snapshot ensure_access(std::string_view feature,
                           const std::function<std::optional<std::string>()>& ask_for_key,
                           const Cancellation* cancellation = nullptr) const;
    void deactivate(std::optional<std::string_view> idempotency_key = std::nullopt,
                    const Cancellation* cancellation = nullptr) const;
    void logout() const;
    void close() const;

    RegistrationResult register_customer(
        std::string_view licence_key, std::string_view username,
        std::string_view email, std::string_view password,
        const Cancellation* cancellation = nullptr) const;
    void resend_registration(const PendingRegistration& pending,
                             const Cancellation* cancellation = nullptr) const;
    Account login(std::string_view username, std::string_view password,
                  const Cancellation* cancellation = nullptr) const;
    std::optional<Account> account() const;
    OwnedLicencePage owned_licences(
        std::optional<std::string_view> cursor = std::nullopt,
        const Cancellation* cancellation = nullptr) const;
    OwnedLicence claim_licence(std::string_view licence_key,
                               std::optional<std::string_view> idempotency_key = std::nullopt,
                               const Cancellation* cancellation = nullptr) const;
    Snapshot activate_account(std::string_view licence_id,
                              std::optional<std::string_view> idempotency_key = std::nullopt,
                              const Cancellation* cancellation = nullptr) const;
    Snapshot activate_account_previous(
        std::string_view licence_id,
        std::optional<std::string_view> previous_credential,
        std::optional<std::string_view> idempotency_key = std::nullopt,
        const Cancellation* cancellation = nullptr) const;
    void logout_account(const Cancellation* cancellation = nullptr) const;
    void request_email_change(std::string_view password,
                              std::string_view new_email,
                              const Cancellation* cancellation = nullptr) const;
    void request_password_recovery(
        std::string_view email,
        const Cancellation* cancellation = nullptr) const;

    // Sensitive Bearer header. Send only to your trusted HTTPS backend; never log or persist it.
    std::string customer_session_authorization() const;

private:
    explicit Client(std::shared_ptr<detail::ClientState> state) noexcept;
#ifdef ORBIT_SDK_TESTING
    friend Client detail::make_test_installed_client(detail::Config, detail::Transport,
        std::shared_ptr<detail::InstalledStorage>);
    friend Client detail::make_test_client(detail::Config, detail::Transport,
        std::shared_ptr<detail::CredentialStorage>);
#endif

    std::shared_ptr<detail::ClientState> state_;
};

// Public randomness utility for hosts that need a stable installation handle.
std::string new_installation_id();

// Returns the scoped machine_v1 digest; the raw operating-system identity is never returned.
std::string native_fingerprint(std::string_view application_id,
                               std::string_view environment_id);
std::string machine_fingerprint(std::string_view application_id,
                                std::string_view environment_id,
                                std::string_view family,
                                std::string_view identity);

} // namespace orbit

#endif // ORBIT_SDK_HPP
