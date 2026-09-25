#ifndef ORBIT_SDK_HPP
#define ORBIT_SDK_HPP

#include <cstdint>
#include <atomic>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace orbit {

class Cancellation;

enum class ErrorKind : std::uint32_t {
    none = 0,
    configuration = 1,
    cancelled = 2,
    transient = 3,
    denied = 4,
    invalid_response = 5,
    transport_security = 6,
    reauthentication_required = 7,
    stale_response = 8,
    storage = 9,
    clock_uncertain = 10,
    internal = 11,
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

enum class StorageMode : std::uint32_t {
    memory = 0,
    windows_dpapi = 1,
    linux_secret_service = 2,
};

struct Storage {
    StorageMode mode = StorageMode::memory;
    std::string path;
};

struct Fingerprint {
    std::string value;
    std::string provider;
};

struct Config {
    std::string api_origin;
    std::string application_id;
    std::string environment_id;
    std::string issuer;
    std::optional<std::string> installation_id;
    std::optional<Fingerprint> fingerprint;
    Storage storage;
};

class Client;

namespace detail {
struct ClientState;
struct CancellationState;
struct PendingRegistrationState;
const std::atomic_bool& cancellation_flag(const ::orbit::Cancellation*,
                                          const std::atomic_bool& fallback);
#ifdef ORBIT_SDK_TESTING
class Transport;
class CredentialStorage;
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
    // JSON: {"accepted": bool, "expires_at": ...}.
    std::string metadata_json;
    PendingRegistration pending;
};

class Client {
public:
    Client(const Client&) noexcept = default;
    Client& operator=(const Client&) noexcept = default;
    Client(Client&& other) noexcept;
    Client& operator=(Client&& other) noexcept;

    static Client connect(Config config);

    const Config& config() const noexcept;
    const std::string& installation_id() const noexcept;

    // JSON outputs contain safe metadata. Parse them with the application's JSON library.
    std::string snapshot(const Cancellation* cancellation = nullptr) const;
    std::string activate(std::string_view licence_key,
                         std::string_view idempotency_key,
                         const Cancellation* cancellation = nullptr) const;
    std::string activate_previous(
        std::string_view licence_key,
        std::optional<std::string_view> previous_credential,
        std::string_view idempotency_key,
        const Cancellation* cancellation = nullptr) const;
    std::string refresh(const Cancellation* cancellation = nullptr) const;
    std::string require_access(std::string_view feature,
                               const Cancellation* cancellation = nullptr) const;
    void deactivate(std::string_view idempotency_key,
                    const Cancellation* cancellation = nullptr) const;
    void local_logout() const;

    RegistrationResult register_customer(
        std::string_view licence_key, std::string_view username,
        std::string_view email, std::string_view password,
        const Cancellation* cancellation = nullptr) const;
    void resend_registration(const PendingRegistration& pending,
                             const Cancellation* cancellation = nullptr) const;
    std::string login(std::string_view username, std::string_view password,
                      const Cancellation* cancellation = nullptr) const;
    std::string account() const;
    std::string owned_licences(
        std::optional<std::string_view> cursor = std::nullopt,
        const Cancellation* cancellation = nullptr) const;
    std::string claim_licence(std::string_view licence_key,
                              std::string_view idempotency_key,
                              const Cancellation* cancellation = nullptr) const;
    std::string activate_account(std::string_view licence_id,
                                 std::string_view idempotency_key,
                                 const Cancellation* cancellation = nullptr) const;
    std::string activate_account_previous(
        std::string_view licence_id,
        std::optional<std::string_view> previous_credential,
        std::string_view idempotency_key,
        const Cancellation* cancellation = nullptr) const;
    void account_logout(const Cancellation* cancellation = nullptr) const;
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
    friend Client detail::make_test_client(Config, detail::Transport,
                                            std::shared_ptr<detail::CredentialStorage>);
#endif

    std::shared_ptr<detail::ClientState> state_;
};

// A cryptographically random public installation ID. Persist and reuse it across restarts.
std::string new_installation_id();

// Returns the application-scoped machine_v1 fingerprint; raw machine identity is never returned.
std::string native_fingerprint(std::string_view application_id,
                               std::string_view environment_id);
std::string machine_fingerprint(std::string_view application_id,
                                std::string_view environment_id,
                                std::string_view family,
                                std::string_view identity);

} // namespace orbit

#endif // ORBIT_SDK_HPP
