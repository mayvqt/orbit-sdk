#ifndef ORBIT_SDK_HPP
#define ORBIT_SDK_HPP

#include "orbit_ffi.h"

#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace orbit {

enum class ErrorKind : std::uint32_t {
    none = ORBIT_FFI_ERROR_NONE,
    configuration = ORBIT_FFI_ERROR_CONFIGURATION,
    cancelled = ORBIT_FFI_ERROR_CANCELLED,
    transient = ORBIT_FFI_ERROR_TRANSIENT,
    denied = ORBIT_FFI_ERROR_DENIED,
    invalid_response = ORBIT_FFI_ERROR_INVALID_RESPONSE,
    transport_security = ORBIT_FFI_ERROR_TRANSPORT_SECURITY,
    reauthentication_required = ORBIT_FFI_ERROR_REAUTHENTICATION_REQUIRED,
    stale_response = ORBIT_FFI_ERROR_STALE_RESPONSE,
    storage = ORBIT_FFI_ERROR_STORAGE,
    clock_uncertain = ORBIT_FFI_ERROR_CLOCK_UNCERTAIN,
    internal = ORBIT_FFI_ERROR_INTERNAL,
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
    memory = ORBIT_FFI_STORAGE_MEMORY,
    windows_dpapi = ORBIT_FFI_STORAGE_WINDOWS_DPAPI,
    linux_secret_service = ORBIT_FFI_STORAGE_LINUX_SECRET_SERVICE,
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

namespace detail {
struct ClientState;
struct CancellationState;
}

class Cancellation {
public:
    Cancellation();
    void cancel() const noexcept;

private:
    std::shared_ptr<detail::CancellationState> state_;
    friend class Client;
};

class PendingRegistration {
public:
    PendingRegistration() noexcept = default;
    ~PendingRegistration();
    PendingRegistration(PendingRegistration&& other) noexcept;
    PendingRegistration& operator=(PendingRegistration&& other) noexcept;
    PendingRegistration(const PendingRegistration&) = delete;
    PendingRegistration& operator=(const PendingRegistration&) = delete;

    explicit operator bool() const noexcept { return handle_ != nullptr; }

private:
    PendingRegistration(std::shared_ptr<detail::ClientState> owner,
                        OrbitPendingRegistration* handle) noexcept;
    void reset() noexcept;

    std::shared_ptr<detail::ClientState> owner_;
    OrbitPendingRegistration* handle_ = nullptr;
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
    std::string call(std::uint32_t operation,
                     std::initializer_list<std::string_view> arguments = {},
                     const Cancellation* cancellation = nullptr,
                     OrbitPendingRegistration* pending = nullptr,
                     OrbitPendingRegistration** pending_out = nullptr) const;

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
