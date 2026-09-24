#include "orbit_sdk.hpp"

#include <array>
#include <memory>
#include <utility>
#include <vector>

namespace orbit {
namespace detail {

struct ClientState {
    ClientState(OrbitClient* value, Config setup) noexcept
        : handle(value), config(std::move(setup)) {}
    ~ClientState() {
        if (handle != nullptr) {
            orbit_client_free(handle);
        }
    }

    OrbitClient* handle;
    Config config;
};

struct CancellationState {
    explicit CancellationState(OrbitCancellation* value) noexcept : handle(value) {}
    ~CancellationState() {
        if (handle != nullptr) {
            orbit_cancellation_free(handle);
        }
    }

    OrbitCancellation* handle;
};

} // namespace detail
namespace {

constexpr std::uint32_t kAbiVersion = ORBIT_FFI_ABI_VERSION;

class ResultGuard {
public:
    explicit ResultGuard(OrbitFfiResult value) noexcept : value_(value) {}
    ~ResultGuard() { orbit_ffi_result_free(&value_); }
    ResultGuard(const ResultGuard&) = delete;
    ResultGuard& operator=(const ResultGuard&) = delete;

    OrbitFfiResult& get() noexcept { return value_; }

private:
    OrbitFfiResult value_;
};

struct PendingDeleter {
    void operator()(OrbitPendingRegistration* value) const noexcept {
        if (value != nullptr) {
            orbit_pending_registration_free(value);
        }
    }
};

struct ClientDeleter {
    void operator()(OrbitClient* value) const noexcept {
        if (value != nullptr) {
            orbit_client_free(value);
        }
    }
};

struct CancellationDeleter {
    void operator()(OrbitCancellation* value) const noexcept {
        if (value != nullptr) {
            orbit_cancellation_free(value);
        }
    }
};

OrbitFfiSlice make_slice(std::string_view value) noexcept {
    static constexpr std::uint8_t empty = 0;
    return OrbitFfiSlice{
        value.empty() && value.data() == nullptr
            ? &empty
            : reinterpret_cast<const std::uint8_t*>(value.data()),
        value.size(),
    };
}

std::string buffer_string(const OrbitFfiBuffer& buffer) {
    if (buffer.len == 0) {
        return {};
    }
    if (buffer.data == nullptr) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal, "invalid_ffi_result", {});
    }
    return std::string(reinterpret_cast<const char*>(buffer.data), buffer.len);
}

std::string checked_output(OrbitFfiResult& result) {
    if (result.abi_version != kAbiVersion) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal, "abi_version_mismatch", {});
    }
    if (result.status != ORBIT_FFI_OK) {
        const auto kind = result.error_kind <= ORBIT_FFI_ERROR_INTERNAL
                              ? static_cast<ErrorKind>(result.error_kind)
                              : ErrorKind::internal;
        throw Error(result.status, kind, buffer_string(result.error_code),
                    buffer_string(result.request_id));
    }
    return buffer_string(result.output);
}

std::string run_helper(OrbitFfiResult result) {
    ResultGuard guard(result);
    return checked_output(guard.get());
}

void throw_configuration() {
    throw Error(ORBIT_FFI_ERROR, ErrorKind::configuration, "configuration", {});
}

} // namespace

Error::Error(std::uint32_t status, ErrorKind kind, std::string code,
             std::string request_id)
    : std::runtime_error("Orbit SDK operation failed"), status_(status), kind_(kind),
      code_(std::move(code)), request_id_(std::move(request_id)) {}

Cancellation::Cancellation() {
    auto* handle = orbit_cancellation_create();
    if (handle == nullptr) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal, "allocation_failed", {});
    }
    std::unique_ptr<OrbitCancellation, CancellationDeleter> guard(handle);
    state_ = std::make_shared<detail::CancellationState>(handle);
    guard.release();
}

void Cancellation::cancel() const noexcept {
    if (state_ && state_->handle != nullptr) {
        orbit_cancellation_cancel(state_->handle);
    }
}

PendingRegistration::PendingRegistration(
    std::shared_ptr<detail::ClientState> owner,
    OrbitPendingRegistration* handle) noexcept
    : owner_(std::move(owner)), handle_(handle) {}

PendingRegistration::~PendingRegistration() { reset(); }

PendingRegistration::PendingRegistration(PendingRegistration&& other) noexcept
    : owner_(std::move(other.owner_)), handle_(std::exchange(other.handle_, nullptr)) {}

PendingRegistration& PendingRegistration::operator=(PendingRegistration&& other) noexcept {
    if (this != &other) {
        reset();
        owner_ = std::move(other.owner_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

void PendingRegistration::reset() noexcept {
    if (handle_ != nullptr) {
        orbit_pending_registration_free(handle_);
        handle_ = nullptr;
    }
    owner_.reset();
}

Client::Client(std::shared_ptr<detail::ClientState> state) noexcept
    : state_(std::move(state)) {}

Client::Client(Client&& other) noexcept : state_(std::move(other.state_)) {}

Client& Client::operator=(Client&& other) noexcept {
    if (this != &other) {
        state_ = std::move(other.state_);
    }
    return *this;
}

Client Client::connect(Config config) {
    if (orbit_ffi_abi_version() != kAbiVersion) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal, "abi_version_mismatch", {});
    }
    if (!config.installation_id || config.installation_id->empty()) {
        config.installation_id = new_installation_id();
    }

    const std::string fingerprint = config.fingerprint ? config.fingerprint->value : "";
    const std::string provider = config.fingerprint ? config.fingerprint->provider : "";
    OrbitFfiClientConfig ffi_config{};
    ffi_config.struct_size = static_cast<std::uint32_t>(sizeof(ffi_config));
    ffi_config.abi_version = kAbiVersion;
    ffi_config.storage_mode = static_cast<std::uint32_t>(config.storage.mode);
    ffi_config.api_origin = make_slice(config.api_origin);
    ffi_config.application_id = make_slice(config.application_id);
    ffi_config.environment_id = make_slice(config.environment_id);
    ffi_config.issuer = make_slice(config.issuer);
    ffi_config.installation_id = make_slice(*config.installation_id);
    ffi_config.fingerprint = make_slice(fingerprint);
    ffi_config.fingerprint_provider = make_slice(provider);
    ffi_config.storage_path = make_slice(config.storage.path);

    OrbitClient* handle = nullptr;
    ResultGuard result(orbit_client_create(&ffi_config, &handle));
    checked_output(result.get());
    if (handle == nullptr) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal, "client_creation_failed", {});
    }
    std::unique_ptr<OrbitClient, ClientDeleter> client_guard(handle);
    auto state = std::make_shared<detail::ClientState>(handle, std::move(config));
    client_guard.release();
    return Client(std::move(state));
}

const Config& Client::config() const noexcept {
    static const Config empty;
    return state_ ? state_->config : empty;
}

const std::string& Client::installation_id() const noexcept {
    static const std::string empty;
    if (!state_ || !state_->config.installation_id) {
        return empty;
    }
    return *state_->config.installation_id;
}

std::string Client::call(std::uint32_t operation,
                         std::initializer_list<std::string_view> arguments,
                         const Cancellation* cancellation,
                         OrbitPendingRegistration* pending,
                         OrbitPendingRegistration** pending_out) const {
    const auto state = state_;
    if (!state || state->handle == nullptr) {
        throw_configuration();
    }

    std::vector<OrbitFfiSlice> slices;
    slices.reserve(arguments.size());
    for (const auto argument : arguments) {
        slices.push_back(make_slice(argument));
    }

    OrbitPendingRegistration* created_pending = nullptr;
    const auto output_pointer = pending_out != nullptr ? &created_pending : nullptr;
    const auto cancel_handle = cancellation != nullptr && cancellation->state_
                                   ? cancellation->state_->handle
                                   : nullptr;
    ResultGuard result(orbit_client_call(
        state->handle, operation, slices.empty() ? nullptr : slices.data(), slices.size(),
        cancel_handle, pending, output_pointer));
    std::unique_ptr<OrbitPendingRegistration, PendingDeleter> pending_guard(created_pending);
    auto output = checked_output(result.get());
    if (pending_out != nullptr) {
        *pending_out = pending_guard.release();
    }
    return output;
}

std::string Client::snapshot(const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_SNAPSHOT, {}, cancellation);
}

std::string Client::activate(std::string_view licence_key,
                             std::string_view idempotency_key,
                             const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_ACTIVATE, {licence_key, idempotency_key}, cancellation);
}

std::string Client::activate_previous(
    std::string_view licence_key,
    std::optional<std::string_view> previous_credential,
    std::string_view idempotency_key,
    const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_ACTIVATE_PREVIOUS,
                {licence_key, previous_credential.value_or(std::string_view{}),
                 idempotency_key},
                cancellation);
}

std::string Client::refresh(const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_REFRESH, {}, cancellation);
}

std::string Client::require_access(std::string_view feature,
                                  const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_REQUIRE_ACCESS, {feature}, cancellation);
}

void Client::deactivate(std::string_view idempotency_key,
                        const Cancellation* cancellation) const {
    (void)call(ORBIT_FFI_OP_DEACTIVATE, {idempotency_key}, cancellation);
}

void Client::local_logout() const {
    (void)call(ORBIT_FFI_OP_LOCAL_LOGOUT);
}

RegistrationResult Client::register_customer(
    std::string_view licence_key, std::string_view username,
    std::string_view email, std::string_view password,
    const Cancellation* cancellation) const {
    OrbitPendingRegistration* handle = nullptr;
    auto metadata = call(ORBIT_FFI_OP_REGISTER,
                         {licence_key, username, email, password}, cancellation,
                         nullptr, &handle);
    if (handle == nullptr) {
        throw Error(ORBIT_FFI_PANIC, ErrorKind::internal,
                    "pending_registration_missing", {});
    }
    return RegistrationResult{std::move(metadata), PendingRegistration(state_, handle)};
}

void Client::resend_registration(const PendingRegistration& pending,
                                 const Cancellation* cancellation) const {
    if (pending.handle_ == nullptr || pending.owner_.get() != state_.get()) {
        throw_configuration();
    }
    (void)call(ORBIT_FFI_OP_RESEND_REGISTRATION, {}, cancellation, pending.handle_);
}

std::string Client::login(std::string_view username, std::string_view password,
                          const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_LOGIN, {username, password}, cancellation);
}

std::string Client::account() const { return call(ORBIT_FFI_OP_ACCOUNT); }

std::string Client::owned_licences(
    std::optional<std::string_view> cursor,
    const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_OWNED_LICENCES,
                {cursor.value_or(std::string_view{})}, cancellation);
}

std::string Client::claim_licence(std::string_view licence_key,
                                  std::string_view idempotency_key,
                                  const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_CLAIM_LICENCE, {licence_key, idempotency_key},
                cancellation);
}

std::string Client::activate_account(std::string_view licence_id,
                                     std::string_view idempotency_key,
                                     const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_ACTIVATE_ACCOUNT, {licence_id, idempotency_key},
                cancellation);
}

std::string Client::activate_account_previous(
    std::string_view licence_id,
    std::optional<std::string_view> previous_credential,
    std::string_view idempotency_key,
    const Cancellation* cancellation) const {
    return call(ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS,
                {licence_id, previous_credential.value_or(std::string_view{}),
                 idempotency_key},
                cancellation);
}

void Client::account_logout(const Cancellation* cancellation) const {
    (void)call(ORBIT_FFI_OP_ACCOUNT_LOGOUT, {}, cancellation);
}

void Client::request_email_change(std::string_view password,
                                  std::string_view new_email,
                                  const Cancellation* cancellation) const {
    (void)call(ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE, {password, new_email},
               cancellation);
}

void Client::request_password_recovery(
    std::string_view email, const Cancellation* cancellation) const {
    (void)call(ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY, {email}, cancellation);
}

std::string Client::customer_session_authorization() const {
    return call(ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION);
}

std::string new_installation_id() {
    return run_helper(orbit_installation_id_new());
}

std::string native_fingerprint(std::string_view application_id,
                               std::string_view environment_id) {
    return run_helper(orbit_native_fingerprint(make_slice(application_id),
                                               make_slice(environment_id)));
}

std::string machine_fingerprint(std::string_view application_id,
                                std::string_view environment_id,
                                std::string_view family,
                                std::string_view identity) {
    return run_helper(orbit_machine_fingerprint(
        make_slice(application_id), make_slice(environment_id),
        make_slice(family), make_slice(identity)));
}

} // namespace orbit
