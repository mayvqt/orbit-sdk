#ifndef ORBIT_FFI_H
#define ORBIT_FFI_H

/*
 * Stable C ABI for the Orbit SDK. ABI version 1.
 *
 * All strings are explicit-length UTF-8. Input slices are borrowed only for
 * the call and must point to readable memory; `data` must be non-null even
 * when `len == 0`. Calls reject invalid UTF-8, slices over 4096 bytes, and
 * aggregate input over 16384 bytes. The argument array may contain at most
 * four slices.
 *
 * Results own their buffers. Release every result with orbit_ffi_result_free;
 * release standalone buffers with orbit_ffi_buffer_free. Both clear the passed
 * descriptor. Do not free or copy an output buffer independently of its
 * descriptor, and do not free a descriptor twice.
 *
 * Client calls are synchronous and may block for network work. Different calls
 * may use one live client concurrently. The caller must keep client, input,
 * cancellation, and pending-registration handles alive through each call, and
 * must wait for calls to finish before freeing a handle. Cancellation may be
 * signalled from another thread. A cancellation handle may be shared by calls.
 *
 * JSON outputs contain access/account/licence metadata only. The
 * CUSTOMER_SESSION_AUTHORIZATION operation returns a raw, sensitive
 * `Bearer ...` header. Send it only to the application's trusted HTTPS backend
 * for online verification. Never log, persist, or send it to arbitrary hosts.
 * A successful registration returns an opaque pending handle; its resend
 * credential is never available through this ABI. Free the handle when it is
 * no longer needed.
 *
 * MEMORY storage is process-local. WINDOWS_DPAPI and LINUX_SECRET_SERVICE use
 * the SDK's current-user OS protected adapters. Their storage_path must name an
 * existing, dedicated, private absolute directory. The SDK validates ownership,
 * leases, and platform restrictions; this ABI does not create directories.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_FFI_ABI_VERSION 1u

typedef struct OrbitClient OrbitClient;
typedef struct OrbitCancellation OrbitCancellation;
typedef struct OrbitPendingRegistration OrbitPendingRegistration;

typedef struct OrbitFfiSlice {
    const uint8_t *data;
    size_t len;
} OrbitFfiSlice;

typedef struct OrbitFfiBuffer {
    uint8_t *data;
    size_t len;
} OrbitFfiBuffer;

typedef struct OrbitFfiResult {
    uint32_t abi_version;
    uint32_t status;
    uint32_t error_kind;
    uint32_t reserved;
    OrbitFfiBuffer error_code;
    OrbitFfiBuffer request_id;
    OrbitFfiBuffer output;
} OrbitFfiResult;

typedef struct OrbitFfiClientConfig {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t storage_mode;
    uint32_t reserved;
    OrbitFfiSlice api_origin;
    OrbitFfiSlice application_id;
    OrbitFfiSlice environment_id;
    OrbitFfiSlice issuer;
    OrbitFfiSlice installation_id;
    OrbitFfiSlice fingerprint;
    OrbitFfiSlice fingerprint_provider;
    OrbitFfiSlice storage_path;
} OrbitFfiClientConfig;

enum OrbitFfiStatus {
    ORBIT_FFI_OK = 0,
    ORBIT_FFI_ERROR = 1,
    ORBIT_FFI_PANIC = 2
};

enum OrbitFfiErrorKind {
    ORBIT_FFI_ERROR_NONE = 0,
    ORBIT_FFI_ERROR_CONFIGURATION = 1,
    ORBIT_FFI_ERROR_CANCELLED = 2,
    ORBIT_FFI_ERROR_TRANSIENT = 3,
    ORBIT_FFI_ERROR_DENIED = 4,
    ORBIT_FFI_ERROR_INVALID_RESPONSE = 5,
    ORBIT_FFI_ERROR_TRANSPORT_SECURITY = 6,
    ORBIT_FFI_ERROR_REAUTHENTICATION_REQUIRED = 7,
    ORBIT_FFI_ERROR_STALE_RESPONSE = 8,
    ORBIT_FFI_ERROR_STORAGE = 9,
    ORBIT_FFI_ERROR_CLOCK_UNCERTAIN = 10,
    ORBIT_FFI_ERROR_INTERNAL = 11
};

enum OrbitFfiStorageMode {
    ORBIT_FFI_STORAGE_MEMORY = 0,
    ORBIT_FFI_STORAGE_WINDOWS_DPAPI = 1,
    ORBIT_FFI_STORAGE_LINUX_SECRET_SERVICE = 2
};

/* Operation argument order is fixed for ABI version 1. Optional string values
 * use a non-null zero-length slice. Operations returning a JSON value say so;
 * void operations return the JSON bytes `null`.
 *
 * SNAPSHOT(): JSON snapshot
 * ACTIVATE(licence_key, idempotency_key): JSON snapshot
 * ACTIVATE_PREVIOUS(licence_key, previous_credential_or_empty, idempotency_key): JSON snapshot
 * REFRESH(): JSON snapshot
 * REQUIRE_ACCESS(feature): JSON snapshot, or a denied result
 * DEACTIVATE(idempotency_key): null
 * LOCAL_LOGOUT(): null; clears local activation state
 * REGISTER(licence_key, username, email, password): JSON {accepted, expires_at};
 *     `pending_out` receives an opaque handle for RESEND_REGISTRATION
 * RESEND_REGISTRATION(): null; requires `pending`
 * LOGIN(username, password): JSON account metadata
 * ACCOUNT(): JSON account metadata or null
 * OWNED_LICENCES(cursor_or_empty): JSON page of licence metadata
 * CLAIM_LICENCE(licence_key, idempotency_key): JSON licence metadata
 * ACTIVATE_ACCOUNT(licence_id, idempotency_key): JSON snapshot
 * ACTIVATE_ACCOUNT_PREVIOUS(licence_id, previous_credential_or_empty, idempotency_key): JSON snapshot
 * ACCOUNT_LOGOUT(): null; clears local session state and requests remote revocation
 * REQUEST_EMAIL_CHANGE(password, new_email): null
 * REQUEST_PASSWORD_RECOVERY(email): null
 * CUSTOMER_SESSION_AUTHORIZATION(): sensitive raw Authorization header bytes
 */
enum OrbitFfiOperation {
    ORBIT_FFI_OP_SNAPSHOT = 1,
    ORBIT_FFI_OP_ACTIVATE = 2,
    ORBIT_FFI_OP_ACTIVATE_PREVIOUS = 3,
    ORBIT_FFI_OP_REFRESH = 4,
    ORBIT_FFI_OP_REQUIRE_ACCESS = 5,
    ORBIT_FFI_OP_DEACTIVATE = 6,
    ORBIT_FFI_OP_LOCAL_LOGOUT = 7,
    ORBIT_FFI_OP_REGISTER = 8,
    ORBIT_FFI_OP_RESEND_REGISTRATION = 9,
    ORBIT_FFI_OP_LOGIN = 10,
    ORBIT_FFI_OP_ACCOUNT = 11,
    ORBIT_FFI_OP_OWNED_LICENCES = 12,
    ORBIT_FFI_OP_CLAIM_LICENCE = 13,
    ORBIT_FFI_OP_ACTIVATE_ACCOUNT = 14,
    ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS = 15,
    ORBIT_FFI_OP_ACCOUNT_LOGOUT = 16,
    ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE = 17,
    ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY = 18,
    ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION = 19
};

/* Returns ORBIT_FFI_ABI_VERSION. */
uint32_t orbit_ffi_abi_version(void);

/* On success, writes a live client to `output_client`; otherwise leaves it null.
 * api_origin is validated by the SDK's strict HTTPS origin parser. */
OrbitFfiResult orbit_client_create(const OrbitFfiClientConfig *config,
                                   OrbitClient **output_client);

/* `pending_out` must be non-null only for REGISTER. `pending` must be non-null
 * only for RESEND_REGISTRATION. `cancellation` is optional and may be null.
 * Unknown operations, wrong argument counts, bad pointers, invalid UTF-8, and
 * out-of-range input lengths return a configuration error. */
OrbitFfiResult orbit_client_call(OrbitClient *client,
                                uint32_t operation,
                                const OrbitFfiSlice *arguments,
                                size_t argument_count,
                                const OrbitCancellation *cancellation,
                                OrbitPendingRegistration *pending,
                                OrbitPendingRegistration **pending_out);

OrbitCancellation *orbit_cancellation_create(void);
void orbit_cancellation_cancel(const OrbitCancellation *cancellation);
void orbit_cancellation_free(OrbitCancellation *cancellation);
void orbit_client_free(OrbitClient *client);
void orbit_pending_registration_free(OrbitPendingRegistration *pending);

/* Free returned allocations. Null descriptor pointers are accepted. */
void orbit_ffi_buffer_free(OrbitFfiBuffer *buffer);
void orbit_ffi_result_free(OrbitFfiResult *result);

/* Helper outputs are raw UTF-8 bytes in result.output. */
OrbitFfiResult orbit_installation_id_new(void);
OrbitFfiResult orbit_native_fingerprint(OrbitFfiSlice application_id,
                                        OrbitFfiSlice environment_id);
OrbitFfiResult orbit_machine_fingerprint(OrbitFfiSlice application_id,
                                         OrbitFfiSlice environment_id,
                                         OrbitFfiSlice family,
                                         OrbitFfiSlice identity);

#ifdef __cplusplus
}
#endif

#endif /* ORBIT_FFI_H */
