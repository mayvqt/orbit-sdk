#![deny(unsafe_op_in_unsafe_fn)]

use orbit_sdk::{
    Access, Account, Cancellation, Client, Config, CustomerSessionProof, Device, Error,
    MemoryStorage, OwnedLicence, OwnedLicences, PendingRegistration, Registration,
    SecretServiceStorage, Snapshot, Storage, Transport, WindowsStorage,
};
use serde_json::{Value, json};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice, str,
    sync::Arc,
};
use tokio::runtime::{Builder, Runtime};

/// Current ABI version. The C header is the source of stable operation numbers.
pub const ORBIT_FFI_ABI_VERSION: u32 = 1;
const MAX_INPUT_BYTES: usize = 4096;
const MAX_TOTAL_INPUT_BYTES: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 4;
const MAX_OUTPUT_BYTES: usize = 512 * 1024;

pub const ORBIT_FFI_OK: u32 = 0;
pub const ORBIT_FFI_ERROR: u32 = 1;
pub const ORBIT_FFI_PANIC: u32 = 2;

pub const ORBIT_FFI_ERROR_NONE: u32 = 0;
pub const ORBIT_FFI_ERROR_CONFIGURATION: u32 = 1;
pub const ORBIT_FFI_ERROR_CANCELLED: u32 = 2;
pub const ORBIT_FFI_ERROR_TRANSIENT: u32 = 3;
pub const ORBIT_FFI_ERROR_DENIED: u32 = 4;
pub const ORBIT_FFI_ERROR_INVALID_RESPONSE: u32 = 5;
pub const ORBIT_FFI_ERROR_TRANSPORT_SECURITY: u32 = 6;
pub const ORBIT_FFI_ERROR_REAUTHENTICATION_REQUIRED: u32 = 7;
pub const ORBIT_FFI_ERROR_STALE_RESPONSE: u32 = 8;
pub const ORBIT_FFI_ERROR_STORAGE: u32 = 9;
pub const ORBIT_FFI_ERROR_CLOCK_UNCERTAIN: u32 = 10;
pub const ORBIT_FFI_ERROR_INTERNAL: u32 = 11;

pub const ORBIT_FFI_STORAGE_MEMORY: u32 = 0;
pub const ORBIT_FFI_STORAGE_WINDOWS_DPAPI: u32 = 1;
pub const ORBIT_FFI_STORAGE_LINUX_SECRET_SERVICE: u32 = 2;

pub const ORBIT_FFI_OP_SNAPSHOT: u32 = 1;
pub const ORBIT_FFI_OP_ACTIVATE: u32 = 2;
pub const ORBIT_FFI_OP_ACTIVATE_PREVIOUS: u32 = 3;
pub const ORBIT_FFI_OP_REFRESH: u32 = 4;
pub const ORBIT_FFI_OP_REQUIRE_ACCESS: u32 = 5;
pub const ORBIT_FFI_OP_DEACTIVATE: u32 = 6;
pub const ORBIT_FFI_OP_LOCAL_LOGOUT: u32 = 7;
pub const ORBIT_FFI_OP_REGISTER: u32 = 8;
pub const ORBIT_FFI_OP_RESEND_REGISTRATION: u32 = 9;
pub const ORBIT_FFI_OP_LOGIN: u32 = 10;
pub const ORBIT_FFI_OP_ACCOUNT: u32 = 11;
pub const ORBIT_FFI_OP_OWNED_LICENCES: u32 = 12;
pub const ORBIT_FFI_OP_CLAIM_LICENCE: u32 = 13;
pub const ORBIT_FFI_OP_ACTIVATE_ACCOUNT: u32 = 14;
pub const ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS: u32 = 15;
pub const ORBIT_FFI_OP_ACCOUNT_LOGOUT: u32 = 16;
pub const ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE: u32 = 17;
pub const ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY: u32 = 18;
pub const ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION: u32 = 19;

/// Borrowed UTF-8 bytes. The caller keeps `data` valid for the duration of the call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OrbitFfiSlice {
    pub data: *const u8,
    pub len: usize,
}

/// Rust-owned bytes. Release with `orbit_ffi_buffer_free` or as part of a result.
#[repr(C)]
pub struct OrbitFfiBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Versioned result. Error codes and request IDs contain safe diagnostic metadata only.
#[repr(C)]
pub struct OrbitFfiResult {
    pub abi_version: u32,
    pub status: u32,
    pub error_kind: u32,
    pub reserved: u32,
    pub error_code: OrbitFfiBuffer,
    pub request_id: OrbitFfiBuffer,
    pub output: OrbitFfiBuffer,
}

/// Client construction inputs. Every slice must have a non-null data pointer, including empty ones.
#[repr(C)]
pub struct OrbitFfiClientConfig {
    pub struct_size: u32,
    pub abi_version: u32,
    pub storage_mode: u32,
    pub reserved: u32,
    pub api_origin: OrbitFfiSlice,
    pub application_id: OrbitFfiSlice,
    pub environment_id: OrbitFfiSlice,
    pub issuer: OrbitFfiSlice,
    pub installation_id: OrbitFfiSlice,
    pub fingerprint: OrbitFfiSlice,
    pub fingerprint_provider: OrbitFfiSlice,
    pub storage_path: OrbitFfiSlice,
}

/// Opaque client handle. Calls may run concurrently while this handle stays alive.
pub struct OrbitClient {
    runtime: Runtime,
    client: Client,
}

/// Opaque cancellation handle. Cancellation may be signalled from another thread.
pub struct OrbitCancellation {
    cancellation: Cancellation,
}

/// Opaque registration resend proof. It must not be serialized or logged.
pub struct OrbitPendingRegistration {
    pending: PendingRegistration,
}

struct Failure {
    kind: u32,
    code: String,
    request_id: Option<String>,
}

impl Failure {
    fn internal(code: &'static str) -> Self {
        Self {
            kind: ORBIT_FFI_ERROR_INTERNAL,
            code: code.into(),
            request_id: None,
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        let (kind, fallback, code, request_id) = match error {
            Error::Configuration => (ORBIT_FFI_ERROR_CONFIGURATION, "configuration", None, None),
            Error::Cancelled => (ORBIT_FFI_ERROR_CANCELLED, "cancelled", None, None),
            Error::Transient { code, request_id } => {
                (ORBIT_FFI_ERROR_TRANSIENT, "transient", code, request_id)
            }
            Error::Denied { code, request_id } => {
                (ORBIT_FFI_ERROR_DENIED, "denied", Some(code), request_id)
            }
            Error::InvalidResponse => (
                ORBIT_FFI_ERROR_INVALID_RESPONSE,
                "invalid_response",
                None,
                None,
            ),
            Error::TransportSecurity => (
                ORBIT_FFI_ERROR_TRANSPORT_SECURITY,
                "transport_security",
                None,
                None,
            ),
            Error::ReauthenticationRequired => (
                ORBIT_FFI_ERROR_REAUTHENTICATION_REQUIRED,
                "reauthentication_required",
                None,
                None,
            ),
            Error::StaleResponse => (ORBIT_FFI_ERROR_STALE_RESPONSE, "stale_response", None, None),
            Error::Storage => (ORBIT_FFI_ERROR_STORAGE, "storage", None, None),
            Error::ClockUncertain => (
                ORBIT_FFI_ERROR_CLOCK_UNCERTAIN,
                "clock_uncertain",
                None,
                None,
            ),
        };
        let safe_code = code
            .filter(|value| valid_diagnostic(value, 128))
            .unwrap_or_else(|| fallback.to_owned());
        let safe_request_id = request_id.filter(|value| valid_request_id(value));
        Self {
            kind,
            code: safe_code,
            request_id: safe_request_id,
        }
    }
}

fn valid_diagnostic(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_request_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn empty_buffer() -> OrbitFfiBuffer {
    OrbitFfiBuffer {
        data: ptr::null_mut(),
        len: 0,
    }
}

fn owned_buffer(bytes: &[u8]) -> OrbitFfiBuffer {
    if bytes.is_empty() {
        return empty_buffer();
    }
    let boxed = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    let data = Box::into_raw(boxed).cast::<u8>();
    OrbitFfiBuffer { data, len }
}

fn clear_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        // This buffer can contain a customer Authorization header.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn result(
    status: u32,
    kind: u32,
    code: Option<&str>,
    request_id: Option<&str>,
    output: &[u8],
) -> OrbitFfiResult {
    OrbitFfiResult {
        abi_version: ORBIT_FFI_ABI_VERSION,
        status,
        error_kind: kind,
        reserved: 0,
        error_code: code.map_or_else(empty_buffer, |value| owned_buffer(value.as_bytes())),
        request_id: request_id.map_or_else(empty_buffer, |value| owned_buffer(value.as_bytes())),
        output: owned_buffer(output),
    }
}

fn error_result(failure: Failure, status: u32) -> OrbitFfiResult {
    result(
        status,
        failure.kind,
        Some(&failure.code),
        failure.request_id.as_deref(),
        &[],
    )
}

fn ffi_result<F>(operation: F) -> OrbitFfiResult
where
    F: FnOnce() -> Result<Vec<u8>, Failure>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(mut output)) => {
            let response = result(ORBIT_FFI_OK, ORBIT_FFI_ERROR_NONE, None, None, &output);
            clear_bytes(&mut output);
            response
        }
        Ok(Err(failure)) => error_result(failure, ORBIT_FFI_ERROR),
        Err(_) => error_result(Failure::internal("panic"), ORBIT_FFI_PANIC),
    }
}

fn json_output(value: &Value) -> Result<Vec<u8>, Failure> {
    let bytes = serde_json::to_vec(value).map_err(|_| Failure::internal("serialization"))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::internal("output_too_large"));
    }
    Ok(bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn orbit_ffi_abi_version() -> u32 {
    catch_unwind(|| ORBIT_FFI_ABI_VERSION).unwrap_or(0)
}

fn snapshot_json(snapshot: Snapshot) -> Value {
    let access = match snapshot.access {
        Access::Denied => "denied",
        Access::Online => "online",
        Access::Offline => "offline",
        Access::RefreshRequired => "refresh_required",
        Access::Expired => "expired",
    };
    json!({
        "access": access,
        "entitlements": snapshot.entitlements,
        "expires_at": snapshot.expires_at,
        "next_check_at": snapshot.next_check_at,
        "credential_expires_at": snapshot.credential_expires_at,
        "reauthentication_required": snapshot.reauthentication_required,
        "offline_allowed": snapshot.offline_allowed,
        "remaining_offline_seconds": snapshot.remaining_offline_seconds,
    })
}

fn account_json(account: Account) -> Value {
    json!({
        "customer": {
            "id": account.customer.id,
            "username": account.customer.username,
            "email": account.customer.email,
            "suspended": account.customer.suspended,
            "created_at": account.customer.created_at,
        },
        "expires_at": account.expires_at,
    })
}

fn licence_json(licence: &OwnedLicence) -> Value {
    json!({
        "id": licence.id,
        "policy_name": licence.policy_name,
        "state": licence.state,
        "expiry_mode": licence.expiry_mode,
        "first_used_at": licence.first_used_at,
        "expires_at": licence.expires_at,
        "duration_seconds": licence.duration_seconds,
        "device_limit": licence.device_limit,
        "hwid_locked": licence.hwid_locked,
        "offline_allowed": licence.offline_allowed,
        "offline_seconds": licence.offline_seconds,
        "entitlements": licence.entitlements,
    })
}

fn owned_licences_json(page: OwnedLicences) -> Value {
    json!({
        "items": page.items.iter().map(licence_json).collect::<Vec<_>>(),
        "next_cursor": page.next_cursor,
    })
}

unsafe fn read_slice<'a>(value: OrbitFfiSlice, total: &mut usize) -> Result<&'a str, Failure> {
    if value.data.is_null() || value.len > MAX_INPUT_BYTES {
        return Err(Error::Configuration.into());
    }
    *total = total
        .checked_add(value.len)
        .filter(|length| *length <= MAX_TOTAL_INPUT_BYTES)
        .ok_or_else(|| Failure::from(Error::Configuration))?;
    // SAFETY: The ABI requires a readable buffer of `len` bytes for this call;
    // null is rejected even for an empty slice and the length is bounded above.
    let bytes = unsafe { slice::from_raw_parts(value.data, value.len) };
    str::from_utf8(bytes).map_err(|_| Error::Configuration.into())
}

unsafe fn read_arguments<'a>(
    arguments: *const OrbitFfiSlice,
    count: usize,
    expected: usize,
) -> Result<Vec<&'a str>, Failure> {
    if count != expected || count > MAX_ARGUMENTS || (count != 0 && arguments.is_null()) {
        return Err(Error::Configuration.into());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: The ABI requires `arguments` to point to `count` readable slice
    // records for the duration of the call. The count is checked above.
    let slices = unsafe { slice::from_raw_parts(arguments, count) };
    let mut total = 0;
    slices
        .iter()
        .map(|value| unsafe { read_slice(*value, &mut total) })
        .collect()
}

unsafe fn read_client_config<'a>(
    config: *const OrbitFfiClientConfig,
) -> Result<(&'a str, Config, Device, u32, &'a str), Failure> {
    if config.is_null() {
        return Err(Error::Configuration.into());
    }
    // SAFETY: The ABI requires a readable config record through the advertised
    // size; the current layout fields are read only after checking that size.
    let config = unsafe { &*config };
    if config.abi_version != ORBIT_FFI_ABI_VERSION
        || usize::try_from(config.struct_size).unwrap_or(0)
            < std::mem::size_of::<OrbitFfiClientConfig>()
    {
        return Err(Error::Configuration.into());
    }
    let mut total = 0;
    let mut next = |value| unsafe { read_slice(value, &mut total) };
    let origin = next(config.api_origin)?;
    let application = next(config.application_id)?;
    let environment = next(config.environment_id)?;
    let issuer = next(config.issuer)?;
    let installation = next(config.installation_id)?;
    let fingerprint = next(config.fingerprint)?;
    let provider = next(config.fingerprint_provider)?;
    let path = next(config.storage_path)?;
    let device = Device {
        installation_id: installation.to_owned(),
        fingerprint: (!fingerprint.is_empty()).then(|| fingerprint.to_owned()),
        fingerprint_provider: (!provider.is_empty()).then(|| provider.to_owned()),
    };
    Ok((
        origin,
        Config {
            application_id: application.to_owned(),
            environment_id: environment.to_owned(),
            issuer: issuer.to_owned(),
        },
        device,
        config.storage_mode,
        path,
    ))
}

fn expected_arguments(operation: u32) -> Option<usize> {
    Some(match operation {
        ORBIT_FFI_OP_SNAPSHOT
        | ORBIT_FFI_OP_REFRESH
        | ORBIT_FFI_OP_LOCAL_LOGOUT
        | ORBIT_FFI_OP_RESEND_REGISTRATION
        | ORBIT_FFI_OP_ACCOUNT
        | ORBIT_FFI_OP_ACCOUNT_LOGOUT
        | ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION => 0,
        ORBIT_FFI_OP_DEACTIVATE
        | ORBIT_FFI_OP_REQUIRE_ACCESS
        | ORBIT_FFI_OP_OWNED_LICENCES
        | ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY => 1,
        ORBIT_FFI_OP_ACTIVATE
        | ORBIT_FFI_OP_LOGIN
        | ORBIT_FFI_OP_CLAIM_LICENCE
        | ORBIT_FFI_OP_ACTIVATE_ACCOUNT
        | ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE => 2,
        ORBIT_FFI_OP_ACTIVATE_PREVIOUS | ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS => 3,
        ORBIT_FFI_OP_REGISTER => 4,
        _ => return None,
    })
}

fn check_call_handles(
    operation: u32,
    pending: *mut OrbitPendingRegistration,
    pending_out: *mut *mut OrbitPendingRegistration,
) -> Result<(), Failure> {
    if operation == ORBIT_FFI_OP_REGISTER {
        if pending_out.is_null() || !pending.is_null() {
            return Err(Error::Configuration.into());
        }
    } else if !pending_out.is_null() {
        return Err(Error::Configuration.into());
    }
    if operation == ORBIT_FFI_OP_RESEND_REGISTRATION {
        if pending.is_null() {
            return Err(Error::Configuration.into());
        }
    } else if !pending.is_null() {
        return Err(Error::Configuration.into());
    }
    Ok(())
}

/// Create a client and its private synchronous-call Tokio runtime.
///
/// # Safety
/// `config` must point to a readable configuration record and its input slices
/// must remain readable through the call. `output_client`, when non-null, must
/// point to writable storage for one client pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_client_create(
    config: *const OrbitFfiClientConfig,
    output_client: *mut *mut OrbitClient,
) -> OrbitFfiResult {
    ffi_result(|| {
        if output_client.is_null() {
            return Err(Error::Configuration.into());
        }
        // SAFETY: The ABI requires `output_client` to be writable for one pointer.
        unsafe { output_client.write(ptr::null_mut()) };
        // SAFETY: All config fields are checked and decoded by this helper.
        let (origin, config, device, storage_mode, path) = unsafe { read_client_config(config)? };
        let transport = Transport::new(origin)?;
        let storage: Arc<dyn Storage> = match storage_mode {
            ORBIT_FFI_STORAGE_MEMORY if path.is_empty() => Arc::new(MemoryStorage::default()),
            ORBIT_FFI_STORAGE_WINDOWS_DPAPI if !path.is_empty() => {
                Arc::new(WindowsStorage::open(path, &config, &device)?)
            }
            ORBIT_FFI_STORAGE_LINUX_SECRET_SERVICE if !path.is_empty() => {
                Arc::new(SecretServiceStorage::open(path, &config, &device)?)
            }
            _ => return Err(Error::Configuration.into()),
        };
        let client = Client::with_storage(config, device, transport, storage)?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| Failure::internal("runtime_unavailable"))?;
        // SAFETY: `output_client` was checked for null and is writable by contract.
        unsafe {
            output_client.write(Box::into_raw(Box::new(OrbitClient { runtime, client })));
        }
        Ok(Vec::new())
    })
}

/// Run one synchronous client operation. Output JSON contains metadata only;
/// customer-session authorization output is a sensitive raw header value.
///
/// # Safety
/// Non-null handles must be live handles returned by this library and must not
/// be freed during the call. `arguments` and each argument's bytes must be
/// readable for the duration of the call. On REGISTER, `pending_out` must point
/// to writable storage for one pending-registration pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_client_call(
    client: *mut OrbitClient,
    operation: u32,
    arguments: *const OrbitFfiSlice,
    argument_count: usize,
    cancellation: *const OrbitCancellation,
    pending: *mut OrbitPendingRegistration,
    pending_out: *mut *mut OrbitPendingRegistration,
) -> OrbitFfiResult {
    ffi_result(|| {
        if client.is_null() {
            return Err(Error::Configuration.into());
        }
        let expected =
            expected_arguments(operation).ok_or_else(|| Failure::from(Error::Configuration))?;
        check_call_handles(operation, pending, pending_out)?;
        // SAFETY: Opaque handles must be live handles returned by this library.
        let client = unsafe { &*client };
        if operation == ORBIT_FFI_OP_REGISTER {
            // SAFETY: The ABI requires a writable output slot for register calls.
            unsafe { pending_out.write(ptr::null_mut()) };
        }
        // SAFETY: The ABI keeps the argument array and its UTF-8 slices alive for this call.
        let args = unsafe { read_arguments(arguments, argument_count, expected)? };
        let owned_cancel;
        let cancel = if cancellation.is_null() {
            owned_cancel = Cancellation::new();
            &owned_cancel
        } else {
            // SAFETY: Opaque handles must be live handles returned by this library.
            unsafe { &(*cancellation).cancellation }
        };
        let runtime = &client.runtime;
        let sdk = &client.client;
        let output = match operation {
            ORBIT_FFI_OP_SNAPSHOT => json_output(&snapshot_json(sdk.snapshot()?))?,
            ORBIT_FFI_OP_ACTIVATE => {
                let snapshot = runtime.block_on(sdk.activate(args[0], args[1], cancel))?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_ACTIVATE_PREVIOUS => {
                let previous = (!args[1].is_empty()).then_some(args[1]);
                let snapshot = runtime
                    .block_on(sdk.activate_with_previous(args[0], previous, args[2], cancel))?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_REFRESH => {
                let snapshot = runtime.block_on(sdk.refresh(cancel))?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_REQUIRE_ACCESS => {
                let snapshot = runtime.block_on(sdk.require_access(args[0], cancel))?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_DEACTIVATE => {
                runtime.block_on(sdk.deactivate(args[0], cancel))?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_LOCAL_LOGOUT => {
                sdk.logout()?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_REGISTER => {
                let pending_registration = runtime.block_on(sdk.register(
                    Registration {
                        licence_key: args[0],
                        username: args[1],
                        email: args[2],
                        password: args[3],
                    },
                    cancel,
                ))?;
                let output = json_output(&json!({
                    "accepted": pending_registration.accepted,
                    "expires_at": pending_registration.expires_at,
                }))?;
                // SAFETY: The ABI requires a writable output slot on registration.
                unsafe {
                    pending_out.write(Box::into_raw(Box::new(OrbitPendingRegistration {
                        pending: pending_registration,
                    })));
                }
                output
            }
            ORBIT_FFI_OP_RESEND_REGISTRATION => {
                // SAFETY: The caller supplies a live opaque handle and keeps it alive for this call.
                let pending_registration = unsafe { &(*pending).pending };
                runtime.block_on(sdk.resend_registration(pending_registration, cancel))?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_LOGIN => {
                let account = runtime.block_on(sdk.login(args[0], args[1], cancel))?;
                json_output(&account_json(account))?
            }
            ORBIT_FFI_OP_ACCOUNT => match sdk.account()? {
                Some(account) => json_output(&account_json(account))?,
                None => json_output(&Value::Null)?,
            },
            ORBIT_FFI_OP_OWNED_LICENCES => {
                let after = (!args[0].is_empty()).then_some(args[0]);
                let page = runtime.block_on(sdk.owned_licences(after, cancel))?;
                json_output(&owned_licences_json(page))?
            }
            ORBIT_FFI_OP_CLAIM_LICENCE => {
                let licence = runtime.block_on(sdk.claim_licence(args[0], args[1], cancel))?;
                json_output(&licence_json(&licence))?
            }
            ORBIT_FFI_OP_ACTIVATE_ACCOUNT => {
                let snapshot = runtime.block_on(sdk.activate_account(args[0], args[1], cancel))?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS => {
                let previous = (!args[1].is_empty()).then_some(args[1]);
                let snapshot = runtime.block_on(
                    sdk.activate_account_with_previous(args[0], previous, args[2], cancel),
                )?;
                json_output(&snapshot_json(snapshot))?
            }
            ORBIT_FFI_OP_ACCOUNT_LOGOUT => {
                runtime.block_on(sdk.logout_account(cancel))?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE => {
                runtime.block_on(sdk.request_email_change(args[0], args[1], cancel))?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY => {
                runtime.block_on(sdk.request_password_recovery(args[0], cancel))?;
                json_output(&Value::Null)?
            }
            ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION => {
                let proof: CustomerSessionProof = sdk.customer_session_proof()?;
                let header = proof.authorization_header();
                if header.len() > MAX_OUTPUT_BYTES {
                    return Err(Failure::internal("output_too_large"));
                }
                header.into_bytes()
            }
            _ => return Err(Error::Configuration.into()),
        };
        Ok(output)
    })
}

/// Create a cancellation handle. Returns null only if allocation or a panic fails.
#[unsafe(no_mangle)]
pub extern "C" fn orbit_cancellation_create() -> *mut OrbitCancellation {
    catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(OrbitCancellation {
            cancellation: Cancellation::new(),
        }))
    }))
    .unwrap_or(ptr::null_mut())
}

/// Signal cancellation for an operation using this handle.
///
/// # Safety
/// A non-null pointer must identify a live cancellation handle that is not
/// concurrently being freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_cancellation_cancel(cancellation: *const OrbitCancellation) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !cancellation.is_null() {
            // SAFETY: The caller passes a live cancellation handle.
            unsafe { (*cancellation).cancellation.cancel() };
        }
    }));
}

/// Release a client handle after all calls using it have returned.
///
/// # Safety
/// A non-null pointer must be a live handle returned by `orbit_client_create`,
/// passed exactly once after all calls using it have completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_client_free(client: *mut OrbitClient) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            // SAFETY: The caller passes a live handle returned by orbit_client_create exactly once.
            unsafe { drop(Box::from_raw(client)) };
        }
    }));
}

/// Release a cancellation handle after all operations using it have returned.
///
/// # Safety
/// A non-null pointer must be a live handle returned by
/// `orbit_cancellation_create`, passed exactly once after all operations using
/// it have completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_cancellation_free(cancellation: *mut OrbitCancellation) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !cancellation.is_null() {
            // SAFETY: The caller passes a live handle returned by orbit_cancellation_create exactly once.
            unsafe { drop(Box::from_raw(cancellation)) };
        }
    }));
}

/// Release an opaque pending registration handle.
///
/// # Safety
/// A non-null pointer must be a live handle returned by a successful REGISTER
/// call, passed exactly once after no call is using it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_pending_registration_free(pending: *mut OrbitPendingRegistration) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !pending.is_null() {
            // SAFETY: The caller passes a live handle returned by a successful register call exactly once.
            unsafe { drop(Box::from_raw(pending)) };
        }
    }));
}

/// Release a standalone result or buffer and clear its fields.
///
/// # Safety
/// `buffer` must be null or a writable descriptor returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_ffi_buffer_free(buffer: *mut OrbitFfiBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffer.is_null() {
            return;
        }
        // SAFETY: The caller passes a writable buffer descriptor returned by this library.
        let buffer = unsafe { &mut *buffer };
        if !buffer.data.is_null() {
            // SAFETY: Owned buffers are allocated as boxed byte slices and retain this length.
            let slice = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
            let mut owned = unsafe { Box::from_raw(slice) };
            clear_bytes(&mut owned);
        }
        *buffer = empty_buffer();
    }));
}

/// Release all buffers in a result and clear the result fields.
///
/// # Safety
/// `result` must be null or a writable result returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_ffi_result_free(result: *mut OrbitFfiResult) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if result.is_null() {
            return;
        }
        // SAFETY: The caller passes a writable result descriptor returned by this library.
        let result = unsafe { &mut *result };
        // SAFETY: These three descriptors are owned fields of the valid result.
        unsafe { orbit_ffi_buffer_free(&mut result.error_code) };
        // SAFETY: These three descriptors are owned fields of the valid result.
        unsafe { orbit_ffi_buffer_free(&mut result.request_id) };
        // SAFETY: These three descriptors are owned fields of the valid result.
        unsafe { orbit_ffi_buffer_free(&mut result.output) };
        *result = OrbitFfiResult {
            abi_version: ORBIT_FFI_ABI_VERSION,
            status: ORBIT_FFI_OK,
            error_kind: ORBIT_FFI_ERROR_NONE,
            reserved: 0,
            error_code: empty_buffer(),
            request_id: empty_buffer(),
            output: empty_buffer(),
        };
    }));
}

/// Generate a cryptographically random URL-safe installation ID using the SDK.
#[unsafe(no_mangle)]
pub extern "C" fn orbit_installation_id_new() -> OrbitFfiResult {
    ffi_result(|| {
        let device = Device::new_installation()?;
        Ok(device.installation_id.into_bytes())
    })
}

/// Derive the SDK's native fingerprint for this machine and public application scope.
///
/// # Safety
/// Each non-null input pointer must reference its declared number of readable
/// bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_native_fingerprint(
    application_id: OrbitFfiSlice,
    environment_id: OrbitFfiSlice,
) -> OrbitFfiResult {
    ffi_result(|| {
        let mut total = 0;
        // SAFETY: The ABI requires both borrowed slices to stay readable during the call.
        let application = unsafe { read_slice(application_id, &mut total)? };
        // SAFETY: Same input lifetime and bounds contract as the first slice.
        let environment = unsafe { read_slice(environment_id, &mut total)? };
        Ok(orbit_sdk::native_fingerprint(application, environment)?.into_bytes())
    })
}

/// Derive the SDK's canonical fingerprint from an explicit supported machine identity.
///
/// # Safety
/// Each non-null input pointer must reference its declared number of readable
/// bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn orbit_machine_fingerprint(
    application_id: OrbitFfiSlice,
    environment_id: OrbitFfiSlice,
    family: OrbitFfiSlice,
    identity: OrbitFfiSlice,
) -> OrbitFfiResult {
    ffi_result(|| {
        let mut total = 0;
        // SAFETY: The ABI requires all borrowed slices to stay readable during the call.
        let application = unsafe { read_slice(application_id, &mut total)? };
        // SAFETY: Same input lifetime and bounds contract as the first slice.
        let environment = unsafe { read_slice(environment_id, &mut total)? };
        // SAFETY: Same input lifetime and bounds contract as the first slice.
        let family = unsafe { read_slice(family, &mut total)? };
        // SAFETY: Same input lifetime and bounds contract as the first slice.
        let identity = unsafe { read_slice(identity, &mut total)? };
        Ok(
            orbit_sdk::machine_fingerprint(application, environment, family, identity)?
                .into_bytes(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice(value: &[u8]) -> OrbitFfiSlice {
        OrbitFfiSlice {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn empty_slice() -> OrbitFfiSlice {
        slice(b"")
    }

    fn ffi_create(
        config: *const OrbitFfiClientConfig,
        client: *mut *mut OrbitClient,
    ) -> OrbitFfiResult {
        // SAFETY: Tests pass a live config and writable client output slot.
        unsafe { orbit_client_create(config, client) }
    }

    fn ffi_call(
        client: *mut OrbitClient,
        operation: u32,
        arguments: *const OrbitFfiSlice,
        argument_count: usize,
        cancellation: *const OrbitCancellation,
        pending: *mut OrbitPendingRegistration,
        pending_out: *mut *mut OrbitPendingRegistration,
    ) -> OrbitFfiResult {
        // SAFETY: Tests keep all handles and argument storage live for each call.
        unsafe {
            orbit_client_call(
                client,
                operation,
                arguments,
                argument_count,
                cancellation,
                pending,
                pending_out,
            )
        }
    }

    fn ffi_result_free(result: *mut OrbitFfiResult) {
        // SAFETY: Tests pass an FFI result they own and free once.
        unsafe { orbit_ffi_result_free(result) }
    }

    fn ffi_client_free(client: *mut OrbitClient) {
        // SAFETY: Tests pass a live handle after all calls have returned.
        unsafe { orbit_client_free(client) }
    }

    fn ffi_cancel(cancellation: *const OrbitCancellation) {
        // SAFETY: Tests pass a live cancellation handle.
        unsafe { orbit_cancellation_cancel(cancellation) }
    }

    fn ffi_cancel_free(cancellation: *mut OrbitCancellation) {
        // SAFETY: Tests free each live cancellation handle once after use.
        unsafe { orbit_cancellation_free(cancellation) }
    }

    fn test_client() -> *mut OrbitClient {
        let config = OrbitFfiClientConfig {
            struct_size: std::mem::size_of::<OrbitFfiClientConfig>() as u32,
            abi_version: ORBIT_FFI_ABI_VERSION,
            storage_mode: ORBIT_FFI_STORAGE_MEMORY,
            reserved: 0,
            api_origin: slice(b"https://orbit.example.test"),
            application_id: slice(b"app"),
            environment_id: slice(b"test"),
            issuer: slice(b"https://orbit.example.test"),
            installation_id: slice(b"installation_123456"),
            fingerprint: empty_slice(),
            fingerprint_provider: empty_slice(),
            storage_path: empty_slice(),
        };
        let mut client = ptr::null_mut();
        let mut result = ffi_create(&config, &mut client);
        assert_eq!(result.status, ORBIT_FFI_OK);
        ffi_result_free(&mut result);
        client
    }

    #[test]
    fn construction_snapshot_and_denied_access_are_offline() {
        let client = test_client();
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_SNAPSHOT,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.status, ORBIT_FFI_OK);
        // SAFETY: Result output is owned by the FFI result until freed below.
        let snapshot = unsafe {
            str::from_utf8(slice::from_raw_parts(result.output.data, result.output.len)).unwrap()
        };
        assert!(snapshot.contains("\"access\":\"denied\""));
        ffi_result_free(&mut result);

        let feature = slice(b"reports");
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_REQUIRE_ACCESS,
            &feature,
            1,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.status, ORBIT_FFI_ERROR);
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_DENIED);
        // SAFETY: Error-code buffer is owned by this result until freed below.
        let code = unsafe {
            str::from_utf8(slice::from_raw_parts(
                result.error_code.data,
                result.error_code.len,
            ))
            .unwrap()
        };
        assert_eq!(code, "access_unavailable");
        ffi_result_free(&mut result);
        ffi_client_free(client);
    }

    #[test]
    fn rejects_invalid_and_oversized_input_without_network() {
        let client = test_client();
        let invalid = slice(&[0xff]);
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_REQUIRE_ACCESS,
            &invalid,
            1,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.status, ORBIT_FFI_ERROR);
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_CONFIGURATION);
        ffi_result_free(&mut result);

        let oversized = vec![b'a'; MAX_INPUT_BYTES + 1];
        let argument = slice(&oversized);
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_REQUIRE_ACCESS,
            &argument,
            1,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.status, ORBIT_FFI_ERROR);
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_CONFIGURATION);
        ffi_result_free(&mut result);
        ffi_client_free(client);
    }

    #[test]
    fn handles_and_owned_results_have_explicit_lifetimes() {
        let client = test_client();
        let cancellation = orbit_cancellation_create();
        assert!(!cancellation.is_null());
        ffi_cancel(cancellation);
        let arguments = [slice(b"alice"), slice(b"password")];
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_LOGIN,
            arguments.as_ptr(),
            arguments.len(),
            cancellation,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.status, ORBIT_FFI_ERROR);
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_CANCELLED);
        ffi_result_free(&mut result);
        assert!(result.output.data.is_null());
        assert!(result.error_code.data.is_null());
        ffi_cancel_free(cancellation);
        ffi_client_free(client);
    }

    #[test]
    fn rejects_null_slice_data_and_unknown_operations() {
        let client = test_client();
        let null_slice = OrbitFfiSlice {
            data: ptr::null(),
            len: 0,
        };
        let mut result = ffi_call(
            client,
            ORBIT_FFI_OP_REQUIRE_ACCESS,
            &null_slice,
            1,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_CONFIGURATION);
        ffi_result_free(&mut result);
        let mut result = ffi_call(
            client,
            u32::MAX,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert_eq!(result.error_kind, ORBIT_FFI_ERROR_CONFIGURATION);
        ffi_result_free(&mut result);
        ffi_client_free(client);
    }

    #[test]
    fn operation_argument_counts_match_the_header_contract() {
        for (operation, count) in [
            (ORBIT_FFI_OP_SNAPSHOT, 0),
            (ORBIT_FFI_OP_ACTIVATE, 2),
            (ORBIT_FFI_OP_ACTIVATE_PREVIOUS, 3),
            (ORBIT_FFI_OP_REFRESH, 0),
            (ORBIT_FFI_OP_REQUIRE_ACCESS, 1),
            (ORBIT_FFI_OP_DEACTIVATE, 1),
            (ORBIT_FFI_OP_LOCAL_LOGOUT, 0),
            (ORBIT_FFI_OP_REGISTER, 4),
            (ORBIT_FFI_OP_RESEND_REGISTRATION, 0),
            (ORBIT_FFI_OP_LOGIN, 2),
            (ORBIT_FFI_OP_ACCOUNT, 0),
            (ORBIT_FFI_OP_OWNED_LICENCES, 1),
            (ORBIT_FFI_OP_CLAIM_LICENCE, 2),
            (ORBIT_FFI_OP_ACTIVATE_ACCOUNT, 2),
            (ORBIT_FFI_OP_ACTIVATE_ACCOUNT_PREVIOUS, 3),
            (ORBIT_FFI_OP_ACCOUNT_LOGOUT, 0),
            (ORBIT_FFI_OP_REQUEST_EMAIL_CHANGE, 2),
            (ORBIT_FFI_OP_REQUEST_PASSWORD_RECOVERY, 1),
            (ORBIT_FFI_OP_CUSTOMER_SESSION_AUTHORIZATION, 0),
        ] {
            assert_eq!(
                expected_arguments(operation),
                Some(count),
                "operation {operation}"
            );
        }
        assert_eq!(expected_arguments(u32::MAX), None);
    }
}
