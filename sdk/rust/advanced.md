# Advanced Rust APIs

Start with the [installed-client guide](README.md). `Client::open(app_key)` creates
one durable installation and uses native `machine_v1` binding by default when the
platform identity is available. `Client::open_with_options` selects an explicit state
directory or binding policy:

```rust,ignore
use orbit_sdk::{Client, MachineBinding, Options};

let orbit = Client::open_with_options(&app_key, Options {
    state_directory: Some(state_directory.into()),
    machine_binding: MachineBinding::Disabled,
    ..Options::default()
}).await?;
```

`MachineBinding::Automatic` is the default, `Disabled` sends no fingerprint, and
`Custom { fingerprint, provider }` accepts a 64-character lowercase hexadecimal value
with a `custom:` provider. If native identity is unavailable, the SDK sends none; it
never substitutes randomness. Before opening changed identity, it creates a new
installation ID and clears the old credential, grant, and pending activation. This
prevents an old machine's cached authority from being used after a move or identity
change.

## Long-term offline files

`Options.offline_keys` accepts a bounded trusted JWKS byte buffer, parsed before the
installation state is opened. Keys must use the `offline-test-` or `offline-live-`
purpose prefix matching the app key. Ship them with trusted application configuration
or fetch them from the app-key origin over verified HTTPS. Imported files never supply
their own verification keys.

`offline_request()` exports the stable installation ID and optional binding pair for
an authorized online issuance workflow; it consumes no slot and sends no request.
`import_offline_file()` verifies the compact `.orbit` file, persists its bytes and
monotonic sequence/clock floors, then switches to that file's signed authority. Drop
the returned future to cancel that caller's operation; `Client::close()` cancels
owned work. Lower sequences and equal-sequence conflicts are rejected. The signed file
is reverified after restart. `Snapshot::offline_file_mode` distinguishes
file access from cached connected-grant fallback, and `require_access()` checks the
local lease, clock, expiry and requested feature without network refresh or prompting.

The signed absolute expiry is unchanged by reimport. Revocation and refunds cannot
promptly revoke access on a disconnected machine. The durable sequence and time floors
prevent ordinary replay and clock rollback, but restoring an entire old machine or VM
snapshot can restore its state; local files cannot provide hardware-counter guarantees.

## Activation and access

`activate(key)` and `activate_account(licence_id)` generate secure operation IDs.
`activate_with_id`, `activate_account_with_id`, `claim_licence_with_id`, and
`deactivate_with_id` accept an application-owned ID for retries after an uncertain
response. Installed activation IDs are saved before sending, so retry the same input
after a lost reply. The key itself is not saved. `activate_with_previous` and
`activate_account_with_previous` are advanced rebind methods for a freshly authenticated
installation.

The async methods do not expose per-call cancellation. Dropping an in-flight future
does not allow a late response to replace newer local state; `close()` cancels owned
network work, joins refresh scheduling, checkpoints clock evidence, and releases the
local lock. It preserves the server activation. `deactivate()` releases that device
slot after confirmation. `logout()` clears local access without revoking a customer
session, while `logout_account()` requests server-side session revocation.

Call `require_access(feature)` immediately before every protected operation.
`Error::NotActivated` and `Error::FeatureUnavailable` are distinct typed errors and
`error.code()` returns the stable protocol code. `ensure_access(feature, ask_for_key)`
accepts a synchronous callback returning `Option<String>`; it invokes the callback only
for `NotActivated`, then activates and checks access again. Temporary outages and
feature denials propagate without prompting.

## Customer accounts

Account sessions remain in memory. A customer can register, confirm their email, sign
in, and select one of their licences on the same client:

```rust,ignore
let pending = orbit.register(Registration {
    licence_key: &key, username: &username, email: &email, password: &password,
}).await?;
orbit.resend_registration(&pending).await?;
orbit.login(&username, &password).await?;
let page = orbit.owned_licences(None).await?;
orbit.activate_account(&page.items[0].id).await?;
orbit.require_access("export").await?;
```

Registration confirmation does not sign the customer in. Passwords require at least
eight characters; preserve whitespace. `PendingRegistration` keeps its resend proof
private and in memory. Pass `page.next_cursor.as_deref()` to fetch the next bounded
licence page. `claim_licence(key)` adds an eligible key to the signed-in account without
activating it. Recovery and email-change requests return generic acceptance.

`account()` returns informational metadata. Account, licence and `Snapshot` dates use
`std::time::SystemTime`; licence durations and `Snapshot::remaining_offline` use
`std::time::Duration`. For your own trusted HTTPS backend,
`customer_session_proof()?.authorization_header()` returns a sensitive session Bearer
header. Never log or persist it. The backend must verify it online and enforce licensed
access separately, as shown in the [backend example](../../examples/rust/licensed-backend/README.md).

## Storage and clock guarantees

Windows state uses current-user DPAPI and a protected ACL. Linux and macOS state use
an owner-only private directory and credential file, including headless installations.
On macOS 10.12 or newer, the SDK derives `machine_v1` from IOKit `IOPlatformUUID`, and its elapsed clock uses
`mach_continuous_time` so sleep counts toward expiry. State and lease files require
`F_FULLFSYNC`; the parent directory is synchronized after atomic replacement. If the
filesystem rejects that durability operation, the SDK fails closed. This is private
POSIX storage, not Keychain encryption.
Corrupt or missing established state is not silently replaced with a new installation.
An interrupted write leaves a recovery marker, preventing a grant or credential from
before an incomplete invalidation from being restored. Keep the default directory
private and persistent; use one client for that directory in a process. macOS native
builds need the Apple SDK to link IOKit and CoreFoundation.

Sleep counts toward expiry. A clock rollback or inconsistent saved clock evidence
requires online validation. Local storage cannot detect every restored disk or VM
snapshot, and a user controlling the machine can modify local state.

## Local development and support

The `local-development` feature enables `Client::open_local` for app keys whose origin
is a literal loopback address. HTTPS remains certificate-verified; redirects remain
disabled. Default builds accept HTTPS origins only.

`error.request_id()` exposes a validated server reference when one exists.
`client.support_summary(&error)` creates safe JSON with scope, error code, request
reference, and local timestamp; it contains no app key, credential, customer session,
fingerprint, or server-private message.

## Access-check performance

Reuse one open client per installation. A warm `require_access` checks the
trusted clock, installed storage and feature in local verified state, and
contacts Orbit only when a refresh is due. On Linux x86-64 it takes about
3.7 µs, with no network request or storage write.

## Explicit online services

Update discovery, download authorization and metering use the current installed
activation proof. They never acquire a floating seat or switch out of offline-file
mode implicitly. A response that arrives after credential replacement, logout or
close is discarded, whether it succeeded or failed.

Metering returns `MutationResult<T>`. An uncertain failure retains the operation ID;
retry the same action and input. Dropping an async future cannot return an ID, so
supply your own durable job ID when cancellation or process restart must be
recoverable. Capacity denial details are validated before they are returned.

Downloads own a fresh verified-HTTPS client with no cookie jar or ambient credentials.
They allow five redirects and forward no bearer after the initial endpoint. Byte
limits apply while streaming, independently of response length headers. Identity
encoding, exact length and SHA-256 are checked before an atomic destination change.
Temporary files are created beside the destination and removed on errors or future
drop. The seller's filename never chooses a destination path.
