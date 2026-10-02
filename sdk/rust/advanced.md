# Advanced Rust APIs

Start with the [installed-client guide](README.md).

## Options and machine binding

`Client::open_with_options` selects an explicit state directory or binding
policy:

```rust,ignore
use orbit_sdk::{Client, MachineBinding, Options};

let orbit = Client::open_with_options(&app_key, Options {
    state_directory: Some(state_directory.into()),
    machine_binding: MachineBinding::Disabled,
    ..Options::default()
}).await?;
```

`MachineBinding::Automatic` is the default, `Disabled` sends no fingerprint,
and `Custom { fingerprint, provider }` accepts a 64-character lowercase
hexadecimal value with a `custom:` provider. On macOS the automatic identity is
a scoped digest of IOKit `IOPlatformUUID`. If native identity is unavailable,
the SDK sends none; it never substitutes randomness.

When the machine identity changes, the SDK creates a new installation ID and
clears the old credential, grant and pending activation before recovery, so a
moved installation cannot use the old machine's cached authority.

## Long-term offline files

`Options.offline_keys` accepts a trusted JWKS of at most 16 KiB, parsed before
installation state opens. Key IDs must use the `offline-test-` or
`offline-live-` prefix matching the app key. Imported files never supply their
own verification keys.

`offline_request()` sends no request and consumes no installation slot.
`import_offline_file()` verifies the compact `.orbit` file, persists it with
monotonic sequence and clock floors, then switches to that file's signed
authority. Lower sequences and equal-sequence conflicts are rejected. The
signed file is verified again after a restart, using the configured keys.
`Snapshot::offline_file_mode` distinguishes file access from cached
connected-grant fallback.

## Activation and access

`activate(key)` and `activate_account(licence_id)` generate secure operation
IDs. `activate_with_id`, `activate_account_with_id`, `claim_licence_with_id` and
`deactivate_with_id` accept an application-owned ID. Installed activation IDs
are saved before sending, so retry the same input after a lost reply; the key
itself is not saved. `activate_with_previous` and
`activate_account_with_previous` rebind a freshly authenticated installation
using its previous credential.

`ensure_access(feature, ask_for_key)` takes a synchronous callback returning
`Option<String>`. It invokes the callback only for `Error::NotActivated`, then
activates and checks access again.

The async methods do not expose per-call cancellation. Dropping an in-flight
future does not allow a late response to replace newer local state. `close()`
cancels owned network work, joins refresh scheduling, checkpoints clock
evidence and releases the local lock; it preserves the server activation.
`deactivate()` releases the device slot after confirmation. `logout()` clears
local access without revoking a customer session, while `logout_account()`
also requests server-side session revocation.

## Customer accounts

Account sessions remain in memory. A customer can register, confirm their
email, sign in and select one of their licences on the same client:

```rust,ignore
let pending = orbit.register(Registration {
    licence_key: Some(&key), username: &username, email: &email, password: &password,
}).await?;
orbit.resend_registration(&pending).await?;
orbit.login(&username, &password).await?;
let page = orbit.owned_licences(None).await?;
orbit.activate_account(&page.items[0].id).await?;
orbit.require_access("export").await?;
```

Set `licence_key` to `None` for customer sign-up without a key when the
application allows it; any sign-up licence the application grants appears in
`owned_licences` after sign-in. Registration confirmation does not sign the
customer in. Passwords require at least eight characters; preserve whitespace.
`PendingRegistration` keeps its resend proof private and in memory. Pass
`page.next_cursor.as_deref()` to fetch the next licence page.
`claim_licence(key)` adds an eligible key to the signed-in account without
activating it. Recovery and email-change requests return generic acceptance.

`OwnedLicence::offline_file_duration` is zero when long-term offline files are
disabled, and between one and 366 days when they are enabled.

For your own trusted HTTPS backend,
`customer_session_proof()?.authorization_header()` returns a sensitive session
Bearer header. Never log or persist it. The backend must verify it online and
enforce licensed access separately, as shown in the
[backend example](../../examples/rust/licensed-backend/README.md).

## Storage and clock guarantees

Windows state uses current-user DPAPI and a protected ACL. Linux and macOS
state use an owner-only private directory and credential file, including
headless installations; on macOS this is private POSIX storage, not Keychain
encryption, and state lives under `~/Library/Application Support/Orbit`. macOS
state and lease files require `F_FULLFSYNC`, and the parent directory is
synchronized after atomic replacement; a filesystem that rejects this fails
closed. macOS builds need the Apple SDK to link IOKit and CoreFoundation.

Corrupt or missing established state is never silently replaced with a new
installation. An interrupted write leaves a recovery marker, so a grant or
credential from before an incomplete invalidation cannot be restored. Keep the
directory private and persistent, and use one client for it per process; a
second process receives `Error::InstallationInUse`.

Sleep counts toward expiry. A clock rollback or inconsistent saved clock
evidence requires online validation. A user who controls the machine can modify
local state.

## Local development and support

The `local-development` feature enables `Client::open_local` for app keys whose
origin is a literal loopback address. Default builds accept HTTPS origins only.

`error.request_id()` exposes a validated server reference when one exists.
`client.support_summary(&error)` creates safe JSON with scope, error code,
request reference and local timestamp; it contains no app key, credential,
customer session, fingerprint or server-private message.

## Access-check performance

Reuse one open client per installation. A warm `require_access` checks the
trusted clock, installed storage and feature in local verified state, and
contacts Orbit only when a refresh is due. On Linux x86-64 it takes about
4 µs, with no network request or storage write.

## Online services

Update discovery, download authorization and metering use the current installed
activation proof. A response that arrives after credential replacement, logout
or close is discarded, whether it succeeded or failed.

Downloads use a fresh verified-HTTPS client with no cookie jar or ambient
credentials. They follow at most five redirects and send the ticket only to the
initial endpoint. Byte limits apply while streaming, independently of response
length headers, and compressed responses are refused. The temporary file is
created beside the destination and removed on error or when the future is
dropped. The seller's filename never chooses a destination path.
