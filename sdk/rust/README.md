# Orbit Rust SDK

The SDK adds licence activation, customer sign-in and feature checks to Rust apps. It
connects to Orbit over HTTPS and supports Windows 11 x64 and Ubuntu 24.04 x64. Source is
under the [MIT licence](../LICENSE).

## Add the SDK

Use Rust/Cargo 1.98.1 or newer. Pin the public source release from Git:

```toml
[dependencies]
orbit-sdk = { git = "https://github.com/mayvqt/orbit-sdk", tag = "v0.1.0" }
```

For a local checkout, use `path = "../orbit-sdk/sdk/rust"` instead. Keep the SDK
directory intact and use it as one dependency.

For a first run, follow the
[console example](../../examples/rust/licensed-export/README.md), then open
**Integration** in the dashboard and copy the Rust startup snippet for your application
and environment.

## Activate and check access

Use the public values from Integration and reuse the same installation ID after
restarts. Neither public ID is secret. `Client::connect` uses strict HTTPS and keeps
credentials in memory. Use `Client::with_storage` for protected storage or
`Transport::local_loopback` for explicit local testing.

```rust,ignore
let orbit = Client::connect(Setup {
    api_origin: "https://orbit.mayvie.dev".into(),
    application_id: application_id.into(),
    environment_id: environment_id.into(),
    issuer: grant_issuer.into(),
    installation_id: stable_installation_id.into(),
})?;
orbit.activate(&user_entered_key, &operation_id, &cancel).await?;
orbit.require_access("export", &cancel).await?;
```

Check access before every protected operation; do not cache a startup result. When
activation delivery is uncertain, retry with the same operation ID and input within 24
hours. Key delivery can be replayed for 15 minutes. `ReauthenticationRequired` needs a
deliberate replacement flow; do not retry mutations with a new ID blindly.
`activate_with_previous` accepts the original credential when rebinding the same
fingerprint to a new installation. The SDK never persists licence keys or passwords.

## Customer accounts

Customer apps use the same `Client`. Registration requires an eligible licence in an
Account or Both app. Email confirmation happens in the browser and does not sign the
customer in.

```rust,ignore
let pending = orbit.register(Registration {
    licence_key: &key,
    username: &username,
    email: &email,
    password: &password, // At least 8 characters; spaces are preserved.
}, &cancel).await?;
// Optional while the original registration remains valid:
orbit.resend_registration(&pending, &cancel).await?;
// After the customer confirms their verification email:
let account = orbit.login(&username, &password, &cancel).await?;
let page = orbit.owned_licences(None, &cancel).await?;
// Select an ID from page.items; login and listing alone grant no access.
orbit.activate_account(&selected_id, &operation_id, &cancel).await?;
orbit.require_access("export", &cancel).await?;
```

`Account`, `Customer`, `OwnedLicence` and `OwnedLicences` contain safe metadata. Their
dates are RFC3339 strings; `Snapshot` dates are Unix seconds. `account()` returns local
login metadata without checking the server or granting access. Pass
`page.next_cursor.as_deref()` to `owned_licences` for the next bounded page.
`claim_licence(key, operation_id, cancel)` lets a signed-in customer claim another
eligible key without activating it; keep its input and operation ID stable for uncertain
delivery retries within 24 hours. `activate_account_with_previous` supports same-
fingerprint rebinding with the original credential, subject to server cooldown and
ownership checks.

`request_password_recovery(email, cancel)` returns generic acceptance.
`request_email_change(password, new_email, cancel)` starts a two-mailbox confirmation
flow; complete the emailed proofs in the browser, then log in again. Registration,
resend, login, recovery and email-change requests are sent once, without automatic
mutation retries. Generic acceptance does not reveal whether an account or eligible
pending request exists.

`PendingRegistration` keeps its resend proof private in memory and has no `Debug` or
`Serialize` implementation. Customer session tokens have no public serialized form and
never enter `Storage`. For your own trusted HTTPS backend,
`customer_session_proof()?.authorization_header()` exposes the sensitive Bearer header.
Do not log or persist it, send it to arbitrary origins, or forward it through redirects.
The backend must verify it online and separately check licensed access. Local account
metadata and offline grants are not customer identity credentials. See the [backend
example](../../examples/rust/licensed-backend/README.md).

## Refresh and sign out

Use `snapshot()` for access state, expiry, next check, offline allowance and the
credential reauthentication deadline. Schedule `refresh()` when the next check is due,
and call `require_access()` before protected work. It refreshes when needed and allows
fallback only for a verified, unexpired offline-enabled grant after a recognized
transient failure. Explicit denial, invalid responses and TLS verification failures
clear access. Unknown features deny.

`logout()` immediately clears local access and the in-memory customer session without
contacting Orbit. `logout_account(cancel)` clears both when called, before its future is
awaited; await success to confirm server session revocation and revocation of that
session's derived activation credentials. Neither logout releases device slots. A remote
failure leaves local access cleared, and a newer login cannot be overwritten by a late
logout response.

`deactivate()` clears activation access but keeps the customer login before contacting
Orbit. The device slot is released only after server acknowledgement. A failed release
needs reconciliation or a deliberate fresh activation and release. Late responses cannot
restore a logged-out context. Customer sessions last 12 hours; ordinary expiry does not
stop an existing activation from refreshing with its separate fixed 30-day credential.
Explicit session revocation, recovery, suspension and completed email changes revoke
derived credentials. A new login clears the previous local access context; select and
activate the intended licence before protected operations.

## Remember an activation

Default storage is memory only. Cached grants are not persisted, missing clock evidence
never grants offline access, and each process restart requires an online check. Save the
nonsecret installation ID separately and reuse it to avoid consuming another device
slot. Custom adapters can implement `Storage` using OS-protected storage. `version` must
provide a cheap current invalidation check before protected access; `save` must compare
its version atomically with `invalidate`. Isolate storage per access context unless the
adapter coordinates every writer. Never save a plaintext bearer file.

On Windows, explicitly open `WindowsStorage::open(directory, &config, &device)` and pass
it in an `Arc` to `Client::with_storage`. Use an existing dedicated absolute local
directory under the current user's private Windows profile, with one directory per
issuer, application, environment and installation. The adapter uses current-user DPAPI;
other platforms return `Error::Storage`. Its fixed `orbit-storage.lock` lease excludes
other openers until Drop. Share the same `Arc` across in-process contexts. Only the
opaque activation credential and existing metadata persist, with a versioned tombstone
after invalidation; customer sessions and signed grants do not. Do not delete or
exchange either fixed file. Corrupt, incompatible or missing existing state fails closed
and needs deliberate host recovery. A write error poisons the adapter until it is
dropped and deliberately reopened. Do not share these files with another language's SDK.
OS protection cannot prevent changes by someone who controls the user's account.

On Linux, explicitly open `SecretServiceStorage::open(directory, &config, &device)` and
pass it in an `Arc` to `Client::with_storage`. It requires an existing operational
Secret Service keyring and `/usr/bin/secret-tool`; the SDK does not install or unlock
them. Use an existing absolute directory owned by the current user with no group/other
permissions. Keep its fixed `orbit-storage.lock` private and in place until Drop. The
adapter rejects links, replaced leases, and ownership or permission changes. Different
directories select distinct scope-bound keyring items. Records are limited to 4096
decoded bytes; each helper command has a five-second deadline and bounded private
output. Ordinary version/load checks use cached state under the lease and do not run a
helper. Invalidation persists a tombstone. Each write first durably marks the lease
pending; successful helper completion clears the marker. Failed writes poison the
object, and interrupted or uncertain writes block reopening even if the keyring later
completes the write. Recover in a new private directory with deliberate online
activation. Missing, corrupt or pending existing state is never reset automatically. No
plaintext credential file, password, customer session, raw licence key or signed grant
is persisted.

Unsupported platforms return a storage error. Check keyring encryption and unlock
settings before relying on it to protect saved credentials.

## Device identity and sleep

Hardware-locked policies require a 64-character lowercase hexadecimal fingerprint and
provider (`machine_v1` or `custom:<name>`). The host supplies these fields; use
`native_fingerprint` for the supported OS identity. Linux uses `CLOCK_BOOTTIME` and
Windows uses biased interrupt time, so sleep counts toward grant expiry. Unsupported
OSes return a clock error instead of allowing access.

## Local development

The explicit `local-development` feature enables `Transport::local_loopback` for HTTP on
a literal loopback IP. Default builds require HTTPS. Redirects are disabled, and TLS
certificate verification cannot be disabled.

For an explicitly HWID-bound app, `native_fingerprint(application_id, environment_id)`
returns the scoped `machine_v1` digest. Set both `Device` fingerprint fields and use
provider `machine_v1`. Linux reads a bounded machine ID; Windows reads the SMBIOS system
UUID through the isolated native adapter. An unavailable identity fails closed. Do not
request a fingerprint when HWID is off. `machine_fingerprint` exposes the same
normalization and framing for explicit adapter integration and tests; never send raw
machine IDs to Orbit.

## Support diagnostics

`Error::Denied` and authoritative HTTP `Error::Transient` failures retain a validated
code and optional request reference. Use `error.request_id()` to correlate requests;
local outages have no reference. Error display and debug text use fixed guidance, never
server messages or unchecked caller fields.

```rust
let summary = client.support_summary(&error);
println!("Support summary: {summary}"); // JSON; also implements serde::Serialize.
```

The serializable summary contains only `application_id`, `environment_id`, `code`,
`request_id` and `timestamp`. The timestamp is local Unix seconds, nullable when
unavailable, and is not an access clock. Request IDs allow 1–64 ASCII letters, digits,
underscores and hyphens; malformed HTTP references reject the response. The summary
validates caller-created errors and reads no account, device, access or storage state;
it makes no network request. Keep the error from the failed operation; there is no
shared last-error state. A summary is diagnostic metadata, not proof of identity or
licensed access. The console prints fixed guidance and this copyable summary for SDK
failures.
