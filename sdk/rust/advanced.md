# Advanced Rust APIs

Start with the [installed client](README.md). Use these APIs when your host owns
installation identity, storage, account UI or mutation reconciliation.

## Explicit identity and storage

`Client::connect(Setup)` constructs a strict HTTPS, memory-only client using a supplied
installation ID. `Client::new(Config, Device, Transport)` accepts explicit transport;
`Client::with_storage` also accepts `Arc<dyn Storage>`. These clients have no owned
refresh worker. Keep the installation ID stable and call `require_access` before each
protected operation; refresh when the displayed next check becomes due.

`StoredCredential::credential_expires_at` is `Option<i64>`: `None` means a revocable
persistent credential. It does not change the original signed access expiry. Validation
must retain the exact credential and expiry. Ordinary activation through explicit
clients requests the finite protocol; installed clients request persistent credentials.

A custom `Storage` must atomically version every save and invalidation, protect bearer
material and isolate each scope. `version()` must provide a cheap invalidation check.
`MemoryStorage` is suitable for ephemeral contexts. Explicit Windows DPAPI and Linux
Secret Service adapters remain available through `WindowsStorage::open` and
`SecretServiceStorage::open`; both take an existing private absolute directory,
`&Config` and `&Device`. Secret Service requires an operational keyring and
`/usr/bin/secret-tool`. Provider failures do not select a fallback. These explicit
adapters retain credentials; cached restart access belongs to the installed client.

## Storage and clock guarantees

Windows uses current-user DPAPI and a private protected DACL. Linux uses an owner-only
credential file (0700 directories, 0600 files), including headless installations. The
selected provider never falls back to a different store. Corrupt or missing established
state requires deliberate recovery; it never silently allocates a new installation.
An interrupted state write leaves a durable recovery marker, so restart cannot restore
a credential or grant from before an incomplete invalidation. Windows services must
open and use storage under their process account, without thread impersonation.

Sleep counts toward expiry. A clock rollback or inconsistent saved evidence requires
online validation. Local files cannot reliably detect restored VM/disk snapshots or
clock rollback above the last saved high-water value. Enforcement is not tamper-proof
against someone controlling the local account or machine.

## Mutation identity and rebinding

`activate(key, operation_id, cancel)` retains caller control over operation IDs.
`activate_with_previous(key, previous_credential, operation_id, cancel)` can rebind a
fingerprint to a fresh installation using an externally supplied original credential.
The old credential need not exist in the fresh client's storage. Server ownership and
transfer limits still apply.

Installed clients persist pending identities before sending. Retry exactly the same
input and operation ID within 24 hours; an older uncertain operation requires deliberate
resolution. Malformed replies, signature failures, TLS failures, cancellation and
uncertain clocks keep its identity. Verified durable acceptance or definitive denial
clears it. While an activation is unresolved, startup, background and explicit refresh
do not validate the previous bearer; retry the matching activation to recover its result.
`resolve_pending_activation()` is an explicit escape hatch after the host
has reconciled the server outcome. Never generate a new identity merely because a
response was lost.

`deactivate(operation_id, cancel)` clears local activation access and asks Orbit to
release its device slot. A failed response needs reconciliation. It retains the current
customer login. `logout()` clears local access and the in-memory account without
releasing a slot. `logout_account(cancel)` additionally revokes the server session and
its derived credentials; await success to confirm server revocation. Closing a client
preserves its installation instead of logging out.

## Customer accounts

Registration claims an eligible key for a customer account:

```rust,ignore
let pending = orbit.register(orbit_sdk::Registration {
    licence_key: &key, username: &username, email: &email, password: &password,
}, &cancel).await?;
orbit.resend_registration(&pending, &cancel).await?;
// After browser email confirmation:
orbit.login(&username, &password, &cancel).await?;
let page = orbit.owned_licences(None, &cancel).await?;
```

Passwords require at least eight characters; preserve whitespace. Confirmation does
not sign the customer in. `PendingRegistration` contains a private memory-only resend
proof. Pass `page.next_cursor.as_deref()` to fetch the next bounded licence page.
Select a licence with `activate_account(licence_id, operation_id, cancel)`.
`activate_account_with_previous` provides the same explicit rebind flow for account
licences. `claim_licence(key, operation_id, cancel)` claims another licence without
activating it. Retain mutation input and explicit operation IDs for uncertain retries.
A claimed key cannot bypass its account authentication.

`request_password_recovery(email, cancel)` returns generic acceptance.
`request_email_change(password, new_email, cancel)` starts confirmation through both
mailboxes; log in again after completing the browser flow. Registration, resend, login,
recovery and email-change requests are sent once. Generic acceptance does not disclose
whether an account exists. A new login clears the previous local access context.

`account()` returns informational local account metadata. Dates on account/licence
objects are RFC3339 strings; `Snapshot` dates are integer Unix seconds. For your own
trusted HTTPS backend, `customer_session_proof()?.authorization_header()` exposes the
sensitive session Bearer header. Never log or save it. The backend must verify it online
and enforce licensed access separately, as shown in the
[backend example](../../examples/rust/licensed-backend/README.md).

## Device binding and local development

For an HWID policy, `native_fingerprint(application_id, environment_id)` returns the
scoped `machine_v1` fingerprint on supported Windows/Linux systems. Supply it and
`fingerprint_provider: Some("machine_v1".into())` in `AppConfig` or `Device`.
Custom providers use `custom:<name>` and a 64-character lowercase hexadecimal digest.
Do not request a fingerprint when HWID is off; raw machine identifiers never go to Orbit.

The explicit `local-development` feature enables `Client::open_local` and
`Transport::local_loopback` for HTTP on a literal loopback IP. Default builds require
HTTPS. Redirects remain disabled and certificate checks cannot be disabled.

## Support information

`error.request_id()` returns a validated server request reference when available.
`client.support_summary(&error)` produces safe JSON containing the scope, error code,
request reference and local timestamp. It contains no key, credential, session, device
identity or private server message. It does not grant access or prove customer identity.

A backward clock correction can force online recovery; a forward correction can consume
an offline allowance. Linux uses `CLOCK_BOOTTIME`, and Windows uses biased interrupt
time, so suspend counts toward original expiry. Unsupported native clocks fail closed.
