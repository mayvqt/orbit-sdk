# Advanced Python integration

Start with [the quickstart](README.md) for normal installed applications.

## Operations

`Client` has named synchronous methods for `snapshot`, `activate`,
`activate_previous`, `refresh`, `require_access`, `deactivate`, `local_logout`,
`register`, `resend_registration`, `login`, `account`, `owned_licences`,
`claim_licence`, `activate_account`, `activate_account_previous`,
`account_logout`, `request_email_change`, `request_password_recovery`, and
`customer_session_authorization`. Network methods accept an optional
`cancellation=Cancellation.create()` keyword argument. Calls may run
concurrently; activation, refresh, login, and session-authenticated account
operations serialize when they change or depend on client state. Closing a
client waits for active calls to return.

`register()` returns `RegistrationResult(accepted, expires_at, pending)`. Its
opaque `pending` handle keeps resend proof in memory; use it only with
`resend_registration()` and close it when finished. `login()` and `account()`
return safe customer metadata. Listing or claiming a licence does not grant
access: activate the chosen licence and call `require_access()`.
`account_logout()` requests remote revocation and clears local account state;
`local_logout()` clears activation and customer session state without a
network request.

Use `with` or call `close()` on clients, cancellation handles and pending
registration handles. Finalizers are only a fallback for forgotten closes.

## Persistence and hosting

On Linux, `open()` stores a private record under
`$XDG_STATE_HOME/orbit/<scope-hash>/` (or `~/.local/state/orbit/<scope-hash>/`).
On Windows, it uses the current user's `LOCALAPPDATA/Orbit/<scope-hash>/` with
DPAPI and an explicit private ACL. New directories and files grant access only
to the current user, SYSTEM and Administrators; an existing directory with
foreign ownership or broader access is rejected without changing its ACL.
Impersonating threads are unsupported; use a client under the service account.
Set `state_path` to an absolute, dedicated private directory for a
service or container, and mount that directory on persistent storage across
restarts. Keep it owned by the service user and mode `0700` on Linux. A lease
allows only one process to own an installation at a time; give concurrent
workers separate installation state. `installation_in_use` means another client
holds the lease; reuse that client or close it before opening the same directory.
Do not delete lock files to bypass an active lease.

The record can cache the original signed access grant and its verified public
key. A restart rechecks those signatures, scope, expiry, and trusted-clock
evidence; offline access ends at the grant's original deadline. It never turns
the grant into a new or longer-lived one. Linux file permissions protect the
record from other users, while Windows DPAPI protects its contents for the
current user. Neither protects against someone who can control that user or
modify the running process. Credentials and grants are not tamper-proof. Raw
licence keys, passwords, customer sessions and registration resend proofs are
not persisted.

## Advanced connection, storage and device identity

`Client.connect(Config(...))` is available when the host manages the
installation ID and storage policy itself. Keep its stable installation ID
between runs; `installation_id_new()` creates one. Its default `StorageMode.MEMORY`
forgets activation credentials at process exit.

Choose a storage mode when the host should remember an activation:

* `StorageMode.MEMORY` keeps credentials in process memory.
* `StorageMode.WINDOWS_DPAPI` uses current-user DPAPI on Windows.
* `StorageMode.LINUX_SECRET_SERVICE` uses the current user's Secret Service on
  Linux and requires an operational keyring and `/usr/bin/secret-tool`.

Protected modes require an existing, dedicated private absolute directory in
`storage_path`. Use one directory per issuer, application, environment and
installation. The adapters validate file ownership, permissions, identity and platform
requirements. Do not
exchange, copy or share these storage files between SDKs. OS protection cannot
prevent changes by someone controlling the user's account. These adapters do
not persist customer sessions, passwords, raw licence keys, signed grants or
resend proofs.

For an HWID-bound application, set a 64-character lowercase hex `fingerprint`
and `fingerprint_provider` (`machine_v1` or `custom:<name>`) in `Config`.
`native_fingerprint(application_id, environment_id)` derives the supported
machine identity; `machine_fingerprint(...)` normalizes an identity supplied by
the host. Do not send raw machine IDs to Orbit, and do not request a fingerprint
when HWID is disabled.

## Errors and sensitive output

`OrbitError` exposes only `kind`, `code`, `request_id` and `status`. Its text
omits server messages and caller inputs. Keep the error from the failed
operation when correlating support requests.

`customer_session_authorization()` returns a redacted
`SensitiveAuthorization`. Reveal its bytes only to send the header to your own
trusted HTTPS backend for online verification. Never log or persist it or send
it to another origin. Use it as a context manager or call `clear()` after use.
`reveal()` creates a caller-owned bytes copy that Python cannot reliably erase;
keep that copy briefly. Local account metadata and offline activation grants do
not prove customer identity.
