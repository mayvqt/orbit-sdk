# Advanced Python integration

Start with [the quickstart](README.md) for normal installed applications.

## Concurrency and cancellation

`Client` methods are synchronous and thread-safe. Calls may run concurrently;
activation, refresh, sign-in and session-authenticated account operations
serialize when they change or depend on client state. Every network method
accepts an optional `cancellation=` keyword:

```python
from orbit_sdk import Cancellation

with Cancellation.create() as cancellation:
    # Call cancellation.cancel() from another thread to stop the operation.
    orbit.refresh(cancellation=cancellation)
```

`close()` stops background refresh, makes a bounded attempt to release a
floating seat and waits for active calls to return. Use `with` or call `close()`
on clients, cancellation handles and pending registration handles; finalizers
are only a fallback.

## Activation retries and explicit IDs

Installed key and account activations save a secure operation ID and an input
digest before sending, never the raw key. After a lost reply, retry the same
input within 24 hours and the SDK reuses the saved ID, including after a
restart. For account activation, sign in again as the same customer first;
another customer cannot reuse the pending operation. Explicit `logout()`
discards it.

Mutating methods accept an optional operation ID of 16–128 characters:
`activate(key, idempotency_key)`, `activate_account(licence_id,
idempotency_key)`, `claim_licence(key, idempotency_key)` and
`deactivate(idempotency_key)`. `activate_previous()` and
`activate_account_previous()` rebind a freshly authenticated installation using
its previous credential. `deactivate()` clears local access and releases the
device slot on the server.

## Customer accounts

`register(licence_key, username, email, password)` returns a frozen
`RegistrationResult(accepted, expires_at, pending)`. The opaque `pending`
handle keeps the resend proof in memory; pass it to `resend_registration()` and
close it when finished. Confirmation does not sign the customer in. When the
application allows customer sign-up, pass `None` as the licence key; any
sign-up licence the application grants appears in `owned_licences()` after
sign-in.
`request_password_recovery(email)` and `request_email_change(password,
new_email)` return once Orbit accepts the request.

`login()` and `account()` return a frozen `Account`. `owned_licences(cursor)`
returns one `OwnedLicencePage`; pass its `next_cursor` to fetch the next page.
`OwnedLicence` values use UTC-aware `datetime`, `timedelta` durations and
immutable maps. `offline_duration` is the connected grant's allowance;
`offline_file_duration` is the long-term file limit, zero when disabled.
`concurrent_session_limit` is separate from `device_limit`. `usage_limits` and
`resource_limits` describe policy, not remaining capacity.

`customer_session_authorization()` returns a redacted `SensitiveAuthorization`
for your own trusted HTTPS backend, which must verify it online. Use it as a
context manager or call `clear()` after use. `reveal()` returns a bytes copy
that Python cannot reliably erase; keep it briefly and never log, persist or
send it to another origin.

## Storage and clock guarantees

`Client.open()` stores a private record under:

* Linux: `$XDG_STATE_HOME/orbit/<scope-hash>/` (or
  `~/.local/state/orbit/<scope-hash>/`).
* macOS: `~/Library/Application Support/Orbit/<scope-hash>/`.
* Windows: `%LOCALAPPDATA%\Orbit\<scope-hash>\`, encrypted with current-user
  DPAPI.

New directories and files grant access only to the current user (on Windows,
also SYSTEM and Administrators). An existing directory with foreign ownership
or broader access is rejected without changing it. A `state_path` must be an
absolute, dedicated directory owned by the service user, mode `0700` on Linux
and macOS, on persistent storage. Windows impersonating threads are unsupported;
run the client under the service account.

A lease allows one process per installation. `installation_in_use` means
another client holds it: reuse that client or close it first, and never delete
lock files to bypass it. Give concurrent workers separate installations.
Corrupt or missing established state is reported as a storage error, never
silently replaced.

The record caches the signed access grant and its public key. A restart
rechecks the signature, scope, expiry and saved clock evidence; access never
extends past the grant's original deadline. Sleep counts toward expiry, and a
clock rollback requires online validation. File permissions and DPAPI protect
the record from other users, not from someone controlling the same account or
modifying the process. Keys, passwords, customer sessions and resend proofs are
never persisted.

On macOS the SDK reads `IOPlatformUUID` through IOKit, measures elapsed time
with `mach_continuous_time`, synchronizes state files with `F_FULLFSYNC` and
fails with a storage error on a filesystem that rejects it. This is private
file storage, not Keychain encryption.

## Machine binding

`Client.open()` binds to the native `machine_v1` identity when it is available
and sends no fingerprint when it is not; it never substitutes a random value.
Pass `machine_binding=False` for cloned containers or VM images. To supply your
own stable identity, pass `device_binding=DeviceBinding(fingerprint, provider)`
with a 64-character lowercase hex fingerprint and a `machine_v1` or
`custom:<name>` provider. `machine_fingerprint(application_id, environment_id,
family, identity)` hashes a host-provided Linux, Windows or macOS identity;
never send the raw identifier.

When the current identity differs from the saved one, the SDK discards the saved
credential and grant and creates a fresh installation ID. The machine must then
activate within the licence's device limit.

## Host-managed storage

`Client.open_with_storage(app_key, installation_id=..., storage_mode=...,
storage_path=...)` suits hosts that manage the installation ID and credential
storage themselves. Keep the installation ID stable between runs;
`installation_id_new()` creates one. It has no background refresh and never
saves a grant.

* `StorageMode.MEMORY` (default) forgets the credential at process exit.
* `StorageMode.WINDOWS_DPAPI` uses current-user DPAPI on Windows.
* `StorageMode.LINUX_SECRET_SERVICE` uses the user's Secret Service and
  requires an operational keyring and `/usr/bin/secret-tool`.

Protected modes need an existing, private, absolute `storage_path` dedicated to
one application, environment and installation. Do not share these files between
SDKs.

## Offline licence files

The seller enables an offline-file duration on the policy, opens the licence's
offline-file action, pastes the installation request and downloads the signed
`.orbit` file. Import it on the same installation.

Explicit online activation switches back to connected access, and `logout()`
removes local access. Both keep the renewal sequence and clock floors, so an
older file cannot undo a newer renewal. A failed online activation does not
restore the previous file. Storage failures deny access, and an uncertain clock
must be corrected before access resumes. Each restart verifies the saved file
against the configured trusted keys, so ship new keys in a trusted application
update before issuing files signed by them.

## Floating sessions

The SDK saves the activation credential before requesting a seat. Session grants
and IDs stay in process memory. `start_session()` returns the current snapshot
when the seat is still valid. During an outage a running client can finish its
current signed interval but cannot extend it, and there is no offline fallback
after it expires. A crash or failed release leaves the old seat occupied until
its interval ends.

## Downloads

`check_for_update()` returns a frozen `Update` with `Release` and `Artifact`;
`UpdateTarget` is required when the runtime platform is not recognized. The
standalone `download_file(authorization, destination, max_bytes=...,
replace=False, cancellation=...)` works without a client; an installed client's
`download()` also stops when the client closes. Transfers have a five-minute
deadline, use no ambient cookies, HTTP credentials or proxy settings, and stage
the file privately beside the destination. Request a fresh authorization for a
later attempt.

## Seller download tickets

Construct one `DownloadTicketVerifier` from trusted configuration and reuse it;
replace it when your keys rotate. It checks the exact endpoint audience,
Test/Live scope, purpose, signature and deadline, and returns aware UTC
`datetime` values. Invalid tickets raise `OrbitError` with code
`invalid_download_ticket`. Read the token from the `Authorization: Bearer`
header and never derive the endpoint or app key from the request or its `Host`
header. Serve the file or return a short-lived storage URL; never forward the
Orbit bearer to that redirect.

## Errors

`OrbitError` exposes `kind`, `code` and `request_id`; its text omits server
messages and caller input. `NotActivatedError` and `FeatureUnavailableError`
subclass it. `LimitReachedError` adds the validated `counter` and
`requested_units`, and it and `MutationUncertainError` carry the
`idempotency_key` needed to recover a write. Keep the error from the failed
operation when correlating support requests.

A denial that only withholds access, such as a suspended or expired licence,
keeps the saved activation, so access resumes at the next validation after the
licence is restored. A revoked licence, invalid credential or device mismatch
clears it, and the device must activate again.

## Access-check performance

Reuse one open client per installation. A warm `require_access()` checks the
clock, storage generation and feature in local verified state and contacts
Orbit only when a refresh is due. On Linux x86-64 it takes about 25 µs, with no
network request or storage write.
