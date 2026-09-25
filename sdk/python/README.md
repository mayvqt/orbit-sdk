# Orbit Python SDK

Install the v0.2.0 wheel from the source release:

```sh
python -m pip install https://github.com/mayvqt/orbit-sdk/releases/download/v0.2.0/orbit_sdk-0.2.0-py3-none-any.whl
```

The package requires Python 3.12 or newer. `orbit_sdk` is implemented in
Python and uses the maintained `cryptography` package for ES256 verification.
It does not require Rust, a compiler, or an Orbit native library. To install
from a source checkout instead, run `python -m pip install ./sdk/python` from
the repository root. A checkout can also be used directly with
`PYTHONPATH=sdk/python`.

## Connect and check access

Use the public values on the Orbit dashboard's **Integration** page. Save an
installation ID in your host application's settings and reuse it after
restarts; it is not secret. `installation_id_new()` creates one. Memory
storage is the default and forgets activation credentials when the process
ends.

```python
from orbit_sdk import Client, Config

config = Config(
    api_origin="https://orbit.example",
    application_id="app_id_from_integration",
    environment_id="environment_id_from_integration",
    issuer="https://issuer.example",
    installation_id="persisted_installation_id",
)

with Client.connect(config) as orbit:
    snapshot = orbit.activate(user_entered_key, stable_operation_id)
    snapshot = orbit.require_access("export")
```

Call `require_access()` before protected work. `snapshot()` reports local state
without checking access. When retrying an uncertain result, keep the
activation's operation ID and input unchanged for up to 24 hours. Resolve the
previous result before retrying a mutation with a new ID.
`activate_previous()` and `activate_account_previous()` support deliberate
same-fingerprint rebinding with the original activation credential.

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

## Storage and device identity

Choose a storage mode when the host should remember an activation:

* `StorageMode.MEMORY` keeps credentials in process memory.
* `StorageMode.WINDOWS_DPAPI` uses current-user DPAPI on Windows.
* `StorageMode.LINUX_SECRET_SERVICE` uses the current user's Secret Service on
  Linux and requires an operational keyring and `/usr/bin/secret-tool`.

Protected modes require an existing, dedicated private absolute directory in
`storage_path`. Use one directory per issuer, application, environment and
installation. The adapters preserve the existing Rust SDK's storage codec,
scope, keyring item identity, lease and tombstone files, so credentials remain
available when upgrading from the earlier Python binding. They validate file
ownership, permissions, identity and protected-platform requirements. Do not
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

## Migration from v0.1.x

The import remains `from orbit_sdk import ...`. Install the wheel above and
remove the old Rust FFI build step and `library_path` arguments from
`Client.connect()`, `Cancellation.create()`, and the fingerprint helpers. The
package now contains its own transport, grant verification, device, clock and
client logic. Keep the existing protected storage directory and installation
ID so the new implementation can load the credential already stored there.
