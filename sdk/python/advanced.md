# Advanced Python integration

Start with [the quickstart](README.md) for normal installed applications.

## Operations

`Client` has named synchronous methods for `snapshot`, `activate`,
`activate_previous`, `refresh`, `require_access`, `ensure_access`, `deactivate`,
`logout`, `register`, `resend_registration`, `login`, `account`,
`owned_licences`, `claim_licence`, `activate_account`,
`activate_account_previous`, `logout_account`, `request_email_change`,
`request_password_recovery`, `customer_session_authorization`, `offline_request`,
and `import_offline_file`. Network methods accept an optional
`cancellation=Cancellation.create()` keyword argument. Calls may run
concurrently; activation, refresh, login, and session-authenticated account
operations serialize when they change or depend on client state. Closing a
client waits for active calls to return.

`register()` returns a frozen `RegistrationResult(accepted, expires_at, pending)`;
`expires_at` is a timezone-aware `datetime`. Its opaque `pending` handle keeps
resend proof in memory; use it only with `resend_registration()` and close it
when finished. `login()` and `account()` return a frozen `Account`.
`owned_licences()` returns an `OwnedLicencePage` whose items are frozen
`OwnedLicence` values. Timestamps use UTC-aware `datetime`, durations use
`timedelta`, and entitlement maps cannot be mutated. Listing or claiming a
licence does not grant access: activate the chosen licence and call
`require_access()`. `logout_account()` requests remote revocation and clears
local account state; `logout()` clears activation and customer session state
without a network request. `claim_licence(key)` generates a secure operation
ID when omitted; pass an explicit ID to reuse it across retries.

Installed key and account activations save their operation ID before sending.
After a lost account-activation response, sign in again as the same customer
and retry the same licence. The SDK recovers the original operation, including
after restart or a failed login. The pending digest is bound to the verified
customer ID; another customer cannot reuse it. Passwords and session tokens
remain in memory. Explicit logout discards local recovery state.

Use `with` or call `close()` on clients, cancellation handles and pending
registration handles. Finalizers are only a fallback for forgotten closes.

## Persistence and hosting

On Linux, `open()` stores a private record under
`$XDG_STATE_HOME/orbit/<scope-hash>/` (or `~/.local/state/orbit/<scope-hash>/`).
On macOS, it uses private files under
`~/Library/Application Support/Orbit/<scope-hash>/`; this is not Keychain storage.
On Windows, it uses the current user's `LOCALAPPDATA/Orbit/<scope-hash>/` with
DPAPI and an explicit private ACL. New directories and files grant access only
to the current user, SYSTEM and Administrators; an existing directory with
foreign ownership or broader access is rejected without changing its ACL.
Impersonating threads are unsupported; use a client under the service account.
Set `state_path` to an absolute, dedicated private directory for a
service or container, and mount that directory on persistent storage across
restarts. Keep it owned by the service user and mode `0700` on Linux/macOS. A lease
allows only one process to own an installation at a time; give concurrent
workers separate installation state. `installation_in_use` means another client
holds the lease; reuse that client or close it before opening the same directory.
Do not delete lock files to bypass an active lease.

The record can cache the original signed access grant and its verified public
key. A restart rechecks those signatures, scope, expiry, and trusted-clock
evidence; offline access ends at the grant's original deadline. It never turns
the grant into a new or longer-lived one. Linux/macOS file permissions protect the
record from other users, while Windows DPAPI protects its contents for the
current user. Neither protects against someone who can control that user or
modify the running process. Credentials and grants are not tamper-proof. Raw
licence keys, passwords, customer sessions and registration resend proofs are
not persisted.

## Advanced connection, storage and device identity

`Client.open_with_storage(app_key, installation_id=...)` is available when the
host manages the installation ID and storage policy itself. Keep its stable
installation ID between runs; `installation_id_new()` creates one. Its default
`StorageMode.MEMORY` forgets activation credentials at process exit.

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

`Client.open()` binds an installation to the supported native machine identity
using provider `machine_v1` when it is available. If identity cannot be read,
the client sends no fingerprint. Use `machine_binding=False` for cloned
containers or virtual machine images with shared IDs. To supply a stable host
identity, construct `DeviceBinding(fingerprint, provider)`; the fingerprint
must be a 64-character lowercase hex value and the provider must be
`machine_v1` or `custom:<name>`. `machine_fingerprint(...)` can hash a
host-provided Linux, Windows or macOS identity. Never send the raw machine identifier
to Orbit. If the current identity differs from the one saved with the
installation, the SDK discards its saved credential and signed grant and
creates a fresh installation ID. The new machine must activate within the
licence's device limit before it can restore access.

## Offline licence files

The candidate implements local request export, verification and durable import.
Server issuance and the dashboard workflow are still pending; this is not yet a
complete customer workflow. The wire format and issuance rules are defined in
the [offline-file contract](../../contracts/sdk/offline.md).

Supply an offline-purpose JWKS from your application's trusted bundle through
`offline_keys`. Never take verification keys from the licence file or an
untrusted upload. On the disconnected machine, export its public request:

```python
import os
from pathlib import Path

from orbit_sdk import Client

trusted_keys = Path("orbit-offline-keys.json").read_bytes()
with Client.open(os.environ["ORBIT_APP_KEY"], offline_keys=trusted_keys) as orbit:
    Path("installation-request.json").write_text(
        orbit.offline_request().to_json(), encoding="utf-8"
    )
```

The request contains public configuration and the installation identity; it is
not proof of ownership or authority. Transfer it to the seller's authenticated
issuance workflow. When you receive the signed file, import it on that same
installation:

```python
import os
from pathlib import Path

from orbit_sdk import Client

trusted_keys = Path("orbit-offline-keys.json").read_bytes()
with Client.open(os.environ["ORBIT_APP_KEY"], offline_keys=trusted_keys) as orbit:
    orbit.import_offline_file(Path("licence.orbit").read_bytes())
    orbit.require_access("export")
    # Perform the protected export here.
```

Subsequent starts only need `open(..., offline_keys=...)` and `require_access()`;
the signed file is saved in private installation storage. Valid offline access
makes no HTTP requests, including background validation. The normal snapshot
reports `AccessStatus.OFFLINE` and its absolute expiry. Missing features and
expired files fail without prompting for an online key. Renew by importing a
newer file; re-importing a still-valid file does not extend its term.

Explicit online activation changes back to connected access. Logout removes local
access. Both preserve renewal and clock high-water values, so an older file cannot
undo a newer renewal. A failed online activation does not restore the previous
offline authority. Storage failures deny access; uncertain clocks must be corrected
before access can resume. Each restart verifies against your configured trusted
keys, so distribute new keys through a trusted application/configuration update
before using files signed by them.

An offline machine cannot learn about a later server-side revocation until it
reconnects or imports updated authority. Someone controlling the whole machine
can restore old files and clocks or patch the program. Private storage, renewal
sequences and fixed signed expiry do not promise protection against a complete
machine snapshot rollback. Native Windows/macOS offline runtime checks remain
pending; Linux behavior and shared signed vectors are covered by the suite.

## Seller download-ticket verification

`DownloadTicketVerifier` is the first part of the seller-hosted download feature.
Release discovery, server ticket issuance and the installed streaming helper are
still pending. The verifier performs no network requests and needs only public
Orbit keys. Configure the endpoint and app key on your backend; do not derive
them from an incoming token or an untrusted `Host` header.

```python
from orbit_sdk import DownloadTicketVerifier


def authorize_artifact(app_key, endpoint, public_jwks, bearer_token, artifacts):
    verifier = DownloadTicketVerifier(app_key, endpoint, public_jwks)
    ticket = verifier.verify(bearer_token)
    artifact = artifacts.get(ticket.artifact_id)
    if artifact is None or (
        artifact["release_id"] != ticket.release_id
        or artifact["sha256"] != ticket.sha256
        or artifact["byte_length"] != ticket.byte_length
    ):
        raise PermissionError("Unknown or changed artifact")
    return artifact
```

Here `artifacts` is your own trusted registry. Match the verified metadata before
selecting a file or creating an expiring URL from your storage provider. Never
turn a ticket's artifact ID directly into a filesystem path. In a running server,
construct and reuse a verifier with your configured keys; replace it when your
trusted key set rotates. It validates the exact endpoint audience, Test/Live scope,
purpose, signature and deadline. Invalid tickets raise `OrbitError` with code
`invalid_download_ticket`. Returned times are aware UTC `datetime` values.

Read the token from the request's `Authorization: Bearer` header and never log
it. Your backend should serve the file or return a short-lived storage URL; the
client must not forward the Orbit bearer to that storage redirect. A ticket is
replayable until its deadline, at most 120 seconds. A permanent public URL remains
shareable and cannot provide subsequent licence enforcement.

The [runnable seller backend](../../examples/python/seller-downloads/README.md)
shows the protected endpoint with private S3-compatible storage and local tests.

## macOS platform checks

The candidate's macOS bindings read `IOPlatformUUID` through IOKit and use
`mach_continuous_time`, including sleep, for elapsed-time checks. Timebase
resolution is cached; time is sampled for every decision. The SDK synchronizes
regular state and lease files with `F_FULLFSYNC` and synchronizes the containing
directory after replacement. A filesystem that rejects the required durability
operation returns a storage error. Other platforms retain their existing paths.

The platform contract and OS references are in
[installed platforms](../../contracts/sdk/platforms.md). Linux checks exercise
the injected framework boundary, overflow, invalid identity and object cleanup,
plus POSIX restart, exclusive leases and replacement rejection. These simulations
are not native macOS validation. Neither macOS x64 nor arm64 has been exercised
on native hardware in this work; both still need native TLS, restart, sleep across
expiry and filesystem-failure checks before a release claims full support.

From the repository root on a Mac with the SDK installed, run:

```sh
python -m unittest discover -s sdk/python/tests -p 'test_macos.py' -v
```

The native test requires a readable platform UUID and a local private filesystem.
It checks framework access, continuous time and durable state reopen. The broader
suite remains `python -m unittest discover -s sdk/python/tests`; platform-specific
skips are reported separately.

## Access-check performance

Reuse one open client per installation. A warm `require_access()` checks the
current clock, storage generation and feature in local verified state. It
contacts Orbit when a refresh is due. Avoid opening a new client for every
protected operation.

From a source checkout, measure the local path with signed synthetic fixtures
and private installation storage:

```sh
python3 sdk/python/benchmarks/access.py
```

On Linux x86-64 with Python 3.14.7, five batches of 5,000 checks measured a
median **23.9 µs** per warm `require_access()`, down from **37.5 µs** before
removing duplicate storage and clock checks. `snapshot()` measured 23.0 µs,
down from 24.3 µs. These timings exclude activation and network refresh and
vary with the machine and filesystem; they are not latency guarantees.
Each call still checks storage validity and trusted elapsed time.
On Windows, the native timer function is resolved once per process, while
every check reads a fresh timer value. The lookup path has mocked regression
coverage; native Windows timing has not been measured in this Linux run.

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
