# Orbit Go SDK

The SDK adds licence activation, customer sign-in and feature checks to Go apps. It
connects to Orbit over HTTPS and supports Windows 11 x64 and Ubuntu 24.04 x64. Source is
under the [MIT licence](../LICENSE).

## Add the SDK

Use Go 1.27.1 or newer. Add the versioned source module with:

```sh
go get github.com/mayvqt/orbit-sdk/sdk/go@v0.1.0
```

The module path is `github.com/mayvqt/orbit-sdk/sdk/go`; its repository release
tag is `sdk/go/v0.1.0`. Import it with
`import orbit "github.com/mayvqt/orbit-sdk/sdk/go"`.

For a first run, follow the [console example](../../examples/go/licensed-export/README.md),
then open **Integration** in the dashboard and copy the Go startup
snippet for your application and environment.

## Activate and check access

```go
client, err := orbit.Connect(orbit.Setup{
    APIOrigin: "https://orbit.mayvie.dev",
    ApplicationID: applicationID,
    EnvironmentID: environmentID,
    Issuer: grantIssuer,
    InstallationID: stableInstallationID,
})
if err != nil { return err }
if _, err := client.Activate(ctx, userEnteredKey, operationID); err != nil { return err }
if _, err := client.RequireAccess(ctx, "export"); err != nil { return err }
// Perform the protected operation here.
```

Call `RequireAccess` before each protected operation. Do not authorize from an
`Account`, licence listing or `Snapshot`, or cache a startup result. Context
cancellation stops retries and body reads. `Error.Kind` and validated `Error.Code`
provide typed, redacted failures; use `errors.Is` with exported sentinel errors. Errors
never contain server messages, URLs, request bodies or secrets.

`Setup` takes public application/environment IDs and the deployment's exact configured
issuer. `Connect` requires HTTPS and keeps credentials in memory. Use
`NewClientWithStorage` for advanced storage or `NewLocalTransport` for explicit loopback
testing. `NewInstallation` creates a random public installation ID; persist and reuse it
across launches. The SDK retains no key or password.

Use a fresh operation ID for each deliberate activation, replacement, claim or
deactivation. For uncertain mutation delivery, preserve the operation ID and input and
retry within the 24-hour replay window. Credential delivery can be replayed for 15
minutes. `ErrReauthenticationRequired` needs deliberate fresh principal authentication;
do not retry with a new mutation ID to recover a missing secret. `ActivateWithPrevious`
and `ActivateAccountWithPrevious` accept the original activation credential for an
authorized same-fingerprint rebind.

## Customer accounts

Customer apps can call `Register`, optionally `ResendRegistration`, complete the email
link, then call `Login`, `OwnedLicences` and `ActivateAccount` with the selected licence
ID. `ClaimLicence` adds an eligible key without activating it. Pass an empty `after`
cursor for the first page and the returned `NextCursor` for the next page. Login clears
the previous access context. Customer sessions remain in memory and never enter
`Storage`.

`CustomerSessionProof()` returns a redacted proof object. Its `AuthorizationHeader()`
exposes the sensitive Bearer header for your own trusted HTTPS backend. Do not log or
persist it or forward it through redirects. The backend must verify it online through
`GET /api/client/v1/sessions/current`, using fixed app/environment configuration, then
separately check licensed access. Account metadata and offline grants are not identity
credentials. The Rust kit has an interoperable [backend
example](../../examples/rust/licensed-backend/README.md).

Customer sessions last 12 hours; ordinary expiry leaves the separate activation
credential valid for its fixed maximum 30-day lifetime. Explicit revocation, recovery or
policy denial clears access. Snapshot timestamps are Unix seconds; account and licence
display timestamps are RFC3339 strings.

## Refresh and sign out

Schedule refresh using `Snapshot.NextCheckAt`. `RequireAccess` also refreshes on demand
and allows offline access only after a recognized outage, with a verified, unexpired
grant that explicitly permits it. TLS failures, malformed data, invalid grants, unknown
keys after one trusted JWKS refresh, and authoritative denial fail closed. `Snapshot`
reports expiry, access state, remaining offline seconds, reauthentication and storage
capability. The SDK creates no background goroutine; the host owns scheduling and
cancellation.

`Logout` clears local state immediately. `LogoutAccount` clears local state before
network work and revokes the remote customer session on acknowledgement. Neither
releases a device slot. `Deactivate` clears activation access, keeps the customer login
and releases a slot only after acknowledgement. Late responses cannot restore
invalidated state. Failed remote logout or deactivation leaves local access cleared and
needs explicit reconciliation.

## Remember an activation

`MemoryStorage` is the default. Custom `Storage` adapters must protect credentials:
`Save` compares its version atomically with `Invalidate`, and `Version` observes other
writers before each protected operation. Isolate storage per context unless the adapter
coordinates all readers and writers. The SDK rejects default JSON serialization of
`StoredCredential`; adapters must choose protected encoding. Do not use a plaintext
bearer file. Grants are not persisted, so restart requires online validation.

On Windows, open `OpenWindowsStorage(directory, config, stableDevice)` and pass it to
`NewClientWithStorage`. The directory must already exist, be absolute and local, and be
in your private Windows user profile. Use one directory per
issuer/application/environment/installation scope. Call `Close` when done and share the
storage object between contexts. A second opener fails promptly while the exclusive
lease is held. Unsupported platforms fail closed.

The adapter stores current-user DPAPI ciphertext in `orbit-storage.bin` and holds a
separate persistent `orbit-storage.lock` lease. It checks fingerprints, rejects reparse
paths and flushes ciphertext before replacement. Invalidation persists its generation
and an empty tombstone across restarts. Corruption, scope mismatch or missing ciphertext
beside an existing lease never resets the store. A failed write poisons the open
adapter; close it and deliberately recover or reopen it. Do not automatically delete
files. The adapter never persists passwords, licence keys, customer sessions or signed
grants.

On Linux, opt in with `OpenSecretServiceStorage(directory, config, stableDevice)`. The
host must provide an operational Secret Service keyring and `/usr/bin/secret-tool`; the
SDK installs and unlocks neither. Use an existing absolute directory owned by the
current user with no group/other permissions. The adapter holds a nonblocking exclusive
lease in a private `orbit-storage.lock` and stores one bounded private record as a
scoped keyring item. It rejects symlinks, changed leases, unsafe ownership or
permissions, corrupt records, and missing items beside an existing lease. Different
directories select different items.

Version and load checks use cached state under the lease. Writes use a bounded five-
second helper and poison the adapter on failure. Before each store, the adapter durably
marks the lease pending; only successful helper completion clears the marker. A failed
or timed-out helper, or a crash during a store, blocks reopening even if the keyring
still has a valid older record. Recover in a new dedicated directory with deliberate
online reactivation; never reset or delete the lease automatically. Share the storage
object between contexts and call `Close` when done. Check the keyring's encryption and
unlock settings before relying on it to protect credentials.

## Device identity and sleep

Linux uses `CLOCK_BOOTTIME` to include suspended time and checks wall-clock drift.
Windows uses `QueryInterruptTimePrecise`, which includes sleep and hibernation. Other
OSes fail closed during client creation. `NativeFingerprint` reads the Linux machine ID
or Windows SMBIOS UUID with a byte cap. `MachineFingerprint` applies the shared
`machine_v1` normalization and framing. For a hardware-locked policy, set both `Device`
fingerprint fields to the digest and provider. Do not request a fingerprint otherwise.

## Networking and local development

By default, HTTPS and certificate verification are required, redirects are disabled,
bodies are limited to 64 KiB, each attempt to 10 seconds and transport operations to 30
seconds. Safe reads and idempotent calls get at most two automatic retries. The explicit
`orbit_local` build tag enables `NewLocalTransport` for HTTP on a literal loopback IP
without a proxy; it does not weaken HTTPS verification.

## Support diagnostics

`Error.RequestID` retains a validated reference on denied and authoritative HTTP
transient failures; local errors have none. `Error.Code` retains the HTTP code, and
`errors.Is` still matches kind/code regardless of the reference. Error formatting uses
fixed guidance and never echoes server messages.

```go
summary := client.SupportSummary(err)
encoded, err := json.Marshal(summary) // Standard encoding/json.
```

The summary contains only `application_id`, `environment_id`, `code`, `request_id` and
`timestamp`; absent reference/time are JSON null. Timestamp is local Unix seconds, not
an access clock. References allow 1–64 ASCII letters, digits, underscores and hyphens;
malformed HTTP references reject the response. `SupportSummary` validates caller-created
errors and unwraps typed errors without copying wrapper text. It reads no account,
device, access or storage state and makes no network request. Keep the error from each
operation; there is no shared last-error state. This metadata grants no access and
proves no identity. The console prints fixed guidance and the copyable JSON summary for
SDK failures.
