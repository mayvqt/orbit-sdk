# Advanced Go integration

Start with the [installed-client guide](README.md). This page covers rarer
options and the exact storage, clock and error behaviour.

## Installed options and machine binding

The zero value of `Options` stores state in the current user's platform
directory and sends the scoped `machine_v1` fingerprint when the native identity
is available. macOS reads `IOPlatformUUID` through IOKit. If the identity is
unavailable, the SDK sends no fingerprint and never substitutes a random value;
a hardware-locked licence then cannot activate.

Set `Options.BindingMode` to `orbit.BindingDisabled` for shared VM or container
images. For an application-owned identity, select `orbit.BindingCustom` and set
`Fingerprint` to a 64-character lowercase SHA-256 hex digest and
`FingerprintProvider` to a value beginning with `custom:`. Never send raw
machine identifiers. When the current identity differs from the saved one, the
SDK creates a new installation ID and clears the old credential, cached grant
and pending activation before the new identity can be used.

## Storage and clock guarantees

Linux and macOS use pinned owner-only files and an exclusive lease. On macOS,
file contents require `F_FULLFSYNC` and the parent directory is synchronized
after replacement; a filesystem that rejects this fails closed. This is private
POSIX storage, not Keychain encryption. Windows uses current-user DPAPI with a
protected DACL.

Corrupt or missing established state is never silently replaced; preserve the
directory after a storage error. A malformed reply or TLS failure keeps the
saved activation for a later retry. A denial that only withholds access, such
as a suspended or expired licence, also keeps it, so access resumes after the
licence is restored; a revoked licence, invalid credential or device mismatch
clears it.
Elapsed time uses a clock that counts sleep (`mach_continuous_time` on macOS),
and a clock rollback or inconsistent saved clock evidence requires online
validation. Local storage cannot detect a restored disk or VM snapshot, and a
user who controls the machine can modify local state.

`ParseAppKey` exposes an app key's public scope. The low-level `NewClient` and
`NewClientWithStorage` take a parsed `AppKey` and a `Device`; they do not own
restart state or a refresh worker. `OpenWindowsStorage` and
`OpenSecretServiceStorage` provide credential-only persistence for them.

## Long-term offline files

`Options.OfflineKeys` accepts a trusted JWKS of at most 16 KiB for the app key's
environment. Only ES256 signing keys with `offline-test-` or `offline-live-`
key IDs are accepted. `OfflineRequest` makes no HTTP request and consumes no
installation slot. `ImportOfflineFile` rejects lower sequence numbers and
conflicting files with an equal sequence, and the file is reverified against
the configured keys after every restart, so distribute rotated keys through a
trusted application update. `Snapshot.OfflineFileMode` distinguishes file
access from a cached connected grant.

## Activation and operation IDs

`Activate`, `ActivateAccount`, `Deactivate` and `ClaimLicence` generate secure
operation IDs; pass an explicit ID as the final argument to control retries
yourself. Installed activation IDs are saved before the request is sent, so
after a lost reply retry the same key or licence and the saved ID is reused.
An unresolved activation returns `ErrPendingActivation` for different input
and `ErrPendingActivationExpired` after 24 hours; `Logout` discards it.
`ActivateWithPrevious` and `ActivateAccountWithPrevious` rebind with the
original credential.

`Deactivate` clears local access first and releases the device slot only when
it returns nil. `Logout` clears local access and the customer session without
revoking either on the server.

## Customer accounts

Use `Register` and the optional `ResendRegistration`, then complete the email
link before `Login`. Leave `Registration.LicenceKey` empty for customer sign-up
without a key when the application allows it; any sign-up licence the
application grants appears in `OwnedLicences` after sign-in. Passwords need at
least eight characters and whitespace is preserved. `ClaimLicence` adds a key to the signed-in account without
activating it. `OwnedLicences` returns one bounded page; pass its `NextCursor`
to the next call. `RequestPasswordRecovery` and `RequestEmailChange` return
generic acceptance. `LogoutAccount` also requests remote session revocation.

Account and licence dates use `time.Time` and durations use `time.Duration`.
`OwnedLicence.OfflineFileDuration` is zero when long-term files are disabled
and otherwise between one and 366 days.

`CustomerSessionProof().AuthorizationHeader()` returns a sensitive Bearer header
for your own trusted HTTPS backend. Never log, persist or forward it through
redirects. The backend must verify it online and check licensed access
separately, as shown in the [backend example](../../examples/rust/licensed-backend/README.md).

## Cancellation, transport and errors

Every network method takes a `context.Context`; cancelling it stops requests
and retries. `Close` cancels owned work, and later calls return an
`ErrCancelled` match whose message says the client is closed. A reply that
arrives after logout, close or credential replacement is discarded.

Transports require HTTPS with certificate verification, disable redirects, cap
responses at 64 KiB and bound each operation to 30 seconds. Only safe reads and
mutations with a fixed operation ID are retried. The `orbit_local` build tag
adds `OpenLocal` and `NewLocalTransport` for HTTP on a literal loopback IP
address.

`*orbit.Error` carries a `Kind`, a stable `Code` and, for server failures, a
validated `RequestID`; its text never includes server messages or caller input.
`client.SupportSummary(err)` returns safe JSON-ready diagnostics with scope,
code, request reference and local timestamp.

Download helpers use a fresh HTTP transport with no cookies, proxy or ambient
credentials, follow at most five HTTPS redirects and write a temporary file
beside the destination. Size limits apply while streaming, independently of
`Content-Length`, and the seller's filename never chooses the path.

## Access-check performance

Reuse one `*Client` per installation. A warm `RequireAccess` checks the trusted
clock, storage and feature in local verified state, and contacts Orbit only
when a refresh is due. On Linux x86-64 it takes about 6 µs, with no network
request or storage write.
