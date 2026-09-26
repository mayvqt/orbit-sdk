# Advanced Go integration

Use [the installed client](README.md) unless your application needs explicit
transport, installation or storage ownership.

## Explicit client ownership

`Connect(Setup)` retains the existing memory-only API with a caller-supplied
installation ID. `NewClientWithStorage` accepts a configured `Device`,
`Transport` and `Storage`. These clients do not own a background worker. Schedule
`Refresh` from `Snapshot.NextCheckAt` and use `RequireAccess` before protected work.

`MemoryStorage` is transient. Existing `OpenWindowsStorage` and
`OpenSecretServiceStorage` adapters remain available for explicit credential-only
persistence; they require an existing private directory and online validation
after restart. Secret Service requires an operational keyring and
`/usr/bin/secret-tool`. Orbit installs or unlocks neither. Custom storage must
atomically compare `Save`'s generation with `Invalidate`, and `Version` must
observe invalidation before access is authorized.

`Activate(ctx, key, operationID)` and account activation accept explicit mutation
IDs. Preserve the same input and ID after uncertain delivery; do not issue a new
mutation to recover a missing secret. `ActivateWithPrevious` and
`ActivateAccountWithPrevious` accept the original bearer for authorized rebinding.
An installed client also records explicit IDs while a mutation is unresolved.

## State protection and recovery

The installed store rejects corrupt or missing initialized data, scope mismatch,
unsafe permissions, links and competing leases. Preserve the directory when
reporting a storage failure; do not delete its lock or silently switch providers.
Linux uses a private owner-only file. Windows uses current-user DPAPI with a
protected owner-only/SYSTEM/Administrators DACL. Both write complete replacements
atomically. Passwords, licence keys and customer sessions never enter the store.

Windows and Linux clocks include sleep. Offline restart uses the original signed
grant and saved clock evidence. Clock rollback or inconsistent evidence requires
online recovery. A clock changed while stopped to above its saved high-water, or
a restored disk/VM snapshot, cannot reliably be detected by portable local state.
This is continuity protection, not tamper-proof enforcement against the local owner.

Linux ARM64 and 32-bit ARM compile checks are separate from native hardware
validation. Do not infer Raspberry Pi hardware testing from an x64 test run.
Unsupported platforms fail closed.

## Hardware binding

Set both `AppConfig.Fingerprint` and `FingerprintProvider` only when the policy
requires hardware binding. `NativeFingerprint(applicationID, environmentID)`
returns a scoped `machine_v1` digest on supported Windows/Linux systems.
`MachineFingerprint` exposes the same normalization for explicit adapters. Never
send raw machine identifiers. An unavailable required identity fails closed.

## Customer accounts and backend proof

Use `Register` and optional `ResendRegistration`, then complete the email link
before `Login`. `ClaimLicence` adds a key to an account; `OwnedLicences` takes an
empty first cursor and then its returned `NextCursor`. Password recovery and
email changes require their browser proofs. `LogoutAccount` clears local access
before attempting remote session revocation. Ordinary session expiry does not
expire a separate installation credential; explicit revocation still applies.

`CustomerSessionProof().AuthorizationHeader()` exposes sensitive Bearer proof
for your own trusted HTTPS backend. Never log, persist or forward it through
redirects. The backend must verify it online at
`GET /api/client/v1/sessions/current` using fixed app/environment configuration,
then separately check licensed access. See the [backend example](../../examples/rust/licensed-backend/README.md).

## Networking and diagnostics

Production transports require HTTPS and certificate verification, disable
redirects, cap responses at 64 KiB and bound each operation to 30 seconds.
Cancellation stops requests and retries. The explicit `orbit_local` build tag
adds `OpenLocal` and `NewLocalTransport` for HTTP on literal loopback addresses.

Errors contain fixed guidance and validated codes/request references, never
unchecked server messages or secrets. `errors.Is` supports the exported sentinel
errors. `client.SupportSummary(err)` produces serializable app/environment,
error code, request reference and local timestamp metadata for support. It grants
no access and exposes no credential or account state.
