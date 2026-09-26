# Advanced C# integration

Use [the installed client](README.md) for ordinary desktop and server applications.
The APIs below preserve explicit ownership for custom integrations.

## Explicit setup and storage

`OrbitClient.Connect(OrbitSetup)` uses memory storage and a caller-supplied stable
installation ID. The constructor accepts an `OrbitConfig`, `Device`, caller-owned
`Transport` and optional `ICredentialStorage`. These clients do not schedule a
worker; refresh from `Snapshot().NextCheckAt` and enforce each operation with
`RequireAccessAsync`.

`WindowsStorage.Open` and `SecretServiceStorage.Open` remain explicit
credential-only adapters. They require an existing private dedicated directory,
retain format-1 records and require online validation after restart. Secret
Service also needs an operational keyring and `/usr/bin/secret-tool`; Orbit does
not install or unlock them. Custom storage must atomically compare `Save`'s
expected generation with `Invalidate`, and observe current invalidation in `Version`.

Explicit activation operation IDs remain supported. Preserve the exact input and
ID when delivery is uncertain. `ActivateWithPreviousAsync` and its account
equivalent accept an original bearer for an authorized rebind, including on a
fresh installation. Never log that bearer.

## State protection and recovery

Installed state includes the scoped installation, credential, pending activation
digest, original signed grant, verification key and clock evidence. It never
contains a raw licence key, password or customer session. Linux files are private
to their owner. Windows uses current-user DPAPI and protected private DACLs;
impersonated threads cannot open or write installed state.

Keep the state directory when reporting corruption or provider failure. Do not
delete its lock or automatically switch storage providers. The SDK rejects links,
unsafe ownership and permissions, missing initialized data, unknown fields and
competing leases. Interrupted writes remain fenced on the next open. State
files are private to this SDK; do not copy them between SDK languages.

Sleep counts toward grant expiry. Offline restart checks saved wall/server clock
progress and retains the original signed deadline. Rollback or inconsistent
evidence requires online recovery. A clock changed while stopped to above its
saved high-water, or a restored VM/disk snapshot, cannot reliably be detected by
portable local storage. This is continuity protection, not tamper-proof local
licence enforcement.

Linux native storage supports x64 and ARM64 with architecture-specific file
flags. Compile checks are separate from native ARM64 or physical Raspberry Pi
testing. The native Linux clock requires a 64-bit process; 32-bit ARM is not
claimed by an ARM64 build. Unsupported native targets fail closed.

## Hardware binding

Only set `AppConfig.Fingerprint` and `FingerprintProvider` for a policy requiring
hardware binding. `DeviceIdentity.NativeFingerprint(appId, environmentId)`
derives a scoped `machine_v1` digest on supported Windows/Linux systems. Never
send the raw machine identifier. A missing required identity fails closed.

## Accounts and backend identity

`RegisterAsync`, `ResendRegistrationAsync`, recovery and email-change methods
start flows completed through browser/email proofs. `ClaimLicenceAsync` adds an
eligible key to a signed-in account. Use the returned `NextCursor` when listing
additional owned licences. Ordinary customer-session expiry does not expire the
separate installation credential; explicit revocation still applies.

`CustomerSessionProof().AuthorizationHeader()` exposes sensitive Bearer proof
for your own trusted HTTPS backend. Never log, persist or forward it through
redirects. The backend must verify it online at
`GET /api/client/v1/sessions/current`, then separately authorize the licensed
operation. See the [backend example](../../examples/rust/licensed-backend/README.md).

## Networking and diagnostics

Production transports require verified HTTPS, disable redirects and bound
response sizes and retries. Cancellation stops networking. The explicit build
property `OrbitLocalDevelopment=true` adds `OpenLocalAsync` and
`Transport.LocalLoopback` for HTTP on a literal loopback address.

`OrbitException.Error`, `Code` and `RequestId` provide redacted classifications
and validated references. `orbit.SupportSummary(error)` is serializable metadata
for support; it contains no credential or account state and grants no access.
[Run the SDK tests](tests/README.md) when modifying an integration boundary.
