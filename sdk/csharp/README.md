# Orbit C# SDK

The SDK adds licence activation, customer sign-in and feature checks to .NET apps. It
connects to Orbit over HTTPS and supports Windows 11 x64 and Ubuntu 24.04 x64. Source is
under the [MIT licence](../LICENSE).

## Add the SDK

Use .NET SDK 10.0.112, selected by the kit's `global.json`. Add a project reference,
adjusting the paths:

```sh
dotnet add MyApp/MyApp.csproj reference orbit-kit/sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj
```

In Visual Studio, add the existing `Orbit.Sdk.csproj` to your solution, then reference
it from your app. Keep the `Orbit.Sdk` folder intact; Visual Studio includes its source
files automatically. Keep the SDK's [NuGet.Config](NuGet.Config) and
`packages.lock.json` files.

For a first run, follow the [console example](../../examples/csharp/licensed-export/README.md),
then open **Integration** in the dashboard and copy the C# startup
snippet for your application and environment.

## Activate and check access

```csharp
using Orbit.Sdk;

using var orbit = OrbitClient.Connect(new OrbitSetup(
    "https://orbit.mayvie.dev", applicationId, environmentId,
    grantIssuer, persistedInstallationId));

await orbit.ActivateAsync(userEnteredKey, operationId, cancellationToken);
await orbit.RequireAccessAsync("export", cancellationToken);
// Perform the protected operation now. Check again before each later operation.
```

`Connect` requires strict HTTPS, keeps credentials in memory and owns its transport. The
existing constructor accepts a caller-owned transport and optional protected storage for
advanced integrations or explicit local testing. Configure the deployment's exact issuer
and public app/environment IDs. Reuse a stable installation ID across restarts;
`Device.NewInstallation()` creates one, but the host must preserve that nonsecret ID. Do
not put keys or passwords in command-line arguments, URLs or logs. The SDK retains
neither passwords nor raw licence keys.

## Refresh and retries

`Snapshot()` returns access, entitlements, policy version, grant expiry, next online
check, remaining offline time and the credential reauthentication deadline. Dates are
Unix seconds. Schedule `RefreshAsync()` for the next check and call
`RequireAccessAsync()` before each protected operation; a startup boolean cannot enforce
expiry, suspension, logout or resumed access.

Only a verified, unexpired grant that permits offline access can survive a recognized
transient refresh failure. Strict-online grants deny after a failed refresh. Explicit
denial, invalid signatures/claims/JSON, unknown bindings and TLS security failures clear
access. Unknown entitlements never grant access. The transport disables redirects,
limits payloads to 64 KiB, uses a three-second connect deadline and ten-second attempt
deadline, and retries safe/idempotent requests at most twice within a thirty-second
operation budget. Cancellation is an `OrbitException` with `OrbitError.Cancelled`.
Exceptions never contain server messages, request bodies or tokens.

For uncertain delivery, keep the idempotency key and exact input stable for retries
within the server's 24-hour replay retention. Raw activation secret replay lasts 15
minutes. `ReauthenticationRequired` needs deliberate fresh authentication or
replacement. `ActivateWithPreviousAsync()` and `ActivateAccountWithPreviousAsync()`
accept the still-valid original credential for same-fingerprint rebinding, subject to
authoritative cooldown rules.

## Customer accounts

```csharp
var pending = await orbit.RegisterAsync(
    new Registration(key, username, email, password), cancellationToken);
await orbit.ResendRegistrationAsync(pending, cancellationToken);
// Customer confirms their email in Orbit's proof form; confirmation is not login.
var account = await orbit.LoginAsync(username, password, cancellationToken);
var page = await orbit.OwnedLicencesAsync(cancellationToken: cancellationToken);
await orbit.ActivateAccountAsync(selectedLicenceId, operationId, cancellationToken);
await orbit.RequireAccessAsync("export", cancellationToken);
```

Pass `page.NextCursor` to `OwnedLicencesAsync()` for another bounded page.
`ClaimLicenceAsync()` claims an eligible key without activating it.
`RequestPasswordRecoveryAsync()` returns generic acceptance. `RequestEmailChangeAsync()`
starts the two-mailbox proof flow after password reauthentication. Complete
registration, recovery and email proofs in Orbit's browser form, then log in
deliberately. `PendingRegistration` keeps its resend proof private in memory.
Registration, resend, login, recovery and email-change mutations are sent once without
automatic retries.

`Account()` returns local metadata and grants no licensed access. Customer sessions stay
in memory and never enter the storage adapter.
`CustomerSessionProof().AuthorizationHeader()` exposes a sensitive Bearer header for
your own trusted HTTPS backend. Do not log or persist it or forward it through
redirects. The backend must verify it online through
`GET /api/client/v1/sessions/current`, using fixed app/environment configuration, then check
licensed access separately. Account metadata and offline grants are not identity
credentials. The Rust kit has an interoperable [backend
example](../../examples/rust/licensed-backend/README.md).

Ordinary 12-hour customer-session expiry does not end the separately issued 30-day
activation credential; explicit session revocation invalidates derived credentials. A
new login clears previous local access. Select and activate the intended licence before
protected work.

## Sign out or release a device

`Logout()` clears local state immediately. `LogoutAccountAsync()` clears it
synchronously before returning its task; await success to confirm server revocation.
Logout does not release a device slot. `DeactivateAsync()` also clears activation access
before returning, keeps the customer login and releases the slot only after server
acknowledgement. A remote failure leaves local access cleared. Serialized operations and
generation checks discard late successes, errors and storage writes after a newer
identity, logout or invalidation.

## Remember an activation

Default storage is `MemoryStorage`. On Windows, open current-user DPAPI storage to
retain an activation credential across restarts:

```csharp
using var storage = WindowsStorage.Open(privateProfileDirectory, config, device);
var orbit = new OrbitClient(config, device, transport, storage);
```

The directory must already exist, be an absolute local path under your private Windows
profile, and be dedicated to one issuer/application/environment/installation scope. The
caller sets its private access permissions. The adapter rejects reparse points, pins the
directory and ancestors while open, and holds `orbit-storage.lock` exclusively until
disposal; a second opener fails promptly. Share the same object between coordinated in-
process contexts and dispose it when done. `StorageCapability` reports
`OperatingSystemProtected`; unsupported platforms fail with `Storage`.

Only DPAPI ciphertext is written to `orbit-storage.bin`. First open commits an empty
scope-bound record; saves and generation-incrementing invalidation survive ordinary
restarts. An existing lock with missing data, corrupt data or a different scope fails
closed and is never reset automatically. A failed write poisons the object until
disposal and deliberate reopening; damaged state needs deliberate host recovery. Cross-
language file interchange is not supported.

Custom `ICredentialStorage` adapters must coordinate `Version`, `Save` and `Invalidate`
atomically; `Save` compares its expected generation. The SDK never writes a plaintext
bearer file and the adapter never stores passwords, raw keys, customer sessions or
signed grants. Each new process still requires online validation. On Linux, select the
optional Secret Service adapter explicitly:

```csharp
using var storage = SecretServiceStorage.Open(privateLinuxDirectory, config, device);
var orbit = new OrbitClient(config, device, transport, storage);
```

The Linux directory must exist with mode 0700 and belong to the current user. The
adapter opens a mode-0600 `orbit-storage.lock`, rejects symlinks and unsafe
ownership/permissions, and holds a nonblocking exclusive `flock` until disposal. Removed
or replaced leases fail closed. Each directory owns one scoped keyring item whose
attributes include the C# SDK identity, exact Config/Device scope and normalized
directory. The native boundary requires x64 Linux with glibc and `statx`; other
architectures or missing native support fail closed.

The host must provide `/usr/bin/secret-tool` and an operational Secret Service keyring.
The SDK does not install or unlock them or provide a keyring password. Only the bounded
private activation record enters the default collection through stdin; no plaintext
record file is created. Helpers have a five-second deadline and bounded private output.
Version/load checks use cached state under the lease. Saves compare generations;
invalidation persists a tombstone. Failed writes poison the adapter. Missing state
beside an existing lease, corruption or wrong scope never causes an automatic reset.

Before each keyring store, the adapter durably writes the single nonsecret byte `0x01`
to mark the lease pending. It clears the marker only after the helper succeeds and has
been reaped. A timeout, uncertain write or process crash blocks reopening even if a
delayed helper later updates the item. Recover in a new private directory with online
reactivation; never delete or clear a damaged or pending lease automatically. Check the
keyring's encryption and unlock settings before relying on it to protect credentials.
Retained credentials require online validation after every restart.

## Device identity and sleep

The isolated Linux 64-bit clock adapter uses `CLOCK_BOOTTIME` to include suspend.
Windows uses `QueryInterruptTimePrecise`. Unsupported platforms fail with
`ClockUncertain`. Uncertain elapsed time or a wall-clock discontinuity discards the
grant and requires an online check. For hardware-locked apps, provide the scoped
lowercase 64-character fingerprint and provider `machine_v1` or versioned
`custom:<name>`; never send a raw machine identifier.

## Local development

The default build allows HTTPS only. Set MSBuild property `OrbitLocalDevelopment=true`
to define `ORBIT_LOCAL_DEVELOPMENT` and enable `Transport.LocalLoopback()` for HTTP on a
literal loopback IP. DNS names, integer/shorthand IPv4 addresses and non-loopback hosts
are rejected. There is no runtime insecure toggle or certificate-validation bypass.

For an explicitly HWID-bound app, set both `Device` fingerprint fields using
`DeviceIdentity.NativeFingerprint(appId, environmentId)` and `DeviceIdentity.Provider`.
Linux reads a bounded machine ID; Windows reads the SMBIOS system UUID. Missing or
invalid identity returns `device_identity_unavailable`; there is no random fallback.
`DeviceIdentity.MachineFingerprint` uses the same scoped derivation for explicit adapter
integration. Never send the raw OS ID or request HWID when disabled.

## Support diagnostics

`OrbitException.RequestId` retains a validated reference on denied and authoritative
HTTP transient failures; local errors have none. `Code` retains the HTTP code while
`OrbitError` classification stays unchanged. Exception messages use fixed guidance,
never server text.

```csharp
var summary = orbit.SupportSummary(error);
var json = System.Text.Json.JsonSerializer.Serialize(summary);
```

The serialized summary contains only `application_id`, `environment_id`, `code`,
`request_id` and `timestamp`; absent reference/time are JSON null. Timestamp is local
Unix seconds, not an access clock. References allow 1–64 ASCII letters, digits,
underscores and hyphens; malformed HTTP references reject the response. `SupportSummary`
validates caller-created errors and reads no account, device, access or storage state or
network data. Keep each operation's exception; there is no shared last-error state. The
summary is diagnostic metadata, not proof of identity or licensed access. The console
prints fixed guidance and this copyable JSON summary for SDK failures.
