# Advanced C# integration

Start with the [quick start](README.md). `OrbitClient.OpenAsync(appKey,
options?)` parses the public app key into its API origin, application and
environment. A build with `-p:OrbitLocalDevelopment=true` adds
`OpenLocalAsync`, which accepts HTTP only for literal loopback addresses;
ordinary builds require HTTPS.

## Storage and clock guarantees

The installed client owns its installation ID, state directory and refresh
worker. Windows state uses current-user DPAPI and private DACLs. Linux and
macOS use owner-only files and an exclusive lease; macOS writes use
`F_FULLFSYNC` plus a parent-directory sync after atomic replacement, and fail
closed on a filesystem that rejects them. macOS storage is private POSIX files,
not Keychain encryption. Unsupported platforms fail closed. Building from
source on macOS compiles a small helper for secure directory opens, so install
the Xcode Command Line Tools first (`xcode-select --install`).

State holds the installation, credential, pending activation digest, signed
grant, verification key and clock evidence. It never holds a raw licence key,
password or customer session. Corrupt or missing established state is never
silently replaced; preserve the directory and treat the `Storage` error as
unavailable access.

Sleep counts toward grant expiry: macOS uses `mach_continuous_time`, Linux
`CLOCK_BOOTTIME` and Windows interrupt time. After a restart, saved server and
wall-clock progress is checked against the original signed deadline, and clock
rollback requires online validation. Someone who controls the user account or
restores the whole machine can modify local state; this protects continuity,
not tamper-proof enforcement.

## Machine binding

On Windows, Linux and macOS x64/arm64, the default `machine_v1` fingerprint is
a scoped digest of the operating system's machine ID (IOKit `IOPlatformUUID`
on macOS). Only the digest leaves the process. Set
`DisableMachineBinding = true` for shared VM or container identities, or pass
`Fingerprint = new Fingerprint(value, "custom:your-provider")` with a
64-character lowercase SHA-256 value. When the current identity differs from
saved state, the SDK creates a new installation ID and clears the old
credential, pending activation and cached grant before the new identity can
activate.

## Activation, retries and cancellation

`ActivateAsync`, `ActivateAccountAsync`, `ClaimLicenceAsync` and
`DeactivateAsync` generate secure operation IDs; pass `idempotencyKey` to
control an uncertain retry yourself. An interrupted activation keeps its
operation ID and input digest for 24 hours: retry the same key or licence
selection and the client reuses the saved ID. For account activation, sign in
again as the same customer after a restart; another customer cannot reuse the
pending operation. `ActivateWithPreviousAsync` and
`ActivateAccountWithPreviousAsync` rebind using the prior credential.

Every network method accepts a `CancellationToken`. A late response never
replaces newer local state. `Logout()` clears local access and keeps the
server activation. `DeactivateAsync()` clears local access first and releases
the device slot once the server acknowledges it. Disposing the client cancels
owned work, checkpoints clock evidence and releases the lease; it throws if
that final checkpoint fails.

`OrbitError.NotActivated` and `OrbitError.FeatureUnavailable` distinguish a
missing activation from a licence without the feature. `Transient` means Orbit
was unreachable; `Denied` is an authoritative refusal whose `Code` says why.
Exception messages are fixed guidance and never contain server text or
credentials.

A denial that only withholds access, such as a suspended or expired licence,
keeps the saved activation, so access resumes at the next validation after the
licence is restored. A revoked licence, invalid credential or device mismatch
clears it, and the device must activate again.

## Long-term offline files

`OfflineKeys.Parse` validates the whole trusted key set before installed state
opens. It reads the Test or Live environment from the `offline-test-` or
`offline-live-` key IDs; pass `"test"` or `"live"` to pin it. Opening fails
when the keys belong to a different environment from the app key.

`CreateOfflineRequest()` returns the installation ID and optional binding pair.
`ImportOfflineFile()` rejects lower sequences and conflicting equal sequences,
then durably stores the signed file with its sequence and clock floors.
Reimporting a file never extends its expiry. After a restart, the configured
trusted keys must still verify the file, which allows trusted key rotation.
`Snapshot().OfflineFileMode` distinguishes file access from a cached connected
grant. Online activation and logout clear file authority but keep the floors,
so an older file cannot undo a renewal. `OwnedLicence.OfflineFileDuration`
reports the policy's file duration.

## Online operations

A floating client renews with at most one renewal in flight. A lost reply
retries the same session ID or renewal sequence, and a transient failure keeps
only the original signed interval. Session grants are never restored from disk.

Downloads use a fresh verified-HTTPS client with no cookies, proxy or ambient
credentials. They request identity encoding, follow at most five redirects and
send the ticket only to the first endpoint, even when a redirect stays on the
same host. A 30-minute deadline covers the whole transfer. The file is staged
beside the destination and removed on failure; the server's filename is display
metadata only.

Resource IDs are 1–128 ASCII letters, digits, `_` or `-`; units are positive
integers up to `2^53-1`. `OwnedLicence.UsageLimits`, `ResourceLimits` and
`ConcurrentSessionLimit` describe policy, not available capacity. For
authoritative metering, consume or acquire on your trusted backend using the
scoped management routes in the
[OpenAPI document](https://orbit.mayvie.dev/api/openapi.json), and keep the
management credential there.

## Customer accounts and backend identity

`RegisterAsync(new Registration(key, username, email, password))` starts
registration; confirmation happens through the email link and does not sign the
customer in. When the application allows customer sign-up, omit the key with
`new Registration(username, email, password)`; any sign-up licence the
application grants appears in `OwnedLicencesAsync` after sign-in. Passwords need at least eight characters. Keep the returned
`RegistrationResult` in memory for `ResendRegistrationAsync`.
`RequestPasswordRecoveryAsync` and `RequestEmailChangeAsync` return generic
acceptance. `ClaimLicenceAsync` adds an eligible key to the signed-in account
without activating it. Pass `OwnedLicencePage.NextCursor` to
`OwnedLicencesAsync` for the next page. `LogoutAccountAsync` clears local state
and requests server-side session revocation. Customer sessions stay in memory.

`CustomerSessionProof().AuthorizationHeader()` returns a sensitive Bearer
header for your own trusted HTTPS backend. Never log, persist or forward it
through a redirect. Your backend must verify it online at
`GET /api/client/v1/sessions/current` and then authorize licensed work
separately; see the
[backend example](../../examples/rust/licensed-backend/README.md).

## Access-check performance

Reuse one client per installation. A warm `RequireAccessAsync` checks the
trusted clock, storage version and feature in local verified state and contacts
Orbit only when a refresh is due. On Linux x86-64 it takes about 4 µs, with no
network request or storage write.
