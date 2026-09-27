# Advanced C# integration

The ordinary entry point is `OrbitClient.OpenAsync(appKey, options?)`; the
public app key is parsed into the origin, application, environment and grant
issuer. It is not a licence key. `OpenLocalAsync` is available only in a build
with `OrbitLocalDevelopment=true` and accepts HTTP only for literal loopback
addresses.

## Installed state and recovery

The installed client owns its installation ID, state directory and automatic
refresh worker. `OrbitOptions.StatePath` selects a dedicated absolute directory.
Linux files are private to the current user; Windows uses current-user DPAPI and
private DACLs. macOS uses owner-only POSIX files, an exclusive pinned lease,
`F_FULLFSYNC` for regular-file writes and a parent-directory sync after atomic
replacement. This macOS profile does not promise Keychain encryption.
Unsupported targets fail closed. Share one client per installation; a second
process is rejected while the lease is held.

State includes the scoped installation, credential, pending activation digest,
signed grant, verification key and clock evidence. It never contains a raw
licence key, password or customer session. Interrupted activation delivery
retains an operation ID and input digest for 24 hours; retry the same key or
licence selection and allow the client to reuse the saved ID. For account
activation, sign in again as the same customer after a restart. Failed sign-in
does not discard the pending operation, and another customer cannot reuse it.
`Logout()` deliberately clears local
state. `DeactivateAsync()` clears local access first and releases the device
slot only after server acknowledgement.

Sleep counts toward grant expiry. Offline restart checks saved server and wall
clock progress against the original signed deadline. Clock rollback or a
restored machine snapshot cannot be reliably detected by portable local state;
this protects continuity but is not tamper-proof local enforcement.

## Machine binding

Installed clients compute the existing scoped `machine_v1` fingerprint by
default on supported Windows, Linux and macOS x64/arm64 systems. macOS reads `IOPlatformUUID`
through IOKit and uses `mach_continuous_time`, which includes system sleep. Set
`DisableMachineBinding = true` for shared VM or container identities, or pass a
custom `Fingerprint(value, provider)` using a `custom:` provider. The SDK never
exports the raw machine ID. Unavailable identity sends no fingerprint. When the
current identity differs from saved state, the SDK creates a new installation
ID and clears the old credential, pending activation and cached grant before
the new identity can activate.

Building from source on macOS compiles a small POSIX helper for secure
directory opens automatically. Install the Xcode Command Line Tools first
(`xcode-select --install`).

## Long-term offline files

`OrbitOptions.OfflineKeys` accepts only trusted offline-purpose public JWKS.
`OfflineKeys.Parse` validates the entire key set before installed state opens.
`CreateOfflineRequest()` returns serializable public scope for an authorized
online issuance workflow; it contains no licence key or account proof.
`ImportOfflineFile()` verifies the signed file and durably stores its original
JWS, sequence and clock floors before returning a typed snapshot. After a
restart, the configured trusted offline-purpose keys must still verify the
file, which allows trusted key rotation.

While a file is active, `Snapshot()`, `RequireAccessAsync()` and
`EnsureAccessAsync()` check the storage lease, clock, expiry and signed feature
locally. They perform no HTTP validation and do not prompt for a key. Expired
files remain available for deliberate renewal, while online activation and
logout clear file authority but preserve its sequence and time floors. A full
old machine snapshot cannot be detected reliably. `OwnedLicence.OfflineFileDuration`
reports the server policy's `offline_file_seconds` value.

## Seller-hosted downloads

Use `DownloadTicketVerifier` on a seller's protected download endpoint. Configure
the public app key, the exact HTTPS endpoint URL and a trusted connected-purpose
JWKS from Orbit. Do not choose the audience from the incoming Host header or take
keys from the ticket. The verifier performs no network requests and needs no
management credential.

```csharp
using Orbit.Sdk;

static DownloadTicket AuthorizeArtifact(
    DownloadTicketVerifier verifier, string bearerTicket,
    string releaseId, string artifactId, string sha256, long byteLength)
{
    var ticket = verifier.Verify(bearerTicket);
    if (ticket.ReleaseId != releaseId || ticket.ArtifactId != artifactId ||
        ticket.Sha256 != sha256 || ticket.ByteLength != byteLength)
        throw new UnauthorizedAccessException("Download is not authorized.");
    return ticket;
}
```

Create the verifier once with
`new DownloadTicketVerifier(appKey, endpointUrl, File.ReadAllBytes("trusted-jwks.json"))`.
Pass artifact metadata from your own registry to the function. Invalid or expired
tickets raise `OrbitException` with `OrbitError.Denied` and code
`invalid_download_ticket`. Times are immutable `DateTimeOffset` values; the
optional `Verify` clock argument accepts a trusted application clock.

After authorization, serve the matching file or redirect to a short provider URL
that expires no later than `ticket.ExpiresAt`. Return `Cache-Control: no-store`
and keep tickets, redirect URLs and provider credentials out of logs. Sellers
own the storage and bandwidth; Orbit does not store or proxy file bytes. Permanent
public URLs remain shareable. See the
[complete Python seller endpoint](../../examples/python/seller-downloads/README.md).

## Customer accounts and backend identity

`RegisterAsync`, `ResendRegistrationAsync`, password recovery and email-change
methods start flows completed through browser or email proofs. `ClaimLicenceAsync`
adds an eligible key to a signed-in account. Use `OwnedLicencePage.NextCursor`
to request more licences. Customer sessions are held only in memory; installed
activation state uses its separate credential.

`CustomerSessionProof().AuthorizationHeader()` exposes a sensitive Bearer proof
for your trusted HTTPS backend. Never log, persist or forward it through a
redirect. Your backend must verify it online at
`GET /api/client/v1/sessions/current` and then authorize licensed work. See the
[backend example](../../examples/rust/licensed-backend/README.md).

The SDK returns native result types. Timestamps use `DateTimeOffset`, elapsed
and offline durations use `TimeSpan`, and `Snapshot.HasFeature` is suitable for
display logic. Always call `RequireAccessAsync` immediately before protected
work; `Snapshot()` is informational.

## Access-check performance

Reuse one client per installation. A warm `RequireAccessAsync` checks the
trusted clock, storage version and feature in local verified state, and contacts
Orbit only when a refresh is due. On Linux x86-64 with .NET 10 it takes about
3.5 µs and 200 bytes of allocation, with no network request or storage write.

See [online operations](ONLINE.md) for floating seats, verified update downloads,
usage reservation and persistent resource allocation.
