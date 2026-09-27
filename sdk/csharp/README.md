# Orbit C# SDK

License a desktop app or customer-hosted service with .NET 10. The installed
client remembers an activation, validates it online and keeps verified offline
access only when the signed grant allows it. The SDK uses .NET's built-in
cryptography and has no NuGet package dependencies.

## Quick start

Add a project reference to the SDK, then copy the public app key from Orbit's
**Integration** page. Start with the **Test** environment.

```sh
dotnet add path/to/YourApp.csproj reference path/to/Orbit-SDK/sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj
export ORBIT_APP_KEY='orbit_app_test_...'
```

```csharp
using Orbit.Sdk;

var appKey = Environment.GetEnvironmentVariable("ORBIT_APP_KEY")
    ?? throw new InvalidOperationException("Set ORBIT_APP_KEY first.");
await using var orbit = await OrbitClient.OpenAsync(appKey);
await orbit.EnsureAccessAsync("export", _ =>
{
    Console.Write("Licence key: ");
    return ValueTask.FromResult(Console.ReadLine()?.Trim());
});
// Run protected export work here.
```

`EnsureAccessAsync` prompts only when no activation exists. It does not prompt
after an outage or when an activated licence lacks the feature. Call
`RequireAccessAsync("export")` again immediately before later protected work;
`Snapshot()` is for display only. Disposing the client closes it and keeps the
activation; it does not release a device slot.

The app key is public: it names the API origin, application and environment,
and grants nothing on its own. Keep licence keys, passwords and customer session
proofs out of command-line arguments and logs. The SDK never saves a raw licence
key or password.

Failures throw `OrbitException`. `Error` classifies the failure
(`NotActivated`, `FeatureUnavailable`, `Transient`, `Denied` and so on), `Code`
holds the stable protocol code and `RequestId` a server reference. Pass the
exception to `orbit.SupportSummary(error)` for a copyable, credential-free
summary.

## Installation state

`OpenAsync` binds the installation to a scoped `machine_v1` fingerprint when
the operating system identity is available, and sends no fingerprint when it
is not. Pass `new OrbitOptions { DisableMachineBinding = true }` for shared
machine images. When the machine identity changes, the SDK starts a new
installation and discards the old credential and cached access.

State is private to the current user: current-user DPAPI on Windows, private
files under `$XDG_STATE_HOME/orbit` (normally `~/.local/state/orbit`) on Linux
and under `~/Library/Application Support/Orbit` on macOS. Set
`OrbitOptions.StatePath` to a dedicated absolute directory for a service
account or container volume. Share one client per installation; a second
process that opens the same state is rejected. See
[storage and clock guarantees](advanced.md#storage-and-clock-guarantees).

## Customer accounts

For Account or Both authentication, register and confirm the customer's email,
then sign in and activate one of their licences:

```csharp
var account = await orbit.LoginAsync(username, password);
var page = await orbit.OwnedLicencesAsync();
await orbit.ActivateAccountAsync(page.Items[0].Id);
await orbit.RequireAccessAsync("export");
```

Sign-in alone does not grant licensed access. Results use native types such as
`DateTimeOffset` and `TimeSpan`. The
[console example](../../examples/csharp/licensed-export/README.md) also shows
registration, recovery, claiming a key and account logout; see
[customer accounts](advanced.md#customer-accounts-and-backend-identity).

## Long-term offline files

For a policy with `offline_file_seconds` enabled, configure the trusted
offline-purpose JWKS, export the installation request for your authorized
issuance workflow, then import the returned `.orbit` file:

```csharp
using Orbit.Sdk;
using System.Text.Json;

var appKey = Environment.GetEnvironmentVariable("ORBIT_APP_KEY")
    ?? throw new InvalidOperationException("Set ORBIT_APP_KEY first.");
var trustedKeys = OfflineKeys.Parse(
    await File.ReadAllTextAsync("trusted-offline-jwks.json"));
await using var orbit = await OrbitClient.OpenAsync(appKey,
    new OrbitOptions { OfflineKeys = trustedKeys });

var request = orbit.CreateOfflineRequest();
await File.WriteAllTextAsync("offline-request.json",
    JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
// Send the public request to your authorized issuance workflow.
orbit.ImportOfflineFile(await File.ReadAllTextAsync("licence.orbit"));
await orbit.RequireAccessAsync("export");
```

Ship the trusted keys with your application or fetch them from the app-key
origin over verified HTTPS; never take them from the file or the person
supplying it. The request contains no licence key or account proof. Import
verifies the file and stores it before returning access. While a file is
active, access checks make no network request and never prompt; an expired
file returns code `offline_file_expired`.

An issued file cannot be revoked while the machine is disconnected. Sequence
and clock floors prevent ordinary replay and clock rollback, but restoring a
complete old machine or VM snapshot cannot be detected reliably. Tell customers
about this limit before issuing long-term access. See
[offline file details](advanced.md#long-term-offline-files).

## Floating seats

Floating policies acquire a seat after activation and renew it automatically.
`Snapshot().Session` shows its ID and sequence. A full seat pool, an expired
seat or an outage never asks for another licence key.

Call `EndSessionAsync()` when your app becomes idle and `StartSessionAsync()`
when it resumes. Ending clears local floating access before contacting Orbit
and disables automatic reacquisition. Both calls leave ordinary and
offline-file access unchanged. Disposing the client makes a bounded attempt to
release the seat; after a crash or failed release, the seat stays occupied
until its short lease expires. A remote end takes effect at the next renewal or
signed expiry.

## Licensed updates

```csharp
using Orbit.Sdk;

static async Task DownloadUpdateAsync(OrbitClient orbit, long installedRelease,
    string destination, CancellationToken cancellationToken)
{
    var update = await orbit.CheckForUpdateAsync(installedRelease,
        cancellationToken: cancellationToken);
    if (update == null) return;
    var authorization = await orbit.AuthorizeDownloadAsync(
        update.Release.Id, update.Artifact.Id, cancellationToken);
    await authorization.DownloadAsync(destination, maximumBytes: 64 * 1024 * 1024,
        cancellationToken: cancellationToken);
}
```

Compare the increasing release number built into your app, not display
versions. Discovery defaults to channel `stable` and the running OS and
architecture; pass `target: new UpdateTarget("windows", "arm64")` for another
target. There is no fallback to a different target.

Authorization checks current licence eligibility separately from discovery.
The file streams directly from the seller over verified HTTPS, and the SDK
checks its length and SHA-256 before atomically moving it into place. An
existing destination is refused unless you pass `replace: true`; a failed or
cancelled download leaves it untouched. The SDK never runs or unpacks the file.
Keep authorizations out of logs.

## Usage and resources

Configure an `exports` usage limit, then reserve a unit before doing the work:

```csharp
var debit = await orbit.ConsumeAsync("exports", units: 1, idempotencyKey: jobId);
Console.WriteLine($"Exports remaining: {debit.Counter.Remaining}");
// Perform the export and record its result with jobId.
```

`UsageAsync(name)` and `ResourcesAsync(name)` read the current counters.
`AcquireResourceAsync(name, resourceId, idempotencyKey: jobId)` returns an
allocation; call `ReleaseResourceAsync(name, allocationId)` when the actual
resource is removed. Closing, logging out and outages do not release
allocations.

Operation IDs are optional and generated securely. Supply a stable job ID of
16–128 letters, digits, `_` or `-` when a retry must survive a restart. On
failure, `OrbitException.OperationId` identifies the operation; retry an
uncertain outcome with that ID and identical input. Capacity denials use code
`usage_limit_reached` or `resource_limit_reached` and carry a validated
`UsageCounter` or `ResourceCounter`.

A usage retry returns its original debit or denial. A resource retry returns
the original allocation with its current state, so an old acquire can return
`AllocationState.Released` without reactivating it. Usage is not refunded if
the work fails. These calls always go online, never acquire a floating seat and
cannot be authorized by an offline file. `RequireAccessAsync` never consumes
usage. Installed programs can be modified to skip reporting, so meter on your
trusted backend when enforcement must be authoritative.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on
your seller backend before serving the file. Configure the exact HTTPS endpoint
and a trusted connected-purpose JWKS; never take keys or the audience from the
request. The verifier makes no network requests.

```csharp
using Orbit.Sdk;

var verifier = new DownloadTicketVerifier(appKey,
    "https://downloads.example.com/artifacts", File.ReadAllBytes("connected-jwks.json"));

DownloadTicket AuthorizeArtifact(string bearerTicket, string releaseId,
    string artifactId, string sha256, long byteLength)
{
    var ticket = verifier.Verify(bearerTicket);
    if (ticket.ReleaseId != releaseId || ticket.ArtifactId != artifactId ||
        ticket.Sha256 != sha256 || ticket.ByteLength != byteLength)
        throw new UnauthorizedAccessException("Download is not authorized.");
    return ticket;
}
```

Pass artifact metadata from your own registry. Invalid or expired tickets throw
`OrbitException` with code `invalid_download_ticket`. A ticket expires within
120 seconds and can be replayed until then: treat it as a secret, never log it
and never use an artifact ID as a filesystem path. After verification, serve
the file or redirect to a storage URL that expires no later than
`ticket.ExpiresAt`, with `Cache-Control: no-store`. The
[seller example](../../examples/python/seller-downloads/README.md) shows a
complete endpoint.

See [advanced integration](advanced.md) for storage, clock, binding and retry
details.
