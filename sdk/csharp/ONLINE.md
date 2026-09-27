# Floating seats, updates and online limits

Use the same `OrbitClient` opened with your app key. Every operation accepts an
optional `CancellationToken`; the methods below use the current activation proof.
An offline licence file cannot authorize an online meter or download request.

## Floating seats

For a floating policy, activation and restart acquire a process session after
saving the activation credential. The client renews it automatically, with at
most one renewal in flight. `Snapshot.Session` exposes its ID and sequence.
Session grants are never restored from disk. A lost reply retries the same
session ID or renewal sequence; a transient renewal failure can retain only the
original signed interval, never extend it locally. An authoritative denial clears
local access. Seat limits and outages do not cause another licence-key prompt.

`await orbit.EndSessionAsync()` immediately stops local floating access and asks
the server to release the seat. Automatic acquisition stays disabled until
`await orbit.StartSessionAsync()`. These methods leave ordinary and offline-file
access unchanged. Disposing the client attempts a bounded release; an unavailable
server can retain the seat until its lease expires. An operator's remote end is
observed at renewal or signed expiry, not instantly by a disconnected client.

## Updates and downloads

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

Discovery defaults to channel `stable` and the current process OS/architecture.
Pass `target: new UpdateTarget("windows", "arm64")` when building a downloader for
another target. Unknown platforms require an explicit target. Release numbers
order updates; display-version strings do not. Results contain only the selected
artifact, and no other target is an automatic fallback.

Authorization is a fresh online request, separate from downloading. Keep URLs
and tickets out of logs; authorization objects redact their text representation.
Downloads use verified HTTPS, no cookies or ambient credentials, identity content
encoding and at most five redirects. The ticket is sent only to the initial
protected endpoint, including when a redirect points to the same host. Length,
streaming size and SHA-256 must all match before the temporary file is atomically
exposed at the caller's path. The server's filename is display metadata.
A 30-minute deadline covers redirects and the entire streamed response body.

An existing destination is refused unless `replace: true` is explicit. Failure
or cancellation removes the staging file and preserves any old destination. The
helper does not run an installer or unpack an archive. Sellers host the bytes;
Orbit authorizes their disclosure. Permanent public URLs are shareable. For
protected delivery, use a [seller ticket verifier](ADVANCED.md#seller-hosted-downloads).

## Usage and resources

```csharp
using Orbit.Sdk;

static async Task ExportAsync(OrbitClient orbit, string jobId, CancellationToken cancellationToken)
{
    await orbit.RequireAccessAsync("export", cancellationToken);
    var debit = await orbit.ConsumeAsync("exports", units: 1,
        idempotencyKey: jobId, cancellationToken: cancellationToken);
    Console.WriteLine($"Report: rows=3, total=42. Exports remaining: {debit.Counter.Remaining}");
}
```

Configure an `exports` usage limit, optionally requiring the `export` feature.
`UsageAsync("exports")` reads its current counter. `ResourcesAsync("projects")`
reads allocated capacity. `AcquireResourceAsync("projects", projectId,
idempotencyKey: jobId)` reserves a persistent allocation; retain its
`AllocationId`. Call `ReleaseResourceAsync("projects", allocationId)` when the
actual project is removed. Resource IDs are 1–128 ASCII letters, digits, `_` or
`-`; units are positive integers no greater than `2^53-1`.

Usage and resources are explicit online operations. Ordinary feature guards
neither meter work nor reserve resources. `OwnedLicence.UsageLimits`,
`ResourceLimits` and `ConcurrentSessionLimit` are informational policy metadata,
not available capacity. Offline failures never deduct a local counter.

Operation IDs are optional secure random values, reused within an invocation's
transport retries. For restart-safe work, supply your stable job ID (16–128 ASCII
letters, digits, `_` or `-`) and keep it with the job. Any mutation
`OrbitException.OperationId` identifies that intent, including cancellation or a
malformed response after an uncertain commit. Retry deliberately with the same
ID and inputs; omitting it on another call creates a new intent.

Capacity denials have code `usage_limit_reached` or `resource_limit_reached`, with
a validated `UsageCounter` or `ResourceCounter` and `RequestedUnits` on the exception. No unvalidated
server counter is exposed. Usage retries preserve the original debit or denial,
including its original period and totals across a UTC boundary. A resource replay
preserves allocation identity and units but returns its current state and the
current counter. An old acquire can return `AllocationState.Released`; do not
create the resource from that replay. A deliberate new allocation needs a new ID.

Usage reserves units before work and is not refunded automatically if the work
fails. Resource allocations persist across close, logout and outages until an
explicit release; use floating seats for temporary process occupancy. Installed
applications cannot prove that every operation was reported. For authoritative
metering, perform the consume/acquire on your trusted backend immediately before
the work, using the scoped management routes in the
[OpenAPI document](https://orbit.mayvie.dev/api/openapi.json).
Keep management credentials on that backend and coordinate its job record with
the returned operation ID; Orbit's transaction is separate from your own database.
