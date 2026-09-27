# Orbit C# SDK

License a desktop app or customer-hosted service with .NET 10. The installed
client remembers an activation, checks it online first, and keeps verified
offline access only when the signed grant allows it.

The SDK uses .NET's built-in cryptography and has no NuGet package dependencies.

## Quickstart

From the repository root, add a project reference to the SDK project, then copy
the public app key from Orbit's **Integration** page. Start with the **Test**
environment.

```sh
dotnet add path/to/YourApp.csproj reference sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj
export ORBIT_APP_KEY='orbit_app_test_...'
```

```csharp
using Orbit.Sdk;

var appKey = Environment.GetEnvironmentVariable("ORBIT_APP_KEY")
    ?? throw new InvalidOperationException("Set ORBIT_APP_KEY first.");
await using var orbit = await OrbitClient.OpenAsync(
    appKey);
await orbit.EnsureAccessAsync("export", _ =>
{
    Console.Write("Licence key: ");
    return ValueTask.FromResult<string?>(Console.ReadLine());
});
// Run protected export work here.
```

`EnsureAccessAsync` prompts only when no activation exists. It does not prompt
after an outage or when an activated licence lacks the feature. Call
`RequireAccessAsync("export")` again immediately before later protected work.
Always close the client when the application exits; closing preserves the
activation and does not release a device slot.

An app key identifies the API origin, application and environment. It is public,
does not activate a licence, and does not grant access. Keep licence keys,
passwords and customer session proofs out of command-line arguments, logs and
storage. The SDK does not save raw licence keys or passwords.

## Installed state and machine binding

`OpenAsync` uses a scoped `machine_v1` fingerprint automatically when the
operating system identity is available. Pass `new OrbitOptions { DisableMachineBinding = true }`
for shared machine images, or provide a scoped custom `Fingerprint` explicitly.
The SDK sends only the derived fingerprint, never the operating-system ID.
If identity is unavailable, it sends no fingerprint. A stored identity mismatch
fails closed and cannot restore cached offline access.

Windows state is protected with current-user DPAPI. Linux state uses private
files under `$XDG_STATE_HOME/orbit` (normally `~/.local/state/orbit`). macOS
uses private POSIX files under `~/Library/Application Support/Orbit`; this is
not Keychain encryption. Set `OrbitOptions.StatePath` to a dedicated absolute
directory when needed. Share one client per installation; a competing process
is rejected.

On macOS, the SDK derives its default `machine_v1` identity from IOKit's
`IOPlatformUUID` and uses `mach_continuous_time` so sleep counts toward access
expiry. It stores only the scoped hash. Native macOS runtime validation is still
required; see [advanced integration](ADVANCED.md).

## Customer accounts

For Account or Both authentication, register and confirm the customer's email,
then sign in and activate one of their licences:

```csharp
var account = await orbit.LoginAsync(username, password);
var page = await orbit.OwnedLicencesAsync();
await orbit.ActivateAccountAsync(page.Items[0].Id);
await orbit.RequireAccessAsync("export");
```

Sign-in alone does not grant licensed access. Account, licence and snapshot
results use native C# types, including `DateTimeOffset` and `TimeSpan` values.
The [console example](../../examples/csharp/licensed-export/README.md) also
shows registration, recovery and account logout.

## Floating seats, updates and metering

Floating policies acquire and renew their session automatically. Use
`EndSessionAsync` to stop seat use and `StartSessionAsync` to resume it.
`CheckForUpdateAsync` discovers the newest eligible release for your runtime;
`AuthorizeDownloadAsync` and `DownloadAsync` authorize and verify a direct download.
`UsageAsync`, `ConsumeAsync`, `ResourcesAsync`, `AcquireResourceAsync` and
`ReleaseResourceAsync` expose typed online counters and allocations. See the
[online operations guide](ONLINE.md) for copy-ready examples and retry rules.

## Long-term offline files

For products with an enabled `offline_file_seconds` policy, configure the
trusted offline-purpose JWKS, export the installation request for an authorized
online issuance workflow, then import the returned `.orbit` file locally:

```csharp
using Orbit.Sdk;
using System.Text.Json;

var appKey = Environment.GetEnvironmentVariable("ORBIT_APP_KEY")
    ?? throw new InvalidOperationException("Set ORBIT_APP_KEY first.");
var trustedKeys = OfflineKeys.Parse(
    await File.ReadAllTextAsync("trusted-offline-jwks.json"), "test");
await using var orbit = await OrbitClient.OpenAsync(appKey,
    new OrbitOptions { OfflineKeys = trustedKeys });

var request = orbit.CreateOfflineRequest();
await File.WriteAllTextAsync("offline-request.json",
    JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
// Transfer the public request to an authorized seller/customer issuance flow.
var signedFile = await File.ReadAllTextAsync("licence.orbit");
var access = orbit.ImportOfflineFile(signedFile);
if (access.HasFeature("export"))
    await orbit.RequireAccessAsync("export");
```

Import verifies scope, binding, signature, expiry and renewal sequence before it
stores the original file. `RequireAccessAsync` and `EnsureAccessAsync` use only
that file while it is active; they do not refresh, make network requests or
prompt for a key. A restart requires currently configured trusted offline-purpose
keys that still verify the file, allowing trusted key rotation. Logout clears
local authority while retaining renewal and clock floors. A disconnected file
cannot be revoked immediately. See [offline storage details](ADVANCED.md#long-term-offline-files).

See [advanced integration](ADVANCED.md) for storage, backend proofs, local HTTP
tests and recovery details. Source and examples are [MIT licensed](LICENSE).
