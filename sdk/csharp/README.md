# Orbit C# SDK

Add licence activation and feature checks to installed .NET applications.
Use .NET SDK 10.0.112, selected by the repository's `global.json`.
[Run the console example](../../examples/csharp/licensed-export/README.md) for a complete application.

## Install and configure

Reference the SDK project from your application's source checkout:

```sh
dotnet add MyApp/MyApp.csproj reference orbit-sdk/sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj
```

In Visual Studio, add the SDK project to your solution and reference it from your
app. Keep the SDK folder, `NuGet.Config` and dependency lockfile together.
Copy the four public values from your application's **Integration** page in
Orbit. Start with the **Test** environment.

```csharp
using Orbit.Sdk;

await using var orbit = await OrbitClient.OpenAsync(new AppConfig(
    "https://orbit.mayvie.dev", applicationId, environmentId, grantIssuer));
```

`OpenAsync` remembers the installation and refreshes its access automatically.
Share the client within your application. Disposing it saves state and stops
refresh without releasing the licence.

## First activation

Check access first. Ask for a licence key only when `access_unavailable` means
there is no activation, then check again:

```csharp
try
{
    await orbit.RequireAccessAsync("export", cancellationToken);
}
catch (OrbitException error) when (error.Error == OrbitError.Denied &&
                                    error.Code == "access_unavailable")
{
    var key = PromptForLicenceKey(); // Your application's input UI.
    await orbit.ActivateAsync(key, cancellationToken: cancellationToken);
}
await orbit.RequireAccessAsync("export", cancellationToken);
// Perform the protected export here.
```

Keep licence keys and passwords out of source, command-line arguments and logs.
Orbit never saves them.

## Access checks and restarts

Call `RequireAccessAsync` before each protected operation. `Snapshot()` is for
display; it cannot authorize work. Reopen the same configuration after restart:
the SDK validates its saved credential online first. During a recognized outage,
a verified offline-enabled grant may authorize access until its original expiry.
Do not reactivate automatically because the service is temporarily unavailable.

Windows state lives under `%LOCALAPPDATA%\Orbit`, protected by current-user
DPAPI. Linux uses private files under `$XDG_STATE_HOME/orbit` (normally
`~/.local/state/orbit`). Set `AppConfig.StatePath` to a dedicated absolute directory
for a service account or persistent container volume. Share one client per
installation; a competing process gets `installation_in_use`.

After uncertain activation delivery, retry the same key. The SDK retains the
operation ID for 24 hours and rejects changed input while it is unresolved.
`Logout()` deliberately clears saved access and pending activation.
`DeactivateAsync()` releases a device slot only after server acknowledgement.
Closing the application does neither.

<a id="customer-accounts"></a>

## Optional: username/password sign-in

These accounts belong to people using **your software**, separately from Orbit
dashboard accounts. Skip them when buyers activate with a licence key.
For Account or Both mode, register and confirm the email link, then sign in:

```csharp
await orbit.LoginAsync(username, password, cancellationToken);
var licences = await orbit.OwnedLicencesAsync(cancellationToken: cancellationToken);
// Let the user select a licence from licences.Items.
await orbit.ActivateAccountAsync(selectedLicenceId, cancellationToken: cancellationToken);
await orbit.RequireAccessAsync("export", cancellationToken);
```

Sign-in alone does not grant access. Customer sessions remain in memory;
installed access uses its separate saved credential. The [console example](../../examples/csharp/licensed-export/README.md)
also demonstrates registration, recovery, claiming a key and account logout.

## Advanced integration

[Advanced APIs and storage](ADVANCED.md) cover explicit installation IDs,
caller-owned transports/storage, hardware binding, backend session proofs and
diagnostics. The SDK and examples are [MIT licensed](LICENSE).
