# Run the C# SDK tests

These tests use synthetic credentials and local test servers. Run them when
changing the SDK, using .NET SDK 10.0.112 and the included dependency lockfiles.
The commands below run from the kit's root.

## Grant verification

```sh
dotnet restore sdk/csharp/tests/Orbit.Sdk.Tests.csproj --locked-mode
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -- contracts/sdk/grants.json
```

The shared corpus checks valid grants and rejects incorrect signatures, claims,
bindings and expiry values. Keep the SDK and corpus from the same download.

## Security and lifecycle

```sh
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -p:OrbitLocalDevelopment=true -- --security
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -p:OrbitLocalDevelopment=true -- --installed
```

This suite checks cancellation, retries, logout, offline expiry, malformed
responses, device parsing and credential storage. The installed suite also covers
first activation, restart, cached access, uncertain mutations, private file ownership,
clock failure, cancellation and automatic refresh. Test HTTP servers bind to
loopback only. The build flag permits those local test connections; ordinary
application builds require HTTPS.

Windows tests use the current user's DPAPI and temporary files. Tests requiring
symbolic-link privileges report a skip if those privileges are unavailable.
The ordinary Linux suite does not access your keyring. Run tests in a development
account with no production credentials.

Some additional modes exercise real sleep or OS storage. They need a dedicated
test environment and are separate from the commands above. Never use the bundled
synthetic signing keys for a real service.
