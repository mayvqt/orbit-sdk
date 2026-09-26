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

## Long-term offline-file verification

```sh
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -- --offline-vectors contracts/sdk/offline-files.json
```

All 104 shared cases exercise the separate offline purpose, keys, scope, binding,
expiry and sequence floor. Additional checks compare the canonical claim digest
with Python, reorder signed JSON fields, and enforce immutable entitlements and
bounded strict keys. This is verifier coverage; installed import, renewal and
restart integration are still pending and need their own lifecycle checks.

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

The security suite includes the scoped macOS fingerprint vector and injected
mach-timebase ratio/overflow cases on every host. A Linux run exercises the
portable private-file lease, restart and failure checks; it does not exercise
IOKit, `mach_continuous_time` or Darwin filesystem calls. The macOS storage
implementation uses private POSIX files rather than Keychain protection. Run
the same three commands above on macOS x64 and arm64 before claiming native
validation.

The `--clock-suspend` and `--grant-suspend` modes exercise real sleep and need a
dedicated interactive test machine; their commands are in `ADVANCED.md`.
Additional modes exercise native OS storage. They are separate from the commands
above. Never use the bundled synthetic signing keys for a real service.
