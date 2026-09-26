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

The macOS native calls and Darwin file ABI were not exercised on Apple hardware
in this environment. Run the locked grants, security and installed suites on
macOS before claiming native macOS validation:

```sh
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -- contracts/sdk/grants.json
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -p:OrbitLocalDevelopment=true -- --security
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -p:OrbitLocalDevelopment=true -- --installed
dotnet build examples/csharp/licensed-export/Orbit.LicensedExport.csproj --no-restore
```

Building from this source checkout on macOS automatically compiles and copies
the small fixed-signature POSIX shim used for secure directory opens. Install
Apple Xcode Command Line Tools first (`xcode-select --install`). The helper
script emits a universal x86_64/arm64 dylib and checks both slices:

```sh
sdk/csharp/prepare-macos-shim.sh /tmp/liborbit_macos_shim.dylib
```

Packing on macOS builds that helper automatically. Packing from Linux or
Windows requires a universal dylib prepared on a Mac; the pack target fails
clearly when one is missing and places it in both NuGet runtime asset paths:

```sh
dotnet pack sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj --no-restore \
  -p:OrbitMacOSShimPath=/path/to/liborbit_macos_shim.dylib
```

Also run the native fingerprint check with an independently calculated
`machine_v1` digest for that Mac, and the interactive suspend check (suspend for
at least two seconds, resume, then press Enter):

```sh
ORBIT_NATIVE_FINGERPRINT_EXPECTED='<independent scoped digest>' dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -- --native-device
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -- --clock-suspend
ORBIT_NATIVE_GRANT_SUSPEND_TEST=1 dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --no-restore -p:OrbitLocalDevelopment=true -- --grant-suspend
```

The last mode verifies grant expiry after at least 45 seconds of actual sleep
and uses only a local synthetic server. Keep the raw `IOPlatformUUID` local;
the check needs only the derived expected digest.

The lower-level SDK constructor and storage adapters remain internal for SDK
fixtures. Application code should use the app-key entry point and the built-in
installed storage.

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
backend example in the repository's Rust SDK.

The SDK returns native result types. Timestamps use `DateTimeOffset`, elapsed
and offline durations use `TimeSpan`, and `Snapshot.HasFeature` is suitable for
display logic. Always call `RequireAccessAsync` immediately before protected
work; `Snapshot()` is informational.

## Warm access benchmark

With the locked dependencies already restored, run the opt-in Release benchmark
from the repository root:

```sh
dotnet run --project sdk/csharp/tests/Orbit.Sdk.Tests.csproj --configuration Release --no-restore -p:OrbitLocalDevelopment=true -- --benchmark-access
```

It activates a signed synthetic grant using private local installed storage and
the native clock, warms both paths, then measures five batches of 10,000 calls
for `RequireAccessAsync` and `Snapshot` separately. It reports median time and
current-thread allocated bytes per call, and verifies that measured loops add
no HTTP requests or storage writes while retaining per-call storage-version
checks.

On CachyOS Linux x86-64 with .NET 10.0.12, Release results were:

| Path | Baseline at `4e735f8` | Current |
| --- | ---: | ---: |
| `RequireAccessAsync` | 6.971 µs/op, 552 B/op | 3.429 µs/op, 192 B/op |
| `Snapshot` | 3.760 µs/op, 240 B/op | 3.235 µs/op, 120 B/op |

After timing, a separate 500-guard/500-snapshot verification pass observed
1,000 storage-version reads. The timed loops had zero writes and no increase
from the two setup HTTP requests. These are local measurements, not
cross-platform performance guarantees; Windows and macOS were not measured.
