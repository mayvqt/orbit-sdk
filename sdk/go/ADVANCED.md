# Advanced Go integration

Use [the installed client](README.md) for normal applications. Parse an app key with `ParseAppKey` when a host needs its public scope fields. Low-level `NewClient` and `NewClientWithStorage` take the parsed `AppKey`; they do not own persistent restart state or a refresh worker.

## Installed options and machine binding

The zero value of `Options` stores private state in the current user's platform directory and computes the scoped `machine_v1` fingerprint from the native identity on Linux, macOS and Windows. macOS reads `IOPlatformUUID` from IOKit and scopes the normalized UUID to the `macos` family. If native identity is unavailable, the SDK sends no fingerprint and never substitutes a random value. The server still requires a fingerprint for HWID-locked licences.

Set `Options.BindingMode` to `BindingDisabled` for shared VM/container images. To use an application-owned digest, select `BindingCustom` and provide both `Fingerprint` (64 lowercase hex characters) and a `FingerprintProvider` beginning with `custom:`. Do not send raw machine identifiers. If the saved identity differs from the current identity, including a transition to or from unavailable, the SDK creates a fresh installation ID and clears the saved credential, cached grant and pending operation before recovery.

`Options.StatePath` selects a dedicated absolute state directory. Preserve the directory after a storage error; corrupt or missing initialized data is never silently reset. Linux and macOS use pinned private owner-only files and an exclusive lease; macOS requires `F_FULLFSYNC` and parent-directory synchronization. Windows uses current-user DPAPI with a protected DACL. The explicit `OpenWindowsStorage` and `OpenSecretServiceStorage` adapters remain available for advanced credential-only persistence and take `AppKey` and `Device` values.

## Long-term offline files

Set `Options.OfflineKeys` to the bounded trusted JWKS JSON for the app's Test or Live
environment. The parser accepts only ES256 signing keys with matching `offline-test-`
or `offline-live-` key IDs. Distribute keys with trusted software/configuration or fetch
them from the parsed app-key origin over verified HTTPS; never import a key from the
signed file itself.

`OfflineRequest()` returns the current installation ID and optional binding pair in a
serializable request. It makes no HTTP request and consumes no installation slot. An
authorized online issuance workflow returns the compact `.orbit` file;
`ImportOfflineFile(ctx, file)` verifies it and durably switches the installation to
that file's authority. Imports reject lower sequence numbers and conflicting equal
sequences. `Snapshot.OfflineFileMode` distinguishes file access from a cached connected
grant; `RequireAccess` uses the local continuous clock and storage lease without
refreshing or prompting. Expiry produces `offline_file_expired`.

The file's signed expiry is absolute and never moves forward on reimport. Expiry,
refunds and revocation cannot promptly recall a file on a disconnected machine. Saved
sequence/time floors resist ordinary file replay and clock changes, while a person who
restores a complete old disk or VM snapshot can roll local history back. Do not promise
protection against whole-machine rollback.

## Seller-side download tickets

Use a separate verifier on the seller's protected endpoint. It takes the public app
key, the endpoint's exact HTTPS URL, and trusted connected-purpose JWKS bytes:

```go
verifier, err := orbit.NewDownloadTicketVerifier(appKey, endpointURL, trustedJWKS)
if err != nil { return err }
ticket, err := verifier.Verify(bearerToken)
if err != nil { return err }
artifact, ok := registry[ticket.ArtifactID()]
if !ok || artifact.ReleaseID != ticket.ReleaseID() || artifact.SHA256 != ticket.SHA256() || artifact.ByteLength != ticket.ByteLength() {
	return errors.New("unknown artifact")
}
```

The verifier uses only copied trusted keys, pins the exact endpoint audience and
app-key scope, and returns typed metadata. It does not fetch keys or files. Compare
the metadata to your own registry before serving an object or issuing a short-lived
storage URL; do not use the token or artifact ID as a path. A valid ticket is replayable
until its short expiry.

## macOS build and validation

Build installed clients on macOS 10.12 or newer with cgo enabled and the Xcode Command Line Tools installed. The macOS files link the system IOKit and CoreFoundation frameworks for platform identity and use `mach_continuous_time` for sleep-inclusive elapsed time. A filesystem that rejects `F_FULLFSYNC` fails closed; the SDK does not fall back to ordinary fsync for file contents. When cgo is disabled, Open returns `ErrNativeSupportRequired`.

Portable Go tests cover the macOS UUID framing fixture, timebase scaling and overflow, while Linux runs the POSIX lease, restart and storage-failure tests. Native macOS compilation and runtime behavior are unverified. Before distributing a Mac application, run the package tests and exercise sleep across expiry, lease contention, copied or replaced state and durable-write failure on a Mac.

## Access and mutation IDs

`RequireAccess` returns errors that can be matched with `errors.Is(err, orbit.ErrNotActivated)` and `orbit.ErrFeatureUnavailable`. The error also retains stable codes `access_unavailable` and `feature_unavailable`. `EnsureAccess` takes `func(context.Context) (string, error)` and invokes it only for `ErrNotActivated`; it never prompts after an outage or feature denial.

The installed client generates secure mutation IDs when callers omit them:

```go
_, err := client.Activate(ctx, key)
_, err = client.ActivateAccount(ctx, licenceID)
err = client.Deactivate(ctx)
```

Pass an explicit ID as the final optional argument to retain control over an uncertain retry. Installed activation IDs are saved before the request and require the same input when retried. `ActivateWithPrevious` and `ActivateAccountWithPrevious` support authorized rebinding with the original credential. Do not generate a new ID to recover an uncertain response.

## Native result types and customer accounts

Snapshots expose `time.Time` dates, `time.Duration` offline allowance and `HasFeature`. Account and licence dates and durations also use Go's native time types. `OwnedLicence.OfflineFileDuration` is zero when long-term files are disabled; otherwise the policy duration is from one day through 366 days. Display metadata does not authorize protected work; call `RequireAccess` immediately before each protected operation.

Use `Register` and optional `ResendRegistration`, then complete the email link before `Login`. `ClaimLicence` adds a key to an account; `OwnedLicences` returns one bounded page and accepts its `NextCursor` on the next call. `Logout` clears local access. `LogoutAccount` also requests remote customer-session revocation. Ordinary session expiry does not expire the separate installation credential.

`CustomerSessionProof().AuthorizationHeader()` exposes sensitive Bearer proof for your own trusted HTTPS backend. Never log, persist or forward it through redirects. The backend must verify it online with `GET /api/client/v1/sessions/current`, then separately check licensed access. See the [backend example](../../examples/rust/licensed-backend/README.md).

## Transport and diagnostics

Production transports require HTTPS and certificate verification, disable redirects, cap responses at 64 KiB and bound each operation to 30 seconds. Go `context.Context` cancellation stops requests and retries. The explicit `orbit_local` build tag adds `OpenLocal` and `NewLocalTransport` for HTTP on literal loopback IP addresses.

`client.SupportSummary(err)` contains only public app/environment scope, a stable error code, validated request reference and local timestamp. It exposes no key, credential, device identity or account state.

## Warm access benchmark

From `sdk/go`, run the opt-in signed installed-client benchmarks with a private local state directory and the native clock:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -run '^$' \
  -bench '^BenchmarkInstalledWarmAccess$' -benchtime=10000x -count=5 -benchmem
```

The benchmark checks that every warm call still reads the storage version, sends no HTTP request, and writes no state. The before measurement used the hot-path code from baseline commit `4af8920` with this same harness. On Linux/amd64 with Go 1.27.1-X:nodwarf5 (Intel Core i7-10700K, Linux 7.2.6), the median of five 10,000-call runs was:

| Operation | Before | After |
| --- | --- | --- |
| `RequireAccess` | 12.03 µs/op, 1,680 B/op, 24 allocs/op | 5.97 µs/op, 840 B/op, 12 allocs/op |
| `Snapshot` | 6.01 µs/op, 792 B/op, 12 allocs/op | 5.93 µs/op, 808 B/op, 12 allocs/op |

The warm `RequireAccess` path now uses one checked snapshot rather than checking it twice. Each snapshot samples the native time anchor once. The small `Snapshot` timing difference is within this single-host benchmark's noise; no cross-platform performance guarantee is implied.
