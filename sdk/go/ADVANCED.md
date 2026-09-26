# Advanced Go integration

Use [the installed client](README.md) for normal applications. Parse an app key with `ParseAppKey` when a host needs its public scope fields. Low-level `NewClient` and `NewClientWithStorage` take the parsed `AppKey`; they do not own persistent restart state or a refresh worker.

## Installed options and machine binding

The zero value of `Options` stores private state in the current user's platform directory and computes the scoped `machine_v1` fingerprint from the native identity on supported Linux and Windows systems. If native identity is unavailable, the SDK sends no fingerprint and never substitutes a random value. The server still requires a fingerprint for HWID-locked licences.

Set `Options.BindingMode` to `BindingDisabled` for shared VM/container images. To use an application-owned digest, select `BindingCustom` and provide both `Fingerprint` (64 lowercase hex characters) and a `FingerprintProvider` beginning with `custom:`. Do not send raw machine identifiers. If the saved identity differs from the current identity, including a transition to or from unavailable, the SDK creates a fresh installation ID and clears the saved credential, cached grant and pending operation before recovery.

`Options.StatePath` selects a dedicated absolute state directory. Preserve the directory after a storage error; corrupt or missing initialized data is never silently reset. Linux uses a private owner-only file; Windows uses current-user DPAPI with a protected DACL. The explicit `OpenWindowsStorage` and `OpenSecretServiceStorage` adapters remain available for advanced credential-only persistence and take `AppKey` and `Device` values.

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

Snapshots expose `time.Time` dates, `time.Duration` offline allowance and `HasFeature`. Account and licence dates and durations also use Go's native time types. Display metadata does not authorize protected work; call `RequireAccess` immediately before each protected operation.

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
