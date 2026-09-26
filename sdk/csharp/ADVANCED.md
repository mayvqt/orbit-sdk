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
private DACLs. Unsupported targets fail closed. Share one client per
installation; a second process is rejected while the lease is held.

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
default on supported Windows and Linux systems. Set
`DisableMachineBinding = true` for shared VM or container identities, or pass a
custom `Fingerprint(value, provider)` using a `custom:` provider. The SDK never
exports the raw machine ID. Unavailable identity sends no fingerprint. When the
current identity differs from saved state, the SDK creates a new installation
ID and clears the old credential, pending activation and cached grant before
the new identity can activate.

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
