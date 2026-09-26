# Installed platform contract

This contract extends installed clients to macOS and JavaScript/TypeScript.
It defines implementation requirements, not evidence of native platform testing.
Each SDK's guide must list the platforms actually exercised by its checks.

## macOS

The public setup remains `Client.open(app_key)` with an optional state directory.
Use `~/Library/Application Support/Orbit/<scope_hash>` by default, with the same
canonical application/environment scope hash as the SDK's other installed
platforms. Never use a temporary directory as the default installation identity.

Use private POSIX files for the native SDK's default installed state, as on Linux.
Require an owner-only directory and regular state/lease files, reject symlinks and
hard-linked files, hold an exclusive process lease, and recheck pinned directory
and lease identities before granting access. Write state atomically with durable
ordering; interrupted writes must fail closed. On macOS use `F_FULLFSYNC` for
regular-file durability and synchronize the parent directory after replacement.
Do not silently weaken persistence if the filesystem rejects the required checks.
This protects against other users; it does not exclude the current user or an
administrator. It is not Keychain encryption.

The default `machine_v1` identity comes from the `IOPlatformUUID` property of
`IOPlatformExpertDevice`, read through IOKit. Normalize the UUID by trimming ASCII
whitespace, removing hyphens and lowercasing. Require exactly 32 hexadecimal
characters, excluding all-zero and all-`f` values. Hash the following UTF-8 bytes
with SHA-256 and return lowercase hex; there is no terminal newline:

```text
orbit-machine-v1\n<application_id>\n<environment_id>\nmacos\n<normalized_uuid>
```

Never transmit or persist the raw platform UUID. If identity cannot be read,
the native identity helper returns the existing device-identity error. Retain
the high-level client's existing best-effort setup and explicit custom or unbound
options. The server must still reject an unbound request for a machine-locked
licence; an unavailable identity cannot relax the licence's binding policy.

Elapsed time must include system sleep. Use `mach_continuous_time` and the cached
`mach_timebase_info` ratio, or an equivalent documented continuous system clock.
Sample fresh time on each decision. Check conversion overflow and clock rollback;
retain the existing wall-clock drift and persisted high-water checks. A wall clock
or process timer alone does not satisfy this requirement.

Apple references: [IOKit property ownership](https://developer.apple.com/documentation/iokit/1514293-ioregistryentrycreatecfproperty/),
[continuous time](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time),
and [durable synchronization](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html).

## Installed JavaScript / TypeScript

Provide a separate installed-client package from the trusted backend SDK. It must
implement the same app-key, signed-grant, installation, recovery and access
contracts in JavaScript/TypeScript, without wrapping another Orbit SDK.
Native operating-system bindings are permitted. Do not require a management
credential in installed software.

Keep `Client.open(appKey)`, `ensureAccess(feature, askForKey)`, `requireAccess`,
`snapshot` and `close` consistent with the installed SDKs. Return typed immutable
results and typed errors. Cancellation, retry identity, strict JSON/JWS validation,
bounded responses, scope checks and invalidation after concurrent operations must
preserve the same guarantees. Consume the shared app-key and grant vectors.

Electron licensing runs in the main process after app readiness. Keep credentials
and activation state out of renderer IPC. Expose only the application's required
operations through a narrow preload bridge; authorize protected work in the main
process. Browser-only JavaScript remains outside the installed-client contract.

Use Electron's asynchronous `safeStorage` encryption where available. Reject
unavailable or plaintext fallback protection; never enable plaintext encryption
as an automatic recovery path. Preserve the exclusive lease and atomic file
checks around encrypted state. Temporary key-store failure must preserve the
installation and return an error, rather than recreate it. Account for key
rotation when decrypting. Document the need for a consistent signed macOS app.
See the [Electron safeStorage contract](https://github.com/electron/electron/blob/v44.4.5/docs/api/safe-storage.md).

Plain Node.js may use the native SDK's private-file profile on Linux/macOS and
current-user DPAPI on Windows. Use the platform's continuous clock and scoped
machine identity; do not substitute `Date.now()` or an unsupported process timer.
Document any platform limitation rather than silently accepting weaker behavior.

## Acceptance

Exercise restart, exclusive lease contention, copied or replaced state, changed
machine identity, failed durable writes, sleep across expiry, wall-clock rollback,
lost activation replies and deliberate retry, logout racing refresh, cancellation,
and real TLS failures. Verify installed examples from a local package and an
unpacked source checkout. Report native execution, cross-compilation and mocked
OS tests separately. Native macOS and Windows runtime checks remain required
before claiming those platforms fully validated.
