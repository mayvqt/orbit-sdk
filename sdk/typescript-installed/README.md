# `@orbit/installed-sdk`

Add licence activation and local feature checks to Node.js and Electron
applications. This installed client is separate from the trusted-backend SDK
and does not require a management credential. The app key names the API scope;
it is not a secret.

To use the SDK from source, install it from your application's directory:

```sh
npm install --save /path/to/Orbit-SDK/sdk/typescript-installed
```

Node.js 22 or newer is required. The package uses Koffi for native clocks,
identity, and protected storage. Linux and macOS use private leased files.
Koffi builds its native binding during installation. If your npm version blocks
dependency install scripts, approve and rebuild Koffi from the application
directory before opening a client:

```sh
npm install-scripts approve koffi
npm rebuild koffi
```

Windows uses current-user DPAPI plus private DACLs, pinned parent handles, and
an exclusive lease. The default POSIX record is not encrypted. Windows DPAPI
protects it from other Windows users, while same-user applications remain inside
DPAPI's documented trust boundary.

Electron can use asynchronous `safeStorage` from the main process. On Linux the
adapter requires a recognized protected backend and rejects missing,
`basic_text`, and unknown backends. Electron's Windows record combines
`safeStorage` encryption with the same protected file and lease handling. The
Electron 44.4.5 asynchronous safeStorage API is the documented baseline; use a
consistent signed macOS application so Keychain recognizes updates as the same
app. [Electron safeStorage documentation](https://github.com/electron/electron/blob/v44.4.5/docs/api/safe-storage.md)

## Basic use

```js
import { Client, FeatureUnavailableError, NotActivatedError } from "@orbit/installed-sdk";

const client = await Client.open(process.env.ORBIT_APP_KEY);
try {
  const access = await client.ensureAccess("export", async () => {
    // Replace this with the application's own trusted key-entry UI.
    return process.env.ORBIT_LICENCE_KEY ?? null;
  });
  if (access.has("export")) await exportProtectedData();
} catch (error) {
  if (error instanceof NotActivatedError) {
    showActivationRequired();
  } else if (error instanceof FeatureUnavailableError) {
    showFeatureUnavailable();
  } else {
    throw error;
  }
} finally {
  await client.close();
}
```

`ensureAccess` asks for a key only when there is no usable installation
credential. Network, storage, feature-policy, cancellation, and invalid-response
errors propagate without prompting. `requireAccess` never prompts. Activation
retries reuse a durable operation ID and require the same input. An
`AbortSignal` can cancel an operation; `close()` cancels in-flight work and
releases the exclusive installation lease.

## Application version

Pass `Client.open(appKey, { appVersion: "2.4.1" })` so your licence policy can
require a minimum application version and offer updates. Use one to four
dot-separated numbers without leading zeros, optionally followed by a
`-pre-release` and `+build` part, in at most 32 bytes (for example
`3.0.0-beta.2+build.5`). `open` rejects an invalid value with a `configuration`
error and sends a valid one with activation and validation.

When the policy blocks this version, access checks throw
`AppVersionUnsupportedError`, and cached or offline access is not used. Ask the
user to update the application; the activation is kept, so the updated version
continues without a new licence key. `snapshot.updateAvailable` contains a
newer version when the policy offers one and is `null` otherwise. Every request
also identifies the SDK with an `Orbit-Client` header containing its language,
version and platform.

## Floating sessions

When the licence policy enables concurrent sessions, activation automatically
acquires a short online session and the SDK renews it while the client is open.
`Snapshot.session` contains immutable session metadata. Session grants and IDs
are never restored from disk; after a restart the client acquires a fresh
session using its saved activation credential. During an outage, a running
client can use its current grant only until the exact signed expiry.

Applications can release a seat while idle and explicitly acquire it again:

```js
import { Client } from "@orbit/installed-sdk";

const client = await Client.open(process.env.ORBIT_APP_KEY);
try {
  const access = await client.ensureAccess("export", async () => process.env.ORBIT_LICENCE_KEY ?? null);
  if (access.session) {
    console.log("Session expires at", access.session.expiresAt);
    await client.endSession();
    await client.startSession();
  }
  await client.requireAccess("export");
} finally {
  await client.close();
}
```

`endSession()` clears local authority before asking Orbit to release the seat
and disables automatic reacquisition until `startSession()` is called.
Ordinary licences and offline-file mode make both methods no-ops. A seat-limit
denial keeps the activation credential and never prompts for another key.

For a policy reset that requires proof of the prior credential, pass
`previousCredential` to `activate` or `activateAccount`. The retry proof stores
only its digest; the credential is sent in the activation request and is not
written to installation state.

The account surface includes `login`, `account`, `ownedLicences`,
`claimLicence`, registration/resend, email-change/password-recovery requests,
and `logoutAccount`. An `OwnedLicence.concurrentSessionLimit` is separate from
its device limit. Customer sessions and pending registration credentials
stay in memory and are cleared when their handles or client are closed. Access
grants and the persistent activation credential are protected by the selected
installation-storage profile.

The `Client.open(appKey)` default uses a best-effort `machine_v1` binding. Set
`machineBinding: false` to request an unbound installation, or pass a
`DeviceBinding` with a caller-managed 32-byte SHA-256 hex fingerprint and a
`custom:` provider. The server still enforces hardware-locked licence policy.
Identity unavailability never substitutes a random fingerprint.

## Long-term offline files

Offline-file verification uses a separately distributed trusted public JWKS.
Supply it when opening the client; never take a verification key from the file
being imported. `offlineRequest()` returns the public installation request as
serializable JSON and makes no network call:

```js
import { readFile, writeFile } from "node:fs/promises";
import { Client } from "@orbit/installed-sdk";

const client = await Client.open(process.env.ORBIT_APP_KEY, {
  offlineKeys: await readFile("offline-jwks.json"),
});
try {
  const request = client.offlineRequest();
  await writeFile("offline-request.json", JSON.stringify(request));
  // Transfer that request to the authorized online issuance workflow.
} finally {
  await client.close();
}
```

On the offline machine, import the returned `.orbit` file and guard the local
operation. `examples/typescript-installed/offline-import.mts` is an unattended
startup example driven by `ORBIT_APP_KEY`, `ORBIT_OFFLINE_JWKS_PATH` and
`ORBIT_OFFLINE_FILE_PATH`. Import and access checks do not contact Orbit or
prompt for a key. A valid file selects its signed entitlements and absolute
expiry; an expired file stays renewal-required until the user deliberately
imports a newer signed file. `logout()` clears the active file but retains the
sequence and clock floors for that installation. Switching back online keeps
those floors, and changing the machine identity starts a fresh installation.
Offline expiry continues to count while the process is closed. If system clock
evidence is inconsistent, the SDK denies access and preserves the file for
recovery or renewal. Desktop files and clocks cannot detect restoration of a
complete old state-and-clock snapshot; this storage profile does not provide a
hardware-backed rollback counter.

## Updates and online limits

```js
const update = await client.checkForUpdate(1);
if (update) {
  const authorization = await client.authorizeDownload(update.release.id, update.artifact.id);
  await client.download(authorization, "./chosen-update.bin", { maxBytes: 200_000_000 });
}
```

Discovery defaults to channel `stable` and this runtime's OS/architecture. Set
`{ channel, target: { platform: "windows", architecture: "arm64" } }` explicitly
when needed. It selects only that target and a greater release number; display
versions are labels. Authorization is a separate online check. Files stream over
verified HTTPS with at most five redirects, and the Orbit ticket is stripped on
every redirect, including one to the same origin. The helper requests identity
encoding, verifies exact length and SHA-256, then atomically exposes the file.
Choose the destination and byte limit explicitly. Set `replace: true` to replace
an existing file; failed transfers preserve it. No installer is run. The exported
`downloadFile` helper also accepts an authorization without a client. Public
delivery URLs can be shared; protected seller endpoints must verify the ticket.
Do not cache or log authorizations; obtain a new one for a later download attempt.

`usage(name)` and `resources(name)` read typed online counters.
`consume(name, units, { idempotencyKey })` reserves usage before work.
`acquireResource(name, resourceId, units, { idempotencyKey })` returns an allocation;
`releaseResource(name, allocationId, { idempotencyKey })` releases it explicitly.
Operation IDs are optional and generated securely; use your durable job ID for
restart-safe retries. `LimitReachedError` exposes the validated `counter`,
`idempotencyKey` and `requestedUnits`. An uncertain write throws
`MutationUncertainError` with the same ID to use for recovery. A new invocation
without that ID starts a new operation. All calls accept an `AbortSignal`.

Usage replay returns the original period and outcome. Resource replay returns the
same allocation identity and units with its current state and current counter;
an old acquire never reactivates a released allocation. Close and logout do not
release resources. Read counters are not reservations, and `requireAccess` never
consumes usage or acquires a resource. Offline files cannot authorize these calls.
Installed clients cannot provide tamper-proof metering: gate valuable work on your
trusted backend when reporting must be enforced. A failed business operation does
not refund consumed usage. See the [installed example](../../examples/typescript-installed/online-operations.mts).

## Electron main process

Import `@orbit/installed-sdk/electron` from the main process after
`app.whenReady()`. The adapter rejects non-main-process calls and invalid
client options. Keep `Client`, licence keys, and account tokens in main;
expose only the application's needed operation through a narrow preload API.
Authorize the operation in the main process even when the renderer requests it.
The example under [`examples/typescript-installed`](../../examples/typescript-installed)
uses exactly one protected operation and never returns credentials to the
renderer.

## Platform notes

Test your packaged application's protected storage, clocks, TLS and restart
behavior on each platform you ship, as part of your normal release checks.
