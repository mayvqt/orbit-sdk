# `@orbit/installed-sdk`

Add licence activation and local feature checks to Node.js and Electron
applications. This installed client needs no management credential. The app
key names the API scope; it is not a secret.

## Install

Node.js 22 or newer is required. To use the SDK from source, install it from
your application's directory:

```sh
npm install --save /path/to/Orbit-SDK/sdk/typescript-installed
```

The package uses Koffi for native clocks, machine identity and protected
storage, and Koffi builds its native binding during installation. If your npm
version blocks dependency install scripts, approve and rebuild it before
opening a client:

```sh
npm install-scripts approve koffi
npm rebuild koffi
```

## Basic use

```js
import { Client, FeatureUnavailableError, NotActivatedError } from "@orbit/installed-sdk";

const client = await Client.open(process.env.ORBIT_APP_KEY);
try {
  await client.ensureAccess("export", async () => {
    // Replace this with the application's own trusted key-entry UI.
    return process.env.ORBIT_LICENCE_KEY ?? null;
  });
  await exportProtectedData();
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

`ensureAccess` resolves only when the licence includes the feature. It asks for
a key only when there is no usable installation credential; network, storage,
feature, cancellation and invalid-response errors propagate without prompting.
Call `requireAccess` immediately before each later protected operation; it
never prompts. Activation retries reuse a durable operation ID and require the
same input. Every operation accepts an `AbortSignal`; `close()` cancels
in-flight work and releases the exclusive installation lease.

## Installation state and machine binding

Linux and macOS store state in private, leased files. The default POSIX record
is not encrypted. Windows uses current-user DPAPI plus private DACLs, pinned
parent handles and an exclusive lease; DPAPI protects the record from other
Windows users, while same-user applications remain inside its trust boundary.
Pass `statePath` to use a dedicated directory.

`Client.open(appKey)` uses a best-effort `machine_v1` binding. Set
`machineBinding: false` for an unbound installation, or pass a `DeviceBinding`
with a caller-managed SHA-256 hex fingerprint and a `custom:` provider. The
server still enforces hardware-locked licence policy, and identity
unavailability never substitutes a random fingerprint.

## Accounts

The client also provides `login`, `account`, `ownedLicences`, `claimLicence`,
`activateAccount`, registration and resend, email-change and password-recovery
requests, and `logoutAccount`. Customer sessions and pending registration
credentials stay in memory and are cleared when their handles or the client
close. `OwnedLicence.concurrentSessionLimit` is separate from its device limit.

For a policy reset that requires proof of the prior credential, pass
`previousCredential` to `activate` or `activateAccount`. The SDK stores only its
digest for retries; the credential itself is never written to installation
state.

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

When the licence policy enables concurrent sessions, activation acquires a
short online session and the SDK renews it while the client is open.
`Snapshot.session` contains immutable session metadata. Session grants and IDs
are never restored from disk; after a restart the client acquires a fresh
session with its saved activation credential. During an outage, a running
client can use its current grant only until the exact signed expiry.

Release a seat while idle and acquire it again explicitly:

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
and disables automatic reacquisition until `startSession()`. Ordinary licences
and offline-file mode make both methods no-ops. A seat-limit denial keeps the
activation credential and never prompts for another key.

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
  await writeFile("offline-request.json", JSON.stringify(client.offlineRequest()));
  // Transfer that request to the authorized online issuance workflow, then
  // import the returned file on this installation:
  await client.importOfflineFile(await readFile("licence.orbit"));
  await client.requireAccess("export");
} finally {
  await client.close();
}
```

Import and access checks do not contact Orbit or prompt for a key. A valid file
selects its signed entitlements and absolute expiry, which keeps counting while
the process is closed. An expired file stays renewal-required until the user
imports a newer signed file. `logout()` clears the active file but keeps the
sequence and clock floors for that installation; a changed machine identity
starts a fresh installation. If clock evidence is inconsistent, the SDK denies
access and preserves the file for recovery or renewal.

Desktop files and clocks cannot detect restoration of a complete old
state-and-clock snapshot. See
[`offline-import.mts`](../../examples/typescript-installed/offline-import.mts)
for an unattended startup example.

## Updates and online limits

```js
const update = await client.checkForUpdate(1);
if (update) {
  const authorization = await client.authorizeDownload(update.release.id, update.artifact.id);
  await client.download(authorization, "./chosen-update.bin", { maxBytes: 200_000_000 });
}
```

Discovery defaults to channel `stable` and this runtime's OS and architecture;
pass `{ channel, target: { platform: "windows", architecture: "arm64" } }` to
choose another. It selects only that target and a greater release number;
display versions are labels. Authorization is a separate online check.

Downloads stream over verified HTTPS with at most five redirects, and the Orbit
ticket is stripped on every redirect, including one to the same origin. The
helper requests identity encoding, verifies exact length and SHA-256, then
atomically exposes the file at your chosen destination. `maxBytes` is required.
Set `replace: true` to replace an existing file; failed transfers preserve it.
No installer is run. The exported `downloadFile` helper accepts an
authorization without a client. Do not cache or log authorizations; obtain a
new one for a later attempt. Public delivery URLs can be shared; protected
seller endpoints must verify the ticket.

`usage(name)` and `resources(name)` read typed online counters.
`consume(name, units, { idempotencyKey })` reserves usage before work.
`acquireResource(name, resourceId, units, { idempotencyKey })` returns an
allocation; `releaseResource(name, allocationId, { idempotencyKey })` releases
it explicitly. Operation IDs are optional and generated securely; use your
durable job ID for restart-safe retries. `LimitReachedError` exposes the
validated `counter`, `idempotencyKey` and `requestedUnits`. An uncertain write
throws `MutationUncertainError` carrying the ID to retry with; a call without
that ID starts a new operation.

Usage replay returns the original period and outcome. Resource replay returns
the same allocation identity and units with its current state and counter; an
old acquire never reactivates a released allocation. Close and logout do not
release resources, and a failed business operation does not refund usage. Read
counters are not reservations, and `requireAccess` never consumes usage or
acquires a resource. Offline files cannot authorize these calls. Installed
clients cannot provide tamper-proof metering: gate valuable work on your
trusted backend when reporting must be enforced. See the
[installed example](../../examples/typescript-installed/online-operations.mts).

## Electron main process

Import `@orbit/installed-sdk/electron` in the main process after
`app.whenReady()` and pass Electron's `app` and `safeStorage`:

```js
import { app, safeStorage } from "electron";
import { openElectronClient } from "@orbit/installed-sdk/electron";

await app.whenReady();
const client = await openElectronClient(process.env.ORBIT_APP_KEY, { app, safeStorage });
```

The adapter uses asynchronous `safeStorage` encryption in addition to the
protected file and lease handling above. On Linux it requires a recognized
protected backend and rejects missing, `basic_text` and unknown backends. Use a
consistently signed macOS application so Keychain recognizes updates as the
same app.

Keep `Client`, licence keys and account tokens in the main process and expose
only the operation your renderer needs through a narrow preload API. Authorize
that operation in the main process even when the renderer requests it; the
[Electron example](../../examples/typescript-installed/main.mjs) does this for
one protected operation.
