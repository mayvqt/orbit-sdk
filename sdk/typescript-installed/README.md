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
identity, and protected storage. Linux and macOS use private leased files; the
Linux profile has automated coverage. Native macOS and Windows execution is
unverified.
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

For a policy reset that requires proof of the prior credential, pass
`previousCredential` to `activate` or `activateAccount`. The retry proof stores
only its digest; the credential is sent in the activation request and is not
written to installation state.

The account surface includes `login`, `account`, `ownedLicences`,
`claimLicence`, registration/resend, email-change/password-recovery requests,
and `logoutAccount`. Customer sessions and pending registration credentials
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

Linux checks cover storage, clock behavior and the Electron storage boundary
using an encrypted mock. Physical suspend/resume and native Electron, macOS and
Windows execution are unverified. Test each target's protected storage, clocks,
TLS and restart behavior on that platform before distributing your application.
