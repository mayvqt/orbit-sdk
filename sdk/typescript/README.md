# Orbit trusted backend SDK for JavaScript and TypeScript

This dependency-free ESM client runs on a trusted Node.js backend (Node 20 or
newer). It uses the built-in Fetch API, needs no build step, makes online API
requests and verifies seller download tickets locally. For installed desktop or
device access and offline licence files, use an installed SDK such as
[Rust](../rust/README.md) or [Node/Electron](../typescript-installed/README.md).

From your backend project, install the package from this SDK checkout:

```sh
npm install /path/to/orbit-sdk/sdk/typescript
```

## Quickstart

Copy the app key from Orbit's **Integration** page (start with the Test
environment) and a management credential with only the permissions your
backend needs. Keep both in server configuration; never put them in browser
code, a URL, an error log or a response to users.

```js
import { OrbitBackendClient } from "@orbit/trusted-backend-sdk";

const orbit = new OrbitBackendClient({
  appKey: process.env.ORBIT_APP_KEY,
  managementToken: process.env.ORBIT_MANAGEMENT_TOKEN,
});

// After your own user authentication and resource authorization:
const decision = await orbit.requireFeature({
  customerSession,
  licenceId: request.body.licence_id,
  activationId: request.body.activation_id,
  entitlement: "export",
});
await assertOrbitCustomerLinkedTo(authenticatedUser, decision.customer_id);
// requireFeature throws OrbitAccessDeniedError when access is denied, so this
// point is reached only when Orbit approved the request.
```

`requireFeature` verifies the customer session with Orbit, sends the verified
customer ID to the management decision endpoint and throws
`OrbitAccessDeniedError` (with a `reason`) on denial. Use `decideFeature` for
the same check when you want to inspect an `allowed: false` result yourself.
`verifyCurrentCustomerSession` returns the verified session alone. The
customer-session bearer may arrive in an `Authorization` header; send it only
to the configured Orbit origin.

Neither method accepts a customer ID. Never take one from the request body,
use an offline grant as backend identity proof or treat sign-in alone as
licence access. If your app links users to Orbit accounts, check that the
authenticated user's stored link matches the returned `customer_id` before
protected work. The licence and activation IDs are selectors: Orbit checks
current ownership, activation validity, licence and customer state, and the
exact entitlement. An approval covers this online request only; it is not
cached, and your app still applies its own resource authorization and
transaction rules. Reuse one client for the configured application environment.

The app key is public: `orbit_app_test_...` or `orbit_app_live_...` followed by
the application and environment IDs. A malformed key throws `TypeError`; call
`AppKey.parse(key)` to validate or inspect one (`api_origin`, `issuer`,
`application_id`, `environment_id`, `environment`) before constructing a
client, which also accepts a parsed `AppKey`. Requests go only to the key's
HTTPS origin, reject redirects, time out after five seconds and cap JSON
responses at 1 MiB.

## Management methods

* `searchLicences({ query, after, status })` sends search text in a POST body.
* `issueLicences({ policyId, quantity, reference, note, idempotencyKey })`
  issues 1 to 100 licences. Returned licence keys are ephemeral secrets; never
  log them.
* `getLicence(id)` returns safe licence metadata. `offline_file_seconds` is the
  policy's long-term file limit (zero means disabled); `offline_seconds` is the
  connected grant's offline allowance. `concurrent_session_limit` gives the
  floating-seat capacity separately from `device_limit`; zero disables
  floating sessions.
* `replaceLicenceKey(id, { reason, idempotencyKey })` invalidates old
  activation credentials and returns any ephemeral key disclosure.
* `revokeLicence(id, reason)` permanently revokes the licence.

Mutations are sent once. `idempotencyKey` is optional: when omitted, the SDK
generates a secure random key and returns it as `idempotencyKey` on the result.
If a response is lost or unusable, `OrbitMutationUncertainError` carries the
key to reuse with the same input instead of starting a new mutation:

```js
import { OrbitMutationUncertainError } from "@orbit/trusted-backend-sdk";

try {
  await orbit.issueLicences({ policyId, quantity: 1, reference, note });
} catch (error) {
  if (!(error instanceof OrbitMutationUncertainError)) throw error;
  await orbit.issueLicences({
    policyId,
    quantity: 1,
    reference,
    note,
    idempotencyKey: error.idempotencyKey,
  });
}
```

`OrbitApiError` exposes only `status`, the safe structured `code` and
`requestId`. `OrbitTransportError` exposes a safe failure `code`.
`OrbitMutationUncertainError` adds the `idempotencyKey` and keeps the failure
as `cause`. None of these contain the API display message, response body,
request credentials or full URL, so they are safe to log. Do not log customer
sessions, management tokens, licence keys or request bodies.

## Release management and licensed update discovery

Use `createRelease({ channel, version, notes })`, then
`createArtifact(releaseId, { platform, architecture, filename, byteLength,
sha256, deliveryMode, url, requiredFeature })`, and `publishRelease(releaseId)`.
`deliveryMode` is `public` or `protected`; the latter requires a seller
endpoint that verifies Orbit tickets. Sellers host files; these calls send only
metadata to Orbit. `listReleases`, `getRelease`, `updateRelease`,
`updateArtifact`, `deleteArtifact` and `unpublishRelease` complete the metadata
surface. Edits supply the complete input and are permitted only before first
publication; publish another release for changes. Unpublishing prevents new
authorization and does not downgrade installed software.

Mutations accept `{ idempotencyKey, signal }` and return `idempotencyKey` with
the typed result. `listReleases({ channel, after, limit })` returns
`{ items, nextCursor }`; pass that opaque cursor unchanged as `after`. Page size
defaults to 50, maximum 100. Reading and writing metadata require
`releases:read` and `releases:write`.

`checkForUpdate(licenceId, installedReleaseNumber, { channel, target, signal })`
returns a typed update or `null`. It defaults to `stable` and the server
runtime's target, so pass the client's explicit `{ platform, architecture }`
when distributing client updates. It selects the exact target and a greater
release number; display version text is not ordered. Call
`authorizeDownload(licenceId, releaseId, artifactId, { signal })` separately
for fresh delivery authorization. Both require `licences:read` and
`releases:read` and check current licence eligibility. Verify that your user
owns the selected licence first, and do not log or cache authorization
responses.

## Usage and resource limits

After authenticating your user and binding their selected licence, reserve the
usage before doing valuable work on your backend:

```js
const consumption = await orbit.consume(licenceId, "exports", 1, {
  idempotencyKey: durableJobId,
});
// Record consumption with this job, then perform the export once.
```

`usage(licenceId, name)` reads a counter; `consume` requires `usage:write` and
returns the counter after that operation. `resources(licenceId, name)` reads
allocated units; `acquireResource(licenceId, name, resourceId, units, options)`
reserves them, and `releaseResource(licenceId, name, allocationId, options)`
releases that exact allocation. Reads require `usage:read` or
`resources:read`; resource mutations require `resources:write`.
`listResourceAllocations` accepts `{ state, after, limit, signal }` and returns
a bounded `{ items, nextCursor }` page; `state` is `active` or `released`.

Use a durable job ID as `idempotencyKey` when a retry may survive a process
restart. `OrbitLimitReachedError` exposes validated `counter`,
`idempotencyKey` and `requestedUnits`. Usage retries retain the original period
and debit or denial; resource retries retain identity and units but report the
allocation's current state and counter, and never reactivate a released
allocation. Resources persist until an explicit release. Read counters are not
reservations, and licence `usage_limits` and `resource_limits` describe policy,
not available capacity.

Consumption is not refunded if the business operation fails, and Orbit's
transaction is separate from your job database: record the result with your job
to coordinate retries. Installed executables can bypass reporting, so
authoritative metering belongs here on your trusted backend. See the
[backend example](../../examples/typescript/online-operations.mts).

## Verify seller download tickets

On your download backend, configure the exact protected HTTPS endpoint and raw
connected-purpose public JWKS JSON supplied through your trusted configuration.
The verifier makes no network request and requires no management credential:

```js
import { readFileSync } from "node:fs";
import { DownloadTicketVerifier } from "@orbit/trusted-backend-sdk";

const downloads = new DownloadTicketVerifier({
  appKey: process.env.ORBIT_APP_KEY,
  endpoint: "https://downloads.example.com/artifacts",
  trustedKeys: readFileSync("connected-jwks.json"),
});

function authorizeArtifact(bearer, registry) {
  const ticket = downloads.verify(bearer); // Throws OrbitDownloadTicketError.
  const artifact = registry.get(ticket.artifactId);
  if (!artifact || artifact.releaseId !== ticket.releaseId ||
      artifact.byteLength !== ticket.byteLength || artifact.sha256 !== ticket.sha256) {
    throw new Error("Artifact unavailable");
  }
  return artifact; // Serve this registry entry or issue a short-lived storage URL.
}
```

Pass the bearer from the request's `Authorization` header. Never take signing
keys, an audience URL or a filesystem path from the request. The immutable
result contains licence, ticket, scope, release and artifact IDs, byte length,
SHA-256 and RFC 3339 issuance and expiry times, never the bearer itself. Match
it against a registry for the configured application environment. Tickets can
be replayed until expiry (at most 120 seconds); never log the bearer or forward
it to a storage redirect. The
[seller storage example](../../examples/python/seller-downloads/README.md)
shows a complete endpoint.

## Run the backend example

Set `ORBIT_APP_KEY`, `ORBIT_MANAGEMENT_TOKEN`, `ORBIT_CUSTOMER_SESSION`,
`ORBIT_LICENCE_ID` and `ORBIT_ACTIVATION_ID` (`ORBIT_ENTITLEMENT` defaults to
`export`), then run from the repository root:

```sh
node examples/typescript/backend.mjs
```

It makes one online decision; call the same method from an authenticated
backend route after your own user and account-binding checks.
