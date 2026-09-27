# Orbit trusted backend SDK for JavaScript and TypeScript

This dependency-free ESM client runs on a trusted Node.js backend (Node 20 or
newer). It uses the built-in Fetch API and needs no build step.
From your backend project, install the package from this SDK checkout:

```sh
npm install /path/to/orbit-sdk/sdk/typescript
```

It makes online API requests and can verify seller download tickets locally.
For installed desktop/device access and offline licence files, use an installed
SDK such as [Rust](../rust/README.md) or [Node/Electron](../typescript-installed/README.md).

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

const decision = await orbit.requireFeature({
  customerSession,
  licenceId: request.body.licence_id,
  activationId: request.body.activation_id,
  entitlement: "export",
});
await assertOrbitCustomerLinkedTo(authenticatedUser, decision.customer_id);
// requireFeature throws OrbitAccessDeniedError when access is denied, so
// protected work below only runs once Orbit has approved this request.
```

The app key is a single public value, not a secret: `orbit_app_test_...` or
`orbit_app_live_...` followed by the application and environment IDs. Parsing
requires an HTTPS origin with no path, query, fragment or embedded
credentials; a malformed key throws `TypeError`. Requests use the origin
encoded in the key, include both scope IDs as query parameters, reject
redirects, time out after five seconds and cap JSON responses at 1 MiB.
Mutations are sent once. If an issue or key replacement response is lost or
unusable, `OrbitMutationUncertainError.idempotencyKey` gives you the exact
generated ID to reuse with the same input. The error is safe to log; it omits
the key itself and all request credentials.

Call `AppKey.parse(key)` directly if you want to validate or inspect a key
(`api_origin`, `issuer`, `application_id`, `environment_id`, `environment`)
before constructing a client; `new OrbitBackendClient({ appKey, ... })` also
accepts an already-parsed `AppKey`.

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

Use the bearer from the request's `Authorization` header. Do not take signing keys,
an audience URL, or a filesystem path from that request. The immutable verified
metadata contains licence, ticket, scope, release and artifact IDs, byte length,
SHA-256 and RFC3339 issuance/expiry times; it never contains the bearer itself.
Match it against a registry dedicated to the configured application/environment.
Tickets can be replayed until expiry (at most 120 seconds); they are not single-use
links. Never log the bearer or forward it to a storage redirect.

Orbit manages release metadata and issues tickets. Sellers host the files and
verify tickets at their download endpoint. The
[seller storage example](../../examples/python/seller-downloads/README.md) shows
the storage boundary; sellers retain their own hosting and credentials.

## Authenticate your own user first

Authenticate the user with your own application and authorize access to your
own account and resource before doing protected work. The customer-session
bearer may arrive in an `Authorization` header; send it only to the configured
Orbit origin. `verifyCurrentCustomerSession` asks Orbit to validate it and
returns the Orbit-derived customer ID. `decideFeature` (and `requireFeature`)
verify the session and send that ID to the authoritative management decision
endpoint. Their immutable result includes the same verified `customer_id`, so
you can check your application's account link without a separate session
lookup. Neither accepts a customer ID argument.

Never take a customer ID from the request body, use an offline grant as
backend identity proof or treat sign-in alone as licence access. If your app
links users to Orbit accounts, check that the authenticated user's stored link
matches the returned customer ID before protected work.

```js
const decision = await orbit.decideFeature({
  customerSession,
  licenceId: request.body.licence_id,
  activationId: request.body.activation_id,
  entitlement: "export",
});
if (!decision.allowed) throw new Error("Feature access denied");
await assertOrbitCustomerLinkedTo(authenticatedUser, decision.customer_id);
// Perform the operation, scoped to authenticatedUser and decision.customer_id.
```

Use `decideFeature` when you want to inspect a denial's `reason` yourself, and
`requireFeature` when you just want to guard protected work: it calls
`decideFeature` and throws `OrbitAccessDeniedError` (with a `reason` property)
instead of returning an `allowed: false` result.

The selected licence and activation IDs are selectors. Orbit checks current
ownership, activation validity, licence state, customer state and the exact
entitlement. `allowed: true` means Orbit approved this online request; your
app still needs its own resource authorization and transaction rules.

Reuse one client for the configured application environment. Each feature
decision makes two requests: a fresh customer-session verification and the
management decision. Using the returned `customer_id` avoids the third request
needed by a separate preliminary session lookup. Authorization is checked on
each call; it is not cached across protected operations.

## Management methods

* `searchLicences({ query, after, status })` sends search text in a POST body.
* `issueLicences({ policyId, quantity, reference, note, idempotencyKey })`
  issues 1 to 100 licences. `idempotencyKey` is optional: if omitted, the SDK
  generates a `crypto.randomUUID()`-strength key and returns it as
  `idempotencyKey` on the result, so you can retry deliberately with the exact
  same key. Returned licence keys are ephemeral secrets; handle them securely
  and never log them.
* `getLicence(id)` returns safe licence metadata. `offline_file_seconds` is the
  policy's separate long-term file limit (zero means disabled); `offline_seconds`
  remains the connected grant's offline allowance. `concurrent_session_limit`
  gives the floating-seat capacity separately from `device_limit`; zero means
  floating sessions are disabled.
* `replaceLicenceKey(id, { reason, idempotencyKey })` invalidates old
  activation credentials and returns any ephemeral key disclosure.
  `idempotencyKey` is optional, generated and returned the same way as above.
* `revokeLicence(id, reason)` permanently revokes the licence.

If a response is uncertain, keep the same input and reuse the ID from the
error instead of starting a new mutation:

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
`OrbitMutationUncertainError` exposes the idempotency key required to recover
an uncertain write, plus the safe failure metadata.
`OrbitAccessDeniedError` (thrown by `requireFeature`) exposes the same
`reason` as a denied `decideFeature` result. None of these contain the API
display message, response body, request credentials or full URL. Do not log
customer sessions, management tokens, licence keys or request bodies.

## Release management and licensed update discovery

Use `createRelease({ channel, version, notes })`, then
`createArtifact(releaseId, { platform, architecture, filename, byteLength, sha256,
deliveryMode, url, requiredFeature })`, and `publishRelease(releaseId)`.
`deliveryMode` is `public` or `protected`; the latter requires a seller endpoint
that verifies Orbit tickets. Public URLs remain shareable. Sellers host files;
these calls send only metadata to Orbit. `listReleases`, `getRelease`,
`updateRelease`, `updateArtifact`, `deleteArtifact` and `unpublishRelease` complete
the metadata surface. Edits supply the complete metadata or artifact input and
are permitted only before first publication. Published bytes and URLs are
immutable; publish another release for changes. Unpublishing prevents new
authorization and does not downgrade installed software.

Mutations accept `{ idempotencyKey, signal }` and return `idempotencyKey` alongside
the typed result; uncertain mutations expose that same ID on the error.
`listReleases({ channel, after, limit })` returns `{ items, nextCursor }`; pass
that opaque cursor unchanged as `after`. Page size defaults to 50, maximum 100.
Reading and writing metadata require `releases:read` and `releases:write`.

`checkForUpdate(licenceId, installedReleaseNumber, { channel, target, signal })`
returns a typed update or `null`. It defaults to `stable` and the server runtime's
target, so a backend distributing client updates should pass the client's
explicit `{ platform, architecture }`. It selects the exact target and a greater
release number; display version text is not ordered. Call
`authorizeDownload(licenceId, releaseId, artifactId, { signal })` separately for
fresh delivery authorization. Both calls require `licences:read` and
`releases:read` and check current licence eligibility. Authenticate your user and
verify ownership of the selected licence before calling these trusted methods.
Do not log or cache authorization responses or put management tokens in clients.

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
releases that exact allocation. Reads require `usage:read` or `resources:read`;
resource mutations require `resources:write`. `listResourceAllocations` accepts
`{ state, after, limit, signal }` and returns a bounded `{ items, nextCursor }` page.
The optional state is `active` or `released`.

These methods accept cancellation and securely generate optional operation IDs.
Use a durable job ID when a retry may survive a process restart.
`OrbitLimitReachedError` exposes validated `counter`, `idempotencyKey` and
`requestedUnits`; `OrbitMutationUncertainError.idempotencyKey` preserves the
operation to resume if its response is lost, invalid or cancelled. Never start a
new operation just to retry an unknown outcome. Usage retries retain the original
period and debit/denial; resource retries retain identity and units but report the
allocation's current state and current counter. Retrying a released acquire cannot
reactivate it. Resources persist until an explicit release and do not expire on a
process heartbeat. Read counters are not reservations.

Consumption is not automatically refunded if the business operation fails, and
Orbit's transaction is separate from your job database. Record the result with
your job to coordinate retries. Installed executables can bypass reporting;
authoritative metering requires gating the actual work here on your trusted
backend. Numeric `usage_limits` and `resource_limits` in licence metadata describe
policy, not currently available capacity. See the
[backend example](../../examples/typescript/online-operations.mts).

## Run the backend example

Set `ORBIT_APP_KEY`, `ORBIT_MANAGEMENT_TOKEN`, `ORBIT_CUSTOMER_SESSION`,
`ORBIT_LICENCE_ID` and `ORBIT_ACTIVATION_ID` in your backend environment.
`ORBIT_ENTITLEMENT` defaults to `export`. Run the example from the repository
root:

```sh
node examples/typescript/backend.mjs
```

It makes one online decision; it does not authenticate your users or start an
HTTP server. Call the same SDK method from an authenticated backend route after
your own user and account-binding checks. Keep real tokens out of shell history
and source files.
