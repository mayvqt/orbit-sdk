# Orbit trusted backend SDK for JavaScript and TypeScript

This dependency-free ESM client runs on a trusted Node.js backend (Node 20 or
newer). It uses the built-in Fetch API and needs no build step. This checkout
contains the unreleased v0.4 candidate; the package is not published to npm.
From your backend project, install the package from this SDK checkout:

```sh
npm install /path/to/orbit-sdk/sdk/typescript
```

It makes online API requests; it does not validate signed grants or provide the
offline/device behavior in Orbit's Rust, Go, C#, C++, and Python SDKs.

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

const subject = await orbit.verifyCurrentCustomerSession(customerSession);
await assertOrbitCustomerLinkedTo(authenticatedUser, subject.customer_id);

await orbit.requireFeature({
  customerSession,
  licenceId: request.body.licence_id,
  activationId: request.body.activation_id,
  entitlement: "export",
});
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

## Authenticate your own user first

Authenticate the user with your own application and authorize access to your
own account and resource before doing protected work. The customer-session
bearer may arrive in an `Authorization` header; send it only to the configured
Orbit origin. `verifyCurrentCustomerSession` asks Orbit to validate it and
returns the Orbit-derived customer ID. `decideFeature` (and `requireFeature`)
verify the session again and send that ID to the authoritative management
decision endpoint. Neither accepts a customer ID argument.

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
// Perform the operation, scoped to authenticatedUser and subject.customer_id.
```

Use `decideFeature` when you want to inspect a denial's `reason` yourself, and
`requireFeature` when you just want to guard protected work: it calls
`decideFeature` and throws `OrbitAccessDeniedError` (with a `reason` property)
instead of returning an `allowed: false` result.

The selected licence and activation IDs are selectors. Orbit checks current
ownership, activation validity, licence state, customer state and the exact
entitlement. `allowed: true` means Orbit approved this online request; your
app still needs its own resource authorization and transaction rules.

## Management methods

* `searchLicences({ query, after, status })` sends search text in a POST body.
* `issueLicences({ policyId, quantity, reference, note, idempotencyKey })`
  issues 1 to 100 licences. `idempotencyKey` is optional: if omitted, the SDK
  generates a `crypto.randomUUID()`-strength key and returns it as
  `idempotencyKey` on the result, so you can retry deliberately with the exact
  same key. Returned licence keys are ephemeral secrets; handle them securely
  and never log them.
* `getLicence(id)` returns safe licence metadata.
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

## Run focused tests

```sh
cd sdk/typescript
npm test
```

Tests mock Fetch and never contact Orbit.
