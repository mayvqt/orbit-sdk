# Orbit trusted backend SDK for JavaScript and TypeScript

This dependency-free ESM client runs on a trusted Node.js backend (Node 20 or
newer). It uses the built-in Fetch API and needs no build step. Check out the
`v0.2.0` source tag, then install the local package folder with
`npm install ./orbit-sdk/sdk/typescript`. No npm registry package is published.
It makes online API requests; it does not validate signed grants or provide the
offline/device behavior in Orbit's Rust, Go, C#, C++, and Python SDKs.

## Configure

Get the public API origin, `application_id` and `environment_id` from Orbit's
Integration page. Create a management credential with only the permissions
your backend needs. Keep the token in server configuration; never put it in
browser code, a URL, an error log or a response to users.

```js
import { OrbitBackendClient } from "@orbit/trusted-backend-sdk";

const orbit = new OrbitBackendClient({
  apiOrigin: process.env.ORBIT_API_ORIGIN,
  applicationId: process.env.ORBIT_APPLICATION_ID,
  environmentId: process.env.ORBIT_ENVIRONMENT_ID,
  managementToken: process.env.ORBIT_MANAGEMENT_TOKEN,
});
```

The origin must use HTTPS and have no path, query, fragment or embedded
credentials. Requests use that fixed origin, include both scope IDs as query
parameters, reject redirects, time out after five seconds and cap JSON
responses at 1 MiB. Mutations are sent once. If an issue or key replacement
request has an uncertain result, retry deliberately with the same input and
idempotency key.

## Authenticate your own user first

Authenticate the user with your own application and authorize access to your
own account and resource before doing protected work. The customer-session
bearer may arrive in an `Authorization` header; send it only to the configured
Orbit origin. `verifyCurrentCustomerSession` asks Orbit to validate it and
returns the Orbit-derived customer ID. `decideFeature` verifies the session
again and sends that ID to the authoritative management decision endpoint. It
does not accept a customer ID argument.

Never take a customer ID from the request body, use an offline grant as
backend identity proof or treat sign-in alone as licence access. If your app
links users to Orbit accounts, check that the authenticated user's stored link
matches the returned customer ID before protected work.

```js
const subject = await orbit.verifyCurrentCustomerSession(customerSession);
await assertOrbitCustomerLinkedTo(authenticatedUser, subject.customer_id);

const decision = await orbit.decideFeature({
  customerSession,
  licenceId: request.body.licence_id,
  activationId: request.body.activation_id,
  entitlement: "export",
});
if (!decision.allowed) throw new Error("Feature access denied");
// Perform the operation, scoped to authenticatedUser and subject.customer_id.
```

The selected licence and activation IDs are selectors. Orbit checks current
ownership, activation validity, licence state, customer state and the exact
entitlement. `allowed: true` means Orbit approved this online request; your
app still needs its own resource authorization and transaction rules.

## Management methods

* `searchLicences({ query, after, status })` sends search text in a POST body.
* `issueLicences({ policyId, quantity, reference, note, idempotencyKey })`
  issues 1 to 100 licences. Returned keys are ephemeral secrets; handle them
  securely and never log them.
* `getLicence(id)` returns safe licence metadata.
* `replaceLicenceKey(id, { reason, idempotencyKey })` invalidates old
  activation credentials and returns any ephemeral key disclosure.
* `revokeLicence(id, reason)` permanently revokes the licence.

`OrbitApiError` exposes only `status`, the safe structured `code` and
`requestId`. `OrbitTransportError` exposes a safe failure `code`. Neither
contains the API display message, response body, request credentials or full
URL. Do not log customer sessions, management tokens, licence keys or request
bodies.

## Run the backend example

Set `ORBIT_API_ORIGIN`, `ORBIT_APPLICATION_ID`, `ORBIT_ENVIRONMENT_ID`,
`ORBIT_MANAGEMENT_TOKEN`, `ORBIT_CUSTOMER_SESSION`, `ORBIT_LICENCE_ID` and
`ORBIT_ACTIVATION_ID` in your backend environment. `ORBIT_ENTITLEMENT` defaults
to `export`. Run the example from the repository root:

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
node --test
```

Tests mock Fetch and never contact Orbit.
