# Use the Orbit HTTP API

Use the HTTP API to integrate a trusted backend or inspect the client protocol.
For licensing inside an installed application, use an Orbit SDK: it verifies
signed grants, handles retries and clock uncertainty, and checks access before
protected work. The runnable [account walkthrough](account_flow.py) shows HTTP
requests without claiming to provide those SDK protections.

## Choose the right API

| API | Caller | Credential | Typical use |
| --- | --- | --- | --- |
| `/api/client/v1` | Installed app or customer | Licence key, customer session or activation credential, as specified by each operation | Register, sign in, activate and validate |
| `/api/management/v1` | Your trusted backend | Scoped management Bearer token | Manage licences or make an online licence decision |
| `/api/v1` | Orbit dashboard | Developer browser session and CSRF token | Configure an application and its credentials |

The dashboard's **Integration** page supplies the public API origin,
`application_id`, `environment_id` and grant issuer for the selected Test or Live
environment. These IDs are not secrets. Test and Live have separate data and
credentials. Use HTTPS for a deployed integration. Never put passwords, licence
keys, sessions, activation credentials or management tokens in URLs, client source
code or logs. A management token belongs only on your backend.

The [OpenAPI document](https://orbit.mayvie.dev/api/openapi.json) provides the
current request/response schemas, required fields, authentication and error
responses. Open it while signed in to the Orbit dashboard. It covers client and
management operations, but is not a complete dashboard API reference.

## Try the customer flow

Create an Account or Both application in the dashboard's **Test** environment,
then create a policy and licence. Register a customer with that licence and
confirm the emailed link. From this repository's root, run:

```sh
python3 examples/http/account_flow.py -- https://orbit.mayvie.dev APP_ID ENVIRONMENT_ID
```

The script prompts for the customer credentials, lists owned licences, activates
one installation, validates it and signs out. It uses only Python's standard
library and retains credentials in memory. Keep `--` before the origin and IDs
so an ID beginning with a hyphen is treated as data. For a local HTTP service,
use `--local` before `--` and a literal loopback address:

```sh
python3 examples/http/account_flow.py --local -- http://127.0.0.1:8080 APP_ID ENVIRONMENT_ID
```

Use a 16–128 character ASCII installation ID made of letters, digits, `_` or
`-`, and reuse it for that installation. The walkthrough uses a licence without
hardware locking. It does not follow redirects or retry mutations. Signing out
revokes the customer session and its derived credentials; it does not release a
device slot. Use a disposable Test account and licence.

## Build an integration

| Step | Endpoint | Credential and result |
| --- | --- | --- |
| Register | `POST /api/client/v1/registrations` | Licence key and customer details in the JSON body; customer confirms email before sign-in |
| Sign in | `POST /api/client/v1/sessions` | Username and password in the JSON body; returns a scoped customer session, not a licence grant |
| List licences | `GET /api/client/v1/licences` | Customer session Bearer header and public scope query; choose a licence owned by that customer |
| Activate | `POST /api/client/v1/activations` | Licence key or customer session plus selected licence, installation ID and idempotency key in the body; returns an activation credential and signed grant |
| Recheck | `POST /api/client/v1/activations/{id}/validate` | Activation credential and the same installation binding in the body; returns a fresh signed grant |
| Sign out | `DELETE /api/client/v1/sessions/current` | Customer session Bearer header and public scope query; revokes the session |

For a key-only application, begin at activation with a key supplied by the user.
For an account application, login alone never permits a licensed feature: select
and activate a licence, then check its grant before each protected operation.
Do not accept a grant as valid merely because the HTTP response succeeded. Verify
its signature, issuer, app/environment scope, binding, expiry and feature rules;
the SDKs implement that validation. The HTTP walkthrough deliberately does not
authorize protected work. See the [Rust SDK example](../rust/licensed-export/README.md)
for a complete access check.

If an activation or claim response is uncertain, retry with the **same** input
and idempotency key within its replay window. A new key can create another
operation. Treat `403` as authoritative denial, including maintenance; a `503`
does not itself grant offline access. Handle the structured `error.code` and
`error.request_id`, not the display message. Full status and retry rules are in
OpenAPI.

## Protect your own backend

For customer-authenticated requests to your backend, the SDK can explicitly
extract a sensitive customer-session Authorization header. Send it only to your
trusted HTTPS backend with redirects disabled. The backend fixes the expected
application and environment, calls
`GET /api/client/v1/sessions/current` to derive the customer ID, then separately
calls `POST /api/management/v1/licence-decisions` with a narrowly scoped
`licences:validate` management token to check the selected licence, activation
and feature. Never trust a customer ID supplied by the client or use an offline
grant as backend identity proof. The runnable [backend example](../rust/licensed-backend/README.md)
implements this boundary.

The [SDK account guides](../../sdk/rust/README.md) cover registration resend,
additional claims, recovery, email changes, grant refresh and protected storage.
