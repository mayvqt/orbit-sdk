# HTTP API walkthrough

[`account_flow.py`](account_flow.py) calls Orbit's client API directly to show
the customer-account flow without an SDK. Orbit's
[HTTP API guide](https://orbit.mayvie.dev/guides/http) explains which API to
use, the credentials each one accepts and the full integration steps; the
[OpenAPI document](https://orbit.mayvie.dev/api/openapi.json) lists every
schema and error response.

The walkthrough does not verify signed grants or authorize protected work. For
licensing inside an installed application, use an Orbit SDK, which verifies
grants, handles retries and clock uncertainty, and checks access before
protected work.

## Run the customer flow

Create an Account or Both application in the dashboard's **Test** environment,
then create a policy and a licence. Register a customer with that licence and
confirm the emailed link. From this repository's root, run:

```sh
python3 examples/http/account_flow.py -- https://orbit.mayvie.dev APP_ID ENVIRONMENT_ID
```

The script prompts for the customer's credentials, lists owned licences,
activates one installation, validates it and signs out. It uses only Python's
standard library and keeps credentials in memory. Keep `--` before the origin
and IDs so an ID beginning with a hyphen is treated as data. For a local HTTP
service, put `--local` before `--` and use a literal loopback address:

```sh
python3 examples/http/account_flow.py --local -- http://127.0.0.1:8080 APP_ID ENVIRONMENT_ID
```

Use a 16–128 character ASCII installation ID made of letters, digits, `_` or
`-`, and reuse it for that installation. The walkthrough uses a licence without
hardware locking, does not follow redirects and does not retry mutations.
Signing out revokes the customer session and its derived credentials; it does
not release a device slot. Use a disposable Test account and licence.

See the [Rust SDK example](../rust/licensed-export/README.md) for a complete
access check and the [backend example](../rust/licensed-backend/README.md) for
verifying a customer on your own server.
