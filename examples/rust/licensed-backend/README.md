# Protect your API with Orbit

This Orbit-authored example is available under the [MIT licence](../../../sdk/LICENSE).

This Rust example checks an Orbit customer session and licence before allowing
an operation on your server. Orbit still handles sign-in and licensing. Any of
the Rust, Go or C# clients can call it after customer login and licence activation.
The backend verifies the presented customer session with Orbit, derives the
customer ID, then checks that customer's selected licence, activation and the
`export` feature using a narrowly scoped management credential. A login alone
does not authorize export. The example returns a placeholder export result; put
your real operation after the successful decision and scope its stored data to
the derived customer ID.

## Configure the server

Use an Account or Both application. Register and verify a customer, log in,
select a licence with `export = true`, and activate it. As workspace owner,
create a management credential with only `licences:validate` for the same app and
environment. Keep this credential exclusively on your backend. Orbit derives
its workspace from the credential; the example needs no caller-supplied workspace.

On a Unix host, create a file readable only by its owner (`chmod 600`) containing:

```json
{
  "orbit_origin": "https://orbit.mayvie.dev",
  "application_id": "YOUR_APPLICATION_ID",
  "environment_id": "YOUR_ENVIRONMENT_ID",
  "management_credential": "YOUR_PRIVATE_MANAGEMENT_CREDENTIAL",
  "port": 8090,
  "local_development": false
}
```

Replace the synthetic values locally. Keep the file outside Git, container
images and public client bundles. The example checks private Unix file
permissions and rejects symlinks, oversized files and unknown fields. From the extracted Rust kit, run:

```sh
cargo build --locked -p orbit-licensed-backend
./target/debug/orbit-licensed-backend /private/path/backend.json
```

The example listens only on `127.0.0.1`. Place your own authenticated application
API behind an HTTPS reverse proxy before accepting remote clients. Inbound
network rate limits belong at that proxy; the example bounds concurrent handlers
to 16, incoming JSON to 1 KiB and each authorization operation to ten seconds.
It does not install a proxy or expose a public listener.

For local development, compile with `--features local-development` and
set `local_development` to `true` with a literal loopback HTTP Orbit origin. This
option never disables TLS verification for HTTPS. The default build refuses it.

## Call the protected operation

After login, deliberately obtain a sensitive Authorization header from your SDK:

```rust,ignore
let authorization = orbit.customer_session_proof()?.authorization_header();
```

```go
proof, err := client.CustomerSessionProof()
if err != nil { return err }
authorization := proof.AuthorizationHeader()
```

```csharp
var authorization = client.CustomerSessionProof().AuthorizationHeader();
```

Use that value as the `Authorization` header of a `POST` to **your own trusted
HTTPS backend's** `/export`, with JSON containing `licence_id` and `activation_id`
from the selected activation. Disable redirects on that HTTP client. Do not put
the header in a URL, log it or save it. Do not send it to arbitrary third parties:
it carries the full authority of the current Orbit customer login session.
The opaque proof object redacts normal formatting; extracting its header is an
explicit secret-handling operation. Previously copied proofs still require
online validation, even after the local SDK has cleared its account.

The backend sends the token only to its fixed Orbit origin:

1. `GET /api/client/v1/sessions/current?application_id=...&environment_id=...`
   verifies the customer session and returns its scoped subject and expiry.
2. `POST /api/management/v1/licence-decisions?application_id=...&environment_id=...`
   binds the selected licence/activation to that derived customer and `export`.

The customer ID and feature are never accepted from the client body. Invalid,
expired, revoked or suspended sessions cannot authenticate. Wrong ownership,
inactive devices and denied features cannot export. Orbit failures, malformed
responses and redirects fail closed; there is no offline fallback or cached
identity decision. Responses use `Cache-Control: no-store`, and no request body,
Authorization header or management credential is logged by the example.

Customer sessions normally last 12 hours; activation credentials can outlive
them. This backend always requires a currently valid customer login session.
Verification is a decision for the current request, not a promise that a session
or licence cannot change immediately afterward. Sensitive transactions in your
own application still need their own resource authorization and concurrency rules.
