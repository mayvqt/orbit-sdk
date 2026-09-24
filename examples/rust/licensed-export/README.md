# Rust licensing example

Try licence activation and customer sign-in before adding the [SDK](../../../sdk/rust/README.md)
to your app. The example checks the `export` feature before producing a sample report.

## Run the example

You need Rust/Cargo 1.98.1 or newer. In the Orbit dashboard, select your application and
**Test** environment. Create a policy with `export` enabled and hardware locking
off, then issue a licence. Open **Integration** for your API origin, application
ID, environment ID and grant issuer. The issuer must match exactly; it may differ
from the API origin.

Run these commands from the extracted kit's root, replacing the four placeholders:

```sh
cargo build --locked -p orbit-licensed-export
./target/debug/orbit-licensed-export API_ORIGIN APP_ID ENVIRONMENT_ID ISSUER
```

On Windows, run `.\target\debug\orbit-licensed-export.exe` with the same arguments.
The default build requires HTTPS. For a local HTTP service only, add
`--features local-development` to the build command; HTTP is limited to a literal
loopback address such as `127.0.0.1`.

Enter `activate`, paste your licence key at the prompt, then enter `export`.
Use `status` to view access and expiry. Keep keys and passwords out of command-line
arguments. Input is visible in this demo's terminal.

## Customer sign-in

For an Account or Both application, enter `register` and follow the prompts.
Confirm the link in your email, then enter `login`, `licences` and `select`.
Choose a licence before running `export`; signing in alone does not grant access.

| Command | What it does |
| --- | --- |
| `more` | Shows the next page of licences. |
| `claim` | Adds another eligible licence key to the signed-in account. |
| `resend` | Sends a new verification email for this session's pending registration. |
| `recover` | Requests a password reset email. |
| `email` | Starts an email change; confirm both mailbox links, then sign in again. |
| `deactivate` | Releases this device slot once Orbit confirms the request. |
| `logout` | Clears local access. |
| `account-logout` | Also revokes the customer session and its activation credentials. |
| `quit` | Closes the example. |

Neither logout command releases a device slot. Credentials stay in memory, so
restart requires activation or sign-in again. Pass the printed installation ID as
the optional final argument to reuse the same installation. The example refreshes
access while open and checks it before every export.

Source and examples use the [MIT licence](../../../sdk/LICENSE).
