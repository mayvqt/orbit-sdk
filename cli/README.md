# Orbit command-line tool

`orbit` manages licences and releases for one application environment from
your terminal or build pipeline. It calls Orbit's management API with a scoped
management token, so it never needs your dashboard password.

## Install

Install Rust, then build and install the `orbit` binary from this repository:

```sh
cargo install --locked --git https://github.com/mayvqt/orbit-sdk orbit-cli
```

From a local checkout, run `cargo install --locked --path cli` instead.

## Save credentials

1. In Orbit, open your application's **Test** or **Live** environment and go to
   **Integration**. Copy the **Application ID** and **Environment ID**.
2. Under **Workspace management credentials**, choose **Create credential** and
   select only the operations you need:
   - `licences:read` and `licences:write` for licence commands;
   - `devices:read` and `devices:write` for devices, floating sessions and
     offline files;
   - `releases:read` and `releases:write` for release commands.
3. Save the token. `orbit` reads it from standard input or a hidden prompt,
   never from a command-line argument:

```sh
orbit credentials set \
  --application-id 'YOUR_APPLICATION_ID' \
  --environment-id 'YOUR_ENVIRONMENT_ID'
```

Paste the `orb_mgmt_…` token at the prompt, or pipe it in from your secret
store. The token and IDs are saved to `credentials.json` in your user
configuration directory (`$XDG_CONFIG_HOME/orbit` or `~/.config/orbit` on
Linux, `~/Library/Application Support/orbit` on macOS, `%APPDATA%\Orbit` on
Windows), readable only by you. On Linux and macOS, `orbit` refuses to use the
file if other users can access it. Set `ORBIT_CONFIG_DIR` to use another
directory.

```sh
orbit credentials show     # token shown as orb_mgmt_…last4
orbit credentials remove
```

Keep Test and Live apart with named profiles. Pass `--profile` to any command,
or set `ORBIT_PROFILE`:

```sh
orbit --profile live credentials set \
  --application-id 'YOUR_APPLICATION_ID' \
  --environment-id 'YOUR_LIVE_ENVIRONMENT_ID'
orbit --profile live licences list
```

In CI, skip the file and set environment variables instead:
`ORBIT_MANAGEMENT_TOKEN`, `ORBIT_APPLICATION_ID` and `ORBIT_ENVIRONMENT_ID`.
They override the saved profile, and `--application-id` and
`--environment-id` override both. `--api-url` or `ORBIT_API_URL` selects
another Orbit origin; the default is `https://orbit.mayvie.dev`.

## Licences

```sh
orbit policies list
orbit licences issue --policy 'POLICY_ID' --quantity 5 --reference 'order-1042'
orbit licences list --query 'order-1042'
orbit licences show 'LICENCE_ID'
```

`issue` and `replace-key` print new licence keys once; store them immediately.
`list` searches by licence ID, full key, key suffix or reference. Add
`--status revoked` or `--status all` to include revoked licences, and pass the
printed `--after` cursor to fetch the next page.

Every change takes an audit `--reason`:

```sh
orbit licences suspend 'LICENCE_ID' --reason 'Chargeback opened'
orbit licences reinstate 'LICENCE_ID' --reason 'Chargeback resolved'
orbit licences revoke 'LICENCE_ID' --reason 'Refunded' --yes
orbit licences extend 'LICENCE_ID' --by 30d --reason 'Renewal order-1043'
orbit licences entitlements 'LICENCE_ID' --enable export --disable beta \
  --reason 'Upgraded to Pro'
orbit licences annotate 'LICENCE_ID' --note 'Priority support' \
  --reason 'Support ticket 88'
orbit licences replace-key 'LICENCE_ID' --reason 'Key posted publicly'
```

Revocation is permanent, so `revoke` requires `--yes`. Durations accept `d`,
`h`, `m` and `s` suffixes. `entitlements` changes only the names you pass and
keeps the licence's other values.

Devices, floating sessions and offline files:

```sh
orbit licences devices 'LICENCE_ID'
orbit licences reset-device 'LICENCE_ID' 'ACTIVATION_ID' --reason 'New laptop'
orbit licences sessions 'LICENCE_ID' --state active
orbit licences end-session 'LICENCE_ID' 'SESSION_ID' --reason 'Crashed client'
orbit licences offline-file 'LICENCE_ID' --request request.json \
  --duration 180d --output licence.orbit
```

Device resets use the licence's transfer allowance. `offline-file` signs the
request file your application exported and writes the result to a new file.

## Releases

Upload each file to your own host first, then register it against a draft.
`add-artifact` reads your local copy to compute the exact byte length and
SHA-256, so the local file must be identical to the one the URL serves.

```sh
orbit releases create --version 2.4.0 --notes-file CHANGELOG.txt
orbit releases add-artifact 'RELEASE_ID' dist/app-linux-x86_64.tar.gz \
  --url 'https://downloads.example.com/2.4.0/app-linux-x86_64.tar.gz' \
  --platform linux --arch x86_64
orbit releases add-artifact 'RELEASE_ID' dist/app-windows-x86_64.zip \
  --url 'https://downloads.example.com/protected/app-windows-x86_64.zip' \
  --platform windows --arch x86_64 --delivery protected \
  --required-feature pro_updates
orbit releases publish 'RELEASE_ID'
```

`create` uses the `stable` channel unless you pass `--channel`. Files are
`--delivery public` by default: anyone holding the URL can download.
`--delivery protected` URLs must verify the Orbit download ticket and cannot
contain a query string. `--required-feature` limits the file to licences with
that entitlement; `--filename` sets the name shown to users when it differs
from the local file name.

```sh
orbit releases list --channel stable
orbit releases show 'RELEASE_ID'
orbit releases edit 'RELEASE_ID' --notes 'Fixes export on Windows'
orbit releases remove-artifact 'RELEASE_ID' 'ARTIFACT_ID'
orbit releases unpublish 'RELEASE_ID'
```

Only drafts can be edited or have files added and removed; publish a new
release to change a published one. Unpublishing stops new update checks and
downloads, and publishing again keeps the release number and files.

## Output, retries and exit status

Commands print tables or fields. Add `--json` to print the API response
exactly as Orbit returned it, for scripts.

Operations that create or replace something send a new idempotency key on each
run. If a connection fails or Orbit is unavailable, the change may still have
been applied; `orbit` prints the key it used. Repeat the same command with
`--idempotency-key` and that key to retry safely without applying it twice.

Errors print Orbit's error code, message and request ID to standard error.
`orbit` exits with `0` on success, `1` when Orbit or the local system reports
an error, and `2` when the command is incomplete or invalid. Run
`orbit help <command>` for every option.
