# Orbit Rust SDK

Use the installed client to activate a licence and check protected features.
To use the SDK from source, add it to your application's `Cargo.toml`:

```toml
[dependencies]
orbit-sdk = { path = "../Orbit-SDK/sdk/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Copy the public app key from **Integration** in your Orbit dashboard. Set it once
before launching your app:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
```

```rust
use orbit_sdk::Client;
use std::{error::Error, io::{self, Write}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app_key = std::env::var("ORBIT_APP_KEY")?;
    let orbit = Client::open(&app_key).await?;
    let access = orbit.ensure_access("export", || {
        print!("Licence key: ");
        io::stdout().flush().ok()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok()?;
        Some(input.trim().to_owned())
    }).await;
    if let Err(error) = access {
        let _ = orbit.close().await;
        return Err(error.into());
    }
    println!("Export authorized: synthetic report");
    orbit.close().await?;
    Ok(())
}
```

`ensure_access` asks for a key only when no activation exists. It never opens a prompt
for a temporary service outage or a licence that lacks the feature. Use `require_access`
before each later protected operation. `Error::NotActivated` and
`Error::FeatureUnavailable` are typed results; `error.code()` retains stable protocol
codes.

## Long-term offline files

For a machine that will remain disconnected longer than a connected grant allows,
configure an offline-purpose public JWKS distributed with your application or fetched
from the app-key origin over verified HTTPS. Keep these trusted keys separate from
imported files and do not accept them from the person providing a file.

```toml
[dependencies]
orbit-sdk = { path = "../Orbit-SDK/sdk/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
```

```rust,ignore
use orbit_sdk::{Client, Options};
use std::{error::Error, fs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let app_key = std::env::var("ORBIT_APP_KEY")?;
    let trusted_keys = fs::read("trusted-offline-jwks.json")?;
    let client = Client::open_with_options(&app_key, Options {
        offline_keys: Some(trusted_keys),
        ..Options::default()
    }).await?;

    let request = client.offline_request()?;
    fs::write("offline-request.json", serde_json::to_vec_pretty(&request)?)?;
    // Transfer this public request to an authorized seller/customer issuance workflow.
    let file = fs::read("licence.orbit")?;
    client.import_offline_file(&file).await?;
    client.require_access("export").await?;
    client.close().await?;
    Ok(())
}
```

The request includes the public app key and stable installation/binding identity; it
contains no licence key, customer session or credential. Issuance and renewal happen
through an authorized online workflow. This SDK verifies and imports the resulting
`.orbit` file locally. Import persists the signed file and sequence/clock floors before
returning access. Reimporting the same file never extends its absolute expiry.
`require_access` does not refresh or prompt while an offline file is active; expiry
returns a typed `offline_file_expired` denial.

An already-issued file cannot be revoked promptly while disconnected. Sequence and
clock floors prevent ordinary replay and rollback, but restoring a complete old machine
or VM snapshot cannot be detected reliably. Tell users this limitation before issuing
long-term access; see [offline storage details](advanced.md#long-term-offline-files).

The zero-argument options use native `machine_v1` identity when available and the
current user's default state directory. On macOS 10.12 or newer, the state path is under
~/Library/Application Support/Orbit; the identity is the scoped digest of
IOPlatformUUID. The native crate links IOKit and CoreFoundation through the Apple
SDK. Orbit stores only the scoped fingerprint, never the raw machine identifier.
To use an explicit persistent directory or change binding policy, call
`Client::open_with_options` with `Options`. Identity changes rotate the installation
ID and clear its saved activation and cached grant before recovery.

See [platform validation](advanced.md#platform-validation) for the tested scope.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on your
seller backend before selecting an object from your own registry. Configure the exact
HTTPS endpoint and a trusted connected-purpose JWKS; never take keys or a destination
URL from the ticket. This verifier makes no network request.

```rust
use orbit_sdk::DownloadTicketVerifier;
use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let app_key = env::var("ORBIT_APP_KEY")?;
    let bearer = env::var("ORBIT_DOWNLOAD_TICKET")?;
    let keys = fs::read("connected-jwks.json")?;
    let verifier = DownloadTicketVerifier::new(
        &app_key,
        "https://downloads.example.com/artifacts",
        &keys,
    )?;
    let ticket = verifier.verify(&bearer)?;
    // Match all returned fields against the seller's artifact registry.
    println!("artifact {}: {} bytes, sha256 {}", ticket.artifact_id(), ticket.byte_length(), ticket.sha256());
    Ok(())
}
```

The ticket expires within 120 seconds and can be replayed until then. Treat the
bearer as sensitive, never log it, and never use an artifact ID as an unchecked
filesystem path. Match the verified metadata against your registry before serving
an object or issuing a short-lived storage URL.

Account licence results retain dates as `SystemTime` and allowances as `Duration`.
`OwnedLicence::offline_file_duration` is zero when long-term offline files are
disabled; an enabled policy uses a duration from one day through 366 days.

Activation retries use a securely generated, durable operation ID automatically. Use
`activate_with_id` when your application needs to supply an ID for an uncertain retry.
The purchase key is never persisted. Customer account methods are available on the
same client; see [advanced APIs](advanced.md#customer-accounts).

See the [console example](../../examples/rust/licensed-export/README.md) for an end-to-end
flow and the [backend example](../../examples/rust/licensed-backend/README.md) for
server-side customer authentication. Storage and clock behavior is described in the
[advanced guide](advanced.md#storage-and-clock-guarantees).

## Floating seats

Floating policies acquire a seat automatically after activation and renew it in
memory. `require_access` checks the current signed interval locally. The snapshot's
`session` exposes its ID, sequence and deadlines for display. A full seat pool,
expired seat or outage never asks for another licence key.

Use `end_session().await` while idle and `start_session().await` on resume. Ending
clears authority before the network request and disables automatic reacquisition.
Confirmed ordinary licences use these calls as local no-ops; unknown policy is checked
online first. Offline-file mode never switches online implicitly.

`close().await` attempts a bounded seat release without deleting the installation
credential. Restart obtains a new seat online. A crash or failed release can hold
capacity for the old interval's remaining lifetime, at most 120 seconds. An outage
permits only the current verified interval; remote revocation can take effect locally
at that deadline. Session IDs and grants are never restored from disk.

## Licensed updates

```rust,ignore
if let Some(update) = client.check_for_updates(installed_release_number).await? {
    let authorization = client
        .authorize_download(&update.release.id, &update.artifact.id).await?;
    authorization.download("update.bin", 128 * 1024 * 1024).await?;
}
```

Use the increasing release number embedded in your app, rather than comparing display
versions. Discovery defaults to `stable` and the actual supported desktop target.
`check_for_updates_with(number, UpdateOptions { .. })` accepts an explicit channel,
platform and architecture. There is no target fallback.

Authorization checks current licence eligibility separately from discovery. The
file streams directly from the seller over verified HTTPS. Every redirect strips
bearer credentials; identity encoding, exact length and SHA-256 are checked before
the temporary file is atomically exposed. Existing destinations are refused unless
`download_with(path, max_size, DownloadOptions { replace_existing: true })` is used.
A failed or cancelled download preserves an existing destination. Dropping the future
removes its temporary file. Nothing executes or unpacks an installer.

Keep authorizations in memory and out of logs. Public URLs are shareable. Protected
seller endpoints must verify the short ticket or broker an expiring storage URL;
see the [seller example](../../examples/python/seller-downloads/README.md).

## Usage and resources

Configure an `exports` usage limit and reserve a unit before performing work:

```rust,ignore
let result = client.consume_with_id("exports", 1, export_job_id).await?;
println!("Remaining exports: {}", result.counter.remaining);
// Perform the export and record its result with export_job_id.
```

`usage(name)` and `resources(name)` read current authoritative counters.
`acquire_resource(name, resource_id, units)` returns an allocation; remove the actual
resource before `release_resource(name, allocation_id)`. These mutations also have
`_with_id` variants. Close, logout and outages do not release allocations.

`consume`, `acquire_resource` and `release_resource` generate secure operation IDs.
`MutationError` retains `operation_id`, `uncertain`, `cause` and a validated capacity
`counter` when applicable. Recover uncertain outcomes with the same ID and identical
input. Use a stable job ID of 16–128 characters for restarts or when you may drop an
in-flight future: a dropped future cannot return an automatically generated ID.
An auto-generated ID stays the same throughout that invocation's bounded retries.

Usage replays retain their original debit or denial across UTC period boundaries.
Resource replays retain allocation identity and charged units, with the current
state and counter. An old acquire can return `ResourceState::Released`; it does not
reactivate that allocation. A later business failure does not refund usage.

These explicit online operations require the current activation credential. They do
not acquire floating seats, and offline files cannot authorize them. `require_access`
never consumes quota or allocates a resource. Installed executables can be modified
or bypass reporting; put the metering check and actual work on your trusted backend
when you need authoritative enforcement.
