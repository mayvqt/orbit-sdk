# Orbit Rust SDK

Add licence activation and feature checks to an installed Rust application. The
client remembers activation, refreshes access in the background and restores
eligible saved access after a restart.

## Quick start

To use the SDK from source, add it to your application's `Cargo.toml`:

```toml
[dependencies]
orbit-sdk = { path = "../Orbit-SDK/sdk/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Copy the public app key from **Integration** in your Orbit dashboard and set it
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

`ensure_access` asks for a key only when the installation has no activation. It
never prompts because of a temporary outage or because the licence lacks the
feature. Call `require_access` before each later protected operation.
`Error::NotActivated` and `Error::FeatureUnavailable` are typed results, and
`error.code()` returns the stable protocol code.

The app key is public configuration, not a secret. Keep licence keys and passwords
out of source, command-line arguments and logs; the SDK never saves the purchase
key. Activation retries use a securely generated, durable operation ID. Use
`activate_with_id` when your application supplies its own ID for an uncertain retry.

See the [console example](../../examples/rust/licensed-export/README.md) for an
end-to-end flow.

## Installation state and machine binding

`Client::open` uses native `machine_v1` identity when available and the current
user's default state directory. On macOS 10.12 or newer, state lives under
`~/Library/Application Support/Orbit` and the identity is a scoped digest of
IOPlatformUUID; the crate links IOKit and CoreFoundation through the Apple SDK.
Orbit stores only the scoped fingerprint, never the raw machine identifier.

Call `Client::open_with_options` with `Options` to choose an explicit persistent
directory or change the binding policy. When the machine identity changes, the
SDK rotates the installation ID and clears its saved activation and cached grant
before recovery. [Storage and clock guarantees](advanced.md#storage-and-clock-guarantees)
describes the details.

## Customer accounts

Customer account methods are available on the same client. Account licence
results report dates as `SystemTime` and allowances as `Duration`.
`OwnedLicence::offline_file_duration` is zero when long-term offline files are
disabled, and between one day and 366 days when they are enabled. See
[customer accounts](advanced.md#customer-accounts) and the
[backend example](../../examples/rust/licensed-backend/README.md) for server-side
customer authentication.

## Long-term offline files

For a machine that stays disconnected longer than a connected grant allows,
configure an offline-purpose public JWKS. Ship it with your application or fetch
it from the app-key origin over verified HTTPS. Keep these trusted keys separate
from imported files, and never accept them from the person providing a file.

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

The request contains the public app key and the installation's binding identity.
It contains no licence key, customer session or credential. An authorized online
workflow issues and renews the file; the SDK verifies and imports the resulting
`.orbit` file locally. Import saves the signed file and its sequence and clock
floors before returning access, and reimporting the same file never extends its
expiry. While an offline file is active, `require_access` neither refreshes nor
prompts; an expired file returns a typed `offline_file_expired` denial.

An issued file cannot be revoked while the machine is disconnected. Sequence and
clock floors prevent ordinary replay and clock rollback, but restoring a complete
old machine or VM snapshot cannot be detected reliably. Tell customers about this
limit before issuing long-term access. See
[offline storage details](advanced.md#long-term-offline-files).

## Floating seats

Floating policies acquire a seat automatically after activation and renew it in
memory. `require_access` checks the current signed interval locally, and the
snapshot's `session` shows its ID, sequence and deadlines. A full seat pool, an
expired seat or an outage never asks for another licence key.

Call `end_session().await` when your app becomes idle and `start_session().await`
when it resumes. Ending clears local access before contacting Orbit and disables
automatic reacquisition. For a confirmed ordinary licence these calls do nothing;
an unknown policy is checked online first. Offline-file mode never switches online
on its own.

`close().await` makes a bounded attempt to release the seat and keeps the
installation credential. A restart obtains a new seat online. After a crash or
failed release, the old seat stays occupied until its interval ends, at most 120
seconds. During an outage the app keeps only the current verified interval, so a
remote revocation takes effect locally at that deadline. Session IDs and grants
are never restored from disk.

## Licensed updates

```rust,ignore
if let Some(update) = client.check_for_updates(installed_release_number).await? {
    let authorization = client
        .authorize_download(&update.release.id, &update.artifact.id).await?;
    authorization.download("update.bin", 128 * 1024 * 1024).await?;
}
```

Compare the increasing release number built into your app, not display versions.
Discovery defaults to the `stable` channel and the running desktop target.
`check_for_updates_with(number, UpdateOptions { .. })` accepts an explicit channel,
platform and architecture; there is no fallback to another target.

Authorization checks current licence eligibility separately from discovery. The
file streams directly from the seller over verified HTTPS. Every redirect strips
bearer credentials, and the SDK checks identity encoding, exact length and SHA-256
before atomically moving the temporary file into place. An existing destination is
refused unless you call `download_with(path, max_size, DownloadOptions {
replace_existing: true })`. A failed or cancelled download leaves an existing
destination untouched, and dropping the future removes its temporary file. The SDK
never runs or unpacks an installer.

Keep authorizations in memory and out of logs. Public URLs can be shared freely;
protected seller endpoints must verify the short-lived ticket or hand out an
expiring storage URL. See the
[seller example](../../examples/python/seller-downloads/README.md).

## Usage and resources

Configure an `exports` usage limit, then reserve a unit before doing the work:

```rust,ignore
let result = client.consume_with_id("exports", 1, export_job_id).await?;
println!("Remaining exports: {}", result.counter.remaining);
// Perform the export and record its result with export_job_id.
```

`usage(name)` and `resources(name)` read the current authoritative counters.
`acquire_resource(name, resource_id, units)` returns an allocation; remove the
actual resource before calling `release_resource(name, allocation_id)`. Closing,
logging out and outages do not release allocations.

`consume`, `acquire_resource` and `release_resource` generate secure operation IDs,
and each has a `_with_id` variant. `MutationError` carries `operation_id`,
`uncertain`, `cause` and, for capacity denials, a validated `counter`. Recover an
uncertain outcome by retrying with the same ID and identical input. Supply a stable
job ID of 16–128 characters when the operation must survive a restart or you may
drop the future, because a dropped future cannot return a generated ID. A generated
ID stays the same across that call's bounded retries.

A usage retry returns its original debit or denial, even across a UTC period
boundary. A resource retry returns the original allocation and charged units with
the current state and counter, so an old acquire can return
`ResourceState::Released` without reactivating the allocation. A later business
failure does not refund usage.

These operations always go online with the current activation credential. They do
not acquire floating seats, and offline files cannot authorize them.
`require_access` never consumes quota or allocates a resource. Installed programs
can be modified to skip reporting, so run the metering check and the actual work on
your trusted backend when enforcement must be authoritative.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on your
seller backend before looking up the artifact in your own registry. Configure the
exact HTTPS endpoint and a trusted connected-purpose JWKS; never take keys or a
destination URL from the ticket. The verifier makes no network requests.

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

A ticket expires within 120 seconds and can be replayed until then. Treat it as a
secret, never log it, and never use an artifact ID as an unchecked filesystem
path. Match the verified metadata against your registry before serving the object
or issuing a short-lived storage URL.
