# Orbit Rust SDK

Use the installed client to activate a licence and check protected features. The
current workspace version is an unreleased v0.4.0 candidate; build it from this
checkout rather than relying on a release tag or registry package.

Use the matching Orbit development server for this candidate. Its app-key
integration has not been deployed to the hosted production service yet.

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

Native macOS compilation and runtime checks are pending; this workspace was checked
on Linux only and has no Apple SDK or hardware.

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
