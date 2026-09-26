# Orbit Rust SDK

Use the installed client to activate a licence and check protected features. The
current workspace version is an unreleased v0.4.0 candidate; build it from this
checkout rather than relying on a release tag or registry package.

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

The zero-argument options use native `machine_v1` identity when available and the
current user's default state directory. Orbit stores only the scoped fingerprint,
never the raw machine identifier. To use an explicit persistent directory or change
binding policy, call `Client::open_with_options` with `Options`. Identity changes rotate
the installation ID and clear its saved activation and cached grant before recovery.

Activation retries use a securely generated, durable operation ID automatically. Use
`activate_with_id` when your application needs to supply an ID for an uncertain retry.
The purchase key is never persisted. Customer account methods are available on the
same client; see [advanced APIs](advanced.md#customer-accounts).

See the [console example](../../examples/rust/licensed-export/README.md) for an end-to-end
flow and the [backend example](../../examples/rust/licensed-backend/README.md) for
server-side customer authentication. Storage and clock behavior is described in the
[advanced guide](advanced.md#storage-and-clock-guarantees).
