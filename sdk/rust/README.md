# Orbit Rust SDK

Add licence activation and feature checks to desktop or customer-hosted Rust software.
The installed client remembers activation, refreshes access, and restores eligible
cached access after a restart. Source is under the [MIT licence](../LICENSE).

## Install and setup

Use Rust/Cargo 1.98.1 or newer. Pin the public source release:

```toml
[dependencies]
orbit-sdk = { git = "https://github.com/mayvqt/orbit-sdk", tag = "v0.3.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Copy the public origin, issuer, application ID and environment ID from **Integration**
in your Orbit dashboard. These values are not secrets.

```rust,ignore
use orbit_sdk::{AppConfig, Cancellation, Client};

let orbit = Client::open(AppConfig {
    api_origin: "https://orbit.mayvie.dev".into(),
    issuer: grant_issuer.into(),
    application_id: application_id.into(),
    environment_id: environment_id.into(),
    fingerprint: None,
    fingerprint_provider: None,
}, None).await?;
let cancel = Cancellation::new();
```

`None` selects the current user's state directory. For a service or container, pass
`Some(Path::new("/absolute/dedicated/directory"))` on a persistent local volume.
Share one cloned `Client` within your process. A second opener for the same directory
returns `InstallationInUse`; leave its lock file in place.

## Activation

First try the protected action. Ask for a purchase key only when access is unavailable:

```rust,ignore
match orbit.require_access("export", &cancel).await {
    Ok(_) => {},
    Err(orbit_sdk::Error::Denied { code, .. }) if code == "access_unavailable" => {
        let key = prompt_for_licence_key();
        orbit.activate_key(&key, &cancel).await?;
        orbit.require_access("export", &cancel).await?;
    }
    Err(error) => return Err(error.into()),
}
```

The SDK creates and remembers installation and activation retry identities. Retry the
same key after an uncertain response; a different key is rejected until you reconcile
the pending activation. Keys, passwords and customer sessions are never saved.

## Check access and restarts

Call `require_access("export", &cancel).await?` immediately before every export.
Use `snapshot()` only to display status. Unknown or disabled features are denied.
`Client::open` tries online validation before permitting any restored offline access;
only a recognized temporary outage and an originally signed offline allowance qualify.
Strict-online licences require online validation after every restart.

Refresh scheduling belongs to the client. Persistent credentials are revocable and do
not grant unlimited access: each signed grant still has a fixed expiry. Closing the app
keeps the activation for its next launch:

```rust,ignore
orbit.close().await?;
```

Close cancels work, joins scheduling and checkpoints clock evidence before releasing
the local lease. It does not release the purchased device slot. `deactivate` deliberately
releases that slot after Orbit confirms the request.

Windows uses current-user DPAPI and a private protected DACL. Linux uses an owner-only
credential file (0700 directories, 0600 files), including headless installations. The
selected provider never falls back to a different store. Corrupt or missing established
state requires deliberate recovery; it never silently allocates a new installation.
An interrupted state write leaves a durable recovery marker, so restart cannot restore
a credential or grant from before an incomplete invalidation. Windows services must
open and use storage under their process account, without thread impersonation.

Sleep counts toward expiry. A clock rollback or inconsistent saved evidence requires
online validation. Local files cannot reliably detect restored VM/disk snapshots or
clock rollback above the last saved high-water value. Enforcement is not tamper-proof
against someone controlling the local account or machine.

## Optional: username/password sign-in

Customer accounts belong to people using **your software**. They are separate from your
Orbit dashboard account. Key-only integrations can skip this section.

After a buyer registers and confirms their email, use the same client:

```rust,ignore
orbit.login(&username, &password, &cancel).await?;
let page = orbit.owned_licences(None, &cancel).await?;
// Select a licence ID from page.items. Retain this operation ID for retries.
orbit.activate_account(&selected_id, &operation_id, &cancel).await?;
orbit.require_access("export", &cancel).await?;
```

Login and licence listing do not authorize protected work. Sessions stay in memory;
ordinary session expiry does not expire a separate installation credential. Explicit
session revocation, recovery and security changes can revoke it.

See [advanced APIs](advanced.md) for registration, account management, custom storage,
binding and explicit operation IDs. Run the [console example](../../examples/rust/licensed-export/README.md)
for activation and restart behavior. The [backend example](../../examples/rust/licensed-backend/README.md)
shows separate server-side customer authentication and licence enforcement.
