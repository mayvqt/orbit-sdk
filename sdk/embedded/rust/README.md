# Orbit embedded Rust

The `no_std` wrapper uses the allocation-free C client and adds no Rust
dependencies.

Add it from the local checkout:

```toml
[dependencies]
orbit-embedded = { path = "path/to/Orbit-SDK/sdk/embedded" }
```

The Cargo manifest lives at the embedded SDK root so the crate contains its C
sources and headers alongside the Rust wrapper. A local crate archive builds
without sibling repository directories; it does not require a separately
downloaded C SDK.

Implement `Platform` with the board's maintained TLS/crypto, trusted clock,
CSPRNG and durable storage. `begin_request` must send the complete request
before returning its HTTP status; `read_response` then streams response chunks.
This keeps request borrows separate from reuse of the transaction arena. Storage
and security requirements are the same as the [C client](../README.md).

Parse the public app key once and keep its `AppKey` alive while the client uses
the borrowed configuration. The decoded origin is stored inline in `AppKey`;
application and environment IDs borrow the input string:

```rust
use orbit_embedded::{AppKey, Buffers, Client};

let app = AppKey::parse(ORBIT_APP_KEY)?;
let mut buffers = Buffers::<8192>::new(); // or Buffers::<32768>::new()
let mut client = Client::new(&mut buffers, &mut platform, app.config())?;
```

The default arena is 32 KiB. `Buffers::<8192>` or `CompactBuffers` reserves the
minimum arena and rejects oversized requests or responses cleanly. The full
buffer object is 41,776 bytes by default and 17,200 bytes with the compact arena.
Both sizes include the same 6,960-byte client state and 2,048-byte parser
scratch. Stable caller-owned storage is recommended when the firmware stack is
smaller than either buffer. Exclusive borrows prevent moving or reusing buffers,
platform state or parsed origin while a client is active; dropping the client
wipes its volatile state without revoking the persistent activation. With services
enabled, drop also attempts bounded seat release and an offline clock checkpoint. Use
`deactivate` or `invalidate` explicitly.

Host builds use the installed `cc` and `ar`. For cross compilation, set `ORBIT_CC`
and `ORBIT_AR` to the installed target tools, and `ORBIT_CFLAGS` to their target
flags. Alternatively enable `external-c` and link `Orbit::EmbeddedClient` from
your firmware build. The build script never downloads tools or dependencies.

`cargo test --offline` checks the actual C ABI layout, default and compact buffer
use, AppKey parsing, callback lifecycle, a compile-fail buffer-reuse example and
a compile-fail check that the AppKey outlives its client. The current checkout
also passes `cargo check` for `thumbv6m-none-eabi` and
`thumbv8m.main-none-eabi`, including the matching C cross-build script. These
checks do not link a board application or establish target firmware operation;
see the [embedded validation record](../docs/validation.md).

## Optional services and files

Enable `features = ["services"]` and allocate `ServiceBuffers::new()`. Then use
`Client::open(&mut buffers, &mut platform, &app, &mut services)` with the same
public app key. `start_session`, `end_session`, `session`, `usage`, `consume`,
`resources`, `acquire_resource`, `release_resource`, `check_for_updates` and
`authorize_download` expose typed results. `close` reports a release/checkpoint
error before clearing the client. `Operation` accepts an optional stable ID and
cancellation closure; preserve `MutationError::operation_id()` when its
`uncertain` flag is set. Reads and warm guards do not mutate counters or seats.

For files, select `offline` (4096 bytes) or `offline-full` (16384 bytes):

```rust
use orbit_embedded::{AppKey, Buffers, Client, OfflineBuffers};

let app = AppKey::parse(ORBIT_APP_KEY)?;
let mut buffers = Buffers::<8192>::new();
let mut files = OfflineBuffers::<4096>::new();
let mut client = Client::open_offline(
    &mut buffers, &mut platform, &app, &mut files, trusted_offline_jwks, None,
)?;
client.import_offline_file(signed_file)?;
client.require_access("export")?;
```

Use `Buffers::<16384>` or larger with the full profile. Place large buffers in
stable caller-owned storage appropriate for the board, rather than a small task
stack. `import_offline_reader` takes a bounded read closure and optional
`Operation`; it reuses `OfflineBuffers` transaction storage and needs no second
file-sized input allocation. `offline_request` writes into caller output.

File mode requires trusted UTC after restart and offline-purpose keys supplied
through a trusted product configuration path. It never silently switches to
network access. `external-c` builds must link C compiled with matching
`ORBIT_ENABLE_SERVICES`, `ORBIT_ENABLE_OFFLINE` and file-profile definitions.

`DownloadIo` supplies verified TLS, finite reads, incremental SHA-256 and atomic
staging for the application's destination medium. Metadata borrows the client;
make an owned artifact `selection()` before calling `authorize_download`, then
call the authorization's `stream`. Streams have an explicit maximum size and
replacement choice. There is no automatic installation. Full callback and
storage requirements are in the [services guide](../docs/services.md).
