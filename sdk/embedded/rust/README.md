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
wipes its volatile state without revoking persistent authority. Use
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
