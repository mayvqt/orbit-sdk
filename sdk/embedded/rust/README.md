# Orbit embedded Rust

This `no_std` wrapper uses the allocation-free C client and has no dependencies.
Add it from your SDK checkout:

```toml
[dependencies]
orbit-embedded = { path = "path/to/Orbit-SDK/sdk/embedded/rust" }
```

Implement `Platform` using your board's maintained TLS/crypto, trusted clock,
CSPRNG and durable storage. `begin_request` must send the complete request before
returning its HTTP status; `read_response` then streams response chunks. This
keeps request borrows separate from reuse of the underlying transaction arena.
The storage and security requirements are the same as the [C client](../README.md).

Create `Buffers`, a platform and `Config`, then pass exclusive borrows to
`Client::new`. Provision a key once with `activate`; call `tick` from your loop
and `require_access` before each protected operation. The client keeps the
buffers, strings and platform borrowed until drop, which wipes RAM without
revoking persistent authority. Use `deactivate` or `invalidate` explicitly.

Use static or otherwise stable caller-owned buffers when your firmware stack
cannot accommodate their 41,776 bytes. No pinning or unsafe application code is
required once those buffers are borrowed. Platform callbacks must not panic;
unwinding across the C boundary aborts execution.

Host builds use the installed `cc` and `ar`. For cross compilation, set `ORBIT_CC`
and `ORBIT_AR` to the installed target tools, and `ORBIT_CFLAGS` to their target
flags. Alternatively enable `external-c` and link `Orbit::EmbeddedClient` from
your firmware build. The build script never downloads tools or dependencies.

`cargo test --offline` checks the actual C ABI layout, callback lifecycle and a
compile-fail exclusive-borrow example. MCU Rust targets/toolchains still need a
board build; host tests do not establish target firmware compatibility.
