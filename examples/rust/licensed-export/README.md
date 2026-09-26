# Rust licensed export example

A small console application that remembers activation across restarts and checks the
`export` entitlement before creating a synthetic report.

Use Rust/Cargo 1.98.1 or newer. From this repository's root:

```sh
cargo run -p orbit-licensed-export -- \
  https://orbit.example.com APP_ID ENVIRONMENT_ID https://orbit.example.com
```

Copy the four public values from **Integration** in your dashboard. The policy must
include `export`. The example checks existing access first, then asks for a key only
when activation is unavailable. Purchase keys are entered locally, never passed on the
command line. Try `export`, `status`, then `quit`; launch again to reuse the activation.

The SDK owns refresh scheduling and installation identity. State uses the OS user state
directory by default. Add an absolute dedicated directory as the final argument for a
service or persistent container volume. Only one process can open that directory;
share a client within your application. `quit` closes the client without releasing its
device slot. An eligible original offline grant can cover a recognized outage after
an online recovery attempt. Security failures and strict-online licences fail closed.

For an isolated local Orbit fixture, build with `--features local-development` and use
an HTTP literal loopback address. HTTPS certificate checks remain enabled otherwise.

See the [SDK guide](../../../sdk/rust/README.md) for integration and the
[account APIs](../../../sdk/rust/advanced.md#customer-accounts) for optional customer
registration and username/password sign-in.
