# Rust licensed export example

This console app remembers activation, checks the `export` entitlement before each
synthetic report, and asks for a key only when activation is missing.

From the repository root, set the public app key from your dashboard's
**Integration** page and run:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
cargo run -p orbit-licensed-export
```

The policy must include `export`. Type the licence key at the prompt, then try
`export`, `status`, and `quit`. Launch again to reuse the activation. Purchase keys are
entered locally and never passed on the command line or saved by the SDK.

The client owns refresh scheduling and uses the OS state directory by default. An
eligible offline grant can cover a recognized outage after online recovery is tried;
strict-online licences and security failures fail closed. Configure a dedicated state
directory through `Client::open_with_options` when hosting a service or persistent
container volume.

For an isolated loopback Orbit fixture, enable `local-development`; that build uses
`Client::open_local` and accepts only a literal loopback origin. TLS checks remain
enabled for HTTPS.

See the [SDK guide](../../../sdk/rust/README.md) and [advanced APIs](../../../sdk/rust/advanced.md).
For long-disconnected installations, those guides also cover trusted offline keys,
installation requests and importing seller-issued `.orbit` files.

Use `idle` and `resume` for explicit floating-seat release and acquisition.
`updates` checks stable releases for the current target; `download` prompts for a
new destination, verifies at most 128 MiB and never runs an installer. The example
uses installed release number `0`; embed your actual release number in your app.

`metered-export` requires an `exports` usage limit and asks for a stable job ID.
Reuse that ID after an uncertain response. Quota is reserved before the synthetic
export; later business failure does not refund it. Gate authoritative metering and
actual work on your trusted backend.
