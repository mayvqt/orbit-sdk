# Rust licensed export example

This console app remembers activation, checks the `export` entitlement before
each synthetic report, and asks for a key only when activation is missing.

Create a Test licence whose policy includes `export`. From the repository root,
set the public app key from your dashboard's **Integration** page and run:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
cargo run -p orbit-licensed-export
```

Type the licence key at the prompt, then use these commands:

- `export` checks access and prints a synthetic report.
- `metered-export` needs an `exports` usage limit and asks for a stable job ID;
  reuse that ID after an uncertain response.
- `updates` checks stable releases for this target; `download` also saves the
  update to a new destination, verified and at most 128 MiB. The example uses
  installed release number `0`; embed your actual release number in your app.
- `idle` and `resume` release and reacquire a floating seat.
- `status` prints the access snapshot, and `quit` exits.

Launch again to reuse the activation. See the [SDK guide](../../../sdk/rust/README.md)
for offline files and the other APIs.
