# Go licensing example

A small console app checks the `export` feature before producing a sample report. Use Go 1.27.1 or newer and the [Go SDK](../../../sdk/go/README.md).

## Run

In Orbit, select your application and **Test** environment, create a policy with `export` enabled, issue a licence, and copy the single app key from **Integration**. Then run:

```sh
export ORBIT_APP_KEY='paste the Test app key from Integration'
go -C examples/go/licensed-export build -mod=readonly -buildvcs=false -o ../../../orbit-example .
./orbit-example
```

On Windows, name the output `orbit-example.exe`. For explicit local HTTP testing, add `-tags orbit_local` to the build command; only literal loopback IPs are allowed. Set `ORBIT_STATE_PATH` only when a service account or persistent container needs a dedicated absolute state directory.

The app asks for a licence key only when the installation has no usable access. Key and password input is visible in this demo; never pass them on the command line. `status` displays current access, and `quit` closes the client without deactivating it. A valid saved activation is reused after restart.

## Optional customer accounts

For Account or Both mode, leave the initial key prompt empty and use `register`. Confirm the email link, then use `login`, `licences` and `select` before `export`. Customer accounts belong to your software, separately from the Orbit dashboard.

Other commands are `more`, `claim`, `resend`, `recover`, `email`, `account-logout` and `deactivate`. `logout` clears local access; `account-logout` also requests session revocation. Only acknowledged deactivation releases a device slot.

The example module references the local SDK source. For your own project, follow the [SDK installation instructions](../../../sdk/go/README.md). Source and examples are [MIT licensed](../../../sdk/LICENSE).

For long-disconnected installations, the SDK guide explains trusted offline JWKS setup,
exporting an installation request and importing a seller-issued `.orbit` file.

Use `idle` and `resume` to release and reacquire floating seats. `updates` discovers
stable releases for this machine; `download` asks for an explicit destination and
verifies at most 128 MiB without running an installer. This example uses installed
release number `0`; embed your actual release number in a distributed application.

`metered-export` requires an `exports` usage limit on the licence's policy and asks
for a stable job ID. Keep that ID when recovering an uncertain result. It reserves
one unit before printing the synthetic export; a later failure does not refund it.
Use backend enforcement for work whose metering must be authoritative.
