# Go licensing example

A console app that checks the `export` feature before producing a synthetic
report, using the [Go SDK](../../../sdk/go/README.md).

## Prerequisites

- Go 1.27.1 or newer.
- In Orbit's **Test** environment, a policy with `export` enabled, an issued
  licence, and the app key from **Integration**.

## Run

From the repository root:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
go -C examples/go/licensed-export run .
```

Set `ORBIT_STATE_PATH` to use a dedicated absolute state directory.

## What it shows

The app asks for a licence key only when the installation has no activation,
then accepts commands; `help` lists them. Input is visible in this demo; never
pass keys or passwords on the command line.

- `status` and `export` show access and run the protected operation.
- `register`, `login`, `licences`, `more`, `select`, `claim`, `resend`,
  `recover`, `email` and `account-logout` use customer accounts. Leave the
  first key prompt empty to use them.
- `idle` and `resume` release and reacquire a floating seat.
- `updates` and `download` find a newer release for this machine and verify a
  download of at most 128 MiB. The example uses installed release number `0`.
- `metered-export` reserves one unit of an `exports` usage limit under a job ID
  you supply; reuse the ID to recover an uncertain result.
- `logout` clears local access, `deactivate` also releases the device slot, and
  `quit` closes the client and keeps the activation.
