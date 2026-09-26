# Go licensing example

A small console app checks the `export` feature before producing a sample report.
Use Go 1.27.1 or newer and the [Go SDK](../../../sdk/go/README.md).

## Run

In Orbit, select your application and **Test** environment. Create a policy with
`export` enabled and hardware locking off, then issue a licence. Copy the four
public values from **Integration**:

```sh
go -C examples/go/licensed-export build -mod=readonly -buildvcs=false -o ../../../orbit-example .
./orbit-example API_ORIGIN APP_ID ENVIRONMENT_ID ISSUER
```

On Windows, name the output `orbit-example.exe`. For explicit local HTTP testing,
add `-tags orbit_local` to the build command; only literal loopback IPs are allowed.

Enter a licence key when first prompted, then enter `export`. Input is visible
in this demo; never put a key or password in the command line. `status` displays
access and expiry, and `quit` closes the application without deactivating it.

The SDK saves the installation and refreshes access automatically. Run the same
command after restart: a valid saved activation needs no key prompt. An optional
fifth argument names a dedicated absolute state directory for a service account
or persistent container volume.

## Optional customer accounts

For Account or Both mode, leave the initial key prompt empty and use `register`.
Confirm the email link, then use `login`, `licences` and `select` before `export`.
Customer accounts belong to your software, separately from the Orbit dashboard.

Other commands are `more`, `claim`, `resend`, `recover`, `email`, `logout`,
`account-logout` and `deactivate`. Logout clears local access; account logout also
requests session revocation. Only acknowledged deactivation releases a device slot.

The example's module references the local SDK source. For your own project, use
the [SDK installation instructions](../../../sdk/go/README.md).
Source and examples are [MIT licensed](../../../sdk/LICENSE).
