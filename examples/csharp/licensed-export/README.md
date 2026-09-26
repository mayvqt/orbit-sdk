# C# licensing example

A console app checks the `export` feature before producing a sample report.
Use .NET SDK 10.0.112 and the [C# SDK](../../../sdk/csharp/README.md).

## Run

In Orbit, select your application and **Test** environment. Create a policy with
`export` enabled and hardware locking off, then issue a licence. Copy the four
public values from **Integration**:

```sh
dotnet run --project examples/csharp/licensed-export -- API_ORIGIN APP_ID ENVIRONMENT_ID ISSUER
```

Enter a licence key when first prompted, then enter `export`. Input is visible
in this demo; never put a key or password in the command line. `status` displays
access and expiry, and `quit` closes the application without deactivating it.

The SDK saves this installation and refreshes access automatically. Run the same
command after restart: a valid saved activation needs no key prompt. An optional
fifth argument names a dedicated absolute state directory for a service account
or persistent container volume.

For an explicit local HTTP test service, add `-p:OrbitLocalDevelopment=true`
before `--`. HTTP is restricted to literal loopback IPs; normal builds use HTTPS.

## Optional customer accounts

For Account or Both mode, leave the initial key prompt empty and enter `register`.
Confirm the email link, then use `login`, `licences` and `select` before `export`.
Customer accounts belong to your software, separately from the Orbit dashboard.

Other commands are `more`, `claim`, `resend`, `recover`, `email`, `logout`,
`account-logout` and `deactivate`. Logout clears local access; account logout also
requests session revocation. Only acknowledged deactivation releases a device slot.

Source and examples are [MIT licensed](../../../sdk/LICENSE).
