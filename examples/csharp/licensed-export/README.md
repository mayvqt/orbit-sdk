# C# licensing example

This console app uses Orbit's installed client to authorize a sample export.
Use .NET SDK 10.0.112 and the [C# SDK](../../../sdk/csharp/README.md).

Copy the public app key from Orbit's **Integration** page, starting with the
**Test** environment:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
dotnet run --project examples/csharp/licensed-export
```

The example asks for a licence key only when there is no activation. Enter
`export` to run the protected sample. Licence and password input is visible in
this demo; never put either in command-line arguments.

The SDK saves this installation and validates it online after restart. Verified
offline access is available only when the signed grant permits it. An optional
`OrbitOptions.StatePath` can select a dedicated absolute state directory in
application code.

For Account or Both authentication, use `register`, confirm the email link, then
`login`, `licences` and `select` before exporting. Other commands show claiming a
licence, registration recovery, account logout and device deactivation. Local
logout clears local access; only acknowledged deactivation releases a device
slot.

The SDK and example source are [MIT licensed](../../../sdk/LICENSE).
