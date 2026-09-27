# C# licensing example

This console app uses the [C# SDK](../../../sdk/csharp/README.md) to authorize
a sample export. It needs the .NET 10 SDK.

Copy the public app key from Orbit's **Integration** page, starting with the
**Test** environment, then run it from the repository root:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
dotnet run --project examples/csharp/licensed-export
```

The app asks for a licence key only when there is no activation; enter `export`
to run the protected sample. Input is visible in this demo, so never use it
with production passwords.

Other commands demonstrate:

- `login`, `licences`, `more` and `select` for Account or Both authentication,
  plus `register`, `resend`, `recover`, `email`, `claim` and `account-logout`.
- `metered-export`, which reserves one unit of an `exports` usage limit with a
  job ID you supply. Reuse that ID after an uncertain reply.
- `seat-end` and `seat-start` for floating seats.
- `status`, `logout` (clears local access) and `deactivate` (releases the
  device slot).
