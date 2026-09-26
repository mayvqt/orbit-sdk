# Orbit Go SDK

Add licence activation and feature checks to installed Go applications.
Use Go 1.27.1 or newer. [Run the console example](../../examples/go/licensed-export/README.md)
for a complete working application.

## Install and configure

```sh
go get github.com/mayvqt/orbit-sdk/sdk/go@v0.3.0
```

Copy the four public values from your application's **Integration** page in Orbit.
Start with the **Test** environment.

```go
import orbit "github.com/mayvqt/orbit-sdk/sdk/go"

client, err := orbit.Open(ctx, orbit.AppConfig{
    APIOrigin:     "https://orbit.mayvie.dev",
    Issuer:        grantIssuer,
    ApplicationID: applicationID,
    EnvironmentID: environmentID,
})
if err != nil { return err }
defer client.Close()
```

`Open` remembers this installation and refreshes its access automatically. Share
one `*Client` within your application. `Close` saves its state and stops refresh;
it does not release the licence.

## First activation

Check access first. Ask for a licence key only when the error code is
`access_unavailable`, then activate and check again:

```go
_, err = client.RequireAccess(ctx, "export")
if err != nil {
    var failure *orbit.Error
    if !errors.As(err, &failure) || failure.Code != "access_unavailable" {
        return err
    }
    key := promptForLicenceKey() // Your application's input UI.
    if _, err = client.Activate(ctx, key); err != nil { return err }
}
if _, err = client.RequireAccess(ctx, "export"); err != nil { return err }
// Perform the protected export here.
```

This example also imports the standard `errors` package. Keep licence keys and
passwords out of source, command-line arguments and logs. Orbit never saves them.

## Access checks and restarts

Call `RequireAccess` immediately before each protected operation. `Snapshot` is
for display; it cannot authorize work. Reopen the same configuration on restart;
the saved credential is checked online first. During a recognized outage, a
verified offline-enabled grant can authorize access until its original expiry.
An outage never means the user should activate again automatically.

State is stored privately under `$XDG_STATE_HOME/orbit` (normally
`~/.local/state/orbit`) on Linux, or `%LOCALAPPDATA%\Orbit` using current-user
DPAPI on Windows. Set `AppConfig.StatePath` to a dedicated absolute directory for
a service account or persistent container volume. Another process opening the
same installation receives `ErrInstallationInUse`; share the existing client or
close the other process.

An uncertain activation can be retried with the same key: the SDK remembers its
operation ID for 24 hours. Different input returns `ErrPendingActivation`.
`Logout` deliberately clears saved access and pending activation; it does not
release a device slot. `Deactivate` releases a slot after server acknowledgement.

<a id="customer-accounts"></a>

## Optional: username/password sign-in

These are accounts for people using **your software**, separate from Orbit
dashboard accounts. Skip this section when buyers activate with a licence key.
For Account or Both mode, register and confirm the email link, then sign in:

```go
_, err = client.Login(ctx, username, password)
if err != nil { return err }
licences, err := client.OwnedLicences(ctx, "")
if err != nil { return err }
// Let the user select a licence from licences.Items.
_, err = client.ActivateAccount(ctx, selectedLicenceID, "")
if err != nil { return err }
_, err = client.RequireAccess(ctx, "export")
```

Sign-in alone does not grant access. Sessions stay in memory; installed access
uses its separate saved credential. See the [console example](../../examples/go/licensed-export/README.md)
for registration, recovery, claiming keys and account logout.

## Advanced integration

[Advanced APIs and storage](ADVANCED.md) cover caller-owned transports and
storage, hardware binding, explicit mutation IDs, customer session proofs and
support diagnostics. The SDK and examples are [MIT licensed](LICENSE).
