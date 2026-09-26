# Orbit Python SDK

Add licence activation and feature checks to Python applications on Windows
and Linux. Requires Python 3.12 or newer. The candidate also includes macOS
bindings; native macOS validation is still pending. See the
[platform checks](advanced.md#macos-platform-checks) before adopting that target.

## Install

This checkout contains the unreleased v0.4 candidate. From its repository
root, install the SDK into your application's virtual environment:

```sh
python -m pip install ./sdk/python
```

## Open and check access

Copy the app key from **Integration** in your Orbit dashboard, starting with
the Test environment. The SDK creates a stable installation, uses the native
machine identity when available, and refreshes access automatically.

```python
from getpass import getpass
import os

from orbit_sdk import Client

with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
    snapshot = orbit.ensure_access("export", lambda: getpass("Licence key: "))
    # Perform the protected export here.
```

`ensure_access()` asks for a licence key only when no usable activation exists.
It does not prompt after an outage, a denied request or a missing feature.
`snapshot()` returns a frozen `Snapshot` with timezone-aware datetimes,
`timedelta` values, an immutable entitlement map and `snapshot.has(name)`.
Always call `require_access()` or `ensure_access()` before protected work;
`snapshot()` is for display.

State uses a private directory on Linux and current-user DPAPI on Windows.
Pass `state_path` to use a dedicated directory for a service or container.
Share one client per installation and close it at shutdown; the `with` block
above handles that automatically. If activation has an uncertain result, retry
with the same key. The SDK keeps the operation ID for up to 24 hours and never
saves the raw key or password.

## Optional: customer accounts

These accounts belong to people using **your software**, separate from Orbit
dashboard accounts. For Account or Both mode, register and confirm the email
link before signing in.

```python
with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
    account = orbit.login(username, password)
    page = orbit.owned_licences()
    licence = choose_licence(page.items)  # Your application's selection UI.
    orbit.activate_account(licence.id)
    orbit.require_access("export")
```

`login()` returns an `Account`, and `owned_licences()` returns an
`OwnedLicencePage`. Claiming a licence does not activate it. Mutation IDs such
as the optional ID for `claim_licence()` are generated securely when omitted;
provide and reuse an ID when your application needs explicit retry control.
`logout()` clears local activation and customer state. `logout_account()` also
asks Orbit to revoke the remote customer session.

## Advanced integration

[Advanced APIs and storage](advanced.md) cover registration, cancellation,
custom machine identities, manual storage and recovery.
[Run the console example](../../examples/python/README.md) for a complete app.
