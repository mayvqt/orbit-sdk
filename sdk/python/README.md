# Orbit Python SDK

Add licence activation and feature checks to Python applications on Windows
and Linux. Requires Python 3.12 or newer.

## Install

```sh
python -m pip install https://github.com/mayvqt/orbit-sdk/releases/download/v0.3.0/orbit_sdk-0.3.0-py3-none-any.whl
```

For a source checkout, run `python -m pip install ./sdk/python` from the
repository root.

## Configure and activate

Copy the public values from **Integration** in your Orbit dashboard.
`Client.open()` remembers this installation and refreshes access automatically.

```python
from getpass import getpass
from orbit_sdk import AppConfig, Client, OrbitError

config = AppConfig(
    api_origin="https://orbit.mayvie.dev",
    application_id="app_id_from_integration",
    environment_id="environment_id_from_integration",
    issuer="https://issuer.example",
)

with Client.open(config) as orbit:
    try:
        orbit.require_access("export")
    except OrbitError as failure:
        if failure.code != "access_unavailable":
            raise
        orbit.activate(getpass("Licence key: "))
        orbit.require_access("export")
    # Perform the protected export here.
```

## Access checks and restarts

Call `require_access()` before each protected operation. `snapshot()` is for
display only. Reopen the same configuration after restarting; the customer
only enters their key for the first activation.

On restart, Orbit checks the saved credential online. During an outage, access
continues only while a verified offline-enabled grant is valid. An outage is
not a reason to ask for the licence key again.

If activation has an uncertain result, retry with the same key. The SDK keeps
the operation ID for up to 24 hours and never saves the raw key or password.

State uses a private directory on Linux and current-user DPAPI on Windows.
For a service or container, pass `state_path` to `Client.open()` with a dedicated
persistent directory. Share one client per installation and close it at shutdown;
the `with` block above handles that automatically.

## Optional: username/password sign-in

These accounts belong to people using **your software**, separate from Orbit
dashboard accounts. Skip this section if customers use licence keys only.
For Account or Both mode, register and confirm the email link before signing in.

After opening a client, sign in and let the customer choose an owned licence:

```python
import uuid

orbit.login(username, password)
licences = orbit.owned_licences()["items"]
licence_id = choose_licence(licences)  # Your application's selection UI.
operation_id = str(uuid.uuid4())  # 16–128 characters; reuse it for retries.
orbit.activate_account(licence_id, operation_id)
orbit.require_access("export")
```

Sign-in alone does not grant access. Create one `operation_id` per selection and
keep it unchanged if you retry that account activation. On later starts, check saved
access before showing a sign-in form.

## Advanced integration

[Advanced APIs and storage](advanced.md) cover registration, cancellation,
hardware binding, custom storage, explicit operation IDs and recovery.
[Run the console example](../../examples/python/README.md) for a complete app.
