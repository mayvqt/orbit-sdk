# Python quickstart

Install the v0.2.0 package from the source release:

```sh
python -m pip install https://github.com/mayvqt/orbit-sdk/releases/download/v0.2.0/orbit_sdk-0.2.0-py3-none-any.whl
```

For source development from the repository root, install with
`python -m pip install ./sdk/python`, or set `PYTHONPATH=sdk/python` to use the
checkout directly. Python 3.12 or newer is required. The Python client uses
native Python logic and the `cryptography` package; no Rust build is needed.

Set the public integration values. `Client.open()` creates a stable
installation ID, persists activation state for the current user, and generates
a retry ID for key activation:

```sh
export ORBIT_API_ORIGIN='https://orbit.example'
export ORBIT_APPLICATION_ID='application_id'
export ORBIT_ENVIRONMENT_ID='environment_id'
export ORBIT_ISSUER='https://issuer.example'
```

Key activation is the default and needs no account or operation-ID setup:

```sh
python examples/python/quickstart.py
```

The quickstart first calls `require_access()` against the credential and signed
grant already stored in the installation directory. A valid online grant or an
allowed offline grant is reused without asking for a key or starting another
activation. It asks for a new key only when access is unavailable; temporary
network failures are shown so a later run can retry the existing installation.
For a key activation whose result is uncertain, the SDK keeps its generated
operation ID and a digest of the input until recovery is resolved. It never
stores the raw key.

For a service or container, set `ORBIT_STATE_PATH` to an absolute dedicated
private directory on a persistent volume. Keep it owned by the service user
and mode `0700` on Linux. Only one process can own an installation directory
at a time; use separate directories for concurrent workers.

## Optional: username/password sign-in

The username and password belong to your app's customer account, not an Orbit
dashboard account. Sign-in lets a customer claim and choose a licence, but
sign-in alone does not grant access. Key activation remains the simple path.

To use account activation, set `ORBIT_MODE=account`, optionally set
`ORBIT_USERNAME`, and provide the explicit operation ID required for this
session-bound mutation:

```sh
export ORBIT_MODE=account
export ORBIT_OPERATION_ID='stable_account_activation_operation_id'
python examples/python/quickstart.py
```

Keep the same ID when retrying the same account mutation in the same customer
session. The caller-supplied account operation ID is not stored by the SDK.
The example prompts for the password without echoing it, and only does so when
the installed credential cannot provide access.
