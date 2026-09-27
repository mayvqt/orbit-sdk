# Orbit Python SDK

Add licence activation and feature checks to Python applications on Windows,
Linux and macOS. Requires Python 3.12 or newer.

## Install

To use the SDK from source, run this from the repository root inside your
application's virtual environment:

```sh
python -m pip install ./sdk/python
```

## Open and check access

Copy the app key from **Integration** in your Orbit dashboard, starting with
the Test environment:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
```

```python
from getpass import getpass
import os

from orbit_sdk import Client

with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
    orbit.ensure_access("export", lambda: getpass("Licence key: "))
    # Perform the protected export here.
```

`ensure_access()` asks for a licence key only when no usable activation exists.
It never prompts after an outage, a denial or a missing feature. Call
`require_access()` immediately before each later protected operation; it never
prompts. Both raise `NotActivatedError` or `FeatureUnavailableError` when
access is unavailable, and `OrbitError` for everything else.

`snapshot()` returns a frozen `Snapshot` for display, with timezone-aware
datetimes, `timedelta` values, an immutable entitlement map and
`snapshot.has(name)`.

The app key is public configuration. Keep licence keys and passwords out of
source, command-line arguments and logs; the SDK never saves them.

## Installation state

`Client.open()` creates a stable installation, binds it to the native machine
identity when one is available and refreshes access in the background. State
lives in a private per-user directory: owner-only files on Linux and macOS,
current-user DPAPI on Windows. Pass `state_path` to use a dedicated absolute
directory for a service or container, and `machine_binding=False` for cloned
images that share a machine identity.

Share one client per installation and close it at shutdown; the `with` block
does that for you. Another process opening the same state gets
`installation_in_use`. If an activation has an uncertain result, retry with the
same key; the SDK keeps the operation ID for 24 hours.

## Customer accounts

These accounts belong to people using **your software**, separate from Orbit
dashboard accounts. For Account or Both mode, the customer registers and
confirms the email link before signing in:

```python
with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
    orbit.login(username, password)
    page = orbit.owned_licences()
    for licence in page.items:
        print(licence.id, licence.policy_name, licence.state)
    orbit.activate_account(input("Licence ID to activate: ").strip())
    orbit.require_access("export")
```

Sign-in alone grants no access; activate a licence first. `claim_licence(key)`
adds a key to the account without activating it. `logout()` clears local
activation and customer state; `logout_account()` also revokes the customer
session on the server.

## Long-term offline files

For a machine that stays disconnected longer than a connected grant allows,
configure trusted offline-purpose public keys from your application bundle.
Never take verification keys from the licence file or an untrusted upload.

```python
import os
from pathlib import Path

from orbit_sdk import Client

trusted_keys = Path("orbit-offline-keys.json").read_bytes()
with Client.open(os.environ["ORBIT_APP_KEY"], offline_keys=trusted_keys) as orbit:
    Path("offline-request.json").write_text(orbit.offline_request().to_json())
    # Transfer the request to your authorized issuance workflow, then:
    orbit.import_offline_file(Path("licence.orbit").read_bytes())
    orbit.require_access("export")
```

The request contains the public app key and installation identity; it is not
proof of ownership. Import verifies the file and saves it privately, so later
starts need only `Client.open(..., offline_keys=...)` and `require_access()`.
While a file is active, `snapshot().offline_file_mode` is true and access checks
make no network request and never prompt. An expired file raises
`offline_file_expired`; import a newer file to renew. Reimporting a file never
extends its term.

A file cannot be revoked while the machine is disconnected, and restoring a
complete old machine or VM snapshot cannot be detected reliably. Tell customers
about this before issuing long-term access. See
[offline storage details](advanced.md#offline-licence-files).

## Floating sessions

When the licence policy enables concurrent sessions, activation acquires a
short online seat and the SDK renews it while the client is open.
`snapshot().session` shows its ID, sequence and deadlines. Release the seat
while idle and acquire it again later:

```python
orbit.end_session()
orbit.start_session()
```

`end_session()` clears local access before asking Orbit to release the seat
and disables automatic reacquisition until `start_session()`. Both are no-ops
for ordinary licences and offline files. A full seat pool, an expired seat or an
outage never asks for another licence key. After a restart the client acquires a
fresh seat; after a crash the old seat stays occupied until its interval ends.

## Updates

Discover the newest eligible release for this runtime, then authorize the
artifact and download it:

```python
update = orbit.check_for_update(installed_release_number)
if update is not None:
    authorization = orbit.authorize_download(update.release.id, update.artifact.id)
    orbit.download(authorization, "./update.bin", max_bytes=200_000_000)
```

Compare the increasing release number built into your app, not display
versions. Discovery defaults to the `stable` channel and this runtime's target;
pass `channel=` or `target=UpdateTarget("windows", "arm64")` to choose another.
Downloads use verified HTTPS, strip the Orbit ticket from every redirect and
check exact length and SHA-256 before the file appears at the destination. An
existing destination requires `replace=True` and is preserved on failure. The
SDK never runs an installer. Keep authorizations out of logs.

## Usage and resources

Configure an `exports` usage limit, then reserve a unit before doing the work:

```python
consumption = orbit.consume("exports", 1, export_job_id)
print("Remaining exports:", consumption.remaining)
```

`usage(name)` and `resources(name)` read the authoritative counters.
`acquire_resource(name, resource_id, units)` returns an allocation; call
`release_resource(name, allocation_id)` once the actual resource is removed.
Closing, logging out and outages do not release allocations.

Operation IDs are optional and generated securely. Pass a durable job ID of
16–128 characters when a retry must survive a restart. A capacity denial raises
`LimitReachedError` with the validated `counter`, `idempotency_key` and
`requested_units`. A lost or invalid reply raises `MutationUncertainError`;
retry with its `idempotency_key` and identical input. A retry returns the
original outcome and never reactivates a released allocation. Usage is not
refunded when the work later fails.

These calls always go online with the activation credential; offline files
cannot authorize them and `require_access()` never consumes or allocates.
Installed programs can be modified to skip reporting, so meter on your trusted
backend when enforcement must be authoritative. See the
[complete example](../../examples/python/online_operations.py).

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on
your seller backend. Configure the exact HTTPS endpoint and trusted
connected-purpose public keys; never take either from the request.

```python
from orbit_sdk import DownloadTicketVerifier

verifier = DownloadTicketVerifier(
    app_key, "https://downloads.example.com/artifacts", public_jwks
)
ticket = verifier.verify(bearer_token)  # Raises OrbitError if invalid.
artifact = registry.get(ticket.artifact_id)
if artifact is None or (artifact.release_id, artifact.sha256, artifact.byte_length) != (
    ticket.release_id, ticket.sha256, ticket.byte_length
):
    raise PermissionError("Unknown or changed artifact")
```

A ticket expires within 120 seconds and can be replayed until then. Treat it as
a secret and never use an artifact ID as a filesystem path. The
[seller example](../../examples/python/seller-downloads/README.md) shows a
complete endpoint. See [advanced integration](advanced.md) for storage,
cancellation, custom machine identities and error details.
