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

## Application version

Pass `Client.open(app_key, app_version="2.4.1")` so your licence policy can
require a minimum application version and offer updates. Use one to four
dot-separated numbers without leading zeros, optionally followed by a
`-pre-release` and `+build` part, in at most 32 bytes (for example
`3.0.0-beta.2+build.5`).
`open` rejects an invalid value with a `configuration` error and sends a valid
one with activation and validation.

When the policy blocks this version, access checks raise
`AppVersionUnsupportedError`, and cached or offline access is not used. Ask the
user to update the application; the activation is kept, so the updated version
continues without a new licence key. `Snapshot.update_available` contains a
newer version when the policy offers one. Every request also identifies the SDK
with an `Orbit-Client` header containing its language, version and platform.

## Floating sessions

When the licence policy enables concurrent sessions, activation automatically
acquires a short online session and the SDK renews it while the client is open.
`Snapshot.session` exposes immutable session metadata. Session grants and IDs
are never restored from disk; after a restart the client acquires a fresh
session using its saved activation credential. During an outage, a running
client can use its current grant only until the exact signed expiry.

Applications can release a seat while idle and explicitly acquire it again:

```python
with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
    snapshot = orbit.ensure_access("export", lambda: getpass("Licence key: "))
    if snapshot.session is not None:
        print("Session expires at", snapshot.session.expires_at)
        orbit.end_session()
        orbit.start_session()
    orbit.require_access("export")
```

`end_session()` clears local authority before asking Orbit to release the seat
and disables automatic reacquisition until `start_session()` is called.
Ordinary licences and offline-file mode make both methods no-ops. A seat-limit
denial keeps the activation credential and never prompts for another key. See
[advanced session details](advanced.md#floating-sessions).

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
    for licence in page.items:
        print(licence.id, licence.policy_name, licence.state)
    licence_id = input("Licence ID to activate: ").strip()
    orbit.activate_account(licence_id)
    orbit.require_access("export")
```

`login()` returns an `Account`, and `owned_licences()` returns an
`OwnedLicencePage`; each `OwnedLicence.concurrent_session_limit` reports the
licence's session capacity separately from its device limit. Claiming a licence
does not activate it. Mutation IDs such as the optional ID for `claim_licence()`
are generated securely when omitted; provide and reuse an ID when your
application needs explicit retry control.
`logout()` clears local activation and customer state. `logout_account()` also
asks Orbit to revoke the remote customer session.

## Updates and online limits

Discover the newest eligible release for this runtime, then authorize the exact
artifact separately. Release numbers order updates; display versions are labels.

```python
update = orbit.check_for_update(installed_release_number=1)
if update is not None:
    authorization = orbit.authorize_download(update.release.id, update.artifact.id)
    orbit.download(authorization, "./chosen-update.bin", max_bytes=200_000_000)
```

The default channel is `stable`; pass `target=UpdateTarget("windows", "arm64")`
for an explicit target. Downloads use verified HTTPS, strip the Orbit ticket
from every redirect, and expose the destination atomically after exact length
and SHA-256 checks. An existing file requires `replace=True`; failed downloads
preserve it. The SDK never runs an installer. Public delivery URLs are shareable;
protected seller endpoints must verify the short-lived ticket. Keep authorization
responses out of logs and request fresh authorization for a later attempt.

`usage(name)` and `resources(name)` read authoritative counters. `consume(name,
units, idempotency_key)` reserves usage before work; `acquire_resource(name,
resource_id, units, idempotency_key)` records a resource until explicit
`release_resource(name, allocation_id, idempotency_key)`. Each mutation's ID is
optional and generated securely. Use your durable job ID to retry across restarts.
`LimitReachedError` contains the validated counter, `idempotency_key` and
`requested_units`. `MutationUncertainError.idempotency_key` identifies the same
operation to resume after a lost or invalid response; omitting it on a new call
starts a new operation.

Usage retries return the original debit or denial, including its original period.
Resource retries preserve allocation identity and units, with the allocation's
current state and current counter; retrying an old acquire cannot reactivate a
released resource. Closing or logging out does not release tracked resources.
Reads are display information, not a reservation; only successful consume/acquire
admits the requested units. Ordinary `require_access` never consumes or acquires.
Offline files cannot authorize these online operations. Installed metering depends
on your software reporting the work; gate valuable work on your trusted backend
when users must not bypass reporting. Usage is not automatically refunded if work
fails. See the [complete installed example](../../examples/python/online_operations.py).

## Advanced integration

[Offline licence files](advanced.md#offline-licence-files) support installations
that cannot contact Orbit. The SDK exports an installation request, verifies a
trusted signed file and stores it durably for local access checks.

[Advanced APIs and storage](advanced.md) cover registration, cancellation,
custom machine identities, manual storage and recovery.
[Run the console example](../../examples/python/README.md) for a complete app.
