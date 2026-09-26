from __future__ import annotations

import json
import os
import sys
from getpass import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from orbit_sdk import AppConfig, Client, OrbitError  # noqa: E402


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set the {name} environment variable")
    return value


config = AppConfig(
    api_origin=required("ORBIT_API_ORIGIN"),
    application_id=required("ORBIT_APPLICATION_ID"),
    environment_id=required("ORBIT_ENVIRONMENT_ID"),
    issuer=required("ORBIT_ISSUER"),
)
state_path = os.environ.get("ORBIT_STATE_PATH")
mode = os.environ.get("ORBIT_MODE", "key")

with Client.open(config, state_path=state_path) as orbit:
    if mode not in ("key", "account"):
        raise SystemExit("ORBIT_MODE must be 'key' or 'account'")

    try:
        snapshot = orbit.require_access("export")
    except OrbitError as failure:
        if failure.code != "access_unavailable":
            raise
        if mode == "key":
            # Only unresolved key activations keep a retry ID on disk; the key
            # itself is never stored. Existing online/offline access is reused.
            orbit.activate(getpass("Licence key: "))
        else:
            # This is an account for your app's customer, not an Orbit dashboard user.
            username = os.environ.get("ORBIT_USERNAME") or input("Username: ").strip()
            operation_id = required("ORBIT_OPERATION_ID")
            orbit.login(username, getpass("Password: "))
            page = orbit.owned_licences()
            for licence in page["items"]:
                print(licence["id"], licence["policy_name"], licence["state"])
            orbit.activate_account(input("Licence ID to activate: ").strip(), operation_id)
        snapshot = orbit.require_access("export")
    print(json.dumps(snapshot, indent=2))
