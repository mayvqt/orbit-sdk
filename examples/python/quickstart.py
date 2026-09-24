from __future__ import annotations

import json
import os
import sys
from getpass import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from orbit_sdk import Client, Config  # noqa: E402


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set the {name} environment variable")
    return value


config = Config(
    api_origin=required("ORBIT_API_ORIGIN"),
    application_id=required("ORBIT_APPLICATION_ID"),
    environment_id=required("ORBIT_ENVIRONMENT_ID"),
    issuer=required("ORBIT_ISSUER"),
    installation_id=required("ORBIT_INSTALLATION_ID"),
)
mode = os.environ.get("ORBIT_MODE", "key")
operation_id = required("ORBIT_OPERATION_ID")

with Client.connect(config, library_path=os.environ.get("ORBIT_FFI_LIBRARY")) as orbit:
    if mode == "key":
        orbit.activate(getpass("Licence key: "), operation_id)
    elif mode == "account":
        username = os.environ.get("ORBIT_USERNAME") or input("Username: ").strip()
        orbit.login(username, getpass("Password: "))
        page = orbit.owned_licences()
        for licence in page["items"]:
            print(licence["id"], licence["policy_name"], licence["state"])
        orbit.activate_account(input("Licence ID to activate: ").strip(), operation_id)
    else:
        raise SystemExit("ORBIT_MODE must be 'key' or 'account'")

    snapshot = orbit.require_access("export")
    print(json.dumps(snapshot, indent=2))
