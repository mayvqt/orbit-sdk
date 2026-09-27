from __future__ import annotations

import os
from getpass import getpass

from orbit_sdk import Client, NotActivatedError


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set the {name} environment variable")
    return value


state_path = os.environ.get("ORBIT_STATE_PATH")
mode = os.environ.get("ORBIT_MODE", "key")

with Client.open(required("ORBIT_APP_KEY"), state_path=state_path) as orbit:
    if mode == "key":
        snapshot = orbit.ensure_access("export", lambda: getpass("Licence key: "))
    elif mode == "account":
        try:
            snapshot = orbit.require_access("export")
        except NotActivatedError:
            username = os.environ.get("ORBIT_USERNAME") or input("Username: ").strip()
            account = orbit.login(username, getpass("Password: "))
            print(f"Signed in as {account.username}")
            page = orbit.owned_licences()
            for licence in page.items:
                print(
                    licence.id,
                    licence.policy_name,
                    licence.state,
                    f"concurrent sessions={licence.concurrent_session_limit}",
                )
            licence_id = input("Licence ID to activate: ").strip()
            orbit.activate_account(licence_id)
            snapshot = orbit.require_access("export")
    else:
        raise SystemExit("ORBIT_MODE must be 'key' or 'account'")

    print(f"Access: {snapshot.access.value}; export={snapshot.has('export')}")
    if snapshot.session is not None:
        print(f"Session {snapshot.session.session_id} expires at {snapshot.session.expires_at.isoformat()}")
