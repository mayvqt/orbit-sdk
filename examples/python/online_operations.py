"""Explicit updates, usage and resources for an installed application."""

from __future__ import annotations

import argparse
from getpass import getpass
import os
from pathlib import Path
from typing import Callable

from orbit_sdk import Client, DownloadAuthorization, ResourceAllocation, UsageConsumption


def export_report(orbit: Client, job_id: str, write_report_once: Callable[[str], None]) -> UsageConsumption:
    orbit.require_access("export")
    consumption = orbit.consume("exports", 1, job_id)
    # Use a durable job ID; the application must also make report writing idempotent.
    # A failed report does not automatically refund this consumption.
    write_report_once(job_id)
    return consumption


def download_update(orbit: Client, installed_number: int, destination: Path) -> Path | None:
    update = orbit.check_for_update(installed_number)
    if update is None:
        return None
    authorization: DownloadAuthorization = orbit.authorize_download(update.release.id, update.artifact.id)
    return Path(orbit.download(authorization, destination, max_bytes=200_000_000))


def track_project(orbit: Client, project_id: str, job_id: str) -> ResourceAllocation:
    # Keep the returned allocation_id alongside the project in your application.
    return orbit.acquire_resource("projects", project_id, 1, job_id)


def forget_removed_project(orbit: Client, allocation_id: str, job_id: str) -> ResourceAllocation:
    # Call after the actual project has been removed, not when this process closes.
    return orbit.release_resource("projects", allocation_id, job_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover and verify a licensed update without installing it.")
    parser.add_argument("installed_number", type=int)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    with Client.open(os.environ["ORBIT_APP_KEY"]) as orbit:
        orbit.ensure_access("export", lambda: getpass("Licence key: "))
        result = download_update(orbit, args.installed_number, args.destination)
        print("No update available." if result is None else "Verified update saved to the chosen destination.")


if __name__ == "__main__":
    main()
