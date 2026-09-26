"""Measure warm access guards with a real signed fixture and private storage.

Run from a source checkout; this harness uses the SDK's synthetic test fixtures
and makes no network requests. Timings are observations, not pass/fail limits.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import timeit
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SDK), str(SDK / "tests")]

from orbit_sdk import Client  # noqa: E402
from test_persistent_client import APP_SCOPE, PersistentTransport  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=5_000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    if args.iterations < 1 or args.repeat < 1:
        parser.error("iterations and repeat must be positive")
    with tempfile.TemporaryDirectory(prefix="orbit-access-benchmark-") as directory:
        transport = PersistentTransport(offline=True)
        with Client._open_for_test(APP_SCOPE, directory, transport) as client:
            client.activate("synthetic-benchmark-key")
            assert client.require_access("export").has("export")
            requests = len(transport.requests)
            results = {}
            for name, operation in (
                ("require_access", lambda: client.require_access("export")),
                ("snapshot", client.snapshot),
            ):
                times = timeit.repeat(operation, number=args.iterations, repeat=args.repeat)
                results[name] = {
                    "median_microseconds": statistics.median(times) * 1_000_000 / args.iterations,
                    "minimum_microseconds": min(times) * 1_000_000 / args.iterations,
                }
            assert len(transport.requests) == requests, "Benchmark crossed a network refresh boundary"
            print(json.dumps({
                "python": platform.python_version(),
                "platform": platform.platform(),
                "iterations": args.iterations,
                "repeat": args.repeat,
                "installed_client": results,
            }, indent=2))


if __name__ == "__main__":
    main()
