from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from orbit_sdk import (Cancellation, Client, DownloadAuthorization, LimitReachedError, MutationUncertainError,
                       NotActivatedError, OrbitError, UpdateTarget)
from orbit_sdk import online
from orbit_sdk.download_file import _download_file
from orbit_sdk.errors import CANCELLED, TRANSIENT, error
from orbit_sdk.transport import Transport
from support import FakeTransport, json_bytes
from test_client import make_config
from test_transport import _Connection, _Response, _trusted_tls_server

PREFIX = "/api/client/v1/activations/activation/"
KEY = "job-20260927-000001"
PAYLOAD = b"a synthetic application artifact\n" * 3000


def artifact(url="https://seller.example.test/file", **changes):
    return dict(id="artifact", release_id="release", platform="linux", architecture="x64", filename="app.bin",
                byte_length=len(PAYLOAD), sha256=hashlib.sha256(PAYLOAD).hexdigest(), delivery_mode="public", url=url,
                required_feature=None) | changes


def release(a=None, **changes):
    return dict(id="release", channel="stable", version="v2", notes="Release notes", release_number=2,
                state="published", created_at="2026-09-01T00:00:00Z", published_at="2026-09-02T00:00:00Z",
                artifacts=[a or artifact()]) | changes


def counter(usage=True, **changes):
    value = dict(name="exports" if usage else "projects", limit=10, used=4, remaining=6)
    if usage:
        value.update(period="day", period_started_at="2026-09-27T00:00:00Z", resets_at="2026-09-28T00:00:00Z")
    return value | changes


class OnlineClientTests(unittest.TestCase):
    def setUp(self):
        config = make_config()
        self.transport = FakeTransport(config)
        self.client = Client._for_test(config, self.transport)
        self.client.activate("synthetic-key")

    def tearDown(self):
        self.client.close()

    def reply(self, route, value):
        self.transport.post_overrides[PREFIX + route] = json_bytes(value)

    def test_update_exact_target_no_fallback_and_separate_authorization(self):
        a = artifact()
        self.reply("updates", dict(release=release(a), artifact=a))
        update = self.client.check_for_update(1, target=UpdateTarget("linux", "x64"))
        self.assertEqual(update.release.release_number, 2)
        self.assertIs(update.release.created_at.tzinfo, timezone.utc)
        body = self.transport.requests[-1][2]
        self.assertEqual(body["credential"], "a" * 43)
        self.assertEqual(body["channel"], "stable")
        self.assertNotIn("management_token", body)
        self.reply("downloads/authorize", dict(artifact=a, ticket=None, expires_at=None))
        authorized = self.client.authorize_download("release", "artifact")
        self.assertEqual(authorized.artifact, update.artifact)
        self.assertNotIn(a["url"], repr(authorized))
        count = len(self.transport.requests)
        self.client.require_access("export")
        self.assertEqual(len(self.transport.requests), count)
        for bad in (dict(release=release(a), artifact=artifact(platform="windows")),
                    dict(release=release(a, release_number=1), artifact=a),
                    dict(release=release(a, artifacts=[a, artifact(id="other", architecture="arm64")]), artifact=a),
                    dict(release=None, artifact=a)):
            self.reply("updates", bad)
            with self.assertRaises(OrbitError):
                self.client.check_for_update(1, target=UpdateTarget("linux", "x64"))
        self.reply("updates", dict(release=None, artifact=None))
        self.assertIsNone(self.client.check_for_update(2))

    def test_usage_resource_replay_semantics_and_inputs(self):
        self.reply("usage/exports", counter())
        self.assertEqual(self.client.usage("exports").remaining, 6)
        self.reply("usage/exports/consume", counter(idempotency_key=KEY, consumed_units=2))
        result = self.client.consume("exports", 2, KEY)
        self.assertEqual(result.idempotency_key, KEY)
        self.assertEqual(result.used, 4)
        # Usage returns the fixed original period even after a local UTC boundary.
        self.assertEqual(self.client.consume("exports", 2, KEY), result)
        self.reply("resources/projects", counter(False))
        self.assertEqual(self.client.resources("projects").remaining, 6)
        allocation = counter(False, allocation_id="allocation", resource_id="project", units=2, state="active", idempotency_key=KEY)
        self.reply("resources/projects/acquire", allocation)
        self.assertEqual(self.client.acquire_resource("projects", "project", 2, KEY).state, "active")
        released = allocation | dict(used=2, remaining=8, state="released")
        self.reply("resources/projects/allocations/allocation/release", released)
        self.assertEqual(self.client.release_resource("projects", "allocation", KEY).state, "released")
        self.reply("resources/projects/acquire", released)
        replay = self.client.acquire_resource("projects", "project", 2, KEY)
        self.assertEqual((replay.allocation_id, replay.state, replay.used), ("allocation", "released", 2))
        count = len(self.transport.requests)
        for units in (0, -1, True, 1.2, 2**53):
            with self.assertRaises(OrbitError): self.client.consume("exports", units)
        for key in ("", "short", " " * 16):
            with self.assertRaises(OrbitError): self.client.consume("exports", 1, key)
        with self.assertRaises(OrbitError): self.client.acquire_resource("projects", "../path")
        self.assertEqual(len(self.transport.requests), count)

    def test_uncertain_failure_malformed_reply_cancel_and_late_logout_keep_operation_id(self):
        route = PREFIX + "usage/exports/consume"
        self.transport.post_overrides[route] = error(TRANSIENT, "network_unavailable")
        with self.assertRaises(MutationUncertainError) as failure:
            self.client.consume("exports")
        generated = failure.exception.idempotency_key
        self.assertEqual(generated, self.transport.requests[-1][2]["idempotency_key"])
        self.assertGreaterEqual(len(generated), 16)
        self.reply("usage/exports/consume", counter(idempotency_key="another-job-000001", consumed_units=1))
        with self.assertRaises(MutationUncertainError) as failure:
            self.client.consume("exports", 1, generated)
        self.assertEqual(failure.exception.idempotency_key, generated)
        with Cancellation() as cancellation:
            def cancel_after_commit(route, body):
                cancellation.cancel()
                return json_bytes(counter(idempotency_key=body["idempotency_key"], consumed_units=1))
            self.transport.post_overrides[route] = cancel_after_commit
            with self.assertRaises(MutationUncertainError) as failure:
                self.client.consume("exports", 1, KEY, cancellation=cancellation)
            self.assertEqual((failure.exception.kind, failure.exception.idempotency_key), (CANCELLED, KEY))
        def logout_after_commit(route, body):
            self.client.logout()
            return json_bytes(counter(idempotency_key=body["idempotency_key"], consumed_units=1))
        self.transport.post_overrides[route] = logout_after_commit
        with self.assertRaises(MutationUncertainError): self.client.consume("exports", 1, KEY)
        with self.assertRaises(NotActivatedError): self.client.usage("exports")

    def test_real_transport_retries_same_id_and_validates_capacity_envelope(self):
        requests = []
        denied = dict(error=dict(code="usage_limit_reached", message="Capacity reached", request_id="req",
                                 counter=counter(used=10, remaining=0), idempotency_key=KEY, requested_units=2))
        response = _Response(409, json_bytes(denied))
        self.client.transport = Transport("https://orbit.example.test", _connection_factory=lambda *a, **k: _Connection(response, requests))
        with self.assertRaises(LimitReachedError) as failure: self.client.consume("exports", 2, KEY)
        self.assertEqual(failure.exception.counter.used, 10)
        for edit in (dict(idempotency_key="different-job-00001"), dict(requested_units=True), dict(counter=counter(name="other")),
                     dict(counter=counter(used=11, remaining=-1)), dict(counter=counter(remaining=5))):
            response = _Response(409, json_bytes(dict(error=denied["error"] | edit)))
            with self.assertRaises(MutationUncertainError) as failure: self.client.consume("exports", 2, KEY)
            self.assertEqual(failure.exception.idempotency_key, KEY)
            self.assertFalse(hasattr(failure.exception, "counter"))
        for status in (201, 204):
            response = _Response(status, json_bytes(counter(idempotency_key=KEY, consumed_units=2)) if status != 204 else b"")
            with self.assertRaises(MutationUncertainError): self.client.consume("exports", 2, KEY)
        attempts = []
        class Connection(_Connection):
            def request(self, method, route, *, body, headers):
                attempts.append(json.loads(body))
                super().request(method, route, body=body, headers=headers)
        responses = iter([_Response(503, json_bytes(dict(error=dict(code="service_unavailable", message="Busy", request_id="req")))),
                          _Response(200, json_bytes(counter(idempotency_key=KEY, consumed_units=2)))])
        self.client.transport = Transport("https://orbit.example.test", _connection_factory=lambda *a, **k: Connection(next(responses), requests))
        with patch("orbit_sdk.transport._wait_cancel", return_value=False): self.client.consume("exports", 2, KEY)
        self.assertEqual([v["idempotency_key"] for v in attempts], [KEY, KEY])

    def test_strict_periods_definitions_and_numbers(self):
        for bad in (counter(limit=True), counter(used=2**53), counter(remaining=5), counter(period="week"),
                    counter(period_started_at="2026-02-30T00:00:00Z"), counter(resets_at="2026-09-29T00:00:00Z")):
            with self.assertRaises(OrbitError): online.parse_counter(bad, "exports", True)
        for year, end in ((2024, "2024-03-01"), (2025, "2025-03-01")):
            value = counter(period="month", period_started_at=f"{year}-02-01T00:00:00Z", resets_at=end + "T00:00:00Z")
            self.assertEqual(online.parse_counter(value, "exports", True).period, "month")
        lifetime = counter(period="lifetime", period_started_at=None, resets_at=None)
        self.assertIsNone(online.parse_counter(lifetime, "exports", True).resets_at)
        for value in ({"exports": {"limit": True, "period": "day", "required_feature": None}},
                      {"exports": {"limit": 10, "period": "day", "required_feature": "INVALID"}}):
            with self.assertRaises(OrbitError): online.parse_definitions(value, True)


class DirectDownloadTests(unittest.TestCase):
    def test_tls_redirect_header_isolation_integrity_limits_and_atomic_replace(self):
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                seen.append((self.path, dict(self.headers)))
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/file?storage=short-lived")
                    self.end_headers()
                elif self.path == "/loop":
                    self.send_response(302); self.send_header("Location", "/loop"); self.end_headers()
                else:
                    self.send_response(200)
                    if self.path == "/encoded": self.send_header("Content-Encoding", "gzip")
                    if self.path == "/short": self.send_header("Content-Length", str(len(PAYLOAD)))
                    self.end_headers()
                    self.wfile.write(PAYLOAD[:10] if self.path == "/short" else PAYLOAD + (b"extra" if self.path == "/oversize" else b""))
        with _trusted_tls_server(Handler) as (origin, context), tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "chosen.bin")
            expiry = datetime.now(timezone.utc) + __import__("datetime").timedelta(seconds=120)
            authorization = DownloadAuthorization(online.parse_artifact(artifact(origin + "/redirect", delivery_mode="protected")), "abc.def.sig", expiry)
            _download_file(authorization, target, max_bytes=len(PAYLOAD), _context=context)
            self.assertEqual(target.read_bytes(), PAYLOAD)
            self.assertEqual(seen[0][1].get("Authorization"), "Bearer abc.def.sig")
            self.assertEqual(seen[1][0], "/file?storage=short-lived")
            self.assertNotIn("Authorization", seen[1][1])
            self.assertTrue(all(v.get("Accept-Encoding") == "identity" and "Cookie" not in v for _, v in seen))
            with self.assertRaises(OrbitError): _download_file(authorization, target, max_bytes=len(PAYLOAD), _context=context)
            for path, digest in (("/file", "0" * 64), ("/short", None), ("/oversize", None), ("/encoded", None), ("/loop", None)):
                a = online.parse_artifact(artifact(origin + path, **({"sha256": digest} if digest else {})))
                with self.assertRaises(OrbitError):
                    _download_file(DownloadAuthorization(a, None, None), target, max_bytes=len(PAYLOAD), replace=True, _context=context)
                self.assertEqual(target.read_bytes(), PAYLOAD)
                self.assertEqual(list(Path(directory).iterdir()), [target])
            with self.assertRaises(OrbitError): _download_file(authorization, target, max_bytes=len(PAYLOAD) - 1, replace=True, _context=context)
            with self.assertRaises(OrbitError): _download_file(authorization, target, max_bytes=len(PAYLOAD), replace=True)
            with Cancellation() as cancelled:
                cancelled.cancel()
                with self.assertRaises(OrbitError): _download_file(authorization, target, max_bytes=len(PAYLOAD), replace=True, cancellation=cancelled, _context=context)

    def test_cancellation_during_stream_removes_staging_and_preserves_destination(self):
        started, release = threading.Event(), threading.Event()
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b"x"); self.wfile.flush()
                started.set(); release.wait(3)
        with _trusted_tls_server(Handler) as (origin, context), tempfile.TemporaryDirectory() as directory, Cancellation() as cancellation:
            target = Path(directory, "existing.bin"); target.write_bytes(b"old")
            failures = []
            authorization = DownloadAuthorization(online.parse_artifact(artifact(origin + "/slow")), None, None)
            def run():
                try: _download_file(authorization, target, max_bytes=len(PAYLOAD), replace=True, cancellation=cancellation, _context=context)
                except OrbitError as exc: failures.append(exc)
            thread = threading.Thread(target=run); thread.start()
            try:
                self.assertTrue(started.wait(2)); cancellation.cancel(); thread.join(2)
                self.assertFalse(thread.is_alive()); self.assertEqual(failures[0].kind, CANCELLED)
                self.assertEqual(target.read_bytes(), b"old"); self.assertEqual(list(Path(directory).iterdir()), [target])
            finally: release.set(); thread.join(3)
