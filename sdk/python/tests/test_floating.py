from __future__ import annotations

import base64
import datetime as dt
import json
import os
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from orbit_sdk import AppKey, Cancellation, Client, OrbitError
from orbit_sdk.client import _AppScope, _Config as Config
from orbit_sdk.clock import Anchor, Start, elapsed_ns, wall_seconds
from orbit_sdk.errors import CANCELLED, DENIED, INVALID_RESPONSE, STALE_RESPONSE, TRANSIENT, error
from support import PRIVATE_KEY_PATH, activation_reply, b64url, fixture_data, json_bytes


APP = AppKey.parse("orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test")
APP_SCOPE = _AppScope(APP.api_origin, APP.application_id, APP.environment_id, APP.issuer, environment=APP.environment)


def signed_session(config: Config, session_id: str, sequence: int) -> tuple[str, int]:
    now = int(time.time())
    claims = {
        "iss": config.issuer,
        "aud": f"orbit-session:{config.application_id}:{config.environment_id}",
        "sub": "licence",
        "jti": f"session-{session_id}-{sequence}",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "application_id": config.application_id,
        "environment_id": config.environment_id,
        "activation_id": "activation",
        "installation_id": config.installation_id,
        "binding_mode": "none",
        "policy_version": 1,
        "entitlements": {"export": True, "sync": False},
        "refresh_after": now + 60,
        "offline_allowed": False,
        "licence_expires_at": None,
        "session_id": session_id,
        "session_sequence": sequence,
    }
    header = {"alg": "ES256", "typ": "orbit-session+jwt", "kid": "test-fixture"}
    signing_input = f"{b64url(json_bytes(header))}.{b64url(json_bytes(claims))}"
    private = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    der = private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return f"{signing_input}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}", now


def timestamp(seconds: int) -> str:
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class FloatingTransport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict, bool]] = []
        self.session_keys = json_bytes(json.loads((Path(__file__).resolve().parents[3] / "contracts/sdk/session-grants.json").read_text())["jwks"])
        self.fail_start = False
        self.deny_start = False
        self.deny_start_code: str | None = None
        self.fail_renew = False
        self.deny_renew: str | None = None
        self.fail_session_jwks = False
        self.before_session_jwks = None
        self.block_start = False
        self.block_renew = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.entered_renew = threading.Event()
        self.release_renew = threading.Event()
        self._renew_lock = threading.Lock()
        self.renew_inflight = 0
        self.max_renew_inflight = 0

    def config(self, body: dict) -> Config:
        return Config(APP.api_origin, body["application_id"], body["environment_id"], APP.issuer,
                      body["installation_id"], body.get("fingerprint") or "", body.get("fingerprint_provider") or "")

    def post(self, route: str, body: dict, retry_safe: bool, cancel=None):
        self.requests.append(("POST", route, dict(body), retry_safe))
        if route == "/api/client/v1/activations":
            return self.activation(self.config(body), previous=False)
        if route.endswith("/validate"):
            return self.activation(self.config(body), previous=True)
        if route.endswith("/sessions") and "/renew" not in route and "/end" not in route:
            if self.block_start:
                self.entered.set()
                while not self.release.wait(0.01):
                    if cancel is not None and cancel.is_set():
                        raise error(CANCELLED, "operation_cancelled")
            if self.fail_start:
                self.fail_start = False
                raise error(TRANSIENT, "network_unavailable")
            if self.deny_start:
                raise error(DENIED, "concurrent_session_limit_reached")
            if self.deny_start_code is not None:
                code, self.deny_start_code = self.deny_start_code, None
                raise error(DENIED, code)
            return self.session_reply(self.config(body), body["session_id"], 1)
        if route.endswith("/renew"):
            with self._renew_lock:
                self.renew_inflight += 1
                self.max_renew_inflight = max(self.max_renew_inflight, self.renew_inflight)
            try:
                if self.block_renew:
                    self.entered_renew.set()
                    # Return a valid late reply even after local cancellation;
                    # the client must fence it at the response boundary.
                    self.release_renew.wait(3)
                if self.deny_renew is not None:
                    code, self.deny_renew = self.deny_renew, None
                    raise error(DENIED, code)
                if self.fail_renew:
                    self.fail_renew = False
                    raise error(TRANSIENT, "network_unavailable")
                session_id = route.rsplit("/", 2)[-2]
                return self.session_reply(self.config(body), session_id, body["sequence"])
            finally:
                with self._renew_lock:
                    self.renew_inflight -= 1
        if route.endswith("/end"):
            return None
        raise AssertionError(f"unexpected route {route}")

    def get(self, route: str, cancel=None):
        self.requests.append(("GET", route, {}, True))
        if route.startswith("/.well-known/orbit-jwks.json?"):
            if self.before_session_jwks is not None:
                self.before_session_jwks()
            if self.fail_session_jwks:
                self.fail_session_jwks = False
                raise error(TRANSIENT, "network_unavailable")
            return self.session_keys
        raise AssertionError(f"unexpected GET {route}")

    @staticmethod
    def activation(config: Config, *, previous: bool) -> bytes:
        now = int(time.time())
        return json_bytes({
            "activation_id": "activation",
            "installation_id": config.installation_id,
            "licence_id": "licence",
            "credential": None if previous else "a" * 43,
            "credential_expires_at": None,
            "grant": None,
            "server_time": timestamp(now),
            "binding_mode": "none",
            "fingerprint_provider": None,
            "licence_expires_at": None,
            "secret_replay_expired": False,
            "session_required": True,
        })

    @staticmethod
    def session_reply(config: Config, session_id: str, sequence: int) -> bytes:
        token, now = signed_session(config, session_id, sequence)
        return json_bytes({
            "session_id": session_id,
            "sequence": sequence,
            "expires_at": timestamp(now + 120),
            "server_time": timestamp(now),
            "grant": token,
        })


class OrdinaryTransport(FloatingTransport):
    def post(self, route: str, body: dict, retry_safe: bool, cancel=None):
        if route == "/api/client/v1/activations":
            self.requests.append(("POST", route, dict(body), retry_safe))
            return activation_reply(self.config(body), persistent=True)
        if route.endswith("/validate"):
            self.requests.append(("POST", route, dict(body), retry_safe))
            return activation_reply(self.config(body), previous=True, persistent=True)
        return super().post(route, body, retry_safe, cancel)

    def get(self, route: str, cancel=None):
        self.requests.append(("GET", route, {}, True))
        if route.startswith("/.well-known/orbit-jwks.json?"):
            return json_bytes(fixture_data()["jwks"])
        raise AssertionError(f"unexpected GET {route}")


@unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux private-storage integration tests")
class FloatingLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="orbit-floating-")
        os.chmod(self.directory.name, 0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def open(self, transport: FloatingTransport, *, start_worker: bool = False) -> Client:
        return Client._open_app(APP_SCOPE, self.directory.name, transport=transport, start_worker=start_worker, app_key=APP)

    def test_end_during_initial_key_or_account_activation_preserves_end_intent(self) -> None:
        for account in (False, True):
            with self.subTest(account=account):
                entered, release = threading.Event(), threading.Event()

                class Transport(FloatingTransport):
                    blocked = False

                    def post(self, route, body, retry_safe, cancel=None):
                        if route == "/api/client/v1/sessions":
                            return json_bytes({"customer": {"id": "alice", "username": "alice",
                                "email": "alice@example.test", "suspended": False,
                                "created_at": "2026-01-01T00:00:00Z"}, "session": "b" * 43,
                                "expires_at": "2030-01-01T00:00:00Z"})
                        if route == "/api/client/v1/activations" and not self.blocked:
                            self.blocked = True
                            entered.set()
                            if not release.wait(3):
                                raise AssertionError("activation was never released")
                        return super().post(route, body, retry_safe, cancel)

                transport = Transport()
                client = Client._open_app(APP_SCOPE, str(Path(self.directory.name, str(account))),
                    transport=transport, start_worker=False, app_key=APP)
                outcomes = []
                if account:
                    client.login("alice", "synthetic-password")

                def activate():
                    try:
                        outcomes.append(client.activate_account("licence") if account else client.activate("floating-key"))
                    except BaseException as exc:
                        outcomes.append(exc)

                worker = threading.Thread(target=activate)
                try:
                    worker.start()
                    self.assertTrue(entered.wait(2))
                    client.end_session()
                    release.set()
                    worker.join(3)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(len(outcomes), 1)
                    self.assertNotIsInstance(outcomes[0], BaseException)
                    self.assertNotEqual(client.snapshot().access.value, "online")
                    self.assertFalse(any(request[1].endswith("/sessions") for request in transport.requests))
                    self.assertIsNotNone(client._credential)
                    self.assertEqual(client.start_session().access.value, "online")
                    client.end_session()
                    self.assertEqual(client.activate("replacement-key").access.value, "online")
                finally:
                    release.set()
                    worker.join(3)
                    client.close()

    def test_terminal_start_errors_stop_background_retries(self) -> None:
        for kind, code, retained in ((DENIED, "licence_revoked", False),
                                     (DENIED, "session_ended", True),
                                     (INVALID_RESPONSE, "invalid_response", True)):
            with self.subTest(code=code):
                rejected = threading.Event()

                class Transport(FloatingTransport):
                    reject = False
                    terminal_starts = 0

                    def post(self, route, body, retry_safe, cancel=None):
                        if route.endswith("/sessions") and self.reject:
                            self.terminal_starts += 1
                            rejected.set()
                            raise error(kind, code)
                        return super().post(route, body, retry_safe, cancel)

                transport = Transport()
                transport.fail_start = True
                client = Client._open_app(APP_SCOPE, str(Path(self.directory.name, code)),
                    transport=transport, start_worker=False, app_key=APP)
                try:
                    with self.assertRaises(OrbitError):
                        client.activate("floating-key")
                    transport.reject = True
                    client._session_retry_deadline = time.monotonic() - 1
                    client._start_lifecycle()
                    self.assertTrue(rejected.wait(2))
                    deadline = time.monotonic() + 2
                    while client._credential is not None and not client._session_disabled and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertEqual(client._credential is not None, retained)
                    self.assertIsNone(client._session_retry_deadline)
                    self.assertTrue(client._credential is None or client._session_disabled)
                    time.sleep(0.05)
                    self.assertEqual(transport.terminal_starts, 1)
                finally:
                    client.close()

    def test_late_start_errors_cannot_poison_replacement_activation(self) -> None:
        for kind, code in ((DENIED, "session_ended"), (TRANSIENT, "network_unavailable")):
            with self.subTest(code=code):
                entered, release, replacement = threading.Event(), threading.Event(), threading.Event()

                class Transport(FloatingTransport):
                    armed = False

                    def post(self, route, body, retry_safe, cancel=None):
                        if route.endswith("/activations") and body.get("licence_key") == "replacement-key":
                            replacement.set()
                        if route.endswith("/sessions") and self.armed:
                            self.armed = False
                            entered.set()
                            if not release.wait(3):
                                raise AssertionError("old start was never released")
                            raise error(kind, code)
                        return super().post(route, body, retry_safe, cancel)

                transport = Transport()
                client = Client._open_app(APP_SCOPE, str(Path(self.directory.name, code)),
                    transport=transport, start_worker=False, app_key=APP)
                outcomes = {}

                def call(label, callback):
                    try:
                        outcomes[label] = callback()
                    except BaseException as exc:
                        outcomes[label] = exc

                client.activate("floating-key")
                client.end_session()
                transport.armed = True
                old = threading.Thread(target=lambda: call("old", client.start_session))
                new = threading.Thread(target=lambda: call("new", lambda: client.activate("replacement-key")))
                try:
                    old.start()
                    self.assertTrue(entered.wait(2))
                    new.start()
                    self.assertTrue(replacement.wait(2))
                    release.set()
                    old.join(3)
                    new.join(3)
                    self.assertFalse(old.is_alive() or new.is_alive())
                    self.assertIsInstance(outcomes["old"], OrbitError)
                    self.assertIn(outcomes["old"].kind, (CANCELLED, STALE_RESPONSE))
                    self.assertNotIsInstance(outcomes["new"], BaseException)
                    self.assertEqual(outcomes["new"].access.value, "online")
                    self.assertFalse(client._session_disabled)
                    self.assertIsNone(client._session_retry_deadline)
                finally:
                    release.set()
                    old.join(3)
                    if new.ident is not None:
                        new.join(3)
                    client.close()

    def test_activation_acquires_unpersisted_session_and_restart_uses_fresh_id(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        first = client.activate("floating-key")
        self.assertEqual(first.access.value, "online")
        self.assertTrue(first.has("export"))
        self.assertEqual(first.session.sequence, 1)
        first_id = first.session.session_id
        record = Path(self.directory.name, "orbit-storage.bin").read_bytes()
        self.assertNotIn(first_id.encode(), record)
        self.assertNotIn(b"orbit-session+jwt", record)
        self.assertIsNone(json.loads(record)["access"])
        client.close()
        self.assertTrue(any(request[1].endswith(f"/sessions/{first_id}/end") for request in transport.requests))

        restarted = self.open(transport)
        try:
            current = restarted.require_access("export")
            self.assertEqual(current.session.sequence, 1)
            self.assertNotEqual(current.session.session_id, first_id)
            self.assertEqual(restarted.snapshot().access.value, "online")
        finally:
            restarted.close()

    def test_seat_denial_preserves_credential_and_never_prompts(self) -> None:
        transport = FloatingTransport()
        transport.deny_start = True
        client = self.open(transport)
        try:
            with self.assertRaises(OrbitError) as raised:
                client.activate("floating-key")
            self.assertEqual((raised.exception.kind, raised.exception.code), (DENIED, "concurrent_session_limit_reached"))
            self.assertIsNotNone(client._credential)
            self.assertEqual(client.snapshot().access.value, "refresh_required")
            prompt = []
            with self.assertRaises(OrbitError) as retry:
                client.ensure_access("export", lambda: prompt.append(True))
            self.assertEqual(retry.exception.code, "concurrent_session_limit_reached")
            self.assertEqual(prompt, [])
            self.assertEqual([request[1] for request in transport.requests].count("/api/client/v1/activations"), 1)
        finally:
            client.close()

    def test_floating_credential_is_durable_before_the_first_session_jwks_request(self) -> None:
        transport = FloatingTransport()
        transport.fail_session_jwks = True
        observed: list[dict] = []
        state_path = Path(self.directory.name, "orbit-storage.bin")
        transport.before_session_jwks = lambda: observed.append(json.loads(state_path.read_bytes()))
        client = self.open(transport)
        try:
            with self.assertRaises(OrbitError) as raised:
                client.activate("floating-key")
            self.assertEqual(raised.exception.kind, TRANSIENT)
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["credential"]["licence_id"], "licence")
            self.assertIsNone(observed[0]["access"])
            self.assertIsNone(observed[0]["pending_activation"])

            recovered = client.refresh()
            self.assertEqual(recovered.session.sequence, 1)
            self.assertEqual(client._credential.licence_id, "licence")
        finally:
            client.close()

    def test_terminal_unacknowledged_start_uses_a_new_session_id_on_explicit_retry(self) -> None:
        transport = FloatingTransport()
        transport.deny_start_code = "session_sequence_conflict"
        client = self.open(transport)
        try:
            with self.assertRaises(OrbitError) as raised:
                client.activate("floating-key")
            self.assertEqual(raised.exception.code, "session_sequence_conflict")
            self.assertIsNone(client._pending_session_id)
            self.assertTrue(client._session_disabled)
            retried = client.start_session()
            starts = [request for request in transport.requests if request[1].endswith("/sessions") and "session_id" in request[2]]
            self.assertEqual(len(starts), 2)
            self.assertNotEqual(starts[0][2]["session_id"], starts[1][2]["session_id"])
            self.assertEqual(retried.session.session_id, starts[1][2]["session_id"])
        finally:
            client.close()

    def test_authoritative_licence_revocation_clears_floating_authority_and_credential(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        try:
            client.activate("floating-key")
            with client._state_lock:
                grant, anchor = client._floating
                client._floating = (replace(grant, refresh_after=anchor.now() - 1), anchor)
            transport.deny_renew = "licence_revoked"
            with self.assertRaises(OrbitError) as raised:
                client._advance_session(None)
            self.assertEqual(raised.exception.code, "licence_revoked")
            self.assertIsNone(client._credential)
            self.assertIsNone(client.snapshot().session)
            self.assertEqual(client.snapshot().access.value, "denied")
            record = json.loads(Path(self.directory.name, "orbit-storage.bin").read_bytes())
            self.assertIsNone(record["credential"])
            self.assertIsNone(record["access"])
        finally:
            client.close()

    def test_require_access_checks_final_expiry_and_pre_cancelled_handle(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        try:
            client.activate("floating-key")
            cancellation = Cancellation.create()
            cancellation.cancel()
            with self.assertRaises(OrbitError) as cancelled:
                client.require_access("export", cancellation=cancellation)
            self.assertEqual(cancelled.exception.kind, CANCELLED)
            cancellation.close()

            with client._state_lock:
                grant, anchor = client._floating
            before_expiry = anchor.start.elapsed + (grant.expires_at - anchor.server - 1) * 1_000_000_000
            at_expiry = anchor.start.elapsed + (grant.expires_at - anchor.server) * 1_000_000_000
            with patch("orbit_sdk.clock.elapsed_ns", side_effect=[before_expiry, before_expiry, at_expiry]), \
                    patch("orbit_sdk.clock.wall_seconds", side_effect=[anchor.start.wall + grant.expires_at - anchor.server - 1,
                                                                         anchor.start.wall + grant.expires_at - anchor.server - 1,
                                                                         anchor.start.wall + grant.expires_at - anchor.server]):
                with self.assertRaises(OrbitError) as expired:
                    client.require_access("export")
            self.assertEqual(expired.exception.code, "session_access_unavailable")
        finally:
            client.close()

    def test_end_with_unknown_floating_policy_never_attempts_a_seat(self) -> None:
        transport = FloatingTransport()
        first = self.open(transport)
        first.activate("floating-key")
        first.close()
        transport.deny_start = True  # Model full concurrent-session capacity.
        reopened = self.open(transport)
        starts_before_end = sum(request[1].endswith("/sessions") for request in transport.requests)
        with reopened._state_lock:
            reopened._session_required = False
            reopened._claims = None
            reopened._floating = None
            reopened._session_disabled = False
        try:
            ended = reopened.end_session()
            self.assertIsNone(ended.session)
            self.assertIsNotNone(reopened._credential)
            self.assertTrue(reopened._session_disabled)
            self.assertEqual(sum(request[1].endswith("/sessions") for request in transport.requests), starts_before_end)
        finally:
            reopened.close()

    def test_blocked_renewal_cannot_restore_authority_after_lifecycle_transition(self) -> None:
        for transition in ("end", "logout", "close", "replace"):
            with self.subTest(transition=transition), tempfile.TemporaryDirectory(prefix="orbit-floating-race-") as root:
                state_dir = Path(root, "state")
                state_dir.mkdir(mode=0o700)
                os.chmod(state_dir, 0o700)
                transport = FloatingTransport()
                client = Client._open_app(APP_SCOPE, str(state_dir), transport=transport, start_worker=False, app_key=APP)
                first = client.activate("floating-key")
                old_session_id = first.session.session_id
                transport.block_renew = True
                with client._state_lock:
                    grant, anchor = client._floating
                    client._floating = (replace(grant, refresh_after=anchor.now() - 1), anchor)
                outcomes: list[BaseException] = []

                def renew(cancel_handle: Cancellation | None = None) -> None:
                    try:
                        with client._operation(cancel_handle) as cancel:
                            client._advance_session(cancel)
                    except BaseException as exc:
                        outcomes.append(exc)

                renewal = threading.Thread(target=renew)
                renewal.start()
                self.assertTrue(transport.entered_renew.wait(2))
                second_started = threading.Event()
                second = threading.Thread(target=lambda: (second_started.set(), renew()))
                second.start()
                self.assertTrue(second_started.wait(2))
                replacement_result: list = []
                replacement_thread: threading.Thread | None = None
                closer: threading.Thread | None = None
                if transition == "end":
                    ended = client.end_session()
                    self.assertIsNone(ended.session)
                elif transition == "logout":
                    client.logout()
                elif transition == "close":
                    close_started = threading.Event()
                    closer = threading.Thread(target=lambda: (close_started.set(), client.close()))
                    closer.start()
                    self.assertTrue(close_started.wait(2))
                    deadline = time.monotonic() + 2
                    while not client._closed and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertTrue(client._closed)
                else:
                    replacement_thread = threading.Thread(target=lambda: replacement_result.append(client.activate("replacement-key")))
                    replacement_thread.start()
                    deadline = time.monotonic() + 2
                    while sum(request[1] == "/api/client/v1/activations" for request in transport.requests) < 2 and time.monotonic() < deadline:
                        time.sleep(0.005)
                    self.assertGreaterEqual(sum(request[1] == "/api/client/v1/activations" for request in transport.requests), 2)

                transport.release_renew.set()
                renewal.join(2)
                second.join(2)
                if replacement_thread is not None:
                    replacement_thread.join(2)
                if closer is not None:
                    closer.join(2)
                self.assertFalse(renewal.is_alive())
                self.assertFalse(second.is_alive())
                self.assertLessEqual(transport.max_renew_inflight, 1)
                self.assertTrue(outcomes)
                self.assertTrue(all(isinstance(item, OrbitError) for item in outcomes))
                self.assertTrue(all(item.kind in ("stale_response", CANCELLED) for item in outcomes))
                if transition == "replace":
                    self.assertEqual(len(replacement_result), 1)
                    self.assertNotEqual(replacement_result[0].session.session_id, old_session_id)
                if not client._closed:
                    client.close()
                record = json.loads(Path(state_dir, "orbit-storage.bin").read_bytes())
                self.assertIsNone(record["access"])
                self.assertNotIn(old_session_id, json.dumps(record))

    def test_cancelled_late_renewal_keeps_only_the_unchanged_current_interval(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        cancellation = Cancellation.create()
        transport.block_renew = True
        try:
            active = client.activate("floating-key")
            with client._state_lock:
                grant, anchor = client._floating
                client._floating = (replace(grant, refresh_after=anchor.now() - 1), anchor)
            failures: list[OrbitError] = []

            def renew() -> None:
                try:
                    with client._operation(cancellation) as cancel:
                        client._advance_session(cancel)
                except OrbitError as exc:
                    failures.append(exc)

            worker = threading.Thread(target=renew)
            worker.start()
            self.assertTrue(transport.entered_renew.wait(2))
            cancellation.cancel()
            transport.release_renew.set()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual([failure.kind for failure in failures], [CANCELLED])
            self.assertEqual(client.snapshot().session.session_id, active.session.session_id)
            self.assertEqual(client.snapshot().session.sequence, active.session.sequence)
        finally:
            transport.release_renew.set()
            cancellation.close()
            client.close()

    def test_close_fences_a_start_that_is_already_in_flight(self) -> None:
        transport = FloatingTransport()
        transport.block_start = True
        client = self.open(transport)
        failures: list[OrbitError] = []

        def activate() -> None:
            try:
                client.activate("floating-key")
            except OrbitError as exc:
                failures.append(exc)

        worker = threading.Thread(target=activate)
        worker.start()
        self.assertTrue(transport.entered.wait(2))
        client.close()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual([failure.kind for failure in failures], [CANCELLED])
        record = json.loads(Path(self.directory.name, "orbit-storage.bin").read_bytes())
        self.assertIsNotNone(record["credential"])
        self.assertIsNone(record["access"])
        self.assertNotIn("orbit-session+jwt", json.dumps(record))

    def test_floating_guard_fails_closed_after_lease_replacement(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        client.activate("floating-key")
        try:
            lease = Path(self.directory.name, "orbit-storage.lock")
            moved = lease.with_name("orbit-storage.old-lock")
            lease.rename(moved)
            lease.write_bytes(b"\x01")
            lease.chmod(0o600)
            with self.assertRaises(OrbitError) as raised:
                client.require_access("export")
            self.assertEqual(raised.exception.kind, "storage")
        finally:
            client.close()

    def test_lost_start_and_renewal_reuse_the_same_operation_identity(self) -> None:
        transport = FloatingTransport()
        transport.fail_start = True
        client = self.open(transport)
        try:
            with self.assertRaises(OrbitError) as start_error:
                client.activate("floating-key")
            self.assertEqual(start_error.exception.kind, TRANSIENT)
            sent_ids = [request[2]["session_id"] for request in transport.requests if request[1].endswith("/sessions") and "session_id" in request[2]]
            recovered = client.require_access("export")
            self.assertEqual(sent_ids[0], recovered.session.session_id)

            with client._state_lock:
                grant, original_anchor = client._floating
                client._floating = (grant, type(original_anchor)(grant.refresh_after, original_anchor.start))
            transport.fail_renew = True
            with client._state_lock:
                expires = client._floating[0].expires_at
            still_valid = client._advance_session(None)
            self.assertEqual(still_valid["session"]["sequence"], 1)
            self.assertEqual(still_valid["session"]["expires_at"], expires)
            with client._state_lock:
                client._session_retry_deadline = None
            renewed = client._advance_session(None)
            self.assertEqual(renewed["session"]["sequence"], 2)
            renewals = [request[2]["sequence"] for request in transport.requests if request[1].endswith("/renew")]
            self.assertEqual(renewals, [2, 2])
        finally:
            client.close()

    def test_expired_session_uses_a_new_id_and_never_authorizes_past_its_interval(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        try:
            initial = client.activate("floating-key")
            session_id = initial.session.session_id
            with client._state_lock:
                grant, _ = client._floating
                now = int(time.time())
                expired = replace(grant, refresh_after=now - 2, expires_at=now - 1)
                client._floating = (expired, Anchor(now, Start(elapsed_ns(), wall_seconds())))

            snapshot = client._advance_session(None)
            self.assertEqual(snapshot["access"], "online")
            self.assertEqual(snapshot["session"]["sequence"], 1)
            self.assertNotEqual(snapshot["session"]["session_id"], session_id)
            starts = [request for request in transport.requests if request[1].endswith("/sessions") and "session_id" in request[2]]
            self.assertEqual(len(starts), 2)
            self.assertNotEqual(starts[0][2]["session_id"], starts[1][2]["session_id"])
        finally:
            client.close()

    def test_logout_clears_session_authority_and_best_effort_releases_seat(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        try:
            active = client.activate("floating-key")
            session_id = active.session.session_id
            client.logout()
            self.assertIsNone(client.snapshot().session)
            self.assertEqual(client.snapshot().access.value, "denied")
            self.assertIsNone(client._credential)
            # The release runs on a background thread after logout returns.
            ended = lambda: any(request[1].endswith(f"/sessions/{session_id}/end") for request in transport.requests)
            release_deadline = time.monotonic() + 2
            while time.monotonic() < release_deadline and not ended():
                time.sleep(0.01)
            self.assertTrue(ended())
        finally:
            client.close()

    def test_cancellation_after_start_request_keeps_only_the_activation_credential(self) -> None:
        transport = FloatingTransport()
        transport.block_start = True
        client = self.open(transport)
        cancellation = Cancellation.create()
        failures: list[OrbitError] = []

        def activate() -> None:
            try:
                client.activate("floating-key", cancellation=cancellation)
            except OrbitError as exc:
                failures.append(exc)

        worker = threading.Thread(target=activate)
        worker.start()
        try:
            self.assertTrue(transport.entered.wait(2))
            cancellation.cancel()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].kind, CANCELLED)
            snapshot = client.snapshot()
            self.assertEqual(snapshot.access.value, "refresh_required")
            self.assertIsNone(snapshot.session)
            state = json.loads(Path(self.directory.name, "orbit-storage.bin").read_text())
            self.assertIsNone(state["access"])
            self.assertIsNotNone(state["credential"])
            self.assertFalse(any("orbit-session+jwt" in value for value in state.values() if isinstance(value, str)))
            release_deadline = time.monotonic() + 2
            while time.monotonic() < release_deadline and not any(request[1].endswith("/end") for request in transport.requests):
                time.sleep(0.01)
            self.assertTrue(any(request[1].endswith("/end") for request in transport.requests))
        finally:
            transport.release.set()
            worker.join(2)
            cancellation.close()
            client.close()

    def test_background_worker_renews_a_due_session_once(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        class PollingStop:
            stopped = False

            def is_set(self) -> bool:
                return self.stopped

            def set(self) -> None:
                self.stopped = True

            def wait(self, timeout: float | None = None) -> bool:
                time.sleep(min(timeout if timeout is not None else 0.01, 0.01))
                return self.stopped

        try:
            client.activate("floating-key")
            client._lifecycle_stop = PollingStop()
            worker = threading.Thread(target=client._lifecycle, daemon=True)
            client._lifecycle_thread = worker
            worker.start()
            with client._state_lock:
                grant, anchor = client._floating
                current_time = anchor.now()
                client._floating = (replace(grant, refresh_after=current_time - 1), anchor)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not any(request[1].endswith("/renew") for request in transport.requests):
                time.sleep(0.01)
            renewals = [request for request in transport.requests if request[1].endswith("/renew")]
            self.assertEqual(len(renewals), 1)
            self.assertEqual(renewals[0][2]["sequence"], 2)
            self.assertEqual(client.snapshot().session.sequence, 2)
        finally:
            client.close()

    def test_wall_rollback_drops_the_local_session_and_never_prompts_for_a_key(self) -> None:
        transport = FloatingTransport()
        client = self.open(transport)
        try:
            active = client.activate("floating-key")
            self.assertTrue(active.has("export"))
            request_count = len(transport.requests)
            original_wall = wall_seconds()
            transport.fail_start = True
            with patch("orbit_sdk.clock.wall_seconds", return_value=original_wall - 31), \
                    patch("orbit_sdk.client.wall_seconds", return_value=original_wall - 31):
                snapshot = client.snapshot()
                self.assertIsNone(snapshot.session)
                self.assertEqual(snapshot.access.value, "refresh_required")
                prompts: list[bool] = []
                with self.assertRaises(OrbitError) as raised:
                    client.ensure_access("export", lambda: prompts.append(True))
                self.assertEqual(raised.exception.kind, TRANSIENT)
                self.assertEqual(prompts, [])
            self.assertEqual(len(transport.requests), request_count + 1)
        finally:
            client.close()

    def test_end_fences_inflight_start_and_disables_automatic_reacquisition(self) -> None:
        transport = FloatingTransport()
        transport.block_start = True
        client = self.open(transport)
        failures: list[OrbitError] = []

        def activate() -> None:
            try:
                client.activate("floating-key")
            except OrbitError as exc:
                failures.append(exc)

        worker = threading.Thread(target=activate)
        worker.start()
        try:
            self.assertTrue(transport.entered.wait(2))
            ended = client.end_session()
            self.assertIsNone(ended.session)
            transport.release.set()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertTrue(failures)
            self.assertEqual(failures[0].kind, CANCELLED)
            with self.assertRaises(OrbitError) as raised:
                client.require_access("export")
            self.assertEqual(raised.exception.code, "session_explicitly_ended")
            self.assertIsNotNone(client._credential)
        finally:
            transport.release.set()
            worker.join(2)
            client.close()

    def test_ordinary_policy_start_and_end_are_idempotent_noops(self) -> None:
        transport = OrdinaryTransport()
        client = self.open(transport)
        try:
            initial = client.activate("ordinary-key")
            request_count = len(transport.requests)
            self.assertIsNone(initial.session)
            self.assertEqual(client.start_session(), initial)
            self.assertEqual(client.end_session(), initial)
            self.assertEqual(len(transport.requests), request_count)
            self.assertFalse(any("/sessions" in request[1] for request in transport.requests))
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
