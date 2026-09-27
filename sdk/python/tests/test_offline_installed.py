from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from orbit_sdk import Cancellation, Client, OrbitError
from orbit_sdk.client import _AppScope
from orbit_sdk.errors import CANCELLED, CLOCK_UNCERTAIN, STORAGE, TRANSIENT, error
from orbit_sdk.offline import OfflineKeys
from support import b64url
from test_persistent_client import APP, APP_SCOPE, PersistentTransport

ROOT = Path(__file__).resolve().parents[3]
CORPUS = json.loads((ROOT / "contracts/sdk/offline-files.json").read_text())
SIGNER = serialization.load_pem_private_key((ROOT / "sdk/rust/tests/fixtures/es256-test-private.pem").read_bytes(), None)


class NoNetwork:
    def post(self, *args, **kwargs):
        raise AssertionError("offline operation made an HTTP request")

    def get(self, *args, **kwargs):
        raise AssertionError("offline operation fetched keys")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux installed storage and injected clock")
class OfflineInstalledTests(unittest.TestCase):
    def setUp(self):
        self.wall = 1_800_000_000
        self.elapsed = 10_000_000_000
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        os.chmod(self.directory, 0o700)
        for name in ("orbit_sdk.clock.wall_seconds", "orbit_sdk.client.wall_seconds"):
            self.stack.enter_context(patch(name, side_effect=lambda: self.wall))
        for name in ("orbit_sdk.clock.elapsed_ns", "orbit_sdk.client.elapsed_ns"):
            self.stack.enter_context(patch(name, side_effect=lambda: self.elapsed))
        self.keys = OfflineKeys.parse(CORPUS["jwks"], "test")

    def open(self, *, keys=True, transport=None):
        return Client._open_app(APP_SCOPE, self.directory, transport=transport or NoNetwork(), start_worker=False, app_key=APP, offline_keys=self.keys if keys else None)

    def issue(self, client, *, sequence=1, duration=183 * 86400, **changes):
        claims = {
            "ver": 1, "iss": APP.issuer, "aud": "orbit-offline:app:test", "sub": "licence",
            "jti": f"issuance_{sequence}", "iat": self.wall, "nbf": self.wall, "exp": self.wall + duration,
            "application_id": "app", "environment_id": "test", "activation_id": "activation",
            "installation_id": client.config.installation_id, "sequence": sequence,
            "binding_mode": "none", "policy_version": 1, "entitlements": {"export": True},
        }
        claims.update(changes)
        header = {"alg": "ES256", "typ": "orbit-offline+jwt", "kid": "offline-test-fixture"}
        encode = lambda value: b64url(json.dumps(value, separators=(",", ":")).encode())
        message = encode(header) + "." + encode(claims)
        r, s = utils.decode_dss_signature(SIGNER.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return message + "." + b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def advance(self, seconds):
        self.wall += seconds
        self.elapsed += seconds * 1_000_000_000

    def test_public_request_and_offline_restart_keep_installation_and_expiry(self):
        with self.open() as client:
            request = json.loads(client.offline_request().to_json())
            self.assertEqual(request["format"], "orbit-offline-request")
            self.assertEqual(request["installation_id"], client.config.installation_id)
            self.assertIsNone(request["fingerprint"])
            file = self.issue(client)
            snapshot = client.import_offline_file(file)
            expiry = snapshot.expires_at
            self.assertEqual(snapshot.access.value, "offline")
            self.assertIsNone(snapshot.next_check_at)
            self.assertFalse(snapshot.reauthentication_required)
            self.assertTrue(client.require_access("export").has("export"))
            self.advance(86400)
        with self.open() as restarted:
            self.assertEqual(json.loads(restarted.offline_request().to_json()), request)
            self.assertEqual(restarted.require_access("export").expires_at, expiry)
        with self.assertRaises(OrbitError) as raised:
            self.open(keys=False)
        self.assertEqual(raised.exception.code, "offline_keys_required")

    def test_expiry_after_sleep_and_restart_does_not_prompt_or_renew(self):
        with self.open() as client:
            file = self.issue(client, duration=365 * 86400)
            client.import_offline_file(file)
            self.advance(365 * 86400)
            self.assertEqual(client.snapshot().access.value, "expired")
            with self.assertRaises(OrbitError) as raised:
                client.ensure_access("export", lambda: self.fail("expired offline file prompted for a key"))
            self.assertEqual(raised.exception.code, "offline_file_expired")
        with self.open() as restarted:
            self.assertEqual(restarted.snapshot().access.value, "expired")
            replacement = self.issue(restarted, sequence=2)
            self.assertTrue(restarted.import_offline_file(replacement).has("export"))

    def test_renewal_and_logout_retain_the_floor_and_reject_conflicting_sequence(self):
        with self.open() as client:
            original = self.issue(client)
            client.import_offline_file(original)
            renewed = self.issue(client, sequence=2, duration=86400)
            expiry = client.import_offline_file(renewed).expires_at
            client.import_offline_file(renewed)
            conflicting = self.issue(client, sequence=2, duration=2 * 86400)
            for rejected in (original, conflicting):
                with self.assertRaises(OrbitError):
                    client.import_offline_file(rejected)
                self.assertEqual(client.require_access("export").expires_at, expiry)
            client.logout()
        with self.open() as restarted:
            with self.assertRaises(OrbitError):
                restarted.import_offline_file(original)
            self.assertEqual(restarted.import_offline_file(renewed).expires_at, expiry)

    def test_clock_rollback_denies_access_in_process_and_after_restart(self):
        client = self.open()
        client.import_offline_file(self.issue(client))
        self.wall -= 60
        self.elapsed += 10_000_000_000
        with self.assertRaises(OrbitError) as raised:
            client.require_access("export")
        self.assertEqual(raised.exception.kind, CLOCK_UNCERTAIN)
        client.close()
        with self.open() as restarted:
            with self.assertRaises(OrbitError) as raised:
                restarted.require_access("export")
            self.assertEqual(raised.exception.kind, CLOCK_UNCERTAIN)

    def test_durable_failure_never_exposes_verified_but_unsaved_authority(self):
        client = self.open()
        file = self.issue(client)
        with patch("orbit_sdk.persistent_storage._write_linux_record", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(OrbitError) as raised:
                client.import_offline_file(file)
            self.assertEqual(raised.exception.kind, STORAGE)
            with self.assertRaises(OrbitError) as raised:
                client.require_access("export")
            self.assertEqual(raised.exception.kind, STORAGE)
        client.close()

    def test_modified_persisted_file_is_rejected_without_recreating_identity(self):
        with self.open() as client:
            client.import_offline_file(self.issue(client))
        path = Path(self.directory, "orbit-storage.bin")
        record = json.loads(path.read_bytes())
        identity = record["installation"]["id"]
        token = record["offline"]["jws"].split(".")
        record["offline"]["jws"] = ".".join(token[:2]) + "." + b64url(bytes(64))
        path.write_text(json.dumps(record))
        with self.assertRaises(OrbitError):
            self.open()
        self.assertEqual(json.loads(path.read_bytes())["installation"]["id"], identity)

    def test_online_activation_changes_mode_without_resetting_renewal_history(self):
        transport = PersistentTransport()
        with patch("support.time.time", side_effect=lambda: self.wall):
            with self.open(transport=transport) as client:
                old = self.issue(client, sequence=1)
                current = self.issue(client, sequence=2)
                client.import_offline_file(current)
                self.advance(120)
                self.assertEqual(client.activate("synthetic-key").access.value, "online")
                state = json.loads(Path(self.directory, "orbit-storage.bin").read_bytes())
                self.assertIsNone(state["offline"]["jws"])
                self.assertEqual(state["offline"]["time_high_water"], self.wall)
                with self.assertRaises(OrbitError):
                    client.import_offline_file(old)
                client.import_offline_file(current)
                count = len(transport.requests)
                client.require_access("export")
                self.assertEqual(len(transport.requests), count)

    def test_failed_online_activation_does_not_restore_offline_access(self):
        transport = PersistentTransport(activation_error=error(TRANSIENT, "network_unavailable"))
        with self.open(transport=transport) as client:
            client.import_offline_file(self.issue(client))
            with self.assertRaises(OrbitError):
                client.activate("synthetic-key")
            self.assertEqual(client.snapshot().access.value, "denied")
        with self.open() as restarted:
            self.assertEqual(restarted.snapshot().access.value, "denied")

    def test_cancelled_import_does_not_replace_authority_or_write_state(self):
        with self.open() as client:
            client.import_offline_file(self.issue(client))
            path = Path(self.directory, "orbit-storage.bin")
            before = path.read_bytes()
            cancellation = Cancellation.create()
            try:
                cancellation.cancel()
                with self.assertRaises(OrbitError) as raised:
                    client.import_offline_file(self.issue(client, sequence=2), cancellation=cancellation)
                self.assertEqual(raised.exception.kind, CANCELLED)
            finally:
                cancellation.close()
            self.assertEqual(path.read_bytes(), before)
            self.assertTrue(client.require_access("export").has("export"))

    def test_reimport_does_not_move_continuous_time_back_between_checkpoints(self):
        with self.open() as client:
            file = self.issue(client, duration=86400)
            client.import_offline_file(file)
            self.advance(86400)
            self.wall -= 20  # Within the permitted wall-clock drift.
            self.assertEqual(client.snapshot().access.value, "expired")
            with self.assertRaises(OrbitError):
                client.import_offline_file(file)
            self.assertEqual(client.snapshot().access.value, "expired")

    def test_clock_uncertainty_cannot_be_cleared_by_reimporting_the_file(self):
        with self.open() as client:
            file = self.issue(client, duration=86400)
            client.import_offline_file(file)
            self.elapsed += 86400 * 1_000_000_000
            with self.assertRaises(OrbitError) as raised:
                client.require_access("export")
            self.assertEqual(raised.exception.kind, CLOCK_UNCERTAIN)
            with self.assertRaises(OrbitError):
                client.import_offline_file(file)
            self.assertEqual(client.snapshot().access.value, "denied")

    def test_replaced_lease_denies_guard_and_never_rewrites_state(self):
        client = self.open()
        client.import_offline_file(self.issue(client))
        path = Path(self.directory, "orbit-storage.bin")
        before = path.read_bytes()
        lease = Path(self.directory, "orbit-storage.lock")
        lease.rename(lease.with_suffix(".old"))
        lease.write_bytes(b"\x01")
        lease.chmod(0o600)
        with self.assertRaises(OrbitError) as raised:
            client.require_access("export")
        self.assertEqual(raised.exception.kind, STORAGE)
        client.close()
        self.assertEqual(path.read_bytes(), before)

    def test_new_machine_does_not_reuse_offline_identity_or_authority(self):
        with self.open() as client:
            identity = client.config.installation_id
            file = self.issue(client)
            client.import_offline_file(file)
        scope = _AppScope(APP.api_origin, APP.application_id, APP.environment_id, APP.issuer, "a" * 64, "custom:test")
        with Client._open_app(scope, self.directory, transport=NoNetwork(), start_worker=False, app_key=APP, offline_keys=self.keys) as changed:
            self.assertNotEqual(changed.config.installation_id, identity)
            self.assertEqual(changed.snapshot().access.value, "denied")
            with self.assertRaises(OrbitError):
                changed.import_offline_file(file)

    def test_lifecycle_checkpoints_offline_access_without_refresh_or_busy_retry(self):
        class OneIteration:
            def __init__(self): self.waits = []
            def is_set(self): return False
            def wait(self, timeout): self.waits.append(timeout); return True
            def set(self): pass
        with self.open() as client:
            client.import_offline_file(self.issue(client))
            self.advance(120)
            stop = OneIteration()
            client._lifecycle_stop = stop
            client._lifecycle()
            self.assertEqual(stop.waits, [60.0])
            state = json.loads(Path(self.directory, "orbit-storage.bin").read_bytes())
            self.assertEqual(state["offline"]["time_high_water"], self.wall)


if __name__ == "__main__":
    unittest.main()
