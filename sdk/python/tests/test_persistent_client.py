from __future__ import annotations

import json
import os
import stat
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from orbit_sdk import AppConfig, Client, Config, OrbitError
from orbit_sdk.errors import CANCELLED, CONFIGURATION, DENIED, STORAGE, TRANSIENT, error
from orbit_sdk.persistent_storage import AccessState, InstallationStorage, _ensure_linux_directory, canonical_scope, scope_key
from orbit_sdk.client import _validate_app_config

from support import activation_reply, fixture_data, sign_grant


APP = AppConfig("https://orbit.example.test", "app", "test", "https://issuer.example.test")


class _WaitProbe:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.observed = threading.Event()
        self.timeouts: list[float | None] = []

    def wait(self, timeout: float | None = None) -> bool:
        self.timeouts.append(timeout)
        self.observed.set()
        return self.event.wait(timeout)

    def set(self) -> None:
        self.event.set()

    def is_set(self) -> bool:
        return self.event.is_set()


class PersistentTransport:
    def __init__(self, *, offline: bool = False, validation_error: OrbitError | None = None, activation_error: OrbitError | None = None) -> None:
        self.offline = offline
        self.validation_error = validation_error
        self.activation_error = activation_error
        self.requests: list[tuple[str, str, dict | None, bool]] = []
        self.jwks = json.dumps(fixture_data()["jwks"], separators=(",", ":")).encode()
        self.credential_expiry: int | None = None
        self.block_validation = False
        self.entered = threading.Event()
        self.release = threading.Event()

    def _config(self, body: dict) -> Config:
        return Config(
            APP.api_origin,
            body["application_id"],
            body["environment_id"],
            APP.issuer,
            body["installation_id"],
            body.get("fingerprint") or "",
            body.get("fingerprint_provider") or "",
        )

    def post(self, route: str, body: dict, retry_safe: bool, cancel=None):
        self.requests.append(("POST", route, dict(body), retry_safe))
        if route == "/api/client/v1/activations":
            if self.activation_error is not None:
                raise self.activation_error
            expiry = self.credential_expiry
            if expiry is None:
                reply = activation_reply(self._config(body), offline=self.offline, persistent=True)
            else:
                reply = activation_reply(self._config(body), offline=self.offline, persistent=True, credential_expiry=expiry)
            return reply
        if route.endswith("/validate"):
            if self.block_validation:
                self.entered.set()
                while not self.release.wait(0.01):
                    if cancel is not None and cancel.is_set():
                        raise error(CANCELLED, "operation_cancelled")
            if self.validation_error is not None:
                raise self.validation_error
            if self.credential_expiry is None:
                return activation_reply(self._config(body), offline=self.offline, previous=True, persistent=True)
            return activation_reply(self._config(body), offline=self.offline, previous=True, persistent=True, credential_expiry=self.credential_expiry)
        raise AssertionError(f"unexpected POST route {route}")

    def get(self, route: str, cancel=None):
        self.requests.append(("GET", route, None, True))
        if route.startswith("/.well-known/orbit-jwks.json?"):
            return self.jwks
        raise AssertionError(f"unexpected GET route {route}")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux installed-client persistence tests")
class PersistentClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="orbit-installed-client-")
        os.chmod(self.directory.name, 0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def open(self, transport: PersistentTransport, *, worker: bool = False) -> Client:
        return Client._open_for_test(APP, self.directory.name, transport, start_worker=worker)

    def _activate_offline(self, *, transport: PersistentTransport | None = None) -> tuple[Client, dict]:
        fake = transport or PersistentTransport(offline=True)
        client = self.open(fake)
        snapshot = client.activate("synthetic-key-for-persistence")
        self.assertEqual(snapshot["access"], "online")
        client.close()
        return client, snapshot

    def test_first_open_key_activation_and_online_restart_without_key(self) -> None:
        transport = PersistentTransport()
        client = self.open(transport)
        try:
            self.assertEqual(transport.requests, [])
            installation_id = client.config.installation_id
            snapshot = client.activate("synthetic-key-never-persist-this")
            self.assertEqual(snapshot["access"], "online")
            method, route, body, _ = transport.requests[0]
            self.assertEqual((method, route), ("POST", "/api/client/v1/activations"))
            self.assertEqual(body["credential_mode"], "persistent")
            self.assertEqual(body["installation_id"], installation_id)
            record = Path(self.directory.name, "orbit-storage.bin").read_bytes()
            self.assertNotIn(b"synthetic-key-never-persist-this", record)
            value = json.loads(record)
            self.assertEqual(value["format"], 2)
            self.assertIsNone(value["credential"]["expires_at"])
            self.assertIsNone(value["pending_activation"])
            self.assertIsNotNone(value["access"])
        finally:
            client.close()

        restarted_transport = PersistentTransport()
        restarted = self.open(restarted_transport)
        try:
            self.assertEqual(restarted.config.installation_id, installation_id)
            self.assertEqual(restarted.snapshot()["access"], "online")
            self.assertEqual(restarted_transport.requests[0][1], "/api/client/v1/activations/activation/validate")
            self.assertEqual(restarted_transport.requests[0][2]["credential"], "a" * 43)
        finally:
            restarted.close()

    def test_external_previous_credential_is_retry_bound_without_local_saved_credential(self) -> None:
        previous = "p" * 43
        operation_id = "explicit-rebind-operation-id"
        transport = PersistentTransport(activation_error=error(TRANSIENT, "network_unavailable"))
        client = self.open(transport)
        try:
            with self.assertRaises(OrbitError):
                client.activate_previous("rebind-key", previous, operation_id)
            pending = client._persistent_storage.pending_activation
            self.assertIsNotNone(pending)
            first_digest = pending.input_digest
            record = Path(self.directory.name, "orbit-storage.bin").read_bytes()
            self.assertNotIn(previous.encode(), record)
            with self.assertRaises(OrbitError) as changed:
                client.activate_previous("rebind-key", "q" * 43, operation_id)
            self.assertEqual(changed.exception.kind, CONFIGURATION)
            self.assertEqual(client._persistent_storage.pending_activation.input_digest, first_digest)

            transport.activation_error = None
            snapshot = client.activate_previous("rebind-key", previous, operation_id)
            self.assertEqual(snapshot["access"], "online")
            activation_requests = [request[2] for request in transport.requests if request[1] == "/api/client/v1/activations"]
            self.assertEqual([request["idempotency_key"] for request in activation_requests], [operation_id, operation_id])
            self.assertEqual([request["previous_credential"] for request in activation_requests], [previous, previous])
            self.assertIsNone(client._persistent_storage.pending_activation)
        finally:
            client.close()

    def test_malformed_activation_reply_keeps_pending_retry_identity(self) -> None:
        transport = PersistentTransport()
        client = self.open(transport)
        try:
            with patch.object(transport, "post", return_value=b"{}"):
                with self.assertRaises(OrbitError) as malformed:
                    client.activate("same-malformed-key")
            self.assertEqual(malformed.exception.kind, "invalid_response")
            pending = client._persistent_storage.pending_activation
            self.assertIsNotNone(pending)
            self.assertIsNone(client._storage.load()[1])
            self.assertIsNone(client._persistent_storage.access)

            snapshot = client.activate("same-malformed-key")
            self.assertEqual(snapshot["access"], "online")
            self.assertIsNone(client._persistent_storage.pending_activation)
            requests = [request[2] for request in transport.requests if request[1] == "/api/client/v1/activations"]
            self.assertEqual(requests[-1]["idempotency_key"], pending.operation_id)
        finally:
            client.close()

    def test_definitive_activation_denial_clears_pending_operation(self) -> None:
        client = self.open(PersistentTransport(activation_error=error(DENIED, "invalid_licence")))
        try:
            with self.assertRaises(OrbitError) as denied:
                client.activate("rejected-key")
            self.assertEqual(denied.exception.kind, DENIED)
            self.assertIsNone(client._persistent_storage.pending_activation)
            self.assertIsNone(client._storage.load()[1])
        finally:
            client.close()

    def test_codec_and_config_validation_do_not_create_tls_context(self) -> None:
        with patch.object(ssl, "create_default_context", wraps=ssl.create_default_context) as create_context:
            _validate_app_config(APP)
            scope_key(canonical_scope(APP))
        create_context.assert_not_called()

    def test_linux_directory_creation_syncs_each_new_parent_entry(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux private-file storage only")
        with tempfile.TemporaryDirectory(prefix="orbit-sync-parent-") as root:
            created_path = Path(root, "private", "installation")
            directory_syncs: list[int] = []
            real_fsync = os.fsync

            def sync(fd: int) -> None:
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    directory_syncs.append(fd)
                real_fsync(fd)

            with patch("orbit_sdk.persistent_storage.os.fsync", side_effect=sync):
                _ensure_linux_directory(str(created_path))
            self.assertGreaterEqual(len(directory_syncs), 2)

    def test_strict_outage_keeps_saved_credential_without_prompting_for_key(self) -> None:
        with self.open(PersistentTransport()) as client:
            client.activate("strict-restart-key")
        transport = PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable"))
        with self.open(transport) as client:
            for _ in range(2):
                with self.assertRaises(OrbitError) as unavailable:
                    client.require_access("export")
                self.assertEqual(unavailable.exception.kind, TRANSIENT)
            self.assertEqual(len(transport.requests), 1)
            self.assertIsNotNone(client._persistent_storage.load()[1])

    def test_offline_restart_keeps_original_signed_deadline(self) -> None:
        _, original = self._activate_offline()
        offline = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            snapshot = offline.snapshot()
            self.assertEqual(snapshot["access"], "offline")
            self.assertEqual(snapshot["expires_at"], original["expires_at"])
            self.assertLessEqual(snapshot["remaining_offline_seconds"], original["remaining_offline_seconds"])
        finally:
            offline.close()

    def test_finite_and_null_persistent_expiry_are_distinct_and_missing_is_rejected(self) -> None:
        finite_expiry = int(time.time()) + 3600
        finite_transport = PersistentTransport()
        finite_transport.credential_expiry = finite_expiry
        client = self.open(finite_transport)
        try:
            with self.assertRaises(OrbitError) as fresh_finite:
                client.activate("finite-key")
            self.assertEqual(fresh_finite.exception.kind, "invalid_response")
            client.local_logout()
        finally:
            client.close()

        record_path = Path(self.directory.name, "orbit-storage.bin")
        successful = self.open(PersistentTransport())
        try:
            successful.activate("persistent-key")
        finally:
            successful.close()
        value = json.loads(record_path.read_bytes())
        value["credential"]["expires_at"] = finite_expiry
        value["access"] = None
        record_path.write_text(json.dumps(value, separators=(",", ":")))
        os.chmod(record_path, 0o600)
        finite_restart_transport = PersistentTransport()
        finite_restart_transport.credential_expiry = finite_expiry
        finite_restarted = self.open(finite_restart_transport)
        try:
            self.assertEqual(finite_restarted.snapshot()["credential_expires_at"], finite_expiry)
        finally:
            finite_restarted.close()

        value = json.loads(record_path.read_bytes())
        value["credential"]["expires_at"] = None
        value["access"] = None
        record_path.write_text(json.dumps(value, separators=(",", ":")))
        os.chmod(record_path, 0o600)
        restarted = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            self.assertIsNone(restarted.snapshot()["credential_expires_at"])
        finally:
            restarted.close()

        missing = PersistentTransport()
        client = self.open(missing)
        try:
            missing.activation_error = None
            missing.post = lambda route, body, retry_safe, cancel=None: b'{"activation_id":"activation"}'
            with self.assertRaises(OrbitError) as raised:
                client.activate("missing-expiry-key")
            self.assertEqual(raised.exception.kind, "invalid_response")
            self.assertIsNone(client._storage.load()[1])
            with self.assertRaises(OrbitError) as opening:
                self.open(PersistentTransport())
            self.assertEqual(opening.exception.kind, STORAGE)
        finally:
            client.close()

    def test_lost_activation_response_reuses_same_pending_id_and_rejects_other_key(self) -> None:
        failing = PersistentTransport(activation_error=error(TRANSIENT, "network_unavailable"))
        client = self.open(failing)
        with self.assertRaises(OrbitError) as raised:
            client.activate("same-key")
        self.assertEqual(raised.exception.kind, TRANSIENT)
        pending = client._persistent_storage.pending_activation
        self.assertIsNotNone(pending)
        first_id = pending.operation_id
        record = Path(self.directory.name, "orbit-storage.bin").read_bytes()
        self.assertNotIn(b"same-key", record)
        client.close()

        restarted_transport = PersistentTransport()
        restarted = self.open(restarted_transport)
        try:
            with self.assertRaises(OrbitError) as different:
                restarted.activate("different-key")
            self.assertEqual(different.exception.kind, CONFIGURATION)
            self.assertEqual(restarted_transport.requests, [])
            result = restarted.activate("same-key")
            self.assertEqual(result["access"], "online")
            retries = [entry[2]["idempotency_key"] for entry in restarted_transport.requests if entry[0] == "POST" and entry[1] == "/api/client/v1/activations"]
            self.assertEqual(retries, [first_id])
            self.assertIsNone(restarted._persistent_storage.pending_activation)
        finally:
            restarted.close()

    def test_pending_recovery_expiry_requires_deliberate_logout(self) -> None:
        client = self.open(PersistentTransport(activation_error=error(TRANSIENT, "network_unavailable")))
        with self.assertRaises(OrbitError):
            client.activate("expired-pending-key")
        client.close()
        path = Path(self.directory.name, "orbit-storage.bin")
        record = json.loads(path.read_bytes())
        record["pending_activation"]["created_at"] = int(time.time()) - 86401
        path.write_text(json.dumps(record, separators=(",", ":")))
        os.chmod(path, 0o600)
        restarted = self.open(PersistentTransport())
        try:
            with self.assertRaises(OrbitError) as raised:
                restarted.activate("expired-pending-key")
            self.assertEqual(raised.exception.code, "pending_activation_recovery_required")
            restarted.local_logout()
            self.assertEqual(restarted.activate("new-key")["access"], "online")
        finally:
            restarted.close()

    def test_clock_rollback_discards_cache_forward_clock_estimates_from_wall_high_water(self) -> None:
        _, original = self._activate_offline()
        path = Path(self.directory.name, "orbit-storage.bin")
        record = json.loads(path.read_bytes())
        access = record["access"]
        rollback = access["wall_high_water"] - 1
        with patch("orbit_sdk.client.wall_seconds", return_value=rollback):
            rejected = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            self.assertEqual(rejected.snapshot()["access"], "refresh_required")
        finally:
            rejected.close()

        # Restore the original cache for a forward-clock estimate from its
        # receipt pair; a fresh process has no monotonic timestamp to reuse.
        record_path = Path(self.directory.name, "orbit-storage.bin")
        recovered_state = InstallationStorage.open(self.directory.name, APP)
        recovered_state.close()
        record = json.loads(record_path.read_bytes())
        record["access"] = access
        record_path.write_text(json.dumps(record, separators=(",", ":")))
        os.chmod(record_path, 0o600)
        forward = access["wall_high_water"] + 20
        with patch("orbit_sdk.client.wall_seconds", return_value=forward), patch("orbit_sdk.clock.wall_seconds", return_value=forward):
            estimated = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
            try:
                self.assertEqual(estimated.snapshot()["access"], "offline")
                self.assertEqual(estimated.snapshot()["expires_at"], original["expires_at"])
            finally:
                estimated.close()

    def test_reboot_uses_wall_estimate_without_reusing_monotonic_origin(self) -> None:
        _, original = self._activate_offline()
        new_boot_elapsed = 50_000_000_000
        with patch("orbit_sdk.client.elapsed_ns", return_value=new_boot_elapsed), patch("orbit_sdk.clock.elapsed_ns", return_value=new_boot_elapsed):
            restarted = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
            try:
                self.assertEqual(restarted.snapshot()["access"], "offline")
                self.assertEqual(restarted.snapshot()["expires_at"], original["expires_at"])
            finally:
                restarted.close()

    def test_expired_or_bad_signature_cache_cannot_authorize_offline(self) -> None:
        _, _ = self._activate_offline()
        path = Path(self.directory.name, "orbit-storage.bin")
        record = json.loads(path.read_bytes())
        original = record["access"]
        record["access"]["jws"] = record["access"]["jws"][:-1] + ("A" if record["access"]["jws"][-1] != "A" else "B")
        path.write_text(json.dumps(record, separators=(",", ":")))
        os.chmod(path, 0o600)
        rejected = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            self.assertEqual(rejected.snapshot()["access"], "refresh_required")
        finally:
            rejected.close()
        # Invalid cache evidence is discarded while the stored credential is
        # retained for the next successful online validation.
        record = json.loads(path.read_bytes())
        record["access"] = original
        path.write_text(json.dumps(record, separators=(",", ":")))
        os.chmod(path, 0o600)
        forward = original["wall_high_water"] + 4000
        with patch("orbit_sdk.client.wall_seconds", return_value=forward), patch("orbit_sdk.clock.wall_seconds", return_value=forward):
            expired = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            self.assertEqual(expired.snapshot()["access"], "refresh_required")
        finally:
            expired.close()

    def test_inconsistent_cache_clock_does_not_block_online_credential_recovery(self) -> None:
        for nonmonotonic in (False, True):
            with self.subTest(nonmonotonic=nonmonotonic):
                self._activate_offline()
                path = Path(self.directory.name, "orbit-storage.bin")
                record = json.loads(path.read_bytes())
                access = record["access"]
                access["server_high_water"] = access["received_server_time"] + (-1 if nonmonotonic else 40)
                path.write_text(json.dumps(record, separators=(",", ":")))
                transport = PersistentTransport(offline=True)
                with self.open(transport) as client:
                    self.assertEqual(client.require_access("export")["access"], "online")
                    self.assertEqual(transport.requests[0][1], "/api/client/v1/activations/activation/validate")
                    self.assertFalse(any(x[1] == "/api/client/v1/activations" for x in transport.requests))

    def test_wrong_scope_signed_cache_is_rejected(self) -> None:
        _, _ = self._activate_offline()
        path = Path(self.directory.name, "orbit-storage.bin")
        record = json.loads(path.read_bytes())
        wrong = Config(APP.api_origin, "other-app", APP.environment_id, APP.issuer, record["installation"]["id"])
        token, received, _ = sign_grant(wrong, offline=True, persistent=True)
        record["access"]["jws"] = token
        record["access"]["received_server_time"] = received
        record["access"]["server_high_water"] = received
        record["access"]["received_wall_time"] = int(time.time())
        record["access"]["wall_high_water"] = record["access"]["received_wall_time"]
        path.write_text(json.dumps(record, separators=(",", ":")))
        os.chmod(path, 0o600)
        client = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        try:
            self.assertEqual(client.snapshot()["access"], "refresh_required")
        finally:
            client.close()

    def test_duplicate_startup_lock_corruption_and_unsafe_paths_fail_closed(self) -> None:
        first = self.open(PersistentTransport())
        try:
            with self.assertRaises(OrbitError) as raised:
                self.open(PersistentTransport())
            self.assertEqual(raised.exception.kind, STORAGE)
            self.assertEqual(raised.exception.code, "installation_in_use")
        finally:
            first.close()
        path = Path(self.directory.name, "orbit-storage.bin")
        path.write_bytes(b"not-json")
        os.chmod(path, 0o600)
        with self.assertRaises(OrbitError) as corrupt:
            self.open(PersistentTransport())
        self.assertEqual(corrupt.exception.kind, STORAGE)
        path.unlink()
        with self.assertRaises(OrbitError) as missing:
            self.open(PersistentTransport())
        self.assertEqual(missing.exception.kind, STORAGE)

        with tempfile.TemporaryDirectory(prefix="orbit-unsafe-parent-") as parent:
            unsafe = Path(parent, "public")
            unsafe.mkdir(mode=0o755)
            with self.assertRaises(OrbitError):
                Client._open_for_test(APP, unsafe, PersistentTransport())
            self.assertEqual(unsafe.stat().st_mode & 0o777, 0o755)
            target = Path(parent, "target")
            target.mkdir(mode=0o700)
            link = Path(parent, "link")
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(OrbitError):
                Client._open_for_test(APP, link, PersistentTransport())

    def test_explicit_denial_invalidates_persisted_grant_and_pending(self) -> None:
        self._activate_offline()
        with self.assertRaises(OrbitError) as denied:
            self.open(PersistentTransport(validation_error=error(DENIED, "licence_revoked")))
        self.assertEqual(denied.exception.kind, DENIED)
        storage = InstallationStorage.open(self.directory.name, APP)
        try:
            generation, credential = storage.load()
            self.assertGreater(generation, 0)
            self.assertIsNone(credential)
            self.assertIsNone(storage.access)
            self.assertIsNone(storage.pending_activation)
        finally:
            storage.close()

    def test_close_cancels_foreground_refresh_and_prevents_commit(self) -> None:
        client = self.open(PersistentTransport(offline=True))
        client.activate("foreground-close-key")
        old_record = Path(self.directory.name, "orbit-storage.bin").read_bytes()
        blocking = PersistentTransport(offline=True)
        blocking.block_validation = True
        client.transport = blocking
        result: list[BaseException | dict] = []

        def refresh() -> None:
            try:
                result.append(client.refresh())
            except BaseException as exc:
                result.append(exc)

        call = threading.Thread(target=refresh)
        call.start()
        self.assertTrue(blocking.entered.wait(2))
        closer = threading.Thread(target=client.close)
        closer.start()
        closer.join(2)
        call.join(2)
        self.assertFalse(closer.is_alive())
        self.assertFalse(call.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, CANCELLED)
        record = json.loads(Path(self.directory.name, "orbit-storage.bin").read_bytes())
        self.assertEqual(record["access"]["jws"], json.loads(old_record)["access"]["jws"])
        self.assertIsNone(client._storage._lease.fd)

    def test_previous_credential_retry_digest_survives_malformed_reply(self) -> None:
        from orbit_sdk.errors import INVALID_RESPONSE
        transport = PersistentTransport(offline=True)
        client = self.open(transport)
        try:
            client.activate("original-key")
            previous = client._credential.credential
            transport.activation_error = error(INVALID_RESPONSE, "invalid_response")
            with self.assertRaises(OrbitError):
                client.activate_previous("replacement-key", previous, "replacement-operation-id")
            pending = client._persistent_storage.pending_activation
            self.assertIsNone(client._credential)
            transport.activation_error = None
            client.activate_previous("replacement-key", previous, "replacement-operation-id")
            self.assertEqual(transport.requests[-1][2]["idempotency_key"], pending.operation_id)
            self.assertIsNone(client._persistent_storage.pending_activation)
        finally:
            client.close()

    def test_unverified_refresh_cannot_keep_cached_offline_authority(self) -> None:
        import base64
        transport = PersistentTransport(offline=True)
        client = self.open(transport)
        try:
            client.activate("unknown-key-refresh")
            reply = json.loads(activation_reply(client.config, previous=True, offline=True, persistent=True))
            parts = reply["grant"].split(".")
            header = json.dumps({"alg": "ES256", "typ": "orbit-access+jwt", "kid": "unknown-key"}, separators=(",", ":")).encode()
            parts[0] = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
            reply["grant"] = ".".join(parts)
            transport.post = lambda *_args: json.dumps(reply, separators=(",", ":")).encode()
            def unavailable(*_args):
                raise error(TRANSIENT, "network_unavailable")
            transport.get = unavailable
            with self.assertRaises(OrbitError) as failure:
                client.refresh()
            self.assertEqual(failure.exception.kind, TRANSIENT)
            self.assertIsNone(client._persistent_storage.access)
            self.assertIsNone(client._claims)
            self.assertIsNotNone(client._credential)
        finally:
            client.close()

    def test_close_cancels_owned_scheduler_before_storage_release(self) -> None:
        client = self.open(PersistentTransport(offline=True))
        client.activate("scheduler-key")
        client._claims["refresh_after"] = int(time.time()) - 1
        blocking = PersistentTransport()
        blocking.block_validation = True
        client.transport = blocking
        client._start_lifecycle()
        self.assertTrue(blocking.entered.wait(2))
        closed = threading.Event()
        closer = threading.Thread(target=lambda: (client.close(), closed.set()))
        closer.start()
        closer.join(2)
        self.assertTrue(closed.is_set())
        self.assertFalse(client._lifecycle_thread.is_alive())
        self.assertIsNone(client._storage._lease.fd)

    def test_close_forces_high_water_checkpoint_before_releasing_lease(self) -> None:
        self._activate_offline()
        client = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        access, anchor = client._persisted_access, client._anchor
        future = anchor.start.wall + 20
        with patch("orbit_sdk.clock.elapsed_ns", return_value=anchor.start.elapsed + 20_000_000_000), patch("orbit_sdk.clock.wall_seconds", return_value=future), patch("orbit_sdk.client.wall_seconds", return_value=future):
            client.close()
        value = json.loads(Path(self.directory.name, "orbit-storage.bin").read_bytes())
        self.assertGreaterEqual(value["access"]["server_high_water"], access.server_high_water + 20)
        self.assertGreaterEqual(value["access"]["wall_high_water"], access.wall_high_water + 20)
        self.assertIsNone(client._storage._lease.fd)

    def test_close_releases_storage_when_forced_checkpoint_fails(self) -> None:
        self._activate_offline()
        client = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))

        def fail_checkpoint(*, force: bool = False, propagate: bool = False) -> None:
            self.assertTrue(force)
            raise error(STORAGE, "storage_failed")

        client._checkpoint_persistent_cache = fail_checkpoint
        with self.assertRaises(OrbitError) as raised:
            client.close()
        self.assertEqual(raised.exception.kind, STORAGE)
        self.assertIsNone(client._storage._lease.fd)

    def test_lifecycle_waits_for_future_retry_after_refresh_deadline(self) -> None:
        self._activate_offline()
        client = self.open(PersistentTransport(validation_error=error(TRANSIENT, "network_unavailable")))
        probe = _WaitProbe()
        client._lifecycle_stop = probe
        client._claims["refresh_after"] = int(time.time()) - 1
        client._transient = True
        client._retry_deadline = time.monotonic() + 20
        try:
            client._start_lifecycle()
            self.assertTrue(probe.observed.wait(2))
            self.assertIsNotNone(probe.timeouts[0])
            self.assertGreaterEqual(probe.timeouts[0], 15)
        finally:
            client.close()

    def test_lifecycle_ignores_expired_retry_deadline_for_pending_activation(self) -> None:
        client = self.open(PersistentTransport(activation_error=error(TRANSIENT, "network_unavailable")))
        with self.assertRaises(OrbitError):
            client.activate("pending-worker-key")
        self.assertIsNotNone(client._persistent_storage.pending_activation)
        probe = _WaitProbe()
        client._lifecycle_stop = probe
        client._retry_deadline = time.monotonic() - 1
        try:
            client._start_lifecycle()
            self.assertTrue(probe.observed.wait(2))
            self.assertIsNotNone(probe.timeouts[0])
            self.assertGreater(probe.timeouts[0], 30)
        finally:
            client.close()

    def test_late_validation_after_logout_cannot_restore_persisted_authority(self) -> None:
        client = self.open(PersistentTransport(offline=True))
        client.activate("late-response-key")
        blocked = PersistentTransport()
        blocked.block_validation = True
        client.transport = blocked
        result: list[BaseException | dict] = []

        def refresh() -> None:
            try:
                result.append(client.refresh())
            except BaseException as exc:
                result.append(exc)

        call = threading.Thread(target=refresh)
        call.start()
        self.assertTrue(blocked.entered.wait(2))
        client.local_logout()
        blocked.release.set()
        call.join(2)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, "stale_response")
        self.assertEqual(client.snapshot()["access"], "denied")
        self.assertIsNone(client._storage.load()[1])
        client.close()


if __name__ == "__main__":
    unittest.main()
