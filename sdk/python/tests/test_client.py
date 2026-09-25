from __future__ import annotations

import json
import threading
import time
import unittest

from orbit_sdk import Cancellation, Client, Config, OrbitError, SensitiveAuthorization
from orbit_sdk.errors import CANCELLED, DENIED, REAUTHENTICATION_REQUIRED, STALE_RESPONSE, TRANSIENT, error
from orbit_sdk.storage import MemoryStorage, StoredCredential

from support import FakeTransport, activation_reply


def make_config() -> Config:
    return Config("https://orbit.example.test", "app", "test", "https://issuer.example.test", "synthetic_installation_123")


class ClientFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = make_config()
        self.transport = FakeTransport(self.config)
        self.client = Client._for_test(self.config, self.transport)

    def tearDown(self) -> None:
        self.client.close()

    def test_activation_access_accounts_registration_and_redacted_customer_proof(self) -> None:
        snapshot = self.client.activate("synthetic-licence-key", "operation-id-00001")
        self.assertEqual(snapshot["access"], "online")
        self.assertTrue(snapshot["entitlements"]["export"])
        self.assertEqual(self.client.require_access("export")["access"], "online")

        account = self.client.login("alice", "synthetic-password")
        self.assertEqual(account["customer"]["username"], "alice")
        self.assertIsNone(self.client.account()["customer"].get("session"))
        proof = self.client.customer_session_authorization()
        self.assertIsInstance(proof, SensitiveAuthorization)
        self.assertEqual(proof.reveal(), b"Bearer " + b"s" * 43)
        self.assertNotIn("s" * 43, repr(proof))
        proof.clear()
        with self.assertRaises(RuntimeError):
            proof.reveal()

        page = self.client.owned_licences()
        self.assertEqual(page["items"][0]["id"], "licence")
        self.assertNotIn("internal_note", page["items"][0])
        claimed = self.client.claim_licence("another-synthetic-key", "operation-id-00002")
        self.assertEqual(claimed["id"], "licence")
        self.client.request_email_change("synthetic-password", "new@example.test")

        registration = self.client.register("synthetic-key", "alice2", "a2@example.test", "synthetic-password")
        self.assertTrue(registration.accepted)
        self.assertNotIn("r" * 43, repr(registration.pending))
        self.client.resend_registration(registration.pending)
        registration.pending.close()
        with self.assertRaises(RuntimeError):
            self.client.resend_registration(registration.pending)

        self.client.account_logout()
        self.assertIsNone(self.client.account())
        methods = [(method, route) for method, route, _, _ in self.transport.requests]
        self.assertIn(("DELETE", "/api/client/v1/sessions/current?application_id=app&environment_id=test"), methods)

    def test_account_activation_keeps_customer_session_and_returns_snapshot(self) -> None:
        self.client.login("alice", "synthetic-password")
        snapshot = self.client.activate_account("licence", "operation-id-account-01")
        self.assertEqual(snapshot["access"], "online")
        self.assertIsNotNone(self.client.account())
        self.assertEqual(self.client.snapshot()["access"], "online")

    def test_denial_clears_persisted_credential_and_cached_access(self) -> None:
        storage = MemoryStorage()
        storage.save(0, StoredCredential("app", "test", "activation", "licence", self.config.installation_id, "a" * 43, int(time.time()) + 3600))
        transport = FakeTransport(self.config)
        transport.post_overrides[f"/api/client/v1/activations/activation/validate"] = error(DENIED, "licence_revoked", "synthetic-request")
        client = Client._for_test(self.config, transport, storage)
        try:
            with self.assertRaises(OrbitError) as raised:
                client.refresh()
            self.assertEqual(raised.exception.kind, DENIED)
            self.assertEqual(raised.exception.request_id, "synthetic-request")
            self.assertEqual(client.snapshot()["access"], "denied")
            self.assertIsNone(storage.load()[1])
        finally:
            client.close()

    def test_transient_unknown_key_fetch_preserves_stored_credential_but_drops_unverified_grant(self) -> None:
        expires = int(time.time()) + 3600
        storage = MemoryStorage()
        stored = StoredCredential("app", "test", "activation", "licence", self.config.installation_id, "a" * 43, expires)
        storage.save(0, stored)
        transport = FakeTransport(self.config)
        transport.post_overrides["/api/client/v1/activations/activation/validate"] = activation_reply(self.config, previous=True, credential_expiry=expires)
        route = "/.well-known/orbit-jwks.json?application_id=app&environment_id=test"
        transport.get_overrides[route] = error(TRANSIENT, "network_unavailable")
        client = Client._for_test(self.config, transport, storage)
        try:
            with self.assertRaises(OrbitError) as raised:
                client.refresh()
            self.assertEqual(raised.exception.kind, TRANSIENT)
            self.assertEqual(storage.load()[1], stored)
            self.assertEqual(client.snapshot()["access"], "refresh_required")
            self.assertIsNone(client._claims)
        finally:
            client.close()

    def test_verified_offline_grant_survives_transport_outage_and_paces_retry(self) -> None:
        # The fake activation reply uses a strict grant; this second call returns
        # a transient network error before any new response can be verified.
        self.transport.post_overrides["/api/client/v1/activations"] = lambda _route, _body: activation_reply(self.config, offline=True)
        self.client.activate("synthetic-key", "operation-id-offline-01")
        validate = "/api/client/v1/activations/activation/validate"
        self.transport.post_overrides[validate] = error(TRANSIENT, "network_unavailable")
        snapshot = self.client.refresh()
        self.assertEqual(snapshot["access"], "offline")
        before = len(self.transport.requests)
        self.assertEqual(self.client.require_access("export")["access"], "offline")
        self.assertEqual(len(self.transport.requests), before)

    def test_duplicate_response_fields_fail_closed(self) -> None:
        self.transport.post_overrides["/api/client/v1/activations"] = b'{"activation_id":"one","activation_id":"two"}'
        with self.assertRaises(OrbitError) as raised:
            self.client.activate("synthetic-key", "operation-id-malformed-01")
        self.assertEqual(raised.exception.kind, "invalid_response")
        self.assertEqual(self.client.snapshot()["access"], "denied")

    def test_logout_fences_a_late_activation_response(self) -> None:
        self.transport.block_route = "/api/client/v1/activations"
        result: list[BaseException | dict] = []

        def activate() -> None:
            try:
                result.append(self.client.activate("synthetic-key", "operation-id-stale-0001"))
            except BaseException as exc:
                result.append(exc)

        thread = threading.Thread(target=activate)
        thread.start()
        self.assertTrue(self.transport.entered.wait(2))
        self.client.local_logout()
        self.transport.release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, STALE_RESPONSE)
        self.assertEqual(self.client.snapshot()["access"], "denied")

    def test_logout_between_generation_check_and_credential_commit_keeps_tombstone(self) -> None:
        storage = MemoryStorage()
        client = Client._for_test(self.config, self.transport, storage)
        checked = threading.Event()
        release = threading.Event()
        checks = 0
        original = client._check_generation

        def gate(generation: int) -> None:
            nonlocal checks
            original(generation)
            checks += 1
            if checks == 5:
                checked.set()
                release.wait(2)

        client._check_generation = gate
        result: list[BaseException | dict] = []

        def activate() -> None:
            try:
                result.append(client.activate("synthetic-key", "operation-id-commit-race-01"))
            except BaseException as exc:
                result.append(exc)

        thread = threading.Thread(target=activate)
        thread.start()
        try:
            self.assertTrue(checked.wait(2))
            client.local_logout()
        finally:
            release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, STALE_RESPONSE)
        self.assertEqual(storage.load(), (2, None))
        self.assertEqual(client.snapshot()["access"], "denied")
        client.close()

    def test_failed_response_invalidation_is_fenced_with_client_state(self) -> None:
        class BlockingStorage(MemoryStorage):
            def __init__(self) -> None:
                super().__init__()
                self.entered = threading.Event()
                self.release = threading.Event()

            def invalidate(self) -> int:
                self.entered.set()
                self.release.wait(2)
                return super().invalidate()

        storage = BlockingStorage()
        stored = StoredCredential("app", "test", "activation", "licence", self.config.installation_id, "a" * 43, int(time.time()) + 3600)
        storage.save(0, stored)
        transport = FakeTransport(self.config)
        route = "/api/client/v1/activations/activation/validate"
        transport.post_overrides[route] = error(DENIED, "licence_revoked")
        client = Client._for_test(self.config, transport, storage)
        result: list[BaseException | dict] = []

        def refresh() -> None:
            try:
                result.append(client.refresh())
            except BaseException as exc:
                result.append(exc)

        thread = threading.Thread(target=refresh)
        thread.start()
        acquired = None
        try:
            self.assertTrue(storage.entered.wait(2))
            acquired = client._state_lock.acquire(blocking=False)
            if acquired:
                client._state_lock.release()
        finally:
            storage.release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(acquired, "failed-response storage invalidation must hold the state fence")
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, DENIED)
        self.assertEqual(storage.load(), (1, None))
        self.assertEqual(client.snapshot()["access"], "denied")
        client.close()

    def test_login_result_after_logout_is_stale_and_cannot_restore_account(self) -> None:
        self.transport.block_route = "/api/client/v1/sessions"
        result: list[BaseException | dict] = []

        def login() -> None:
            try:
                result.append(self.client.login("alice", "synthetic-password"))
            except BaseException as exc:
                result.append(exc)

        thread = threading.Thread(target=login)
        thread.start()
        self.assertTrue(self.transport.entered.wait(2))
        self.client.local_logout()
        self.transport.release.set()
        thread.join(2)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, STALE_RESPONSE)
        self.assertIsNone(self.client.account())

    def test_cancelled_operation_settles_as_cancelled(self) -> None:
        self.transport.block_route = "/api/client/v1/activations"
        cancellation = Cancellation.create()
        result: list[BaseException | dict] = []

        def activate() -> None:
            try:
                result.append(self.client.activate("synthetic-key", "operation-id-cancel-001", cancellation=cancellation))
            except BaseException as exc:
                result.append(exc)

        thread = threading.Thread(target=activate)
        thread.start()
        self.assertTrue(self.transport.entered.wait(2))
        cancellation.cancel()
        self.transport.release.set()
        thread.join(2)
        cancellation.close()
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], OrbitError)
        self.assertEqual(result[0].kind, CANCELLED)

    def test_client_close_waits_for_active_calls(self) -> None:
        self.transport.block_route = "/api/client/v1/activations"
        result: list[BaseException | dict] = []
        closed = threading.Event()

        def activate() -> None:
            try:
                result.append(self.client.activate("synthetic-key", "operation-id-close-0001"))
            except BaseException as exc:
                result.append(exc)

        call = threading.Thread(target=activate)
        call.start()
        self.assertTrue(self.transport.entered.wait(2))
        closer = threading.Thread(target=lambda: (self.client.close(), closed.set()))
        closer.start()
        time.sleep(0.05)
        self.assertFalse(closed.is_set())
        self.transport.release.set()
        call.join(2)
        closer.join(2)
        self.assertTrue(closed.is_set())
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
