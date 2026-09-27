from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from orbit_sdk import AppVersionUnsupportedError, Client, OrbitError
from orbit_sdk.app_version import CLIENT_HEADER, configured, format_client_header, sdk_version, update_hint, valid
from orbit_sdk.errors import CONFIGURATION, DENIED, INVALID_RESPONSE
from orbit_sdk.transport import Transport

from support import activation_reply
from test_persistent_client import APP, APP_SCOPE, PersistentTransport
from test_transport import _Connection, _Response

ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "contracts" / "sdk" / "app-versions.json").read_text())


class AppVersionVectorTests(unittest.TestCase):
    def test_app_version_grammar_matches_shared_vectors(self) -> None:
        for case in VECTORS["app_versions"]:
            with self.subTest(value=case["value"]):
                self.assertEqual(valid(case["value"]), case["valid"])
                if case["valid"]:
                    self.assertEqual(configured(case["value"]), case["value"])
                else:
                    with self.assertRaises(OrbitError) as raised:
                        configured(case["value"])
                    self.assertEqual(raised.exception.kind, CONFIGURATION)
        self.assertIsNone(configured(None))

    def test_client_header_matches_shared_vectors_and_package_version(self) -> None:
        for case in VECTORS["client_headers"]:
            with self.subTest(case=case):
                self.assertEqual(
                    format_client_header(case["language"], case["sdk_version"], case["platform"]),
                    case["header"],
                )
        self.assertEqual(sdk_version(), "0.4.0")
        prefix = f"python/{sdk_version()} ("
        self.assertTrue(CLIENT_HEADER.startswith(prefix), CLIENT_HEADER)
        platform = CLIENT_HEADER[len(prefix):-1]
        self.assertEqual(format_client_header("python", sdk_version(), platform), CLIENT_HEADER)

    def test_update_hint_matches_shared_vectors(self) -> None:
        for case in VECTORS["update_available"]:
            with self.subTest(name=case["name"]):
                reply = {"activation_id": "activation"}
                if "value" in case:
                    reply["update_available"] = case["value"]
                if case["valid"]:
                    self.assertEqual(update_hint(reply), case["version"])
                else:
                    with self.assertRaises(OrbitError) as raised:
                        update_hint(reply)
                    self.assertEqual(raised.exception.kind, INVALID_RESPONSE)

    def test_transport_sends_client_header_and_types_unsupported_version(self) -> None:
        requests: list[tuple[str, str, dict[str, str]]] = []
        body = b'{"error":{"code":"app_version_unsupported","message":"Update required","request_id":"version-1"}}'
        transport = Transport(
            "https://orbit.example.test",
            _connection_factory=lambda *_args, **_kwargs: _Connection(_Response(403, body), requests),
        )
        with self.assertRaises(AppVersionUnsupportedError) as raised:
            transport.post("/api/client/v1/activations/activation/validate", {"app_version": "1.0"}, True)
        self.assertEqual((raised.exception.kind, raised.exception.code), (DENIED, "app_version_unsupported"))
        self.assertEqual(raised.exception.request_id, "version-1")
        self.assertEqual(len(requests), 1, "a final denial is not retried")
        self.assertEqual(requests[0][2]["Orbit-Client"], CLIENT_HEADER)

    def test_open_rejects_invalid_app_version(self) -> None:
        with self.assertRaises(OrbitError) as raised:
            Client.open(APP, app_version="01")
        self.assertEqual(raised.exception.kind, CONFIGURATION)


class _VersionTransport(PersistentTransport):
    def __init__(self) -> None:
        super().__init__(offline=True)
        self.update_available: dict | None = {"version": "2.5.0"}

    def post(self, route: str, body: dict, retry_safe: bool, cancel=None):
        reply = super().post(route, body, retry_safe, cancel)
        if self.update_available is None or reply is None:
            return reply
        value = json.loads(reply)
        value["update_available"] = self.update_available
        return json.dumps(value).encode()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux installed-client persistence tests")
class AppVersionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="orbit-app-version-")
        os.chmod(self.directory.name, 0o700)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def open(self, transport: PersistentTransport) -> Client:
        return Client._open_for_test(APP_SCOPE, self.directory.name, transport, app_version="2.4.1-beta.2")

    def test_app_version_is_sent_and_unsupported_version_denies_without_fallback(self) -> None:
        transport = _VersionTransport()
        client = self.open(transport)
        try:
            snapshot = client.activate("synthetic-key")
            self.assertEqual(snapshot.access.value, "online")
            self.assertEqual(snapshot.update_available, "2.5.0")
            transport.validation_error = AppVersionUnsupportedError("version-1")
            with self.assertRaises(AppVersionUnsupportedError):
                client.refresh()
            sent = [body.get("app_version") for method, route, body, _ in transport.requests if method == "POST"]
            self.assertEqual(sent, ["2.4.1-beta.2", "2.4.1-beta.2"])
            snapshot = client.snapshot()
            self.assertEqual(snapshot.access.value, "refresh_required")
            self.assertFalse(snapshot.has("export"))
            self.assertIsNone(snapshot.update_available)
            prompted: list[bool] = []
            with self.assertRaises(AppVersionUnsupportedError):
                client.ensure_access("export", lambda: prompted.append(True) or "replacement-key")
            self.assertEqual(prompted, [])
            self.assertEqual(len([r for r in transport.requests if r[1].endswith("/validate")]), 1)
            record = json.loads(Path(self.directory.name, "orbit-storage.bin").read_bytes())
            self.assertIsNotNone(record["credential"])
            self.assertIsNone(record["access"])
        finally:
            client.close()

        reopened_transport = PersistentTransport(validation_error=AppVersionUnsupportedError("version-2"))
        reopened = self.open(reopened_transport)
        try:
            with self.assertRaises(AppVersionUnsupportedError):
                reopened.require_access("export")
        finally:
            reopened.close()

    def test_activation_denial_is_typed(self) -> None:
        transport = PersistentTransport(activation_error=AppVersionUnsupportedError("version-3"))
        client = self.open(transport)
        try:
            with self.assertRaises(AppVersionUnsupportedError):
                client.activate("synthetic-key")
            self.assertEqual(client.snapshot().access.value, "denied")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
