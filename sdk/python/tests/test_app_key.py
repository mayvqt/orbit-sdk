from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from orbit_sdk import AppKey
from orbit_sdk.client import DeviceBinding, _parse_app_key, _resolve_binding
from orbit_sdk.errors import OrbitError


ROOT = Path(__file__).resolve().parents[3]


class AppKeyTests(unittest.TestCase):
    def test_every_shared_app_key_vector(self) -> None:
        corpus = json.loads((ROOT / "contracts" / "sdk" / "app-keys.json").read_text())
        self.assertEqual(corpus["format_version"], 1)
        self.assertTrue(corpus["cases"])
        for case in corpus["cases"]:
            with self.subTest(case=case["name"]):
                if case["valid"]:
                    key = AppKey.parse(case["key"])
                    self.assertEqual(key.api_origin, case["api_origin"])
                    self.assertEqual(key.issuer, case["issuer"])
                    self.assertEqual(key.application_id, case["application_id"])
                    self.assertEqual(key.environment_id, case["environment_id"])
                    self.assertEqual(key.environment, case["environment"])
                else:
                    with self.assertRaises(OrbitError):
                        AppKey.parse(case["key"])

    def test_direct_app_key_construction_is_revalidated(self) -> None:
        direct = AppKey("http://orbit.example.test", "app", "test", "test")
        with self.assertRaises(OrbitError):
            _parse_app_key(direct)

    def test_default_disabled_and_custom_machine_binding(self) -> None:
        key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test")
        with patch("orbit_sdk.client.native_fingerprint", return_value="a" * 64) as native:
            automatic = _resolve_binding(key, None, True)
        native.assert_called_once_with("app", "test")
        self.assertEqual(automatic, DeviceBinding("a" * 64, "machine_v1"))

        with patch("orbit_sdk.client.native_fingerprint", side_effect=AssertionError("must not probe")):
            self.assertIsNone(_resolve_binding(key, None, False))
        custom = DeviceBinding("b" * 64, "custom:host-v1")
        self.assertEqual(_resolve_binding(key, custom, True), custom)

    def test_unavailable_native_identity_falls_back_to_unbound(self) -> None:
        key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test")
        with patch(
            "orbit_sdk.client.native_fingerprint",
            side_effect=OrbitError("denied", "device_identity_unavailable"),
        ):
            self.assertIsNone(_resolve_binding(key, None, True))


if __name__ == "__main__":
    unittest.main()
