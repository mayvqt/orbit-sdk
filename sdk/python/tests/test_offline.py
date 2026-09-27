from __future__ import annotations

import json
from pathlib import Path
import unittest

from orbit_sdk import AppKey, OrbitError
from orbit_sdk.offline import Expected, OfflineKeys, verify


class OfflineFileTests(unittest.TestCase):
    def test_shared_offline_security_vectors(self):
        path = Path(__file__).resolve().parents[3] / "contracts/sdk/offline-files.json"
        corpus = json.loads(path.read_text())
        self.assertEqual(corpus["format_version"], 1)
        for case in corpus["cases"]:
            with self.subTest(case=case["name"]):
                context = corpus["expected"] | case.get("expected", {})
                context["app_key"] = AppKey.parse(context["app_key"])
                expected = Expected(**context)
                def check():
                    keys = OfflineKeys.parse(case.get("jwks", corpus["jwks"]), expected.app_key.environment)
                    return verify(case["token"], keys, expected)
                if case["valid"]:
                    result = check()
                    self.assertTrue(result.entitlements["export"])
                    self.assertGreater(result.expires_at, expected.now)
                    self.assertNotIn(case["token"], repr(result))
                    with self.assertRaises(TypeError):
                        result.entitlements["export"] = False
                else:
                    with self.assertRaises(OrbitError):
                        check()


if __name__ == "__main__":
    unittest.main()
