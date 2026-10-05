from __future__ import annotations

import json
import unittest
from pathlib import Path

from orbit_sdk.errors import DENIED, TRANSIENT, discards_credential, error

ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "contracts" / "sdk" / "credential-retention.json").read_text())


class CredentialRetentionTests(unittest.TestCase):
    def test_denials_match_shared_vectors(self) -> None:
        for case in VECTORS["denials"]:
            with self.subTest(code=case["code"]):
                self.assertEqual(discards_credential(error(DENIED, case["code"])), case["discard_credential"])
        self.assertFalse(discards_credential(error(TRANSIENT, "licence_revoked")))


if __name__ == "__main__":
    unittest.main()
