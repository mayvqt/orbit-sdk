from __future__ import annotations

import json
import unittest

from orbit_sdk.errors import OrbitError
from orbit_sdk.grants import Expected, Keys, parse_header, verify
from orbit_sdk.jsonutil import unique_json

from support import fixture_data


class GrantVectorTests(unittest.TestCase):
    def test_all_shared_grant_vectors(self) -> None:
        corpus = fixture_data()
        self.assertEqual(corpus["format_version"], 1)
        self.assertEqual(len(corpus["cases"]), 101)
        for case in corpus["cases"]:
            data = dict(corpus["expected"])
            data.update(case.get("expected") or {})
            expected = Expected(
                issuer=data["issuer"],
                application=data["application"],
                environment=data["environment"],
                licence=data["licence"],
                activation=data["activation"],
                installation=data["installation"],
                fingerprint=data["fingerprint"],
                fingerprint_provider=data["fingerprint_provider"],
                credential_expires_at=data["credential_expires_at"],
                licence_expires_at=data["licence_expires_at"],
                now=data["now"],
            )
            actual = True
            try:
                keys = Keys.parse(case.get("jwks", corpus["jwks"]))
                verify(case["token"], keys, expected)
            except OrbitError:
                actual = False
            self.assertEqual(actual, case["valid"], case["name"])

    def test_duplicate_keys_and_noncanonical_encodings_are_rejected(self) -> None:
        for raw in (b'{"kid":"one","kid":"two"}', b'{"x":NaN}', b'{"x":"\\ud800"}'):
            with self.assertRaises(OrbitError):
                unique_json(raw)
        corpus = fixture_data()
        token = corpus["cases"][0]["token"]
        header, payload, signature = token.split(".")
        for malformed in (
            header + "=" + "." + payload + "." + signature,
            header + "." + payload + "." + signature[:-1],
            "!" + header[1:] + "." + payload + "." + signature,
        ):
            with self.assertRaises(OrbitError):
                parse_header(malformed)

    def test_jwks_rejects_duplicate_and_untrusted_metadata(self) -> None:
        corpus = fixture_data()
        key = corpus["jwks"]["keys"][0]
        for mutated in (
            {"keys": [dict(key, d="private")]},
            {"keys": [dict(key, x="A" * 43)]},
            {"keys": [key, dict(key)]},
        ):
            with self.assertRaises(OrbitError):
                Keys.parse(mutated)


if __name__ == "__main__":
    unittest.main()
