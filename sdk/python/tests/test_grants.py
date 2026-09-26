from __future__ import annotations

import json
import unittest
from dataclasses import replace

from orbit_sdk.app_key import AppKey
from orbit_sdk.client import _Config as Config
from orbit_sdk.errors import OrbitError
from orbit_sdk.grants import Expected, Keys, parse_header, verify
from orbit_sdk.jsonutil import unique_json

from support import b64url, fixture_data, sign_grant


class GrantVectorTests(unittest.TestCase):
    def test_valid_app_key_scope_does_not_inherit_an_individual_id_limit(self) -> None:
        corpus = fixture_data()
        keys = Keys.parse(corpus["jwks"])
        long_origin = "https://" + ".".join(["a" * 50] * 3) + ".test"
        for origin, application, environment in (
            (long_origin, "app", "test"),
            ("https://orbit.example.test", "a" * 128, "e" * 128),
        ):
            with self.subTest(origin=origin, application_length=len(application)):
                app = AppKey.parse(f"orbit_app_test_{b64url(origin.encode())}.{application}.{environment}")
                config = Config(app.api_origin, app.application_id, app.environment_id, app.issuer, "installation")
                token, now, expiry = sign_grant(config, server_time=corpus["expected"]["now"])
                expected = replace(Expected(**corpus["expected"]), issuer=app.issuer, application=application,
                                   environment=environment, now=now, credential_expires_at=expiry)
                self.assertTrue(verify(token, keys, expected)["entitlements"]["export"])
                with self.assertRaises(OrbitError):
                    verify(token, keys, replace(expected, issuer="https://other.example.test"))
                with self.assertRaises(OrbitError):
                    verify(token, keys, replace(expected, application="other"))

    def test_all_shared_grant_vectors(self) -> None:
        corpus = fixture_data()
        self.assertEqual(corpus["format_version"], 1)
        self.assertEqual(len(corpus["cases"]), 104)
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

    def test_signed_unbound_grant_with_local_fingerprint_requires_runtime_opt_in(self) -> None:
        corpus = fixture_data()
        case = next(case for case in corpus["cases"] if case["valid"] and case.get("expected", {}).get("fingerprint") is None)
        data = dict(corpus["expected"])
        data.update(case.get("expected") or {})
        expected = Expected(
            issuer=data["issuer"],
            application=data["application"],
            environment=data["environment"],
            licence=data["licence"],
            activation=data["activation"],
            installation=data["installation"],
            fingerprint="a" * 64,
            fingerprint_provider="machine_v1",
            credential_expires_at=data["credential_expires_at"],
            licence_expires_at=data["licence_expires_at"],
            now=data["now"],
        )
        keys = Keys.parse(case.get("jwks", corpus["jwks"]))
        with self.assertRaises(OrbitError):
            verify(case["token"], keys, expected)
        verify(case["token"], keys, replace(expected, allow_unbound_fingerprint=True))


if __name__ == "__main__":
    unittest.main()
