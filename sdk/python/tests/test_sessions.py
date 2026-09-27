from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from orbit_sdk import AppKey, DownloadTicketVerifier, OrbitError
from orbit_sdk.grants import Expected as GrantExpected, parse_header
from orbit_sdk.offline import Expected as OfflineExpected, OfflineKeys, verify as verify_offline
from orbit_sdk.sessions import Expected, SessionKeys, verify


class SessionGrantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts = Path(__file__).resolve().parents[3] / "contracts/sdk"
        cls.corpus = json.loads((cls.contracts / "session-grants.json").read_text())

    def context(self, overrides=None):
        value = self.corpus["expected"] | (overrides or {})
        session_id = value.pop("session_id")
        sequence = value.pop("sequence")
        environment = value.pop("key_environment")
        return Expected(GrantExpected(**value), session_id, sequence), environment

    def test_shared_session_security_vectors(self):
        self.assertEqual(self.corpus["format_version"], 1)
        self.assertEqual(len(self.corpus["cases"]), 184)
        for case in self.corpus["cases"]:
            with self.subTest(case=case["name"]):
                expected, environment = self.context(case.get("expected"))
                def check():
                    keys = SessionKeys.parse(case.get("jwks", self.corpus["jwks"]), environment)
                    return verify(case["token"], keys, expected)
                if case["valid"]:
                    result = check()
                    self.assertEqual(result.session_id, expected.session_id)
                    self.assertEqual(result.sequence, expected.sequence)
                    self.assertGreater(result.expires_at, expected.grant.now)
                    self.assertLessEqual(result.expires_at - result.issued_at, 120)
                else:
                    with self.assertRaises(OrbitError):
                        check()

    def test_result_is_immutable_and_redacted(self):
        expected, environment = self.context()
        keys = SessionKeys.parse(self.corpus["jwks"], environment)
        result = verify(self.corpus["cases"][0]["token"], keys, expected)
        self.assertEqual(repr(result), "SessionGrant(<redacted>)")
        with self.assertRaises(FrozenInstanceError):
            result.sequence = 2
        with self.assertRaises(TypeError):
            result.entitlements["premium"] = True

    def test_trusted_keys_are_bounded_strict_and_owned(self):
        expected, environment = self.context()
        token = self.corpus["cases"][0]["token"]
        encoded = json.dumps(self.corpus["jwks"])
        exact = encoded + " " * (16384 - len(encoded))
        self.assertEqual(verify(token, SessionKeys.parse(exact, environment), expected).sequence, 1)
        for malformed in (exact + " ", encoded[:-1] + ',"keys":[]}'):
            with self.assertRaises(OrbitError) as raised:
                SessionKeys.parse(malformed, environment)
            self.assertEqual(raised.exception.code, "invalid_session_keys")
        value = json.loads(encoded)
        keys = SessionKeys.parse(value, environment)
        value["keys"].clear()
        self.assertEqual(verify(token, keys, expected).sequence, 1)

    def test_other_verifiers_reject_session_purpose(self):
        token = self.corpus["cases"][0]["token"]
        with self.assertRaises(OrbitError):
            parse_header(token)
        offline = json.loads((self.contracts / "offline-files.json").read_text())
        keys = OfflineKeys.parse(offline["jwks"], "test")
        context = offline["expected"]
        with self.assertRaises(OrbitError):
            verify_offline(token, keys, OfflineExpected(AppKey.parse(context["app_key"]), context["installation_id"], context["now"]))
        downloads = json.loads((self.contracts / "download-tickets.json").read_text())
        context = downloads["expected"]
        verifier = DownloadTicketVerifier(context["app_key"], context["endpoint"], downloads["jwks"])
        with self.assertRaises(OrbitError):
            verifier.verify(token)

    def test_errors_do_not_expose_the_bearer(self):
        expected, environment = self.context()
        keys = SessionKeys.parse(self.corpus["jwks"], environment)
        token = self.corpus["cases"][0]["token"] + "secret"
        with self.assertRaises(OrbitError) as raised:
            verify(token, keys, expected)
        self.assertEqual(raised.exception.code, "invalid_session_grant")
        self.assertNotIn(token, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
