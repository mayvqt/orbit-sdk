from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from orbit_sdk import DownloadTicketVerifier, OrbitError


class DownloadTicketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[3] / "contracts/sdk/download-tickets.json"
        cls.corpus = json.loads(path.read_text())
        cls.context = cls.corpus["expected"]

    def verifier(self, **overrides):
        return DownloadTicketVerifier(
            overrides.get("app_key", self.context["app_key"]),
            overrides.get("endpoint", self.context["endpoint"]),
            overrides.get("public_keys", self.corpus["jwks"]),
        )

    def test_shared_download_security_vectors(self):
        self.assertEqual(self.corpus["format_version"], 1)
        for case in self.corpus["cases"]:
            with self.subTest(case=case["name"]):
                expected = self.context | case.get("expected", {})
                def check():
                    verifier = self.verifier(**expected, public_keys=case.get("jwks", self.corpus["jwks"]))
                    return verifier.verify(case["token"], now=datetime.fromtimestamp(expected["now"], timezone.utc))
                if case["valid"]:
                    result = check()
                    self.assertGreater(result.expires_at.timestamp(), expected["now"])
                    self.assertIs(result.issued_at.tzinfo, timezone.utc)
                    self.assertEqual(len(result.sha256), 64)
                    self.assertNotIn(case["token"], repr(result))
                    with self.assertRaises(FrozenInstanceError):
                        result.byte_length = 0
                else:
                    with self.assertRaises(OrbitError):
                        check()

    def test_endpoint_is_explicit_https_without_credentials_or_token_parameters(self):
        for endpoint in (
            "http://downloads.example.test/file", "//downloads.example.test/file",
            "https://user:password@downloads.example.test/file", "https://downloads.example.test/file?",
            "https://downloads.example.test/file#", "https://downloads.example.test/file?ticket=secret",
            "https://downloads.example.test/has space", "https://downloads.example.test/\nfile",
            "https://downloads.example.test/\\file", "https://downloads.example.test/☃",
            "https://downloads.example.test:0/file", "https://downloads.example.test:65536/file",
            "https://downloads.example.test:/file", "https://%64ownloads.example.test/file",
            "https://@downloads.example.test/file", "https://:443/file",
            "https://[::1]extra/file", "https://[::1]:/file", "https://[v1.test]/file",
            "https://[::1]:0/file", "https://[::1]:65536/file", "https://::1/file",
            "https://downloads.example.test:+443/file",
            "https://downloads.example.test/<file>", "https://downloads.example.test/%xx",
            "https://downloads.example.test/%", "https://downloads.example.test/{file}",
            "https:///file", "https://downloads.example.test/" + "a" * 2048,
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(OrbitError) as raised:
                self.verifier(endpoint=endpoint)
            self.assertEqual(raised.exception.code, "invalid_download_endpoint")

    def test_endpoint_preserves_valid_ports_ipv6_and_encoded_paths(self):
        for endpoint in (
            "https://downloads.example.test", "https://downloads.example.test:443/file",
            "https://downloads.example.test:65535/file", "https://downloads.example.test:000443/file",
            "https://[::1]/file", "https://[::1]:8443/file", "https://[::ffff:192.0.2.1]/file",
            "https://xn--bcher-kva.example/%E2%98%83", "https://downloads.example.test/a%2Fb",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.verifier(endpoint=endpoint)._endpoint, endpoint)

    def test_key_input_is_bounded_strict_and_copied(self):
        encoded = json.dumps(self.corpus["jwks"])
        for invalid in (encoded + " " * 16384, encoded[:-1] + ',"keys":[]}', {"keys": []}):
            with self.assertRaises(OrbitError) as raised:
                self.verifier(public_keys=invalid)
            self.assertEqual(raised.exception.code, "invalid_download_keys")
        keys = json.loads(encoded)
        verifier = self.verifier(public_keys=keys)
        keys["keys"].clear()
        result = verifier.verify(self.corpus["cases"][0]["token"], now=datetime.fromtimestamp(self.context["now"], timezone.utc))
        self.assertEqual(result.byte_length, 1024)

    def test_clock_must_be_aware_and_expiry_is_exact(self):
        verifier = self.verifier()
        token = self.corpus["cases"][0]["token"]
        for now in (datetime(2026, 1, 1), datetime(1960, 1, 1, tzinfo=timezone.utc), True):
            with self.assertRaises(OrbitError):
                verifier.verify(token, now=now)
        verifier.verify(token, now=datetime.fromtimestamp(self.context["now"] + 119.999, timezone.utc))
        with self.assertRaises(OrbitError):
            verifier.verify(token, now=datetime.fromtimestamp(self.context["now"] + 120, timezone.utc))


if __name__ == "__main__":
    unittest.main()
