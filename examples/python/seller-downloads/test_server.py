from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import NoCredentialsError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from server import create_app


class SellerDownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[3]
        cls.corpus = json.loads((root / "contracts/sdk/download-tickets.json").read_text())
        cls.key = serialization.load_pem_private_key((root / "sdk/rust/tests/fixtures/es256-test-private.pem").read_bytes(), None)
        cls.storage = boto3.client(
            "s3", endpoint_url="https://storage.example.test", region_name="us-east-1",
            aws_access_key_id="orbit-fixture-key", aws_secret_access_key="public-synthetic-fixture-secret",
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.artifact = {
            "release_id": "release_1", "sha256": "ab" * 32, "byte_length": 1024,
            "bucket": "private-fixture-bucket", "object_key": "releases/fixture.zip",
        }
        self.configuration = {
            "app_key": self.corpus["expected"]["app_key"],
            "endpoint": self.corpus["expected"]["endpoint"],
            "public_keys": self.corpus["jwks"], "artifacts": {"artifact_1": self.artifact},
        }
        self.path = urlsplit(self.configuration["endpoint"]).path

    def token(self, **changes):
        claims = {
            "ver": 1, "iss": "https://orbit.example.test", "aud": self.configuration["endpoint"],
            "sub": "licence", "jti": "ticket_fixture", "iat": int(self.now.timestamp()),
            "nbf": int(self.now.timestamp()), "exp": int(self.now.timestamp()) + 120,
            "application_id": "app", "environment_id": "test", "release_id": "release_1",
            "artifact_id": "artifact_1", "sha256": "ab" * 32, "byte_length": 1024,
        } | changes
        header = {"alg": "ES256", "typ": "orbit-download+jwt", "kid": "test-fixture"}
        encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
        message = ".".join(encode(json.dumps(value, separators=(",", ":")).encode()) for value in (header, claims))
        r, s = utils.decode_dss_signature(self.key.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return message + "." + encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def client(self, storage=None, clock=None):
        return create_app(self.configuration, storage=self.storage if storage is None else storage,
                          clock=clock or (lambda: self.now)).test_client()

    def test_valid_ticket_returns_actual_sigv4_url_without_contacting_storage(self):
        token = self.token()
        response = self.client().get(self.path, headers={"Authorization": "Bearer " + token})
        self.assertEqual(response.status_code, 302)
        parsed = urlsplit(response.headers["Location"])
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, "storage.example.test")
        self.assertEqual(parsed.path, "/private-fixture-bucket/releases/fixture.zip")
        query = parse_qs(parsed.query)
        self.assertEqual(query["X-Amz-Algorithm"], ["AWS4-HMAC-SHA256"])
        self.assertEqual(query["X-Amz-Expires"], ["60"])
        self.assertIn("X-Amz-Signature", query)
        self.assertNotIn(token, response.headers["Location"])
        self.assertEqual(response.data, b"")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_missing_invalid_expired_or_wrong_audience_never_signs_storage_url(self):
        storage = Mock()
        client = self.client(storage)
        tokens = ["", "bad", self.token(exp=int(self.now.timestamp())),
                  self.token(aud="https://forged.example.test" + self.path)]
        for token in tokens:
            with self.subTest(token_type="missing" if not token else "invalid"):
                response = client.get(self.path, headers={"Authorization": "Bearer " + token, "Host": "forged.example.test"})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.data, b"")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
        storage.generate_presigned_url.assert_not_called()

    def test_unknown_or_changed_artifact_never_selects_a_storage_object(self):
        storage = Mock()
        client = self.client(storage)
        for changes in ({"artifact_id": "unknown"}, {"release_id": "other"}, {"sha256": "00" * 32}, {"byte_length": 1}):
            response = client.get(self.path, headers={"Authorization": "Bearer " + self.token(**changes)})
            self.assertEqual(response.status_code, 403)
        storage.generate_presigned_url.assert_not_called()

    def test_query_tickets_and_non_get_requests_are_rejected(self):
        storage = Mock()
        client = self.client(storage)
        headers = {"Authorization": "Bearer " + self.token()}
        self.assertEqual(client.get(self.path + "?ticket=not-accepted", headers=headers).status_code, 401)
        self.assertEqual(client.head(self.path, headers=headers).status_code, 405)
        self.assertEqual(client.post(self.path, headers=headers).status_code, 405)
        storage.generate_presigned_url.assert_not_called()

    def test_expired_extended_or_insecure_storage_url_is_not_disclosed(self):
        stamp = self.now.strftime("%Y%m%dT%H%M%SZ")
        urls = [
            f"http://storage.example.test/file?X-Amz-Date={stamp}&X-Amz-Expires=60",
            f"https://storage.example.test/file?X-Amz-Date={stamp}&X-Amz-Expires=121",
            "https://storage.example.test/file?X-Amz-Date=20000101T000000Z&X-Amz-Expires=60",
            f"https://storage.example.test/file?X-Amz-Date={stamp}&X-Amz-Expires=60&X-Amz-Expires=60",
        ]
        for url in urls:
            storage = Mock()
            storage.generate_presigned_url.return_value = url
            response = self.client(storage).get(self.path, headers={"Authorization": "Bearer " + self.token()})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("Location", response.headers)
            self.assertEqual(response.data, b"")

    def test_url_signing_delay_cannot_extend_the_ticket_deadline(self):
        storage = Mock()
        later = self.now + timedelta(seconds=90)
        storage.generate_presigned_url.return_value = (
            "https://storage.example.test/file?X-Amz-Date=" + later.strftime("%Y%m%dT%H%M%SZ") + "&X-Amz-Expires=60"
        )
        response = self.client(storage).get(self.path, headers={"Authorization": "Bearer " + self.token()})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("Location", response.headers)

    def test_storage_failure_returns_no_provider_details(self):
        storage = Mock()
        storage.generate_presigned_url.side_effect = NoCredentialsError()
        response = self.client(storage).get(self.path, headers={"Authorization": "Bearer " + self.token()})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, b"")


if __name__ == "__main__":
    unittest.main()
