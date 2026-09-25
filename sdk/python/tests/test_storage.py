from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from orbit_sdk import Config
from orbit_sdk.errors import OrbitError
from orbit_sdk.storage import (
    MAX_GENERATION,
    MemoryStorage,
    SecretServiceStorage,
    StoredCredential,
    WindowsStorage,
    decode_record,
    decode_secret_record,
    encode_record,
    encode_secret_record,
    secret_service_scope,
)


def config() -> Config:
    return Config("https://orbit.example.test", "app", "test", "https://issuer.example.test", "synthetic_installation_123")


def credential() -> StoredCredential:
    return StoredCredential("app", "test", "activation", "licence", "synthetic_installation_123", "s" * 43, 1800000000)


class MemoryStorageTests(unittest.TestCase):
    def test_generation_fences_a_late_secret_write(self) -> None:
        storage = MemoryStorage()
        version, _ = storage.load()
        storage.invalidate()
        with self.assertRaises(OrbitError):
            storage.save(version, credential())
        self.assertIsNone(storage.load()[1])


class ProtectedCodecTests(unittest.TestCase):
    def test_python_codec_reads_the_rust_private_json_record_and_tombstones(self) -> None:
        settings = config()
        device = type("Device", (), {"installation_id": settings.installation_id, "fingerprint": None, "fingerprint_provider": None})()
        raw = encode_record(settings, device, 7, credential())
        self.assertEqual(
            raw,
            b'{"sdk":"orbit.rust.storage","format":1,"generation":7,"issuer":"https://issuer.example.test","application_id":"app","environment_id":"test","installation_id":"synthetic_installation_123","fingerprint":null,"fingerprint_provider":null,"credential":{"activation_id":"activation","licence_id":"licence","bearer":"sssssssssssssssssssssssssssssssssssssssssss","expires_at":1800000000}}',
        )
        generation, loaded = decode_record(settings, device, raw)
        self.assertEqual(generation, 7)
        self.assertEqual(loaded, credential())
        self.assertEqual(decode_record(settings, device, encode_record(settings, device, MAX_GENERATION, None)), (MAX_GENERATION, None))

    def test_rust_record_decoder_rejects_duplicates_wrong_scope_and_bad_types(self) -> None:
        settings = config()
        device = type("Device", (), {"installation_id": settings.installation_id, "fingerprint": None, "fingerprint_provider": None})()
        raw = encode_record(settings, device, 0, credential())
        duplicate = raw[:-1] + b',"format":1}'
        malformed = json.loads(raw)
        malformed["generation"] = True
        wrong_scope = json.loads(raw)
        wrong_scope["installation_id"] = "different"
        unknown = json.loads(raw)
        unknown["unknown"] = True
        for value in (duplicate, json.dumps(malformed).encode(), json.dumps(wrong_scope).encode(), json.dumps(unknown).encode(), raw[:-1]):
            with self.assertRaises(OrbitError):
                decode_record(settings, device, value)

    def test_secret_service_scope_and_base64_codec_match_existing_rust_item_identity(self) -> None:
        settings = config()
        device = type("Device", (), {"installation_id": settings.installation_id, "fingerprint": None, "fingerprint_provider": None})()
        directory = "/tmp/orbit-private-α"
        entropy = hashlib.sha256(
            b"orbit.sdk.storage.v1\0"
            + len(settings.issuer.encode()).to_bytes(4, "big") + settings.issuer.encode()
            + (3).to_bytes(4, "big") + b"app"
            + (4).to_bytes(4, "big") + b"test"
            + len(settings.installation_id.encode()).to_bytes(4, "big") + settings.installation_id.encode()
        ).digest()
        expected_scope = hashlib.sha256(
            b"orbit.sdk.secret-service.v1\0" + (4).to_bytes(4, "big") + b"rust" + entropy
            + len(directory.encode()).to_bytes(4, "big") + directory.encode()
        ).hexdigest()
        self.assertEqual(secret_service_scope(settings, device, directory), expected_scope)
        record = encode_secret_record(settings, device, 9, credential())
        self.assertEqual(base64.b64decode(record), encode_record(settings, device, 9, credential()))
        self.assertEqual(decode_secret_record(settings, device, record + b"\n"), (9, credential()))
        for bad in (record + b"\n\n", record + b" ", b"Zh==", b""):
            with self.assertRaises(OrbitError):
                decode_secret_record(settings, device, bad)


class _DeterministicSecretHelper:
    def __init__(self) -> None:
        self.records: dict[str, bytes] = {}
        self.lookups: list[str] = []
        self.stores: list[str] = []
        self.fail_store = False

    def lookup(self, scope: str) -> bytes | None:
        self.lookups.append(scope)
        return self.records.get(scope)

    def store(self, scope: str, record: bytes) -> None:
        self.stores.append(scope)
        if self.fail_store:
            raise RuntimeError("synthetic helper failure")
        self.records[scope] = record


@unittest.skipUnless(sys.platform == "linux", "Linux Secret Service storage tests")
class SecretServiceStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="orbit-python-storage-")
        os.chmod(self.directory.name, 0o700)
        self.settings = config()
        self.device = type("Device", (), {"installation_id": self.settings.installation_id, "fingerprint": None, "fingerprint_provider": None})()
        self.helper = _DeterministicSecretHelper()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_restart_load_save_invalidate_and_existing_scope(self) -> None:
        storage = SecretServiceStorage.open(self.directory.name, self.settings, self.device, _helper=self.helper)
        self.assertEqual(storage.version(), 0)
        self.assertIsNone(storage.load()[1])
        storage.save(0, credential())
        self.assertEqual(storage.load(), (0, credential()))
        self.assertTrue(all(scope == self.helper.stores[0] for scope in self.helper.stores + self.helper.lookups))
        storage.close()

        restarted = SecretServiceStorage.open(self.directory.name, self.settings, self.device, _helper=self.helper)
        self.assertEqual(restarted.load(), (0, credential()))
        self.assertEqual(restarted.invalidate(), 1)
        self.assertIsNone(restarted.load()[1])
        restarted.close()

    def test_pending_marker_poisons_adapter_and_fences_reopen_before_helper(self) -> None:
        storage = SecretServiceStorage.open(self.directory.name, self.settings, self.device, _helper=self.helper)
        self.helper.fail_store = True
        with self.assertRaises(OrbitError):
            storage.save(0, credential())
        self.assertEqual(Path(self.directory.name, "orbit-storage.lock").read_bytes(), b"\x01")
        lookup_count = len(self.helper.lookups)
        storage.close()
        with self.assertRaises(OrbitError):
            SecretServiceStorage.open(self.directory.name, self.settings, self.device, _helper=self.helper)
        self.assertEqual(len(self.helper.lookups), lookup_count)

    def test_symlink_directory_and_other_scope_fail_closed(self) -> None:
        symlink_dir = self.directory.name + "-link"
        os.symlink(self.directory.name, symlink_dir)
        try:
            with self.assertRaises(OrbitError):
                SecretServiceStorage.open(symlink_dir, self.settings, self.device, _helper=self.helper)
        finally:
            os.unlink(symlink_dir)

        storage = SecretServiceStorage.open(self.directory.name, self.settings, self.device, _helper=self.helper)
        storage.close()
        wrong = Config("https://orbit.example.test", "other_app", "test", "https://issuer.example.test", "synthetic_installation_123")
        other_device = type("Device", (), {"installation_id": wrong.installation_id, "fingerprint": None, "fingerprint_provider": None})()
        with self.assertRaises(OrbitError):
            SecretServiceStorage.open(self.directory.name, wrong, other_device, _helper=self.helper)


@unittest.skipUnless(os.name == "nt", "Windows DPAPI runtime tests")
class WindowsStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="orbit-python-dpapi-")
        self.settings = config()
        self.device = type("Device", (), {"installation_id": self.settings.installation_id, "fingerprint": None, "fingerprint_provider": None})()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_dpapi_fresh_save_reopen_load_and_invalidate(self) -> None:
        storage = WindowsStorage.open(self.directory.name, self.settings, self.device)
        self.assertEqual(storage.load(), (0, None))
        storage.save(0, credential())
        storage.close()

        reopened = WindowsStorage.open(self.directory.name, self.settings, self.device)
        self.assertEqual(reopened.load(), (0, credential()))
        self.assertEqual(reopened.invalidate(), 1)
        self.assertEqual(reopened.load(), (1, None))
        reopened.close()
        ciphertext = Path(self.directory.name, "orbit-storage.bin").read_bytes()
        self.assertNotIn(credential().credential.encode(), ciphertext)
        self.assertFalse(list(Path(self.directory.name).glob("orbit-storage-*.tmp")))

    def test_dpapi_write_failure_poisons_and_removes_temporary_file(self) -> None:
        storage = WindowsStorage.open(self.directory.name, self.settings, self.device)

        def fail_rename(_source: int) -> None:
            raise RuntimeError("synthetic rename failure")

        storage._rename_into_place = fail_rename
        with self.assertRaises(OrbitError):
            storage.save(0, credential())
        self.assertTrue(storage._poisoned)
        self.assertFalse(list(Path(self.directory.name).glob("orbit-storage-*.tmp")))
        with self.assertRaises(OrbitError):
            storage.version()
        storage.close()


if __name__ == "__main__":
    unittest.main()
