from __future__ import annotations

import base64
import hashlib
import struct
import unittest
from unittest.mock import patch

from orbit_sdk import Config, installation_id_new, machine_fingerprint
from orbit_sdk.clock import Anchor, Start, timestamp
from orbit_sdk.device import _smbios_uuid, native_fingerprint
from orbit_sdk.errors import OrbitError


class ClockTests(unittest.TestCase):
    def test_anchor_counts_suspend_and_rejects_wall_rollback(self) -> None:
        with patch("orbit_sdk.clock.elapsed_ns", return_value=1_000_000_000):
            anchor = Anchor(1_800_000_000, Start(1_000_000_000, 1_800_000_000))
        with patch("orbit_sdk.clock.elapsed_ns", return_value=3_601_000_000_000), patch("orbit_sdk.clock.wall_seconds", return_value=1_800_003_600):
            self.assertEqual(anchor.now(), 1_800_003_600)
        with patch("orbit_sdk.clock.elapsed_ns", return_value=3_601_000_000_000), patch("orbit_sdk.clock.wall_seconds", return_value=1_800_003_539):
            with self.assertRaises(OrbitError):
                anchor.now()
        with patch("orbit_sdk.clock.elapsed_ns", return_value=500_000_000), patch("orbit_sdk.clock.wall_seconds", return_value=1_800_000_000):
            with self.assertRaises(OrbitError):
                anchor.now()

    def test_timestamp_requires_whole_seconds_and_valid_rfc3339(self) -> None:
        self.assertEqual(timestamp("2026-09-25T00:00:00Z"), timestamp("2026-09-25T12:00:00+12:00"))
        self.assertEqual(timestamp("2026-09-25T00:00:00.000Z"), timestamp("2026-09-25T00:00:00Z"))
        for invalid in ("2026-09-25", "2026-09-25T00:00:00.001Z", "2026-09-25T00:00:00", "not-a-date"):
            with self.assertRaises(OrbitError):
                timestamp(invalid)


class DeviceTests(unittest.TestCase):
    def test_installation_id_is_random_urlsafe_24_byte_value(self) -> None:
        value = installation_id_new()
        self.assertEqual(len(base64.urlsafe_b64decode(value + "==")), 24)
        self.assertTrue(value.isascii())
        self.assertNotEqual(value, installation_id_new())

    def test_scoped_machine_fingerprint_vectors_and_invalid_identities(self) -> None:
        vectors = (
            ("app", "test", "linux", "00112233445566778899aabbccddeeff"),
            ("app", "test", "linux", " \t\r\n00112233-4455-6677-8899-AABBCCDDEEFF\v\f "),
            ("app", "test", "windows", "00112233-4455-6677-8899-AABBCCDDEEFF"),
            ("other_app", "live", "linux", "0123456789ABCDEF0123456789ABCDEF"),
        )
        for app, env, family, identity in vectors:
            normalized = identity.strip(" \t\n\r\v\f").replace("-", "").lower()
            preimage = f"orbit-machine-v1\n{app}\n{env}\n{family}\n{normalized}".encode()
            self.assertEqual(machine_fingerprint(app, env, family, identity), hashlib.sha256(preimage).hexdigest())
        for identity in ("", "0" * 32, "F" * 32, "00112233445566778899aabbccddeef", "00112233445566778899aabbccddeefg", "00112233 445566778899aabbccddeeff", "\u00a000112233445566778899aabbccddeeff"):
            with self.assertRaises(OrbitError):
                machine_fingerprint("app", "test", "linux", identity)
        with self.assertRaises(OrbitError):
            machine_fingerprint("app/other", "test", "linux", "00112233445566778899aabbccddeeff")

    def test_smbios_uuid_parser_accepts_only_modern_complete_system_record(self) -> None:
        uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
        type_one = bytes([1, 25, 0, 0]) + b"\x00" * 4 + uuid + b"\x00"
        type_one += b"\x00\x00"
        end = b"\x7f\x04\x00\x00\x00\x00"
        table = bytes([0, 3, 0, 0]) + struct.pack("<I", len(type_one + end)) + type_one + end
        self.assertEqual(_smbios_uuid(table), "33221100554477668899aabbccddeeff")
        for invalid in (table[:7], bytes([0, 2, 5, 0]) + table[4:], table[:-1], bytes([0, 3, 0, 0]) + struct.pack("<I", 5) + table[8:]):
            with self.assertRaises(OrbitError):
                _smbios_uuid(invalid)


if __name__ == "__main__":
    unittest.main()
