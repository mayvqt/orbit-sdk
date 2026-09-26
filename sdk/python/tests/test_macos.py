from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from orbit_sdk import AppKey, OrbitError, machine_fingerprint
from orbit_sdk import _macos
from orbit_sdk.client import _AppScope
from orbit_sdk.clock import elapsed_ns
from orbit_sdk.device import native_fingerprint
from orbit_sdk.persistent_storage import InstallationStorage, default_state_directory
from orbit_sdk.storage import _sync_posix

KEY = AppKey.parse("orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test")
SCOPE = _AppScope(KEY.api_origin, KEY.application_id, KEY.environment_id, KEY.issuer)
UUID = "00112233-4455-6677-8899-AABBCCDDEEFF"


class MacOSBindingsTests(unittest.TestCase):
    def test_continuous_clock_caches_ratio_but_samples_each_call(self):
        def timebase(output):
            ctypes.cast(output, ctypes.POINTER(_macos._Timebase))[0] = _macos._Timebase(125, 3)
            return 0

        library = SimpleNamespace(
            mach_timebase_info=Mock(side_effect=timebase),
            mach_continuous_time=Mock(side_effect=[3, 6, (1 << 64) - 1]),
        )
        _macos._continuous_clock.cache_clear()
        self.addCleanup(_macos._continuous_clock.cache_clear)
        with patch("orbit_sdk._macos.ctypes.CDLL", return_value=library) as load, patch("sys.platform", "darwin"):
            self.assertEqual(elapsed_ns(), 125)
            self.assertEqual(elapsed_ns(), 250)
            with self.assertRaises(OrbitError) as raised:
                elapsed_ns()
            self.assertEqual(raised.exception.code, "clock_uncertain")
        load.assert_called_once()
        library.mach_timebase_info.assert_called_once()
        self.assertEqual(library.mach_continuous_time.call_count, 3)

    def test_invalid_timebase_fails_closed(self):
        for status, numer, denom in [(1, 1, 1), (0, 0, 1), (0, 1, 0)]:
            with self.subTest(status=status, numer=numer, denom=denom):
                def timebase(output):
                    ctypes.cast(output, ctypes.POINTER(_macos._Timebase))[0] = _macos._Timebase(numer, denom)
                    return status
                _macos._continuous_clock.cache_clear()
                library = SimpleNamespace(mach_timebase_info=Mock(side_effect=timebase))
                with patch("orbit_sdk._macos.ctypes.CDLL", return_value=library), patch("sys.platform", "darwin"):
                    with self.assertRaises(OrbitError):
                        elapsed_ns()
        _macos._continuous_clock.cache_clear()

    def test_identity_is_scoped_and_core_foundation_values_are_released(self):
        def copy(_value, buffer, _size, _encoding):
            buffer.value = UUID.encode("ascii")
            return True
        core = SimpleNamespace(
            CFStringCreateWithCString=Mock(return_value=11),
            CFStringGetTypeID=Mock(return_value=7), CFGetTypeID=Mock(return_value=7),
            CFStringGetLength=Mock(return_value=36), CFStringGetCString=Mock(side_effect=copy),
            CFRelease=Mock(),
        )
        io = SimpleNamespace(
            IOServiceMatching=Mock(return_value=9), IOServiceGetMatchingService=Mock(return_value=10),
            IORegistryEntryCreateCFProperty=Mock(return_value=12), IOObjectRelease=Mock(),
        )
        with patch("orbit_sdk._macos._identity_frameworks", return_value=(core, io)), patch("sys.platform", "darwin"):
            fingerprint = native_fingerprint("app", "test")
            self.assertEqual(fingerprint, hashlib.sha256(b"orbit-machine-v1\napp\ntest\nmacos\n00112233445566778899aabbccddeeff").hexdigest())
            self.assertNotEqual(fingerprint, machine_fingerprint("app", "live", "macos", UUID))
            core.CFRelease.assert_has_calls([call(12), call(11)])
            io.IOObjectRelease.assert_called_with(10)
            for failure in ["type", "length", "copy"]:
                with self.subTest(failure=failure):
                    core.CFGetTypeID.return_value = 8 if failure == "type" else 7
                    core.CFStringGetLength.return_value = 37 if failure == "length" else 36
                    core.CFStringGetCString.side_effect = None if failure == "copy" else copy
                    core.CFStringGetCString.return_value = failure != "copy"
                    core.CFRelease.reset_mock()
                    io.IOObjectRelease.reset_mock()
                    with self.assertRaises(OrbitError):
                        native_fingerprint("app", "test")
                    core.CFRelease.assert_has_calls([call(12), call(11)])
                    io.IOObjectRelease.assert_called_once_with(10)

    @unittest.skipUnless(os.name == "posix", "POSIX file adapter")
    def test_darwin_private_state_reopens_and_rejects_replaced_lease(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = str(Path(parent).resolve() / "state")
            # Exercise POSIX behavior on this host. Native full-sync is covered
            # separately below; this is not a native macOS filesystem test.
            with patch("sys.platform", "darwin"), patch("orbit_sdk.storage._sync_posix", side_effect=os.fsync), patch("orbit_sdk.persistent_storage._sync_posix", side_effect=os.fsync):
                self.assertIn("/Library/Application Support/Orbit/", default_state_directory(SCOPE))
                store = InstallationStorage.open(directory, SCOPE)
                identity = store.installation_id
                store.close()
                store = InstallationStorage.open(directory, SCOPE)
                self.addCleanup(store.close)
                self.assertEqual(store.installation_id, identity)
                with self.assertRaises(OrbitError) as raised:
                    InstallationStorage.open(directory, SCOPE)
                self.assertEqual(raised.exception.code, "installation_in_use")
                lease = Path(directory) / "orbit-storage.lock"
                lease.rename(lease.with_suffix(".old"))
                lease.touch(mode=0o600)
                with self.assertRaises(OrbitError):
                    store.version()
                self.assertTrue(store._poisoned)

    @unittest.skipUnless(os.name == "posix", "POSIX file adapter")
    def test_full_sync_failure_is_not_downgraded_to_fsync(self):
        with tempfile.TemporaryFile() as file:
            with patch("sys.platform", "darwin"), patch("fcntl.fcntl", side_effect=OSError("unsupported")) as sync, patch("os.fsync") as ordinary:
                with self.assertRaises(OSError):
                    _sync_posix(file.fileno())
                sync.assert_called_once_with(file.fileno(), 51)
                ordinary.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "native macOS hardware/framework check")
    def test_native_identity_clock_and_durable_state(self):
        self.assertEqual(len(native_fingerprint("app", "test")), 64)
        self.assertGreaterEqual(elapsed_ns(), 0)
        with tempfile.TemporaryDirectory() as parent:
            path = str(Path(parent).resolve() / "state")
            store = InstallationStorage.open(path, SCOPE)
            identity = store.installation_id
            store.close()
            reopened = InstallationStorage.open(path, SCOPE)
            try:
                self.assertEqual(reopened.installation_id, identity)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
