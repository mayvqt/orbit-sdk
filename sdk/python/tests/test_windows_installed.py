from __future__ import annotations

import ctypes
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from orbit_sdk import AppConfig, OrbitError
from orbit_sdk.persistent_storage import InstallationStorage
from orbit_sdk.storage import StoredCredential


@unittest.skipUnless(sys.platform == "win32", "Windows installed-client ACL/DPAPI runtime tests")
class WindowsInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = tempfile.TemporaryDirectory(prefix="orbit-installed-windows-")
        self.directory = Path(self.parent.name, "state")
        self.config = AppConfig("https://orbit.example.test", "app", "test", "https://issuer.example.test")

    def tearDown(self) -> None:
        self.parent.cleanup()

    def test_private_creation_dpapi_roundtrip_and_exclusive_lease(self) -> None:
        store = InstallationStorage.open(self.directory, self.config)
        try:
            installed = store.installation_id
            credential = StoredCredential("app", "test", "activation", "licence", installed, "k" * 43, None)
            store.save(0, credential)
            with self.assertRaises(OrbitError) as busy:
                InstallationStorage.open(self.directory, self.config)
            self.assertEqual(busy.exception.code, "installation_in_use")
            ciphertext = (self.directory / "orbit-storage.bin").read_bytes()
            self.assertNotIn(credential.credential.encode(), ciphertext)
            self.assertNotIn(installed.encode(), ciphertext)
        finally:
            store.close()
        reopened = InstallationStorage.open(self.directory, self.config)
        try:
            self.assertEqual(reopened.installation_id, installed)
            self.assertEqual(reopened.load(), (0, credential))
        finally:
            reopened.close()

    def test_existing_public_leaf_is_rejected_without_acl_repair(self) -> None:
        from orbit_sdk.storage_windows_security import _libraries, _current_user, _SecurityAttributes, _local_free
        kernel, security = _libraries()
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
        kernel.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_SecurityAttributes)]
        kernel.CreateDirectoryW.restype = ctypes.c_int
        descriptor = ctypes.c_void_p()
        self.assertTrue(security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{_current_user()}D:P(A;OICI;FA;;;WD)", 1, ctypes.byref(descriptor), None))
        try:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            self.assertTrue(kernel.CreateDirectoryW(str(self.directory), ctypes.byref(attributes)))
        finally:
            _local_free(descriptor)
        for _ in range(2):
            with self.assertRaises(OrbitError) as insecure:
                InstallationStorage.open(self.directory, self.config)
            self.assertEqual(insecure.exception.code, "storage_insecure")
        self.assertFalse((self.directory / "orbit-storage.lock").exists())

    def test_failed_invalidation_blocks_reopening_old_credential(self) -> None:
        from orbit_sdk.errors import STORAGE, error
        from orbit_sdk.storage_windows import WindowsStorage
        store = InstallationStorage.open(self.directory, self.config)
        credential = StoredCredential("app", "test", "activation", "licence", store.installation_id, "k" * 43, None)
        store.save(0, credential)
        with patch.object(WindowsStorage, "_write_replace", side_effect=error(STORAGE, "storage_failed")):
            with self.assertRaises(OrbitError):
                store.invalidate()
        store.close()
        self.assertEqual((self.directory / "orbit-storage.lock").stat().st_size, 1)
        with self.assertRaises(OrbitError):
            InstallationStorage.open(self.directory, self.config)

    def test_hard_linked_record_is_rejected(self) -> None:
        store = InstallationStorage.open(self.directory, self.config)
        store.close()
        os.link(self.directory / "orbit-storage.bin", Path(self.parent.name, "alias.bin"))
        with self.assertRaises(OrbitError):
            InstallationStorage.open(self.directory, self.config)

    def test_missing_record_behind_initialization_marker_is_not_reinitialized(self) -> None:
        store = InstallationStorage.open(self.directory, self.config)
        store.close()
        (self.directory / "orbit-storage.bin").unlink()
        with self.assertRaises(OrbitError):
            InstallationStorage.open(self.directory, self.config)
        self.assertFalse((self.directory / "orbit-storage.bin").exists())
