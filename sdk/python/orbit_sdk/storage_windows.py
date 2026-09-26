from __future__ import annotations

import ctypes
import ntpath
import os
import secrets
import sys
import threading
from typing import Any

from .errors import OrbitError, STALE_RESPONSE, STORAGE, error
from .storage import MAX_CIPHERTEXT, MAX_GENERATION, MAX_PLAINTEXT, StoredCredential, decode_record, encode_record, storage_entropy

LOCK_FILE = "orbit-storage.lock"
DATA_FILE = "orbit-storage.bin"
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x00010000
_FILE_SHARE_READ_WRITE = 3
_OPEN_EXISTING = 3
_CREATE_NEW = 1
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleInfo(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation", _FileTime),
        ("access", _FileTime),
        ("write", _FileTime),
        ("volume", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32),
        ("index_low", ctypes.c_uint32),
    ]


class _DataBlob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32.dll", use_last_error=True)


def _open_handle(path: str, access: int, share: int, creation: int, flags: int) -> int:
    kernel = _kernel32()
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    handle = kernel.CreateFileW(path, access, share, None, creation, flags, None)
    if handle == _INVALID_HANDLE or handle is None:
        raise error(STORAGE, "storage_failed")
    return int(handle)


def _close(handle: int | None) -> None:
    if handle is not None:
        try:
            kernel = _kernel32()
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel.CloseHandle.restype = ctypes.c_int
            kernel.CloseHandle(ctypes.c_void_p(handle))
        except OSError:
            pass


def _info(handle: int) -> _ByHandleInfo:
    value = _ByHandleInfo()
    kernel = _kernel32()
    kernel.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByHandleInfo)]
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    if not kernel.GetFileInformationByHandle(ctypes.c_void_p(handle), ctypes.byref(value)):
        raise error(STORAGE, "storage_failed")
    return value


def _check_directory(handle: int) -> None:
    info = _info(handle)
    if not info.attributes & _FILE_ATTRIBUTE_DIRECTORY or info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise error(STORAGE, "storage_failed")


def _check_regular(handle: int, *, minimum_size: int = 0, maximum_size: int | None = None) -> int:
    info = _info(handle)
    size = (info.size_high << 32) | info.size_low
    if info.attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT) or size < minimum_size or maximum_size is not None and size > maximum_size:
        raise error(STORAGE, "storage_failed")
    return size


class _DPAPI:
    @staticmethod
    def _call(name: str, data: bytes, entropy: bytes, maximum: int) -> bytes:
        if len(data) > (MAX_PLAINTEXT if name == "CryptProtectData" else MAX_CIPHERTEXT) or not 1 <= len(entropy) <= 1024:
            raise error(STORAGE, "storage_failed")
        input_buffer = ctypes.create_string_buffer(data)
        entropy_buffer = ctypes.create_string_buffer(entropy)
        input_blob = _DataBlob(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        entropy_blob = _DataBlob(len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        output = _DataBlob()
        crypt = ctypes.WinDLL("crypt32.dll", use_last_error=True)
        function = getattr(crypt, name)
        if name == "CryptProtectData":
            function.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_wchar_p, ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_DataBlob)]
        else:
            function.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_DataBlob)]
        function.restype = ctypes.c_int
        success = function(ctypes.byref(input_blob), None, ctypes.byref(entropy_blob), None, None, 1, ctypes.byref(output))
        if not success:
            raise error(STORAGE, "storage_failed")
        try:
            if output.size > maximum or output.size and not output.data:
                raise error(STORAGE, "storage_failed")
            return ctypes.string_at(output.data, output.size) if output.size else b""
        finally:
            if output.data:
                ctypes.memset(output.data, 0, output.size)
                kernel = _kernel32()
                kernel.LocalFree.argtypes = [ctypes.c_void_p]
                kernel.LocalFree.restype = ctypes.c_void_p
                kernel.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))

    @classmethod
    def protect(cls, data: bytes, entropy: bytes) -> bytes:
        return cls._call("CryptProtectData", data, entropy, MAX_CIPHERTEXT)

    @classmethod
    def unprotect(cls, data: bytes, entropy: bytes) -> bytes:
        return cls._call("CryptUnprotectData", data, entropy, MAX_PLAINTEXT)


class WindowsStorage:
    def __init__(self, directory: str, config: Any, device: Any, entropy: bytes, directories: list[tuple[str, int]], lease: int, created: bool) -> None:
        self._directory, self._config, self._device, self._entropy = directory, config, device, entropy
        self._directories, self._lease = directories, lease
        self._generation = 0
        self._credential: StoredCredential | None = None
        self._poisoned = False
        self._lock = threading.Lock()
        if created:
            self._commit(0, None)

    @classmethod
    def open(cls, directory: str, config: Any, device: Any) -> WindowsStorage:
        if sys.platform != "win32":
            raise error(STORAGE, "storage_unavailable")
        entropy = storage_entropy(config, device)
        encode_record(config, device, 0, None)
        dirs: list[tuple[str, int]] = []
        lease = None
        try:
            drive, tail = ntpath.splitdrive(directory)
            if not drive or len(drive) != 2 or drive[1] != ":" or not tail.startswith(("\\", "/")) or "\0" in directory:
                raise error(STORAGE, "storage_failed")
            if any(part == ".." or ":" in part for part in tail.replace("/", "\\").split("\\") if part):
                raise error(STORAGE, "storage_failed")
            kernel = _kernel32()
            kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
            kernel.GetDriveTypeW.restype = ctypes.c_uint
            if kernel.GetDriveTypeW(drive.upper() + "\\") not in (2, 3, 6):
                raise error(STORAGE, "storage_failed")
            paths = [drive.upper() + "\\"]
            current = paths[0]
            for part in tail.replace("/", "\\").split("\\"):
                if not part or part == ".":
                    continue
                current = ntpath.join(current, part)
                paths.append(current)
            for path in paths:
                handle = _open_handle(path, _GENERIC_READ, _FILE_SHARE_READ_WRITE, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)
                try:
                    _check_directory(handle)
                except BaseException:
                    _close(handle)
                    raise
                dirs.append((path, handle))
            parent = dirs[-1][0]
            lease_path = ntpath.join(parent, LOCK_FILE)
            try:
                lease = _open_handle(lease_path, _GENERIC_READ | _GENERIC_WRITE, 0, _CREATE_NEW, _FILE_FLAG_OPEN_REPARSE_POINT)
                created = True
            except OrbitError:
                # Only an already existing entry permits the second open; all
                # other native errors stay fail closed.
                if not os.path.exists(lease_path):
                    raise
                lease = _open_handle(lease_path, _GENERIC_READ | _GENERIC_WRITE, 0, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
                created = False
            _check_regular(lease)
            state = cls.__new__(cls)
            state._directory, state._config, state._device, state._entropy = parent, config, device, entropy
            state._directories, state._lease = dirs, lease
            state._generation, state._credential, state._poisoned, state._lock = 0, None, False, threading.Lock()
            state._check()
            ciphertext = state._read_ciphertext()
            if ciphertext is None:
                if not created:
                    raise error(STORAGE, "storage_failed")
                state._commit(0, None)
            else:
                plaintext = _DPAPI.unprotect(ciphertext, entropy)
                state._generation, state._credential = decode_record(config, device, plaintext)
            return state
        except BaseException:
            _close(lease)
            for _, handle in dirs:
                _close(handle)
            raise error(STORAGE, "storage_failed")

    def _check(self) -> None:
        if self._poisoned:
            raise error(STORAGE, "storage_failed")
        for _, handle in self._directories:
            _check_directory(handle)

    def _read_ciphertext(self) -> bytes | None:
        path = ntpath.join(self._directory, DATA_FILE)
        try:
            handle = _open_handle(path, _GENERIC_READ, 0, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
        except OrbitError:
            if not os.path.lexists(path):
                return None
            raise
        try:
            size = _check_regular(handle, minimum_size=1, maximum_size=MAX_CIPHERTEXT)
            kernel = _kernel32()
            kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
            kernel.ReadFile.restype = ctypes.c_int
            output = ctypes.create_string_buffer(size)
            read = ctypes.c_uint32()
            if not kernel.ReadFile(ctypes.c_void_p(handle), output, size, ctypes.byref(read), None) or read.value != size:
                raise error(STORAGE, "storage_failed")
            return output.raw[:size]
        finally:
            _close(handle)

    def _write_replace(self, ciphertext: bytes) -> None:
        if not ciphertext or len(ciphertext) > MAX_CIPHERTEXT:
            raise error(STORAGE, "storage_failed")
        destination = ntpath.join(self._directory, DATA_FILE)
        try:
            existing = _open_handle(destination, _GENERIC_READ, 0, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
        except OrbitError:
            if os.path.lexists(destination):
                raise
        else:
            try:
                _check_regular(existing)
            finally:
                _close(existing)
        suffix = secrets.token_hex(16)
        temporary_path = ntpath.join(self._directory, f"orbit-storage-{suffix}.tmp")
        source = _open_handle(temporary_path, _GENERIC_WRITE | _DELETE, 0, _CREATE_NEW, _FILE_FLAG_OPEN_REPARSE_POINT)
        replaced = False
        try:
            _check_regular(source)
            kernel = _kernel32()
            kernel.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
            kernel.WriteFile.restype = ctypes.c_int
            buffer = ctypes.create_string_buffer(ciphertext)
            written = ctypes.c_uint32()
            if not kernel.WriteFile(ctypes.c_void_p(source), buffer, len(ciphertext), ctypes.byref(written), None) or written.value != len(ciphertext):
                raise error(STORAGE, "storage_failed")
            kernel.FlushFileBuffers.argtypes = [ctypes.c_void_p]
            kernel.FlushFileBuffers.restype = ctypes.c_int
            if not kernel.FlushFileBuffers(ctypes.c_void_p(source)):
                raise error(STORAGE, "storage_failed")
            self._check()
            self._rename_into_place(source)
            replaced = True
            if not kernel.FlushFileBuffers(ctypes.c_void_p(source)):
                raise error(STORAGE, "storage_failed")
        finally:
            _close(source)
            if not replaced:
                kernel = _kernel32()
                kernel.DeleteFileW.argtypes = [ctypes.c_wchar_p]
                kernel.DeleteFileW.restype = ctypes.c_int
                if not kernel.DeleteFileW(temporary_path) and ctypes.get_last_error() != 2:
                    raise error(STORAGE, "storage_failed")

    def _rename_into_place(self, source: int) -> None:
        # FILE_RENAME_INFO's first union member is a 32-bit flags field; the
        # name tail follows the native pointer-aligned header.
        class RenameInfo(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32), ("root", ctypes.c_void_p), ("length", ctypes.c_uint32), ("name", ctypes.c_wchar * 1)]

        kernel = _kernel32()
        kernel.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        chars = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(ctypes.c_void_p(self._directories[-1][1]), chars, len(chars), 0)
        if not length or length >= len(chars):
            raise error(STORAGE, "storage_failed")
        directory = chars.value.rstrip("\\")
        name = (directory + "\\" + DATA_FILE).encode("utf-16-le")
        offset = RenameInfo.name.offset
        # Win32 rename metadata needs a terminal WCHAR beyond the counted name.
        allocation = ctypes.create_string_buffer(
            max(ctypes.sizeof(RenameInfo), offset + len(name) + ctypes.sizeof(ctypes.c_wchar))
        )
        ctypes.cast(allocation, ctypes.POINTER(RenameInfo)).contents.flags = 1
        ctypes.cast(allocation, ctypes.POINTER(RenameInfo)).contents.root = None
        ctypes.cast(allocation, ctypes.POINTER(RenameInfo)).contents.length = len(name)
        ctypes.memmove(ctypes.addressof(allocation) + offset, name, len(name))
        kernel.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        kernel.SetFileInformationByHandle.restype = ctypes.c_int
        if not kernel.SetFileInformationByHandle(ctypes.c_void_p(source), 3, allocation, len(allocation)):
            raise error(STORAGE, "storage_failed")

    def _commit(self, generation: int, credential: StoredCredential | None) -> None:
        try:
            self._check()
            plaintext = encode_record(self._config, self._device, generation, credential)
            ciphertext = _DPAPI.protect(plaintext, self._entropy)
            self._check()
            self._write_replace(ciphertext)
        except BaseException as exc:
            self._poisoned = True
            self._credential = None
            raise error(STORAGE, "storage_failed") from exc
        self._generation, self._credential = generation, credential

    def version(self) -> int:
        with self._lock:
            self._check()
            return self._generation

    def load(self) -> tuple[int, StoredCredential | None]:
        with self._lock:
            self._check()
            return self._generation, self._credential

    def save(self, version: int, credential: StoredCredential) -> None:
        with self._lock:
            self._check()
            if version != self._generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._commit(version, credential)

    def invalidate(self) -> int:
        with self._lock:
            self._check()
            if self._generation == MAX_GENERATION:
                self._poisoned = True
                self._credential = None
                raise error(STORAGE, "storage_failed")
            generation = self._generation + 1
            self._commit(generation, None)
            return generation

    def close(self) -> None:
        _close(self._lease)
        self._lease = None
        for _, handle in self._directories:
            _close(handle)
        self._directories.clear()

    def __repr__(self) -> str:
        return "WindowsStorage(<redacted>)"
