from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import struct
import sys

from .errors import CONFIGURATION, DENIED, OrbitError, error


def opaque(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError:
        return False
    return 1 <= size <= 128 and value.isascii() and all(char.isalnum() or char in "_-" for char in value)


def lower_hex(value: str, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def valid_provider(value: str) -> bool:
    if value == "machine_v1":
        return True
    if not value.startswith("custom:") or not 1 <= len(value[7:]) <= 48:
        return False
    return all(c in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for c in value[7:])


def installation_id_new() -> str:
    return base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode("ascii")


def machine_fingerprint(application_id: str, environment_id: str, family: str, identity: str) -> str:
    if not opaque(application_id) or not opaque(environment_id) or family not in ("linux", "windows"):
        raise error(CONFIGURATION, "invalid_configuration")
    normalized = identity.strip(" \t\n\r\v\f").replace("-", "").lower()
    if not lower_hex(normalized, 32) or normalized in ("0" * 32, "f" * 32):
        raise error(DENIED, "device_identity_unavailable")
    framed = f"orbit-machine-v1\n{application_id}\n{environment_id}\n{family}\n{normalized}".encode("ascii")
    return hashlib.sha256(framed).hexdigest()


def _smbios_uuid(data: bytes) -> str:
    if len(data) < 8 or len(data) > 1 << 20 or data[1] < 2 or (data[1] == 2 and data[2] < 6):
        raise error(DENIED, "device_identity_unavailable")
    if struct.unpack_from("<I", data, 4)[0] != len(data) - 8:
        raise error(DENIED, "device_identity_unavailable")
    identity: str | None = None
    offset = 8
    while offset < len(data):
        if len(data) - offset < 4:
            raise error(DENIED, "device_identity_unavailable")
        record_type, size = data[offset], data[offset + 1]
        if size < 4 or size > len(data) - offset:
            raise error(DENIED, "device_identity_unavailable")
        end = offset + size
        while end + 1 < len(data) and data[end : end + 2] != b"\0\0":
            end += 1
        if end + 1 >= len(data):
            raise error(DENIED, "device_identity_unavailable")
        if record_type == 1:
            if identity is not None or size < 25:
                raise error(DENIED, "device_identity_unavailable")
            uuid = bytearray(data[offset + 8 : offset + 24])
            uuid[:4] = reversed(uuid[:4])
            uuid[4:6] = reversed(uuid[4:6])
            uuid[6:8] = reversed(uuid[6:8])
            identity = uuid.hex()
            if identity in ("0" * 32, "f" * 32):
                raise error(DENIED, "device_identity_unavailable")
        elif record_type == 127:
            if identity is None:
                raise error(DENIED, "device_identity_unavailable")
            return identity
        offset = end + 2
    raise error(DENIED, "device_identity_unavailable")


def native_fingerprint(application_id: str, environment_id: str) -> str:
    if not opaque(application_id) or not opaque(environment_id):
        raise error(CONFIGURATION, "invalid_configuration")
    try:
        if sys.platform.startswith("linux"):
            fd = os.open("/etc/machine-id", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                value = os.read(fd, 257)
            finally:
                os.close(fd)
            if len(value) > 256:
                raise ValueError
            identity = value.decode("utf-8", "strict")
            return machine_fingerprint(application_id, environment_id, "linux", identity)
        if sys.platform == "win32":
            function = ctypes.WinDLL("kernel32.dll").GetSystemFirmwareTable
            function.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
            function.restype = ctypes.c_uint
            provider = 0x52534D42
            size = function(provider, 0, None, 0)
            if size < 8 or size > 1 << 20:
                raise ValueError
            buffer = ctypes.create_string_buffer(size)
            written = function(provider, 0, buffer, size)
            if written != size:
                raise ValueError
            identity = _smbios_uuid(buffer.raw[:size])
            return machine_fingerprint(application_id, environment_id, "windows", identity)
    except OrbitError:
        raise
    except (OSError, UnicodeError, ValueError, AttributeError) as exc:
        raise error(DENIED, "device_identity_unavailable") from exc
    raise error(DENIED, "device_identity_unavailable")
