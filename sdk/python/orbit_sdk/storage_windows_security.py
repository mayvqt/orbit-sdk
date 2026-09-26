"""Handle-based access control for installed-client state on Windows."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from typing import Iterator

from .errors import STORAGE, error


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("descriptor", ctypes.c_void_p), ("inherit", ctypes.c_int)]


class _Acl(ctypes.Structure):
    _fields_ = [("revision", ctypes.c_ubyte), ("reserved", ctypes.c_ubyte),
                ("size", ctypes.c_uint16), ("count", ctypes.c_uint16), ("reserved2", ctypes.c_uint16)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", ctypes.c_uint16)]


def _libraries():
    return (ctypes.WinDLL("kernel32.dll", use_last_error=True),
            ctypes.WinDLL("advapi32.dll", use_last_error=True))


def _local_free(value: ctypes.c_void_p) -> None:
    if value:
        kernel, _ = _libraries()
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(value)


def _sid_text(sid: int) -> str:
    _, security = _libraries()
    security.IsValidSid.argtypes = [ctypes.c_void_p]
    security.IsValidSid.restype = ctypes.c_int
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    security.ConvertSidToStringSidW.restype = ctypes.c_int
    result = ctypes.c_void_p()
    if not sid or not security.IsValidSid(sid) or not security.ConvertSidToStringSidW(sid, ctypes.byref(result)):
        raise error(STORAGE, "storage_failed")
    try:
        return ctypes.wstring_at(result)
    finally:
        _local_free(result)


def _current_user() -> str:
    kernel, security = _libraries()
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetCurrentThread.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    security.OpenThreadToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    security.OpenThreadToken.restype = ctypes.c_int
    token = ctypes.c_void_p()
    # A background worker runs under the process identity. Do not mix its
    # DPAPI state with an impersonating caller's identity.
    if security.OpenThreadToken(kernel.GetCurrentThread(), 8, True, ctypes.byref(token)):
        kernel.CloseHandle(token)
        raise error(STORAGE, "storage_impersonation_unsupported")
    if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
        raise error(STORAGE, "storage_failed")
    security.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    security.GetTokenInformation.restype = ctypes.c_int
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise error(STORAGE, "storage_failed")
    try:
        size = ctypes.c_uint32()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser, not TokenOwner
        if not ctypes.sizeof(ctypes.c_void_p) <= size.value <= 65536:
            raise error(STORAGE, "storage_failed")
        data = ctypes.create_string_buffer(size.value)
        if not security.GetTokenInformation(token, 1, data, len(data), ctypes.byref(size)):
            raise error(STORAGE, "storage_failed")
        return _sid_text(ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0])
    finally:
        kernel.CloseHandle(token)


@contextmanager
def private_attributes() -> Iterator[_SecurityAttributes]:
    """Create with an explicit user owner and a protected, private DACL."""
    _, security = _libraries()
    sid = _current_user()
    sddl = f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise error(STORAGE, "storage_failed")
    try:
        yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    finally:
        _local_free(descriptor)


def create_private_directory(path: str) -> None:
    kernel, _ = _libraries()
    kernel.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_SecurityAttributes)]
    kernel.CreateDirectoryW.restype = ctypes.c_int
    with private_attributes() as attributes:
        if not kernel.CreateDirectoryW(path, ctypes.byref(attributes)) and ctypes.get_last_error() != 183:
            raise error(STORAGE, "storage_failed")
    # An existing/raced entry is inspected by its pinned handle, never changed.


def check_private(handle: int) -> None:
    """Reject foreign ownership, null/inherited/public access and exotic ACEs."""
    _, security = _libraries()
    security.GetSecurityInfo.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32,
                                        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                        ctypes.POINTER(ctypes.c_void_p)]
    security.GetSecurityInfo.restype = ctypes.c_uint32
    security.GetSecurityDescriptorControl.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint32)]
    security.GetSecurityDescriptorControl.restype = ctypes.c_int
    security.IsValidAcl.argtypes = [ctypes.c_void_p]
    security.IsValidAcl.restype = ctypes.c_int
    security.GetAce.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    security.GetAce.restype = ctypes.c_int
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    if security.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)):
        raise error(STORAGE, "storage_failed")
    try:
        current = _current_user()
        if _sid_text(owner.value) != current or not dacl or not security.IsValidAcl(dacl):
            raise error(STORAGE, "storage_insecure")
        control, revision = ctypes.c_uint16(), ctypes.c_uint32()
        if not security.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)) or control.value & 0x1004 != 0x1004:
            raise error(STORAGE, "storage_insecure")
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        allowed = {current, "S-1-5-18", "S-1-5-32-544"}
        user_allowed = False
        for index in range(acl.count):
            ace = ctypes.c_void_p()
            if not security.GetAce(dacl, index, ctypes.byref(ace)):
                raise error(STORAGE, "storage_failed")
            header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
            # Ordinary allow/deny ACEs have a DWORD mask followed by their SID.
            if header.kind not in (0, 1) or header.size < 16:
                raise error(STORAGE, "storage_insecure")
            trustee = _sid_text(ace.value + 8)
            if header.kind == 0:
                if trustee not in allowed:
                    raise error(STORAGE, "storage_insecure")
                if trustee == current and not header.flags & 8:  # INHERIT_ONLY_ACE
                    user_allowed = True
        if not user_allowed:
            raise error(STORAGE, "storage_insecure")
    finally:
        _local_free(descriptor)
