"""Small bindings to system frameworks; no native Orbit SDK dependency."""

from __future__ import annotations

import ctypes
from functools import cache


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


@cache
def _continuous_clock():
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    info = library.mach_timebase_info
    info.argtypes = [ctypes.POINTER(_Timebase)]
    info.restype = ctypes.c_int
    ratio = _Timebase()
    if info(ctypes.byref(ratio)) != 0 or not ratio.numer or not ratio.denom:
        raise ValueError("continuous clock unavailable")
    clock = library.mach_continuous_time
    clock.argtypes = []
    clock.restype = ctypes.c_uint64
    return clock, ratio.numer, ratio.denom


def continuous_ns() -> int:
    clock, numer, denom = _continuous_clock()
    ticks = clock()
    if not 0 <= ticks <= (1 << 64) - 1:
        raise ValueError("invalid continuous clock")
    value = ticks * numer // denom
    if value > (1 << 63) - 1:
        raise ValueError("continuous clock overflow")
    return value


def _function(library, name, arguments, result):
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = result
    return function


@cache
def _identity_frameworks():
    core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    io = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    pointer, uint = ctypes.c_void_p, ctypes.c_uint32
    _function(io, "IOServiceMatching", [ctypes.c_char_p], pointer)
    _function(io, "IOServiceGetMatchingService", [uint, pointer], uint)
    _function(io, "IORegistryEntryCreateCFProperty", [uint, pointer, pointer, uint], pointer)
    _function(io, "IOObjectRelease", [uint], ctypes.c_int)
    _function(core, "CFStringCreateWithCString", [pointer, ctypes.c_char_p, uint], pointer)
    _function(core, "CFStringGetTypeID", [], ctypes.c_ulong)
    _function(core, "CFGetTypeID", [pointer], ctypes.c_ulong)
    _function(core, "CFStringGetLength", [pointer], ctypes.c_long)
    _function(core, "CFStringGetCString", [pointer, pointer, ctypes.c_long, uint], ctypes.c_bool)
    _function(core, "CFRelease", [pointer], None)
    return core, io


def platform_uuid() -> str:
    core, io = _identity_frameworks()
    matching = io.IOServiceMatching(b"IOPlatformExpertDevice")
    if not matching:
        raise ValueError("platform identity unavailable")
    # GetMatchingService consumes the matching dictionary, including on failure.
    service = io.IOServiceGetMatchingService(0, matching)
    if not service:
        raise ValueError("platform identity unavailable")
    key = value = None
    try:
        key = core.CFStringCreateWithCString(None, b"IOPlatformUUID", 0x08000100)
        if not key:
            raise ValueError("platform identity unavailable")
        value = io.IORegistryEntryCreateCFProperty(service, key, None, 0)
        if not value or core.CFGetTypeID(value) != core.CFStringGetTypeID():
            raise ValueError("invalid platform identity")
        length = core.CFStringGetLength(value)
        if not 1 <= length <= 256:
            raise ValueError("invalid platform identity")
        buffer = ctypes.create_string_buffer(257)
        if not core.CFStringGetCString(value, buffer, len(buffer), 0x08000100):
            raise ValueError("invalid platform identity")
        raw = buffer.value
        if len(raw) != length:
            # ASCII has one byte per CF character. Reject embedded NULs and
            # truncated/native conversion results instead of hashing a prefix.
            raise ValueError("invalid platform identity")
        return raw.decode("ascii", "strict")
    finally:
        if value:
            core.CFRelease(value)
        if key:
            core.CFRelease(key)
        io.IOObjectRelease(service)
