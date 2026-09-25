from __future__ import annotations

import ctypes
import datetime as dt
import os
import re
import sys
import time
from dataclasses import dataclass

from .errors import CLOCK_UNCERTAIN, INVALID_RESPONSE, error

_RFC3339 = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$"
)


def elapsed_ns() -> int:
    if sys.platform.startswith("linux") and hasattr(time, "CLOCK_BOOTTIME"):
        value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if value < 0:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        return value
    if sys.platform == "win32":
        try:
            function = ctypes.WinDLL("api-ms-win-core-realtime-l1-1-1.dll").QueryInterruptTimePrecise
            value = ctypes.c_ulonglong()
            function.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
            function.restype = None
            function(ctypes.byref(value))
            if value.value > ((1 << 63) - 1) // 100:
                raise ValueError
            return value.value * 100
        except (AttributeError, OSError, ValueError) as exc:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain") from exc
    raise error(CLOCK_UNCERTAIN, "clock_uncertain")


def wall_seconds() -> int:
    value = time.time_ns() // 1_000_000_000
    if value < 0 or value > (1 << 63) - 1:
        raise error(CLOCK_UNCERTAIN, "clock_uncertain")
    return value


def timestamp(value: str) -> int:
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise error(INVALID_RESPONSE, "invalid_timestamp")
    whole, fraction, zone = match.groups()
    if fraction and any(digit != "0" for digit in fraction):
        raise error(INVALID_RESPONSE, "invalid_timestamp")
    try:
        normalized = whole + ("+00:00" if zone == "Z" else zone)
        instant = dt.datetime.fromisoformat(normalized).replace(microsecond=0)
        if instant.tzinfo is None:
            raise ValueError
        result = int(instant.timestamp())
        if result < -(1 << 63) or result > (1 << 63) - 1:
            raise ValueError
        return result
    except (ValueError, OverflowError, OSError) as exc:
        raise error(INVALID_RESPONSE, "invalid_timestamp") from exc


@dataclass(frozen=True)
class Start:
    elapsed: int
    wall: int

    @classmethod
    def capture(cls) -> Start:
        return cls(elapsed_ns(), wall_seconds())


@dataclass(frozen=True)
class Anchor:
    server: int
    start: Start

    def now(self) -> int:
        current = elapsed_ns()
        if current < self.start.elapsed:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        delta = (current - self.start.elapsed) // 1_000_000_000
        expected = self.start.wall + delta
        if not -(1 << 63) <= expected <= (1 << 63) - 1:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        if abs(wall_seconds() - expected) > 30:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        result = self.server + delta
        if not -(1 << 63) <= result <= (1 << 63) - 1:
            raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        return result
