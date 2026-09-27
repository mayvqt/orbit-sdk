"""Application-version grammar, SDK identification and update hints."""

from __future__ import annotations

import platform as _platform
import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path
from typing import Any

from .errors import CONFIGURATION, INVALID_RESPONSE, error

LANGUAGE = "python"
_NUMBER = r"(?:0|[1-9][0-9]*)"
_IDENTIFIER = r"[0-9A-Za-z-]+"
_PRE_PART = rf"(?:{_NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_VERSION = re.compile(
    rf"{_NUMBER}(?:\.{_NUMBER}){{0,3}}"
    rf"(?:-{_PRE_PART}(?:\.{_PRE_PART})*)?"
    rf"(?:\+{_IDENTIFIER}(?:\.{_IDENTIFIER})*)?"
)
_LANGUAGE = re.compile(r"[a-z][a-z0-9-]{0,15}")
_PLATFORM = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")


def valid(value: object) -> bool:
    """Return whether ``value`` is ``N[.N[.N[.N]]][-PRE][+BUILD]`` in at most 32 bytes."""
    return (
        isinstance(value, str)
        and value.isascii()
        and len(value) <= 32
        and _VERSION.fullmatch(value) is not None
    )


def configured(value: str | None) -> str | None:
    """Validate an application-supplied version before any request uses it."""
    if value is not None and not valid(value):
        raise error(CONFIGURATION, "invalid_app_version")
    return value


def format_client_header(language: str, sdk_version: str, platform: str) -> str | None:
    """Return an ``Orbit-Client`` value, or ``None`` when a part is outside the grammar."""
    if not all(isinstance(part, str) and part.isascii() for part in (language, sdk_version, platform)):
        return None
    if _LANGUAGE.fullmatch(language) is None or _PLATFORM.fullmatch(platform) is None or not valid(sdk_version):
        return None
    header = f"{language}/{sdk_version} ({platform})"
    return header if len(header) <= 128 else None


def sdk_version() -> str:
    """This package's version: the source project metadata, else the installed distribution."""
    project = Path(__file__).resolve().parent.parent / "pyproject.toml"
    version: str | None = None
    try:
        with project.open("rb") as handle:
            data = tomllib.load(handle)
        if data.get("project", {}).get("name") == "orbit-sdk":
            version = data["project"].get("version")
    except (OSError, tomllib.TOMLDecodeError):
        version = None
    if version is None:
        try:
            version = metadata.version("orbit-sdk")
        except metadata.PackageNotFoundError:
            version = None
    if valid(version):
        return str(version)
    core = str(version or "").split("+", 1)[0].split("-", 1)[0]
    return core if valid(core) else "0.0.0"


def _platform_name() -> str:
    system = {"darwin": "macos", "win32": "windows"}.get(sys.platform, sys.platform)
    system = "linux" if system.startswith("linux") else system
    machine = _platform.machine().lower()
    machine = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64", "i386": "x86", "i686": "x86"}.get(machine, machine)
    value = re.sub(r"[^a-z0-9_.-]", "_", f"{system}-{machine or 'unknown'}".lower())[:32]
    return value if _PLATFORM.fullmatch(value) else "unknown"


CLIENT_HEADER = (
    format_client_header(LANGUAGE, sdk_version(), _platform_name())
    or format_client_header(LANGUAGE, sdk_version(), "unknown")
    or f"{LANGUAGE}/0.0.0 (unknown)"
)


def update_hint(reply: Any) -> str | None:
    """Return the optional ``update_available`` version; a malformed hint invalidates the reply."""
    if not isinstance(reply, dict) or "update_available" not in reply:
        return None
    hint = reply["update_available"]
    if not isinstance(hint, dict) or not valid(hint.get("version")):
        raise error(INVALID_RESPONSE, "invalid_update_available")
    return str(hint["version"])
