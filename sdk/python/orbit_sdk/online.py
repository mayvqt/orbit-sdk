"""Typed, strictly validated online release and limit results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from ipaddress import IPv6Address
import platform as runtime_platform
import re
import secrets
import struct
import sys
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import CONFIGURATION, DENIED, INVALID_RESPONSE, OrbitError, error
from .jsonutil import fields, strict_int, text

MAX_INTEGER = (1 << 53) - 1
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_TARGET = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


def invalid() -> None:
    raise error(INVALID_RESPONSE, "invalid_online_response")


def integer(value: Any, minimum: int = 0) -> bool:
    return strict_int(value, minimum=minimum, maximum=MAX_INTEGER)


def identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def name(value: Any) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def require(value: Any, predicate: Any) -> Any:
    if not predicate(value):
        raise error(CONFIGURATION, "invalid_request")
    return value


def operation_id(value: str | None) -> str:
    if value is None:
        return secrets.token_urlsafe(24)
    return require(value, lambda v: isinstance(v, str) and re.fullmatch(r"[!-~]{16,128}", v) is not None)


def instant(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", value):
        invalid()
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.year < 1970:
            invalid()
        return result
    except ValueError:
        invalid()


def delivery_url(value: Any, protected: bool = False) -> str:
    """Validate raw authority before urlsplit can normalise it."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048 or not value.isascii()
            or not value.startswith("https://") or any(ord(c) <= 32 or ord(c) == 127 or c in '\\#<>"{}|^`' for c in value)
            or protected and "?" in value or re.search(r"%(?![0-9a-fA-F]{2})", value)):
        invalid()
    try:
        parsed = urlsplit(value)
        authority = parsed.netloc
        if not authority or any(c in authority for c in "@%") or not parsed.hostname:
            invalid()
        if authority.startswith("["):
            end = authority.index("]")
            IPv6Address(authority[1:end])
            suffix = authority[end + 1:]
            if suffix and not suffix.startswith(":"):
                invalid()
            port = suffix[1:] if suffix else None
        else:
            if any(c in authority for c in "[]") or authority.count(":") > 1:
                invalid()
            host, separator, port_text = authority.partition(":")
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                invalid()
            port = port_text if separator else None
        if port is not None and (not port.isdecimal() or not 1 <= int(port) <= 65535):
            invalid()
    except (ValueError, UnicodeError):
        invalid()
    return value


@dataclass(frozen=True)
class UpdateTarget:
    platform: str
    architecture: str


def update_input(installed: int, channel: str, target: UpdateTarget | None) -> dict[str, Any]:
    require(installed, integer)
    require(channel, lambda v: isinstance(v, str) and _TARGET.fullmatch(v))
    if target is None:
        os_name = {"win32": "windows", "darwin": "macos", "linux": "linux"}.get(sys.platform)
        arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64",
                "i386": "x86", "i686": "x86", "x86": "x86", "armv7l": "armv7"}.get(runtime_platform.machine().lower())
        if struct.calcsize("P") == 4:
            arch = "x86" if arch == "x64" else None if arch == "arm64" else arch
        if os_name is None or arch is None:
            raise error(CONFIGURATION, "explicit_update_target_required")
        target = UpdateTarget(os_name, arch)
    require(target, lambda v: isinstance(v, UpdateTarget))
    for value in (target.platform, target.architecture):
        require(value, lambda v: isinstance(v, str) and _TARGET.fullmatch(v))
    return dict(installed_release_number=installed, channel=channel, platform=target.platform, architecture=target.architecture)


@dataclass(frozen=True)
class Artifact:
    id: str
    release_id: str
    platform: str
    architecture: str
    filename: str
    byte_length: int
    sha256: str
    delivery_mode: str
    url: str = field(repr=False)
    required_feature: str | None = None


@dataclass(frozen=True)
class Release:
    id: str
    channel: str
    version: str
    notes: str
    release_number: int | None
    state: str
    created_at: datetime
    published_at: datetime | None
    artifacts: tuple[Artifact, ...]


@dataclass(frozen=True)
class Update:
    release: Release
    artifact: Artifact


@dataclass(frozen=True)
class DownloadAuthorization:
    artifact: Artifact
    ticket: str | None = field(repr=False)
    expires_at: datetime | None


def parse_artifact(value: Any) -> Artifact:
    v = fields(value, dict(id=str, release_id=str, platform=str, architecture=str, filename=str,
                         byte_length=int, sha256=str, delivery_mode=str, url=str, required_feature=(str, type(None))), exact=True)
    if (not identifier(v["id"]) or not identifier(v["release_id"])
            or not all(_TARGET.fullmatch(v[k]) for k in ("platform", "architecture"))
            or not text(v["filename"], minimum=1, maximum=255) or v["filename"] in (".", "..")
            or any(ord(c) < 32 or ord(c) == 127 or c in "/\\" for c in v["filename"])
            or not integer(v["byte_length"], 1) or re.fullmatch(r"[0-9a-f]{64}", v["sha256"]) is None
            or v["delivery_mode"] not in ("public", "protected")
            or v["required_feature"] is not None and not name(v["required_feature"])):
        invalid()
    delivery_url(v["url"], v["delivery_mode"] == "protected")
    return Artifact(**v)


def parse_release(value: Any) -> Release:
    v = fields(value, dict(id=str, channel=str, version=str, notes=str, release_number=(int, type(None)),
                         state=str, created_at=str, published_at=(str, type(None)), artifacts=list), exact=True)
    number, state = v["release_number"], v["state"]
    if (not identifier(v["id"]) or not _TARGET.fullmatch(v["channel"])
            or not text(v["version"], minimum=1, maximum=64) or not text(v["notes"], maximum=8192)
            or state not in ("draft", "published", "unpublished") or len(v["artifacts"]) > 32
            or number is not None and not integer(number, 1)
            or (state == "draft") != (number is None) or (number is None) != (v["published_at"] is None)):
        invalid()
    artifacts = tuple(parse_artifact(a) for a in v["artifacts"])
    if (any(a.release_id != v["id"] for a in artifacts)
            or len({a.id for a in artifacts}) != len(artifacts)
            or len({(a.platform, a.architecture) for a in artifacts}) != len(artifacts)
            or state == "published" and not artifacts):
        invalid()
    return Release(v["id"], v["channel"], v["version"], v["notes"], number, state,
                   instant(v["created_at"]), None if v["published_at"] is None else instant(v["published_at"]), artifacts)


def parse_update(value: Any, expected: dict[str, Any]) -> Update | None:
    v = fields(value, {"release": (dict, type(None)), "artifact": (dict, type(None))}, exact=True)
    if v["release"] is None and v["artifact"] is None:
        return None
    release, artifact = parse_release(v["release"]), parse_artifact(v["artifact"])
    if (release.state != "published" or release.channel != expected["channel"]
            or release.release_number <= expected["installed_release_number"]
            or artifact.platform != expected["platform"] or artifact.architecture != expected["architecture"]
            or release.artifacts != (artifact,)):
        invalid()
    return Update(release, artifact)


def parse_authorization(value: Any, release_id: str, artifact_id: str) -> DownloadAuthorization:
    v = fields(value, dict(artifact=dict, ticket=(str, type(None)), expires_at=(str, type(None))), exact=True)
    artifact = parse_artifact(v["artifact"])
    if artifact.id != artifact_id or artifact.release_id != release_id:
        invalid()
    if artifact.delivery_mode == "public":
        if v["ticket"] is not None or v["expires_at"] is not None:
            invalid()
        return DownloadAuthorization(artifact, None, None)
    ticket = v["ticket"]
    expiry = instant(v["expires_at"])
    now = datetime.now(timezone.utc)
    if (not isinstance(ticket, str) or len(ticket) > 16384
            or re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", ticket) is None
            or not now < expiry <= now + timedelta(seconds=150)):
        invalid()
    return DownloadAuthorization(artifact, ticket, expiry)


@dataclass(frozen=True)
class UsageLimit:
    limit: int
    period: str
    required_feature: str | None


@dataclass(frozen=True)
class ResourceLimit:
    limit: int
    required_feature: str | None


def parse_definitions(value: Any, usage: bool) -> Mapping[str, UsageLimit | ResourceLimit]:
    if not isinstance(value, dict) or len(value) > 32 or any(not name(k) for k in value):
        invalid()
    result = {}
    for key, item in value.items():
        expected = dict(limit=int, required_feature=(str, type(None)))
        if usage:
            expected["period"] = str
        fields(item, expected, exact=True)
        if (not integer(item["limit"]) or item["required_feature"] is not None and not name(item["required_feature"])
                or usage and item["period"] not in ("day", "month", "lifetime")):
            invalid()
        result[key] = UsageLimit(**item) if usage else ResourceLimit(**item)
    return MappingProxyType(result)


@dataclass(frozen=True)
class ResourceCounter:
    name: str
    limit: int
    used: int
    remaining: int


@dataclass(frozen=True)
class UsageCounter(ResourceCounter):
    period: str
    period_started_at: datetime | None
    resets_at: datetime | None


@dataclass(frozen=True)
class UsageConsumption(UsageCounter):
    idempotency_key: str
    consumed_units: int


@dataclass(frozen=True)
class ResourceAllocation(ResourceCounter):
    allocation_id: str
    resource_id: str
    units: int
    state: str
    idempotency_key: str


def parse_counter(value: Any, expected_name: str, usage: bool, *, extras: tuple[str, ...] = ()) -> UsageCounter | ResourceCounter:
    names = {"name", "limit", "used", "remaining"}
    if usage:
        names |= {"period", "period_started_at", "resets_at"}
    if not isinstance(value, dict) or value.keys() != names | set(extras):
        invalid()
    if (value["name"] != expected_name or not name(value["name"])
            or not all(integer(value[k]) for k in ("limit", "used", "remaining"))
            or value["used"] > value["limit"] or value["remaining"] != value["limit"] - value["used"]):
        invalid()
    basic = {k: value[k] for k in ("name", "limit", "used", "remaining")}
    if not usage:
        return ResourceCounter(**basic)
    period = value["period"]
    start, reset = value["period_started_at"], value["resets_at"]
    if period == "lifetime":
        if start is not None or reset is not None:
            invalid()
    elif period in ("day", "month"):
        start, reset = instant(start), instant(reset)
        if (start.hour or start.minute or start.second or start.microsecond
                or period == "day" and reset - start != timedelta(days=1)
                or period == "month" and (start.day != 1 or reset.day != 1 or reset.hour or reset.minute or reset.second
                    or reset.microsecond or not 28 <= (reset - start).days <= 31)):
            invalid()
    else:
        invalid()
    return UsageCounter(**basic, period=period, period_started_at=start, resets_at=reset)


def parse_consumption(value: Any, expected_name: str, key: str, units: int) -> UsageConsumption:
    counter = parse_counter(value, expected_name, True, extras=("idempotency_key", "consumed_units"))
    if value["idempotency_key"] != key or not integer(value["consumed_units"], 1) or value["consumed_units"] != units or counter.used < units:
        invalid()
    return UsageConsumption(**vars(counter), idempotency_key=key, consumed_units=units)


def parse_allocation(value: Any, expected_name: str, key: str, *, resource_id: str | None = None,
                     units: int | None = None, allocation_id: str | None = None) -> ResourceAllocation:
    counter = parse_counter(value, expected_name, False, extras=("allocation_id", "resource_id", "units", "state", "idempotency_key"))
    if (not identifier(value["allocation_id"]) or not identifier(value["resource_id"]) or not integer(value["units"], 1)
            or value["state"] not in ("active", "released") or value["idempotency_key"] != key
            or resource_id is not None and value["resource_id"] != resource_id or units is not None and value["units"] != units
            or allocation_id is not None and (value["allocation_id"] != allocation_id or value["state"] != "released")
            or value["state"] == "active" and value["units"] > counter.used):
        invalid()
    return ResourceAllocation(**vars(counter), **{k: value[k] for k in ("allocation_id", "resource_id", "units", "state", "idempotency_key")})


class LimitReachedError(OrbitError):
    """An authoritative capacity denial, validated against this operation."""

    def __init__(self, code: str, request_id: str, counter: UsageCounter | ResourceCounter, key: str, units: int):
        self.counter, self.idempotency_key, self.requested_units = counter, key, units
        super().__init__(DENIED, code, request_id, 409)


class MutationUncertainError(OrbitError):
    """Retry deliberately using idempotency_key; no local quota was changed."""

    def __init__(self, key: str, cause: OrbitError):
        self.idempotency_key = key
        super().__init__(cause.kind, cause.code, cause.request_id, cause.status)


def capacity_error(value: Any, route: str, request: dict[str, Any]) -> LimitReachedError:
    fields(value, dict(code=str, message=str, request_id=str, counter=dict, idempotency_key=str, requested_units=int), exact=True)
    usage = value["code"] == "usage_limit_reached"
    match = re.fullmatch(r"/api/client/v1/activations/[A-Za-z0-9_-]+/(usage|resources)/([a-z][a-z0-9_]{0,63})/(consume|acquire)", route)
    if (match is None or (match[1], match[3]) != (("usage", "consume") if usage else ("resources", "acquire"))
            or value["code"] not in ("usage_limit_reached", "resource_limit_reached")
            or value["idempotency_key"] != request.get("idempotency_key")
            or not integer(value["requested_units"], 1) or value["requested_units"] != request.get("units")):
        invalid()
    counter = parse_counter(value["counter"], match[2], usage)
    if value["requested_units"] <= counter.remaining:
        invalid()
    return LimitReachedError(value["code"], value["request_id"], counter, value["idempotency_key"], value["requested_units"])
