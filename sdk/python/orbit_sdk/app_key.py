from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from .device import opaque
from .errors import CONFIGURATION, OrbitError, error
from .transport import _safe_origin

MAX_KEY_LENGTH = 512
_B64_URLSAFE_NOPAD = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_PREFIXES = {"orbit_app_test_": "test", "orbit_app_live_": "live"}


@dataclass(frozen=True)
class AppKey:
    """A parsed public Orbit app key from the Integration page.

    Not a secret: it only names the API origin, application and environment.
    """

    api_origin: str
    application_id: str
    environment_id: str
    environment: str

    @property
    def issuer(self) -> str:
        return self.api_origin

    def validate(self) -> AppKey:
        """Recheck directly constructed instances before they establish trust."""
        if (
            self.environment not in ("test", "live")
            or not opaque(self.application_id)
            or not opaque(self.environment_id)
        ):
            raise error(CONFIGURATION, "invalid_app_key")
        if not isinstance(self.api_origin, str):
            raise error(CONFIGURATION, "invalid_app_key")
        try:
            encoded = base64.urlsafe_b64encode(self.api_origin.encode("utf-8", "strict")).rstrip(b"=").decode("ascii")
        except UnicodeError as exc:
            raise error(CONFIGURATION, "invalid_app_key") from exc
        parsed = AppKey.parse(
            f"orbit_app_{self.environment}_{encoded}.{self.application_id}.{self.environment_id}"
        )
        if parsed.api_origin != self.api_origin:
            raise error(CONFIGURATION, "invalid_app_key")
        return self

    @classmethod
    def parse(cls, value: str) -> AppKey:
        if not isinstance(value, str):
            raise TypeError("app key must be a string")
        trimmed = value.strip()
        if not trimmed or len(trimmed) > MAX_KEY_LENGTH:
            raise error(CONFIGURATION, "invalid_app_key")
        environment = None
        rest = ""
        for prefix, name in _PREFIXES.items():
            if trimmed.startswith(prefix):
                environment, rest = name, trimmed[len(prefix) :]
                break
        if environment is None:
            raise error(CONFIGURATION, "invalid_app_key")
        parts = rest.split(".")
        if len(parts) != 3:
            raise error(CONFIGURATION, "invalid_app_key")
        origin_b64, application_id, environment_id = parts
        api_origin = _decode_origin(origin_b64)
        if not opaque(application_id) or not opaque(environment_id):
            raise error(CONFIGURATION, "invalid_app_key")
        return AppKey(api_origin, application_id, environment_id, environment)

    def __repr__(self) -> str:
        return (
            f"AppKey(api_origin={self.api_origin!r}, application_id={self.application_id!r}, "
            f"environment_id={self.environment_id!r}, environment={self.environment!r})"
        )


def _decode_origin(origin_b64: str) -> str:
    if not origin_b64 or any(char not in _B64_URLSAFE_NOPAD for char in origin_b64):
        raise error(CONFIGURATION, "invalid_app_key")
    padding = "=" * (-len(origin_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(origin_b64 + padding)
    except binascii.Error as exc:
        raise error(CONFIGURATION, "invalid_app_key") from exc
    # Reject non-canonical encodings (e.g. stray set bits in trailing padding
    # bits) by requiring the decode to round-trip back to the same text.
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != origin_b64:
        raise error(CONFIGURATION, "invalid_app_key")
    try:
        origin = decoded.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise error(CONFIGURATION, "invalid_app_key") from exc
    try:
        _safe_origin(origin)
    except OrbitError as exc:
        raise error(CONFIGURATION, "invalid_app_key") from exc
    if origin.endswith("/"):
        raise error(CONFIGURATION, "invalid_app_key")
    return origin
