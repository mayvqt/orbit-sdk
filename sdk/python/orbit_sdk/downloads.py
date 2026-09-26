"""Verification for a seller's protected download endpoint; no file hosting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .app_key import AppKey
from .device import lower_hex, opaque
from .errors import CONFIGURATION, DENIED, OrbitError, error
from .grants import Keys, _canonical_b64
from .jsonutil import strict_int, unique_json
from .transport import _safe_origin

_MAX_BYTES = 16 * 1024
_MAX_TIME = 253_402_300_799
_CLAIMS = frozenset((
    "ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id",
    "environment_id", "release_id", "artifact_id", "sha256", "byte_length",
))


@dataclass(frozen=True, repr=False)
class DownloadTicket:
    licence_id: str
    release_id: str
    artifact_id: str
    sha256: str
    byte_length: int
    ticket_id: str
    issued_at: datetime
    expires_at: datetime

    def __repr__(self) -> str:
        return "DownloadTicket(<redacted>)"


class DownloadTicketVerifier:
    """Verify download capabilities with caller-configured scope and public keys.

    This class never follows token URLs or fetches keys. Match the verified
    artifact ID, digest and length against your own registry before delivery.
    """

    def __init__(self, app_key: str, endpoint: str, public_keys: Any) -> None:
        self._app = AppKey.parse(app_key)
        try:
            if (
                not isinstance(endpoint, str) or not 1 <= len(endpoint) <= 2048
                or not endpoint.isascii() or not endpoint.startswith("https://")
                or any(ord(char) <= 32 or ord(char) == 127 or char in "\\?#" for char in endpoint)
            ):
                raise ValueError("invalid endpoint")
            parsed = urlsplit(endpoint)
            _safe_origin(f"https://{parsed.netloc}")
            self._endpoint = endpoint
        except (OrbitError, ValueError, TypeError, UnicodeError) as exc:
            raise error(CONFIGURATION, "invalid_download_endpoint") from exc
        try:
            if isinstance(public_keys, (bytes, bytearray, str)):
                encoded = public_keys.encode("utf-8") if isinstance(public_keys, str) else public_keys
                if len(encoded) > _MAX_BYTES:
                    raise ValueError("oversized keys")
                public_keys = unique_json(encoded)
            elif len(json.dumps(public_keys, separators=(",", ":")).encode("utf-8")) > _MAX_BYTES:
                raise ValueError("oversized keys")
            if not isinstance(public_keys, dict) or public_keys.keys() != {"keys"}:
                raise ValueError("invalid keys")
            keys = Keys.parse(public_keys)
            prefix = f"{self._app.environment}-"
            if any(not opaque(kid) or not kid.startswith(prefix) or len(kid) == len(prefix) for kid in keys._entries):
                raise ValueError("invalid key purpose")
            self._keys = keys
        except (OrbitError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise error(CONFIGURATION, "invalid_download_keys") from exc

    def verify(self, token: str, *, now: datetime | None = None) -> DownloadTicket:
        """Return verified metadata; invalid or expired tickets raise OrbitError.

        ``now`` is an optional aware datetime for an application's trusted clock.
        Do not accept this value from an incoming download request.
        """
        try:
            current = datetime.now(timezone.utc) if now is None else now
            if not isinstance(current, datetime) or current.utcoffset() is None:
                raise ValueError("invalid clock")
            timestamp = current.timestamp()
            if not 0 <= timestamp <= _MAX_TIME:
                raise ValueError("invalid clock")
            return self._verify(token, timestamp)
        except (OrbitError, ValueError, TypeError, UnicodeError, InvalidSignature, OverflowError) as exc:
            raise error(DENIED, "invalid_download_ticket") from exc

    def _verify(self, token: str, now: float) -> DownloadTicket:
        if not isinstance(token, str) or not token.isascii() or not 1 <= len(token) <= _MAX_BYTES:
            raise ValueError("invalid token")
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid token")
        header_raw, payload, signature = (_canonical_b64(part) for part in parts)
        header = unique_json(header_raw)
        if (
            not isinstance(header, dict) or header.keys() != {"alg", "typ", "kid"}
            or header["alg"] != "ES256" or header["typ"] != "orbit-download+jwt"
            or not isinstance(header["kid"], str) or len(signature) != 64
        ):
            raise ValueError("invalid header")
        public = self._keys._entries.get(header["kid"])
        if public is None:
            raise ValueError("untrusted key")
        der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        public.verify(der, ".".join(parts[:2]).encode("ascii"), ec.ECDSA(hashes.SHA256()))
        claims = unique_json(payload)
        if not isinstance(claims, dict) or claims.keys() != _CLAIMS:
            raise ValueError("invalid claims")
        if (
            not strict_int(claims["ver"], minimum=1, maximum=1)
            or not all(strict_int(claims[name], minimum=0, maximum=_MAX_TIME) for name in ("iat", "nbf", "exp"))
            or not strict_int(claims["byte_length"], minimum=1, maximum=(1 << 53) - 1)
            or not lower_hex(claims["sha256"], 64)
            or not all(opaque(claims[name]) for name in ("sub", "jti", "application_id", "environment_id", "release_id", "artifact_id"))
            or claims["iss"] != self._app.issuer or claims["aud"] != self._endpoint
            or claims["application_id"] != self._app.application_id
            or claims["environment_id"] != self._app.environment_id
            or claims["nbf"] != claims["iat"] or claims["iat"] > now + 30
            or claims["exp"] <= now or not 0 < claims["exp"] - claims["iat"] <= 120
        ):
            raise ValueError("invalid claims")
        return DownloadTicket(
            claims["sub"], claims["release_id"], claims["artifact_id"], claims["sha256"],
            claims["byte_length"], claims["jti"], datetime.fromtimestamp(claims["iat"], timezone.utc),
            datetime.fromtimestamp(claims["exp"], timezone.utc),
        )
