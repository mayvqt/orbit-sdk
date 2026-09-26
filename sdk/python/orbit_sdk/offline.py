"""Strict offline-file verification. Installed import/persistence is separate."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .app_key import AppKey
from .device import lower_hex, opaque, valid_provider
from .errors import INVALID_RESPONSE, OrbitError, error
from .grants import Keys, _canonical_b64, valid_entitlements
from .jsonutil import strict_int, unique_json

MAX_FILE_BYTES = 16 * 1024
MAX_LIFETIME = 366 * 86_400
MAX_TIME = 253_402_300_799
MAX_SEQUENCE = (1 << 53) - 1
_REQUIRED = frozenset((
    "ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id",
    "environment_id", "activation_id", "installation_id", "sequence", "binding_mode",
    "policy_version", "entitlements",
))


@dataclass(frozen=True, repr=False)
class OfflineRequest:
    app_key: str
    installation_id: str
    fingerprint: str | None
    fingerprint_provider: str | None

    def to_json(self) -> str:
        return json.dumps({
            "format": "orbit-offline-request", "version": 1, "app_key": self.app_key,
            "installation_id": self.installation_id, "fingerprint": self.fingerprint,
            "fingerprint_provider": self.fingerprint_provider,
        }, separators=(",", ":"))

    def __repr__(self) -> str:
        return "OfflineRequest(<redacted>)"


def request(key: AppKey, installation_id: str, fingerprint: str | None, provider: str | None) -> OfflineRequest:
    origin = base64.urlsafe_b64encode(key.api_origin.encode("utf-8")).rstrip(b"=").decode("ascii")
    app_key = f"orbit_app_{key.environment}_{origin}.{key.application_id}.{key.environment_id}"
    return OfflineRequest(app_key, installation_id, fingerprint, provider)


def _invalid() -> None:
    raise error(INVALID_RESPONSE, "invalid_offline_file")


@dataclass(frozen=True)
class Expected:
    app_key: AppKey
    installation_id: str
    now: int
    fingerprint: str | None = None
    fingerprint_provider: str | None = None
    minimum_sequence: int = 1


@dataclass(frozen=True, repr=False)
class OfflineFile:
    token: str
    key_id: str
    licence_id: str
    activation_id: str
    installation_id: str
    issuance_id: str
    issued_at: int
    expires_at: int
    licence_expires_at: int | None
    sequence: int
    policy_version: int
    entitlements: Mapping[str, bool]
    content_digest: str

    def __repr__(self) -> str:
        return "OfflineFile(<redacted>)"


class OfflineKeys:
    def __init__(self, keys: Keys, environment: str) -> None:
        self._keys = keys
        self.environment = environment

    @classmethod
    def parse(cls, value: Any, environment: str) -> OfflineKeys:
        try:
            if environment not in ("test", "live"):
                _invalid()
            if isinstance(value, (bytes, bytearray, str)):
                value = unique_json(value)
            if not isinstance(value, dict) or value.keys() != {"keys"}:
                _invalid()
            keys = Keys.parse(value)
            prefix = f"offline-{environment}-"
            if any(not opaque(kid) or not kid.startswith(prefix) or len(kid) == len(prefix) for kid in keys._entries):
                _invalid()
            return cls(keys, environment)
        except (OrbitError, ValueError, TypeError, UnicodeError) as exc:
            raise error(INVALID_RESPONSE, "invalid_offline_keys") from exc


def verify(token: str | bytes, keys: OfflineKeys, expected: Expected) -> OfflineFile:
    try:
        return _verify(token, keys, expected)
    except (OrbitError, ValueError, TypeError, UnicodeError, InvalidSignature) as exc:
        raise error(INVALID_RESPONSE, "invalid_offline_file") from exc


def _verify(token: str | bytes, keys: OfflineKeys, expected: Expected) -> OfflineFile:
    if isinstance(token, bytes):
        token = token.decode("ascii", "strict")
    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_FILE_BYTES:
        _invalid()
    token = token.strip(" \t\r\n\v\f")
    parts = token.split(".")
    if len(parts) != 3:
        _invalid()
    header_raw, payload, signature = (_canonical_b64(part) for part in parts)
    header = unique_json(header_raw)
    if (
        not isinstance(header, dict) or header.keys() != {"alg", "typ", "kid"}
        or header["alg"] != "ES256" or header["typ"] != "orbit-offline+jwt"
        or not isinstance(header["kid"], str)
        or not header["kid"].startswith(f"offline-{expected.app_key.environment}-")
        or len(signature) != 64 or keys.environment != expected.app_key.environment
    ):
        _invalid()
    public = keys._keys._entries.get(header["kid"])
    if public is None:
        _invalid()
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    public.verify(der, ".".join(parts[:2]).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    claims = unique_json(payload)
    if not isinstance(claims, dict):
        _invalid()
    names = _REQUIRED | ({"licence_expires_at"} if "licence_expires_at" in claims else set())
    if claims.get("binding_mode") == "hwid":
        names = names | {"fingerprint", "fingerprint_provider"}
    if claims.keys() != names:
        _invalid()
    if not strict_int(expected.now, minimum=0, maximum=MAX_TIME) or not strict_int(expected.minimum_sequence, minimum=1, maximum=MAX_SEQUENCE):
        _invalid()
    if not all(strict_int(claims[name], minimum=0, maximum=MAX_TIME) for name in ("iat", "nbf", "exp")):
        _invalid()
    if (
        not strict_int(claims["ver"], minimum=1, maximum=1)
        or not strict_int(claims["sequence"], minimum=expected.minimum_sequence, maximum=MAX_SEQUENCE)
        or not strict_int(claims["policy_version"], minimum=1, maximum=(1 << 31) - 1)
        or not valid_entitlements(claims["entitlements"])
        or not all(opaque(claims[name]) for name in ("sub", "jti", "application_id", "environment_id", "activation_id", "installation_id"))
        or not 16 <= len(claims["installation_id"]) <= 128
    ):
        _invalid()
    expiry = claims.get("licence_expires_at")
    if "licence_expires_at" in claims and not strict_int(expiry, minimum=claims["exp"], maximum=MAX_TIME):
        _invalid()
    if (
        claims["iss"] != expected.app_key.issuer
        or claims["aud"] != f"orbit-offline:{expected.app_key.application_id}:{expected.app_key.environment_id}"
        or claims["application_id"] != expected.app_key.application_id
        or claims["environment_id"] != expected.app_key.environment_id
        or claims["installation_id"] != expected.installation_id
        or claims["nbf"] != claims["iat"] or claims["iat"] > expected.now + 30
        or claims["exp"] <= expected.now or not 0 < claims["exp"] - claims["iat"] <= MAX_LIFETIME
    ):
        _invalid()
    if claims["binding_mode"] == "hwid":
        if (
            not lower_hex(claims["fingerprint"], 64)
            or not isinstance(claims["fingerprint_provider"], str)
            or not valid_provider(claims["fingerprint_provider"])
            or claims["fingerprint"] != expected.fingerprint
            or claims["fingerprint_provider"] != expected.fingerprint_provider
        ):
            _invalid()
    elif claims["binding_mode"] != "none":
        _invalid()
    canonical = json.dumps(claims, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return OfflineFile(
        token, header["kid"], claims["sub"], claims["activation_id"], claims["installation_id"],
        claims["jti"], claims["iat"], claims["exp"], expiry, claims["sequence"], claims["policy_version"],
        MappingProxyType(dict(claims["entitlements"])), hashlib.sha256(canonical).hexdigest(),
    )
