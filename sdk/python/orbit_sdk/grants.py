from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .errors import INVALID_RESPONSE, error
from .jsonutil import fields, strict_int, text, unique_json

_CLAIM_TYPES: dict[str, Any] = {
    "iss": str,
    "aud": str,
    "sub": str,
    "jti": str,
    "iat": int,
    "nbf": int,
    "exp": int,
    "application_id": str,
    "environment_id": str,
    "activation_id": str,
    "installation_id": str,
    "binding_mode": str,
    "fingerprint": (str, type(None)),
    "fingerprint_provider": (str, type(None)),
    "policy_version": int,
    "entitlements": dict,
    "refresh_after": int,
    "offline_allowed": bool,
    "licence_expires_at": (int, type(None)),
}
_TOKEN_SEGMENTS = re.compile(r"^[A-Za-z0-9_-]+$")


def _invalid() -> None:
    raise error(INVALID_RESPONSE, "invalid_grant")


def _canonical_b64(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or not _TOKEN_SEGMENTS.fullmatch(value):
        _invalid()
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise error(INVALID_RESPONSE, "invalid_grant") from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        _invalid()
    return decoded


def parse_header(token: str) -> tuple[dict[str, str], bytes, bytes, bytes]:
    if not isinstance(token, str) or len(token.encode("utf-8", "strict")) > 16384 or not token.isascii():
        _invalid()
    parts = token.split(".")
    if len(parts) != 3:
        _invalid()
    header_bytes, payload_bytes, signature = (_canonical_b64(part) for part in parts)
    if len(signature) != 64:
        _invalid()
    header = fields(unique_json(header_bytes), {"alg": str, "typ": str, "kid": str}, exact=True)
    if header["alg"] != "ES256" or header["typ"] != "orbit-access+jwt" or not text(header["kid"], minimum=1, maximum=128, ascii_only=True):
        _invalid()
    return header, header_bytes, payload_bytes, signature


class Keys:
    """A bounded set of validated P-256 verification keys."""

    def __init__(self, entries: dict[str, ec.EllipticCurvePublicKey]) -> None:
        self._entries = entries

    @classmethod
    def parse(cls, value: Any) -> Keys:
        if isinstance(value, (bytes, bytearray, str)):
            value = unique_json(value)
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list) or not 1 <= len(value["keys"]) <= 8:
            _invalid()
        entries: dict[str, ec.EllipticCurvePublicKey] = {}
        for raw in value["keys"]:
            item = fields(raw, {"kty": str, "crv": str, "alg": str, "use": str, "kid": str, "x": str, "y": str}, exact=True)
            if item["kty"] != "EC" or item["crv"] != "P-256" or item["alg"] != "ES256" or item["use"] != "sig":
                _invalid()
            kid = item["kid"]
            if not text(kid, minimum=1, maximum=128, ascii_only=True) or kid in entries:
                _invalid()
            x, y = _canonical_b64(item["x"]), _canonical_b64(item["y"])
            if len(x) != 32 or len(y) != 32:
                _invalid()
            try:
                public = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
            except ValueError as exc:
                raise error(INVALID_RESPONSE, "invalid_jwks") from exc
            entries[kid] = public
        return cls(entries)

    def contains(self, token: str) -> bool:
        header, *_ = parse_header(token)
        return header["kid"] in self._entries


@dataclass(frozen=True)
class Expected:
    issuer: str
    application: str
    environment: str
    licence: str | None
    activation: str
    installation: str
    fingerprint: str | None
    fingerprint_provider: str | None
    credential_expires_at: int
    licence_expires_at: int | None
    now: int


def valid_entitlements(value: Any) -> bool:
    if not isinstance(value, dict) or len(value) > 64:
        return False
    for name, enabled in value.items():
        if not text(name, minimum=1, maximum=64, ascii_only=True) or name[0] not in "abcdefghijklmnopqrstuvwxyz":
            return False
        if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in name) or not isinstance(enabled, bool):
            return False
    return True


def verify(token: str, keys: Keys, expected: Expected) -> dict[str, Any]:
    header, header_bytes, payload, signature = parse_header(token)
    public = keys._entries.get(header["kid"])
    if public is None:
        _invalid()
    claims = fields(
        unique_json(payload),
        _CLAIM_TYPES,
        optional=("fingerprint", "fingerprint_provider", "licence_expires_at"),
    )
    if any(not strict_int(claims[name]) for name in ("iat", "nbf", "exp", "refresh_after", "policy_version")):
        _invalid()
    if claims["policy_version"] > (1 << 31) - 1 or claims["policy_version"] < 1:
        _invalid()
    if claims["licence_expires_at"] is not None and not strict_int(claims["licence_expires_at"]):
        _invalid()
    if not valid_entitlements(claims["entitlements"]):
        _invalid()
    for name in ("iss", "aud", "sub", "jti", "application_id", "environment_id", "activation_id", "installation_id", "binding_mode"):
        if not text(claims[name], maximum=128):
            _invalid()
    for name in ("fingerprint", "fingerprint_provider"):
        if claims[name] is not None and not text(claims[name], maximum=128):
            _invalid()
    signing_input = token.rsplit(".", 1)[0].encode("ascii")
    der_signature = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        public.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise error(INVALID_RESPONSE, "invalid_grant") from exc
    except (ValueError, TypeError) as exc:
        raise error(INVALID_RESPONSE, "invalid_grant") from exc
    audience = f"orbit:{expected.application}:{expected.environment}"
    bound = (
        claims["binding_mode"] == "none"
        and claims["fingerprint"] is None
        and claims["fingerprint_provider"] is None
        and expected.fingerprint is None
        and expected.fingerprint_provider is None
    ) or (
        claims["binding_mode"] == "hwid"
        and claims["fingerprint"] == expected.fingerprint
        and claims["fingerprint_provider"] == expected.fingerprint_provider
        and expected.fingerprint is not None
        and expected.fingerprint_provider is not None
    )
    allowance = 86400 if claims["offline_allowed"] else 300
    iat, nbf, exp = claims["iat"], claims["nbf"], claims["exp"]
    sat_add = lambda left, right: max(-(1 << 63), min((1 << 63) - 1, left + right))
    if (
        claims["iss"] != expected.issuer
        or claims["aud"] != audience
        or not claims["sub"] or len(claims["sub"].encode()) > 128
        or expected.licence is not None and claims["sub"] != expected.licence
        or not claims["jti"] or len(claims["jti"].encode()) > 128
        or claims["application_id"] != expected.application
        or claims["environment_id"] != expected.environment
        or claims["activation_id"] != expected.activation
        or claims["installation_id"] != expected.installation
        or not bound
        or iat < 0 or nbf != iat
        or iat > sat_add(expected.now, 30) or iat < sat_add(expected.now, -30)
        or exp <= expected.now or exp <= iat or exp > sat_add(iat, allowance)
        or exp > expected.credential_expires_at
        or claims["licence_expires_at"] != expected.licence_expires_at
        or claims["licence_expires_at"] is not None and exp > claims["licence_expires_at"]
        or claims["refresh_after"] <= iat or claims["refresh_after"] > exp
        or claims["refresh_after"] > sat_add(iat, 75)
        or claims["refresh_after"] < sat_add(iat, 45) and claims["refresh_after"] != exp
    ):
        _invalid()
    return claims
