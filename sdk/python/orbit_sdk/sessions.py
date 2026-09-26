"""Internal floating-session verification; acquisition and renewal are separate."""

from __future__ import annotations

from dataclasses import dataclass
import json
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .device import lower_hex, opaque, valid_provider
from .errors import INVALID_RESPONSE, OrbitError, error
from .grants import Expected as GrantExpected, Keys, _canonical_b64, _CLAIM_TYPES, valid_entitlements
from .jsonutil import fields, strict_int, text, unique_json

MAX_BYTES = 16 * 1024
MAX_SEQUENCE = (1 << 53) - 1
MAX_TIME = 253_402_300_799
_TYPES = _CLAIM_TYPES | {"session_id": str, "session_sequence": int}


def _invalid() -> None:
    raise error(INVALID_RESPONSE, "invalid_session_grant")


@dataclass(frozen=True)
class Expected:
    grant: GrantExpected
    session_id: str
    sequence: int


@dataclass(frozen=True, repr=False)
class SessionGrant:
    session_id: str
    sequence: int
    licence_id: str
    activation_id: str
    installation_id: str
    token_id: str
    issued_at: int
    expires_at: int
    refresh_after: int
    licence_expires_at: int | None
    policy_version: int
    entitlements: Mapping[str, bool]

    def __repr__(self) -> str:
        return "SessionGrant(<redacted>)"


class SessionKeys:
    def __init__(self, keys: Keys) -> None:
        self._keys = keys

    @classmethod
    def parse(cls, value: Any, environment: str) -> SessionKeys:
        try:
            if environment not in ("test", "live"):
                _invalid()
            if isinstance(value, (str, bytes, bytearray)):
                encoded = value.encode("utf-8") if isinstance(value, str) else value
                if len(encoded) > MAX_BYTES:
                    _invalid()
                value = unique_json(encoded)
            elif len(json.dumps(value, separators=(",", ":")).encode("utf-8")) > MAX_BYTES:
                _invalid()
            if not isinstance(value, dict) or value.keys() != {"keys"}:
                _invalid()
            keys = Keys.parse(value)
            prefix = f"{environment}-"
            if any(not opaque(kid) or not kid.startswith(prefix) or len(kid) == len(prefix) for kid in keys._entries):
                _invalid()
            return cls(keys)
        except (OrbitError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise error(INVALID_RESPONSE, "invalid_session_keys") from exc


def verify(token: str, keys: SessionKeys, expected: Expected) -> SessionGrant:
    try:
        return _verify(token, keys, expected)
    except (OrbitError, ValueError, TypeError, UnicodeError, InvalidSignature, OverflowError) as exc:
        raise error(INVALID_RESPONSE, "invalid_session_grant") from exc


def _verify(token: str, keys: SessionKeys, expected: Expected) -> SessionGrant:
    context = expected.grant
    if (
        not isinstance(token, str) or not token.isascii() or not 1 <= len(token) <= MAX_BYTES
        or not opaque(expected.session_id) or len(expected.session_id) < 16
        or not strict_int(expected.sequence, minimum=1, maximum=MAX_SEQUENCE)
        or not strict_int(context.now, minimum=0, maximum=MAX_TIME)
    ):
        _invalid()
    parts = token.split(".")
    if len(parts) != 3:
        _invalid()
    header_raw, payload, signature = (_canonical_b64(part) for part in parts)
    header = fields(unique_json(header_raw), {"alg": str, "typ": str, "kid": str}, exact=True)
    if header["alg"] != "ES256" or header["typ"] != "orbit-session+jwt" or len(signature) != 64:
        _invalid()
    public = keys._keys._entries.get(header["kid"])
    if public is None:
        _invalid()
    der = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    public.verify(der, ".".join(parts[:2]).encode("ascii"), ec.ECDSA(hashes.SHA256()))
    raw = unique_json(payload)
    if isinstance(raw, dict) and raw.get("binding_mode") == "none" and (
        "fingerprint" in raw or "fingerprint_provider" in raw
    ):
        _invalid()
    claims = fields(raw, _TYPES, optional=("fingerprint", "fingerprint_provider", "licence_expires_at"))
    if (
        not all(strict_int(claims[name], minimum=0, maximum=MAX_TIME) for name in ("iat", "nbf", "exp", "refresh_after"))
        or not strict_int(claims["policy_version"], minimum=1, maximum=(1 << 31) - 1)
        or not strict_int(claims["session_sequence"], minimum=1, maximum=MAX_SEQUENCE)
        or not opaque(claims["session_id"]) or len(claims["session_id"]) < 16
        or claims["session_id"] != expected.session_id or claims["session_sequence"] != expected.sequence
        or claims["offline_allowed"] is not False or not valid_entitlements(claims["entitlements"])
    ):
        _invalid()
    # Issuer and audience are compared to trusted scope below. A valid audience
    # can contain two 128-byte IDs, so neither inherits an individual ID's limit.
    for name in ("sub", "jti", "application_id", "environment_id", "activation_id", "installation_id"):
        if not text(claims[name], minimum=1, maximum=128):
            _invalid()
    licence_expiry = claims["licence_expires_at"]
    if licence_expiry is not None and not strict_int(licence_expiry, minimum=0, maximum=MAX_TIME):
        _invalid()
    bound = (
        claims["binding_mode"] == "none"
        and (context.fingerprint is None and context.fingerprint_provider is None
             or context.allow_unbound_fingerprint and context.fingerprint is not None and context.fingerprint_provider is not None)
    ) or (
        claims["binding_mode"] == "hwid"
        and lower_hex(claims["fingerprint"], 64) and isinstance(claims["fingerprint_provider"], str)
        and valid_provider(claims["fingerprint_provider"])
        and claims["fingerprint"] == context.fingerprint and claims["fingerprint_provider"] == context.fingerprint_provider
    )
    issued, expires, refresh = claims["iat"], claims["exp"], claims["refresh_after"]
    if (
        claims["iss"] != context.issuer or claims["aud"] != f"orbit-session:{context.application}:{context.environment}"
        or context.licence is not None and claims["sub"] != context.licence
        or claims["application_id"] != context.application or claims["environment_id"] != context.environment
        or claims["activation_id"] != context.activation or claims["installation_id"] != context.installation or not bound
        or claims["nbf"] != issued or issued > context.now + 30 or expires <= context.now or not 0 < expires - issued <= 120
        or context.credential_expires_at is not None and expires > context.credential_expires_at
        or licence_expiry != context.licence_expires_at or licence_expiry is not None and expires > licence_expiry
        or not issued < refresh <= expires or refresh > issued + 75 or refresh < issued + 45 and refresh != expires
    ):
        _invalid()
    return SessionGrant(
        claims["session_id"], claims["session_sequence"], claims["sub"], claims["activation_id"],
        claims["installation_id"], claims["jti"], issued, expires, refresh, licence_expiry,
        claims["policy_version"], MappingProxyType(dict(claims["entitlements"])),
    )
