from __future__ import annotations

import base64
import datetime as dt
import json
import time
from pathlib import Path
from threading import Event, Lock
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from orbit_sdk import Config
from orbit_sdk.errors import CANCELLED, error

ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = ROOT / "contracts" / "sdk" / "grants.json"
PRIVATE_KEY_PATH = ROOT / "sdk" / "rust" / "tests" / "fixtures" / "es256-test-private.pem"


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def fixture_data() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text())


def sign_grant(
    config: Config,
    *,
    activation_id: str = "activation",
    licence_id: str = "licence",
    offline: bool = False,
    server_time: int | None = None,
    credential_expires_at: int | None = None,
) -> tuple[str, int, int]:
    now = int(time.time()) if server_time is None else server_time
    credential_expiry = now + 3600 if credential_expires_at is None else credential_expires_at
    claims: dict[str, Any] = {
        "iss": config.issuer,
        "aud": f"orbit:{config.application_id}:{config.environment_id}",
        "sub": licence_id,
        "jti": "synthetic-jti",
        "iat": now,
        "nbf": now,
        "exp": now + (3600 if offline else 300),
        "application_id": config.application_id,
        "environment_id": config.environment_id,
        "activation_id": activation_id,
        "installation_id": config.installation_id,
        "binding_mode": "hwid" if config.fingerprint else "none",
        "policy_version": 1,
        "entitlements": {"export": True, "sync": False},
        "refresh_after": now + 60,
        "offline_allowed": offline,
        "licence_expires_at": None,
    }
    if config.fingerprint:
        claims["fingerprint"] = config.fingerprint
        claims["fingerprint_provider"] = config.fingerprint_provider
    header = {"alg": "ES256", "typ": "orbit-access+jwt", "kid": "test-key"}
    signing_input = f"{b64url(json_bytes(header))}.{b64url(json_bytes(claims))}"
    private = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    assert isinstance(private, ec.EllipticCurvePrivateKey)
    der = private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input + "." + b64url(signature), now, credential_expiry


def activation_reply(config: Config, *, account: bool = False, offline: bool = False, previous: bool = False, credential_expiry: int | None = None) -> bytes:
    licence = "licence" if account else "licence"
    token, server_time, expiry = sign_grant(config, licence_id=licence, offline=offline, credential_expires_at=credential_expiry)
    instant = dt.datetime.fromtimestamp(server_time, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expiry_text = dt.datetime.fromtimestamp(expiry, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    body = {
        "activation_id": "activation",
        "installation_id": config.installation_id,
        "credential": None if previous else "a" * 43,
        "credential_expires_at": expiry_text,
        "grant": token,
        "server_time": instant,
        "binding_mode": "hwid" if config.fingerprint else "none",
        "fingerprint_provider": config.fingerprint_provider or None,
        "licence_expires_at": None,
        "secret_replay_expired": False,
    }
    return json_bytes(body)


class FakeTransport:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.jwks = json_bytes(fixture_data()["jwks"])
        self.requests: list[tuple[str, str, Any, bool]] = []
        self.lock = Lock()
        self.block_route: str | None = None
        self.entered = Event()
        self.release = Event()
        self.post_overrides: dict[str, Any] = {}
        self.get_overrides: dict[str, Any] = {}
        self.last_credential_expiry: int | None = None

    def post(self, route: str, body: dict[str, Any], retry_safe: bool, cancel: Any = None) -> bytes | None:
        with self.lock:
            self.requests.append(("POST", route, body, retry_safe))
        if self.block_route == route:
            self.entered.set()
            self.release.wait(5)
        if cancel is not None and cancel.is_set():
            raise error(CANCELLED, "operation_cancelled")
        override = self.post_overrides.get(route)
        if override is not None:
            if isinstance(override, BaseException):
                raise override
            return override(route, body) if callable(override) else override
        if route == "/api/client/v1/activations":
            reply = activation_reply(self.config, account="licence_id" in body)
            parsed = json.loads(reply)
            self.last_credential_expiry = int(dt.datetime.fromisoformat(parsed["credential_expires_at"].replace("Z", "+00:00")).timestamp())
            return reply
        if route.endswith("/validate"):
            expiry = self.last_credential_expiry or int(time.time()) + 3600
            return activation_reply(self.config, previous=True, credential_expiry=expiry)
        if route == "/api/client/v1/sessions":
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            return json_bytes({
                "customer": {"id": "customer", "username": body["username"], "email": "alice@example.test", "suspended": False, "created_at": now.isoformat().replace("+00:00", "Z")},
                "session": "s" * 43,
                "expires_at": (now + dt.timedelta(hours=12)).isoformat().replace("+00:00", "Z"),
            })
        if route == "/api/client/v1/registrations":
            expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).replace(microsecond=0)
            return json_bytes({"accepted": True, "expires_at": expiry.isoformat().replace("+00:00", "Z"), "resend_credential": "r" * 43})
        if route in ("/api/client/v1/registrations/resend", "/api/client/v1/email-changes", "/api/client/v1/password-recovery"):
            return json_bytes({"accepted": True})
        if route == "/api/client/v1/licence-claims":
            return json_bytes(licence_value())
        if route.endswith("/deactivate"):
            return None
        raise AssertionError(f"unexpected test route {route}")

    def get(self, route: str, cancel: Any = None) -> bytes:
        with self.lock:
            self.requests.append(("GET", route, None, True))
        override = self.get_overrides.get(route)
        if override is not None:
            if isinstance(override, BaseException):
                raise override
            return override(route) if callable(override) else override
        if route.startswith("/.well-known/orbit-jwks.json?"):
            return self.jwks
        raise AssertionError(f"unexpected test route {route}")

    def get_bearer(self, route: str, token: str, cancel: Any = None) -> bytes:
        with self.lock:
            self.requests.append(("GET", route, {"Authorization": "Bearer " + token}, True))
        return json_bytes({"items": [licence_value()], "next_cursor": None})

    def delete_bearer(self, route: str, token: str, cancel: Any = None) -> None:
        with self.lock:
            self.requests.append(("DELETE", route, {"Authorization": "Bearer " + token}, False))


def licence_value() -> dict[str, Any]:
    return {
        "id": "licence",
        "policy_name": "Desktop",
        "state": "active",
        "expiry_mode": "never",
        "first_used_at": None,
        "expires_at": None,
        "duration_seconds": None,
        "device_limit": 2,
        "hwid_locked": False,
        "offline_allowed": True,
        "offline_seconds": 900,
        "entitlements": {"export": True},
    }
