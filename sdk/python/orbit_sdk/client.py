from __future__ import annotations

import json
import hashlib
import os
import random
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterator

from .clock import Anchor, Start, elapsed_ns, timestamp, wall_seconds
from .device import installation_id_new, lower_hex, opaque, valid_provider
from .errors import (
    CANCELLED,
    CLOCK_UNCERTAIN,
    CONFIGURATION,
    DENIED,
    INVALID_RESPONSE,
    REAUTHENTICATION_REQUIRED,
    STALE_RESPONSE,
    STORAGE,
    TRANSIENT,
    OrbitError,
    error,
)
from .grants import Expected, Keys, verify
from .jsonutil import fields, strict_int, text, unique_json
from .storage import MemoryStorage, StoredCredential, WindowsStorage, SecretServiceStorage, valid_credential
from .persistent_storage import AccessState, InstallationStorage, PendingActivation, canonical_scope
from .transport import CLIENT_PREFIX, JWKS_PATH, Transport, _safe_origin


class StorageMode(str, Enum):
    MEMORY = "memory"
    WINDOWS_DPAPI = "windows_dpapi"
    LINUX_SECRET_SERVICE = "linux_secret_service"


@dataclass(frozen=True)
class Config:
    """Public runtime settings for ``Client.connect``."""

    api_origin: str
    application_id: str
    environment_id: str
    issuer: str
    installation_id: str
    fingerprint: str = ""
    fingerprint_provider: str = ""
    storage_mode: StorageMode | str = StorageMode.MEMORY
    storage_path: str | os.PathLike[str] = ""

    def __post_init__(self) -> None:
        try:
            mode = StorageMode(self.storage_mode)
        except ValueError as exc:
            raise ValueError("storage_mode must be a supported StorageMode") from exc
        object.__setattr__(self, "storage_mode", mode)
        try:
            path = os.fspath(self.storage_path)
        except TypeError as exc:
            raise TypeError("storage_path must be a text path") from exc
        if not isinstance(path, str):
            raise TypeError("storage_path must be a text path")
        object.__setattr__(self, "storage_path", path)
        if mode is StorageMode.MEMORY:
            if path:
                raise ValueError("memory storage does not use storage_path")
        elif not path or not os.path.isabs(path) or not os.path.isdir(path):
            raise ValueError("protected storage needs an existing absolute directory")
        elif mode is StorageMode.WINDOWS_DPAPI and os.name != "nt":
            raise ValueError("Windows DPAPI storage is available only on Windows")
        elif mode is StorageMode.LINUX_SECRET_SERVICE and not sys_platform_linux():
            raise ValueError("Linux Secret Service storage is available only on Linux")


@dataclass(frozen=True)
class AppConfig:
    """Public trusted scope for the persistent ``Client.open`` convenience."""

    api_origin: str
    application_id: str
    environment_id: str
    issuer: str
    fingerprint: str | None = None
    fingerprint_provider: str | None = None


@dataclass(frozen=True)
class RegistrationResult:
    accepted: bool
    expires_at: str | None
    pending: PendingRegistration


class _CombinedCancellation:
    def __init__(self, lifecycle: threading.Event, caller: threading.Event) -> None:
        self.lifecycle, self.caller = lifecycle, caller

    def is_set(self) -> bool:
        return self.lifecycle.is_set() or self.caller.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = 0.05 if deadline is None else min(0.05, deadline - time.monotonic())
            if remaining <= 0:
                return self.is_set()
            self.lifecycle.wait(remaining)
        return True


class Cancellation:
    """A shareable cancellation signal for an operation in progress."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._event = threading.Event()
        self._active = 0
        self._closed = False

    @classmethod
    def create(cls) -> Cancellation:
        return cls()

    @contextmanager
    def _borrow(self) -> Iterator[threading.Event]:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit cancellation handle is closed")
            self._active += 1
        try:
            yield self._event
        finally:
            with self._condition:
                self._active -= 1
                if not self._active:
                    self._condition.notify_all()

    def cancel(self) -> None:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit cancellation handle is closed")
            self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            while self._active:
                self._condition.wait()

    def __enter__(self) -> Cancellation:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit cancellation handle is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "Cancellation(<opaque>)"

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class PendingRegistration:
    """Opaque in-memory resend proof returned by ``Client.register``."""

    def __init__(self, credential: str, owner: Client) -> None:
        self._condition = threading.Condition()
        self._credential = bytearray(credential.encode("ascii"))
        self._owner = owner
        self._active = 0
        self._closed = False
        self._application_id = owner.config.application_id
        self._environment_id = owner.config.environment_id

    @contextmanager
    def _borrow(self) -> Iterator[str]:
        with self._condition:
            if self._closed:
                raise RuntimeError("pending registration handle is closed")
            self._active += 1
            value = self._credential.decode("ascii")
        try:
            yield value
        finally:
            with self._condition:
                self._active -= 1
                if not self._active:
                    self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            while self._active:
                self._condition.wait()
            for index in range(len(self._credential)):
                self._credential[index] = 0
            self._credential.clear()

    def __enter__(self) -> PendingRegistration:
        with self._condition:
            if self._closed:
                raise RuntimeError("pending registration handle is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "PendingRegistration(<opaque>)"

    def __str__(self) -> str:
        return "<redacted pending registration>"

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class SensitiveAuthorization:
    """A redacted, clearable customer Authorization header."""

    __slots__ = ("_value",)

    def __init__(self, value: bytearray) -> None:
        self._value = value

    def reveal(self) -> bytes:
        if not self._value:
            raise RuntimeError("authorization value has been cleared")
        return bytes(self._value)

    def clear(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0
        self._value.clear()

    def __enter__(self) -> SensitiveAuthorization:
        if not self._value:
            raise RuntimeError("authorization value has been cleared")
        return self

    def __exit__(self, *_: object) -> None:
        self.clear()

    def __repr__(self) -> str:
        return "SensitiveAuthorization(<redacted>)"

    def __str__(self) -> str:
        return "<redacted customer authorization>"

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:
            pass


@dataclass(frozen=True)
class _AccountSession:
    token: str
    metadata: dict[str, Any]


class Client:
    """Synchronous Orbit client. Use ``with Client.open(...)`` or ``connect``."""

    def __init__(self, config: Config, transport: Any, storage: Any, *, persistent: bool = False) -> None:
        self.config = config
        self.transport = transport
        self._storage = storage
        self._persistent_storage = storage if persistent and isinstance(storage, InstallationStorage) else None
        self._persistent = self._persistent_storage is not None
        version, credential = storage.load()
        if credential is not None and not valid_credential(credential, config, self._device(config)):
            raise error(STORAGE, "storage_failed")
        self._state_lock = threading.RLock()
        self._condition = threading.Condition()
        self._serial = threading.Lock()
        self._active = 0
        self._closed = False
        self._generation = 0
        self._storage_version = version
        self._credential = credential
        self._claims: dict[str, Any] | None = None
        self._anchor: Anchor | None = None
        self._transient = False
        self._retry_deadline: float | None = None
        self._account: _AccountSession | None = None
        self._device_value = self._device(config)
        self._keys: Keys | None = None
        self._keys_lock = threading.Lock()
        self._persisted_access: AccessState | None = None
        self._lifecycle_condition = threading.Condition()
        self._lifecycle_stop = threading.Event()
        self._lifecycle_thread: threading.Thread | None = None
        self._close_deferred = False
        self._last_checkpoint_elapsed = elapsed_ns() if self._persistent else 0
        if self._persistent_storage is not None:
            self._restore_cached_access()

    @staticmethod
    def _device(config: Config) -> _Device:
        return _Device(
            config.installation_id,
            config.fingerprint or None,
            config.fingerprint_provider or None,
        )

    @classmethod
    def connect(cls, config: Config) -> Client:
        if not isinstance(config, Config):
            raise TypeError("config must be an orbit_sdk.Config")
        _validate_config(config)
        transport = Transport(config.api_origin)
        device = cls._device(config)
        if config.storage_mode is StorageMode.MEMORY:
            storage = MemoryStorage()
        elif config.storage_mode is StorageMode.WINDOWS_DPAPI:
            storage = WindowsStorage.open(config.storage_path, config, device)
        elif config.storage_mode is StorageMode.LINUX_SECRET_SERVICE:
            storage = SecretServiceStorage.open(config.storage_path, config, device)
        else:
            raise error(CONFIGURATION, "unsupported_storage")
        return cls(config, transport, storage)

    @classmethod
    def open(cls, config: AppConfig, state_path: str | os.PathLike[str] | None = None) -> Client:
        """Open a stable installation with private credential and grant storage."""
        return cls._open_app(config, state_path, transport=None, start_worker=True)

    @classmethod
    def _open_for_test(
        cls,
        config: AppConfig,
        state_path: str | os.PathLike[str],
        transport: Any,
        *,
        start_worker: bool = False,
    ) -> Client:
        """Private injection point for persistent lifecycle and storage tests."""
        return cls._open_app(config, state_path, transport=transport, start_worker=start_worker)

    @classmethod
    def _open_app(
        cls,
        app_config: AppConfig,
        state_path: str | os.PathLike[str] | None,
        *,
        transport: Any | None,
        start_worker: bool,
    ) -> Client:
        if not isinstance(app_config, AppConfig):
            raise TypeError("config must be an orbit_sdk.AppConfig")
        _validate_app_config(app_config)
        # Validate the complete trusted origin before creating private state.
        live_transport = transport if transport is not None else Transport(app_config.api_origin)
        storage = InstallationStorage.open(state_path, app_config)
        client = None
        try:
            config = Config(
                api_origin=app_config.api_origin,
                application_id=app_config.application_id,
                environment_id=app_config.environment_id,
                issuer=app_config.issuer,
                installation_id=storage.installation_id,
                fingerprint=app_config.fingerprint or "",
                fingerprint_provider=app_config.fingerprint_provider or "",
            )
            _validate_config(config)
            client = cls(config, live_transport, storage, persistent=True)
            if storage.pending_activation is None:
                try:
                    client._refresh(None, respect_retry=False)
                except OrbitError as exc:
                    if exc.kind not in (TRANSIENT, REAUTHENTICATION_REQUIRED):
                        raise
            client._checkpoint_persistent_cache(force=True)
            if start_worker:
                client._start_lifecycle()
            return client
        except BaseException:
            if client is not None:
                client.close()
            else:
                storage.close()
            raise

    @classmethod
    def _for_test(cls, config: Config, transport: Any, storage: Any | None = None) -> Client:
        """Private deterministic dependency injection for the SDK test suite."""
        _validate_config(config)
        return cls(config, transport, storage if storage is not None else MemoryStorage())

    def _restore_cached_access(self) -> None:
        assert self._persistent_storage is not None
        access = self._persistent_storage.access
        if access is None:
            return
        try:
            wall = wall_seconds()
            if (
                wall < access.wall_high_water
                or access.server_high_water < access.received_server_time
                or access.wall_high_water < access.received_wall_time
                or abs((access.server_high_water - access.received_server_time) -
                       (access.wall_high_water - access.received_wall_time)) > 30
            ):
                raise error(CLOCK_UNCERTAIN, "clock_uncertain")
            estimated = max(access.server_high_water, access.received_server_time + wall - access.received_wall_time)
            if not 0 <= estimated <= (1 << 63) - 1:
                raise error(CLOCK_UNCERTAIN, "clock_uncertain")
            keys = Keys.parse(access.jwks)
            if len(keys._entries) != 1:
                raise error(INVALID_RESPONSE, "invalid_jwks")
            credential = self._credential
            if credential is None:
                raise error(INVALID_RESPONSE, "invalid_grant")
            expected = Expected(
                issuer=self.config.issuer,
                application=self.config.application_id,
                environment=self.config.environment_id,
                licence=credential.licence_id,
                activation=credential.activation_id,
                installation=self.config.installation_id,
                fingerprint=self.config.fingerprint or None,
                fingerprint_provider=self.config.fingerprint_provider or None,
                credential_expires_at=credential.credential_expires_at,
                licence_expires_at=access.licence_expires_at,
                now=access.received_server_time,
            )
            claims = verify(access.jws, keys, expected)
            if (
                claims["exp"] <= estimated
                or credential.credential_expires_at is not None and credential.credential_expires_at <= estimated
                or access.licence_expires_at is not None and access.licence_expires_at <= estimated
            ):
                raise error(INVALID_RESPONSE, "expired_grant")
            anchor = Anchor(estimated, Start.capture())
            anchor.now()
        except OrbitError:
            self._persistent_storage.clear_access()
            self._persisted_access = None
            return
        self._keys = keys
        self._persisted_access = access
        self._claims, self._anchor = claims, anchor

    def _checkpoint_persistent_cache(self, *, force: bool = False, propagate: bool = False) -> None:
        if self._persistent_storage is None:
            return
        elapsed = elapsed_ns()
        if not force and elapsed - self._last_checkpoint_elapsed < 60_000_000_000:
            return
        with self._state_lock:
            access, anchor = self._persisted_access, self._anchor
            if access is None or anchor is None or self._claims is None:
                self._last_checkpoint_elapsed = elapsed
                return
            try:
                server_now = anchor.now()
                wall_now = wall_seconds()
                server_delta = server_now - access.server_high_water
                wall_delta = wall_now - access.wall_high_water
                if server_delta < 0 or wall_delta < 0 or abs(server_delta - wall_delta) > 30:
                    raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                checkpoint = replace(access, server_high_water=server_now, wall_high_water=wall_now)
                self._persistent_storage.checkpoint_access(checkpoint)
                self._persisted_access = checkpoint
            except OrbitError as exc:
                if exc.kind == STORAGE:
                    self._clear_all_locked()
                    raise
                try:
                    self._persistent_storage.clear_access()
                except BaseException as storage_error:
                    self._clear_all_locked()
                    raise error(STORAGE, "storage_failed") from storage_error
                self._persisted_access = None
                self._claims = None
                self._anchor = None
                self._generation += 1
                if propagate:
                    raise
            self._last_checkpoint_elapsed = elapsed

    def _start_lifecycle(self) -> None:
        with self._lifecycle_condition:
            if self._lifecycle_thread is not None:
                return
            thread = threading.Thread(target=self._lifecycle, name=f"orbit-sdk-client-{id(self):x}", daemon=True)
            self._lifecycle_thread = thread
            thread.start()

    def _lifecycle(self) -> None:
        try:
            while not self._lifecycle_stop.is_set():
                timeout = 60.0
                try:
                    with self._operation():
                        self._checkpoint_persistent_cache()
                        snapshot = self._snapshot()
                        pending_activation = self._persistent_storage is not None and self._persistent_storage.pending_activation is not None
                        needs_refresh = not pending_activation and snapshot["access"] in ("refresh_required", "expired", "offline")
                        with self._state_lock:
                            if needs_refresh and self._anchor is not None and self._claims is not None:
                                try:
                                    refresh_remaining = max(0.0, self._claims["refresh_after"] - self._anchor.now())
                                except OrbitError:
                                    refresh_remaining = 0.0
                            else:
                                refresh_remaining = 60.0
                            retry = self._retry_deadline
                        now = time.monotonic()
                        retry_remaining = None if retry is None else max(0.0, retry - now)
                        if needs_refresh and (retry_remaining is None or retry_remaining <= 0.0):
                            try:
                                self._refresh(self._lifecycle_stop, respect_retry=True)
                            except OrbitError as exc:
                                if exc.kind not in (TRANSIENT, CANCELLED, REAUTHENTICATION_REQUIRED, STALE_RESPONSE, CLOCK_UNCERTAIN, STORAGE):
                                    pass
                            with self._state_lock:
                                retry = self._retry_deadline
                            if retry is not None:
                                timeout = min(timeout, max(0.0, retry - time.monotonic()))
                            else:
                                timeout = min(timeout, 1.0)
                        elif needs_refresh and retry_remaining is not None:
                            # A passed refresh deadline is no longer actionable while a
                            # bounded retry is pending; wait for that retry instead.
                            timeout = min(timeout, retry_remaining)
                        else:
                            timeout = min(timeout, refresh_remaining)
                            if needs_refresh and retry_remaining is not None:
                                timeout = min(timeout, retry_remaining)
                except RuntimeError:
                    return
                except OrbitError:
                    timeout = min(timeout, 5.0)
                if self._lifecycle_stop.wait(timeout):
                    return
        finally:
            with self._condition:
                deferred = self._close_deferred
            if deferred:
                try:
                    self._finish_close()
                except OrbitError:
                    pass

    @contextmanager
    def _operation(self, cancellation: Cancellation | None = None) -> Iterator[threading.Event | None]:
        if cancellation is not None and not isinstance(cancellation, Cancellation):
            raise TypeError("cancellation must be a Cancellation handle")
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit client is closed")
            self._active += 1
        try:
            if cancellation is None:
                yield self._lifecycle_stop if self._persistent else None
            else:
                with cancellation._borrow() as signal:
                    yield _CombinedCancellation(self._lifecycle_stop, signal) if self._persistent else cancellation
        finally:
            with self._condition:
                self._active -= 1
                if not self._active:
                    self._condition.notify_all()

    def _sync_storage(self) -> None:
        while True:
            try:
                version = self._storage.version()
            except BaseException as exc:
                with self._state_lock:
                    self._clear_all_locked()
                raise error(STORAGE, "storage_failed") from exc
            with self._state_lock:
                if version < self._storage_version:
                    continue
                if version != self._storage_version:
                    self._clear_all_locked()
                    self._storage_version = version
                return

    def _clear_access_locked(self) -> None:
        self._generation += 1
        self._credential = None
        self._claims = None
        self._anchor = None
        self._persisted_access = None
        self._transient = False
        self._retry_deadline = None

    def _clear_all_locked(self) -> None:
        self._clear_access_locked()
        self._account = None

    def _invalidate(self, *, clear_account: bool = True, preserve_pending: bool = False) -> int:
        with self._state_lock:
            if clear_account:
                self._clear_all_locked()
            else:
                self._clear_access_locked()
            generation = self._generation
            try:
                if self._persistent_storage is not None:
                    self._storage_version = self._persistent_storage.invalidate(preserve_pending=preserve_pending)
                else:
                    self._storage_version = self._storage.invalidate()
            except BaseException as exc:
                raise error(STORAGE, "storage_failed") from exc
            return generation

    def _generation_now(self) -> int:
        self._sync_storage()
        with self._state_lock:
            return self._generation

    def _check_generation(self, generation: int) -> None:
        self._sync_storage()
        with self._state_lock:
            if self._generation != generation:
                raise error(STALE_RESPONSE, "stale_response")

    def _acquire_serial(self, generation: int, cancel: threading.Event | None) -> None:
        while True:
            _check_cancel(cancel)
            if self._serial.acquire(timeout=0.05):
                break
        try:
            self._check_generation(generation)
        except BaseException:
            self._serial.release()
            raise

    def snapshot(self) -> dict[str, Any]:
        with self._operation():
            return self._snapshot()

    def _snapshot(self) -> dict[str, Any]:
        self._sync_storage()
        with self._state_lock:
            if self._anchor is not None:
                try:
                    self._anchor.now()
                except OrbitError:
                    self._claims = None
                    self._anchor = None
                    self._generation += 1
                    self._persisted_access = None
                    if self._persistent_storage is not None:
                        try:
                            self._persistent_storage.clear_access()
                        except BaseException as exc:
                            self._clear_all_locked()
                            raise error(STORAGE, "storage_failed") from exc
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "access": "refresh_required" if self._credential is not None else "denied",
            "entitlements": {},
            "expires_at": None,
            "next_check_at": None,
            "credential_expires_at": self._credential.credential_expires_at if self._credential else None,
            "reauthentication_required": self._credential is None,
            "offline_allowed": False,
            "remaining_offline_seconds": 0,
        }
        if self._claims is None or self._anchor is None:
            return result
        try:
            now = self._anchor.now()
        except OrbitError:
            return result
        claims = self._claims
        expiry, refresh = claims["exp"], claims["refresh_after"]
        result["expires_at"] = expiry
        result["next_check_at"] = refresh
        result["reauthentication_required"] = (
            self._credential is None
            or self._credential.credential_expires_at is not None and self._credential.credential_expires_at <= now + 86400
        )
        result["offline_allowed"] = claims["offline_allowed"]
        if expiry <= now:
            result["access"] = "expired"
        elif self._transient:
            result["access"] = "offline" if claims["offline_allowed"] else "refresh_required"
        elif refresh <= now:
            result["access"] = "refresh_required"
        else:
            result["access"] = "online"
        if result["access"] in ("online", "offline"):
            result["entitlements"] = dict(claims["entitlements"])
            if claims["offline_allowed"]:
                result["remaining_offline_seconds"] = max(0, expiry - now)
        return result

    def local_logout(self) -> None:
        with self._operation():
            self._sync_storage()
            self._invalidate(clear_account=True)

    def activate(self, licence_key: str, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            return self._activate("key", licence_key, None, "", idempotency_key, cancel)

    def activate_previous(self, licence_key: str, previous_credential: str | None, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            return self._activate("key", licence_key, None, previous_credential or "", idempotency_key, cancel)

    def activate_account(self, licence_id: str, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            return self._activate("account", "", licence_id, "", idempotency_key, cancel)

    def activate_account_previous(self, licence_id: str, previous_credential: str | None, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            return self._activate("account", "", licence_id, previous_credential or "", idempotency_key, cancel)

    def _activate(self, principal: str, key: str, licence: str | None, previous: str, operation_id: str | None, cancel: threading.Event | None) -> dict[str, Any]:
        _validate_texts(key, licence or "", previous, operation_id or "")
        if principal == "key" and (not key or len(key.encode()) > 256):
            raise error(CONFIGURATION, "invalid_request")
        if principal == "account" and not opaque(licence or ""):
            raise error(CONFIGURATION, "invalid_request")
        if operation_id is not None and not 16 <= len(operation_id.encode()) <= 128 or previous and not _bearer(previous):
            raise error(CONFIGURATION, "invalid_request")
        if principal == "account" and operation_id is None or not self._persistent and operation_id is None:
            raise error(CONFIGURATION, "invalid_request")
        original = self._generation_now()
        self._acquire_serial(original, cancel)
        try:
            self._check_generation(original)
            with self._state_lock:
                if self._generation != original:
                    raise error(STALE_RESPONSE, "stale_response")
                session = self._account
                if principal == "account" and session is None:
                    raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
                saved_before = self._credential
            effective_operation_id = operation_id
            if self._persistent_storage is not None and principal == "key":
                digest = _activation_input_digest(
                    self.config,
                    "key",
                    key,
                    None,
                    previous,
                )
                pending = self._persistent_storage.pending_activation
                if pending is not None:
                    now = wall_seconds()
                    if now < pending.created_at:
                        raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                    if now - pending.created_at > 86400:
                        raise error(CONFIGURATION, "pending_activation_recovery_required")
                    if pending.principal_kind != "key" or pending.input_digest != digest:
                        raise error(CONFIGURATION, "pending_activation_conflict")
                    if operation_id is not None and operation_id != pending.operation_id:
                        raise error(CONFIGURATION, "pending_activation_conflict")
                    effective_operation_id = pending.operation_id
                    pending = PendingActivation(pending.operation_id, pending.principal_kind, pending.input_digest, pending.created_at)
                else:
                    effective_operation_id = operation_id or secrets.token_urlsafe(24)
                    pending = PendingActivation(effective_operation_id, "key", digest, wall_seconds())
                with self._state_lock:
                    if self._generation != original:
                        raise error(STALE_RESPONSE, "stale_response")
                    version = self._persistent_storage.begin_activation(
                        self._storage_version,
                        pending,
                        preserve_credential=bool(previous),
                    )
                    self._generation += 1
                    generation = self._generation
                    self._storage_version = version
                    self._credential = saved_before if previous else None
                    self._claims = None
                    self._anchor = None
                    self._persisted_access = None
                    self._transient = False
                    self._retry_deadline = None
                    self._account = None
            else:
                if self._persistent_storage is not None and self._persistent_storage.pending_activation is not None:
                    raise error(CONFIGURATION, "pending_activation_conflict")
                generation = self._invalidate(clear_account=principal == "key")
            body: dict[str, Any] = {
                "application_id": self.config.application_id,
                "environment_id": self.config.environment_id,
                "installation_id": self.config.installation_id,
                "fingerprint": self.config.fingerprint or None,
                "fingerprint_provider": self.config.fingerprint_provider or None,
                "previous_credential": previous or None,
                "idempotency_key": effective_operation_id,
            }
            if self._persistent:
                body["credential_mode"] = "persistent"
            if principal == "key":
                body["licence_key"] = key
            else:
                body["customer_session"] = session.token
                body["licence_id"] = licence
            started = Start.capture()
            try:
                response = self.transport.post(CLIENT_PREFIX + "activations", body, True, cancel)
                response_error = None
            except OrbitError as exc:
                response, response_error = None, exc
            return self._accept(response, response_error, generation, None, licence if principal == "account" else None, started, cancel)
        finally:
            self._serial.release()

    def refresh(self, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            return self._refresh(cancel, respect_retry=False)

    def _refresh(self, cancel: threading.Event | None, *, respect_retry: bool) -> dict[str, Any]:
        if self._persistent_storage is not None and self._persistent_storage.pending_activation is not None:
            raise error(CONFIGURATION, "pending_activation_recovery_required")
        generation = self._generation_now()
        self._acquire_serial(generation, cancel)
        try:
            self._check_generation(generation)
            if respect_retry:
                snapshot = self._snapshot()
                with self._state_lock:
                    retry_due = self._retry_deadline is None or time.monotonic() >= self._retry_deadline
                if snapshot["access"] not in ("refresh_required", "expired", "offline") or not retry_due:
                    return snapshot
            with self._state_lock:
                saved = self._credential
            if saved is None:
                raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
            started = Start.capture()
            body = self._credential_body(saved)
            try:
                response = self.transport.post(f"{CLIENT_PREFIX}activations/{saved.activation_id}/validate", body, True, cancel)
                response_error = None
            except OrbitError as exc:
                response, response_error = None, exc
            return self._accept(response, response_error, generation, saved, None, started, cancel)
        finally:
            self._serial.release()

    def _credential_body(self, saved: StoredCredential) -> dict[str, Any]:
        return {
            "application_id": self.config.application_id,
            "environment_id": self.config.environment_id,
            "credential": saved.credential,
            "installation_id": self.config.installation_id,
            "fingerprint": self.config.fingerprint or None,
            "fingerprint_provider": self.config.fingerprint_provider or None,
        }

    def _accept(self, response: bytes | None, response_error: OrbitError | None, generation: int, previous: StoredCredential | None, expected_licence: str | None, started: Start, cancel: threading.Event | None) -> dict[str, Any]:
        self._check_generation(generation)
        verifying = response_error is None
        result: tuple[StoredCredential, dict[str, Any], Anchor, AccessState | None] | None = None
        failure = response_error
        if failure is None:
            try:
                if response is None:
                    raise error(INVALID_RESPONSE, "missing_activation_response")
                result = self._verify_reply(response, previous, expected_licence, started, cancel)
            except OrbitError as exc:
                failure = exc
        self._check_generation(generation)
        _check_cancel(cancel)
        if result is not None:
            saved, claims, anchor, access = result
            self._check_generation(generation)
            with self._state_lock:
                try:
                    version = self._storage.version()
                except BaseException as exc:
                    self._clear_all_locked()
                    raise error(STORAGE, "storage_failed") from exc
                if version != self._storage_version:
                    self._clear_all_locked()
                    self._storage_version = version
                if self._generation != generation:
                    raise error(STALE_RESPONSE, "stale_response")
                _check_cancel(cancel)
                try:
                    if self._persistent_storage is not None:
                        if access is None:
                            raise error(STORAGE, "storage_failed")
                        self._persistent_storage.save_verified(self._storage_version, saved, access)
                    else:
                        self._storage.save(self._storage_version, saved)
                except OrbitError as exc:
                    self._clear_all_locked()
                    if exc.kind == STALE_RESPONSE:
                        raise error(STALE_RESPONSE, "stale_response") from exc
                    raise error(STORAGE, "storage_failed") from exc
                except BaseException as exc:
                    self._clear_all_locked()
                    raise error(STORAGE, "storage_failed") from exc
                self._credential, self._claims, self._anchor = saved, claims, anchor
                self._persisted_access = access
                self._transient = False
                self._retry_deadline = None
                return self._snapshot_locked()
        assert failure is not None
        if failure.kind == TRANSIENT:
            with self._state_lock:
                if self._generation != generation:
                    raise error(STALE_RESPONSE, "stale_response")
                if verifying:
                    self._generation += 1
                    self._claims = None
                    self._anchor = None
                    self._persisted_access = None
                    generation = self._generation
                    if self._persistent_storage is not None:
                        self._persistent_storage.clear_access()
                self._transient = True
                self._retry_deadline = time.monotonic() + random.randrange(15, 45)
                snapshot = self._snapshot_locked()
            if snapshot["access"] == "offline":
                return snapshot
            raise failure
        if failure.kind == CANCELLED:
            raise failure
        preserve_pending = (
            self._persistent_storage is not None
            and self._persistent_storage.pending_activation is not None
            and failure.kind not in (DENIED, REAUTHENTICATION_REQUIRED)
        )
        with self._state_lock:
            if self._generation != generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._clear_all_locked()
            try:
                self._storage_version = (
                    self._persistent_storage.invalidate(preserve_pending=preserve_pending)
                    if self._persistent_storage is not None
                    else self._storage.invalidate()
                )
            except BaseException as exc:
                raise error(STORAGE, "storage_failed") from exc
        raise failure

    def _verify_reply(self, data: bytes, previous: StoredCredential | None, expected_licence: str | None, started: Start, cancel: threading.Event | None) -> tuple[StoredCredential, dict[str, Any], Anchor, AccessState | None]:
        reply = unique_json(data)
        expected_fields = {
            "activation_id": str,
            "installation_id": str,
            "credential": (str, type(None)),
            "credential_expires_at": (str, type(None)) if self._persistent else str,
            "grant": (str, type(None)),
            "server_time": str,
            "binding_mode": str,
            "fingerprint_provider": (str, type(None)),
            "licence_expires_at": (str, type(None)),
            "secret_replay_expired": bool,
        }
        optional = ("credential", "grant", "fingerprint_provider", "licence_expires_at")
        if not self._persistent:
            optional += ("credential_expires_at",)
        reply = fields(reply, expected_fields, optional=optional)
        if reply["secret_replay_expired"]:
            raise error(REAUTHENTICATION_REQUIRED, "secret_replay_expired")
        binding = "hwid" if self.config.fingerprint else "none"
        if (
            not opaque(reply["activation_id"])
            or reply["installation_id"] != self.config.installation_id
            or reply["fingerprint_provider"] != (self.config.fingerprint_provider or None)
            or reply["binding_mode"] != binding
            or reply["grant"] is None
        ):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        anchor = Anchor(timestamp(reply["server_time"]), started)
        now = anchor.now()
        expiry = None if reply["credential_expires_at"] is None else timestamp(reply["credential_expires_at"])
        if expiry is not None and (expiry <= now or expiry > now + 30 * 86400):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        if self._persistent and previous is None and expiry is not None:
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        if previous is not None and (
            reply["activation_id"] != previous.activation_id
            or expiry != previous.credential_expires_at
            or reply["credential"] is not None
        ):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        token = reply["grant"]
        with self._keys_lock:
            known = self._keys is not None and self._keys.contains(token)
        if not known:
            _check_cancel(cancel)
            jwks_route = f"{JWKS_PATH}?application_id={self.config.application_id}&environment_id={self.config.environment_id}"
            jwks = self.transport.get(jwks_route, cancel)
            if jwks is None:
                raise error(INVALID_RESPONSE, "missing_jwks")
            keys = Keys.parse(jwks)
            with self._keys_lock:
                self._keys = keys
        with self._keys_lock:
            keys = self._keys
        assert keys is not None
        licence_expiry = timestamp(reply["licence_expires_at"]) if reply["licence_expires_at"] is not None else None
        expected = Expected(
            issuer=self.config.issuer,
            application=self.config.application_id,
            environment=self.config.environment_id,
            licence=expected_licence if expected_licence is not None else previous.licence_id if previous is not None else None,
            activation=reply["activation_id"],
            installation=self.config.installation_id,
            fingerprint=self.config.fingerprint or None,
            fingerprint_provider=self.config.fingerprint_provider or None,
            credential_expires_at=expiry,
            licence_expires_at=licence_expiry,
            now=anchor.now(),
        )
        claims = verify(token, keys, expected)
        credential = (
            reply["credential"]
            if reply["credential"] is not None
            else previous.credential if previous is not None
            else None
        )
        if credential is None or not _bearer(credential):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        stored = StoredCredential(
            application_id=self.config.application_id,
            environment_id=self.config.environment_id,
            activation_id=reply["activation_id"],
            licence_id=claims["sub"],
            installation_id=self.config.installation_id,
            credential=credential,
            credential_expires_at=expiry,
            fingerprint=self.config.fingerprint or None,
            fingerprint_provider=self.config.fingerprint_provider or None,
        )
        access = None
        if self._persistent:
            server_high_water = anchor.now()
            wall_high_water = wall_seconds()
            access = AccessState(
                jws=token,
                jwks=keys.single_jwks(token),
                licence_expires_at=claims["licence_expires_at"],
                received_server_time=timestamp(reply["server_time"]),
                received_wall_time=started.wall,
                server_high_water=server_high_water,
                wall_high_water=wall_high_water,
            )
        return stored, claims, anchor, access

    def require_access(self, feature: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            snapshot = self._snapshot()
            if snapshot["access"] in ("refresh_required", "expired", "offline"):
                try:
                    self._refresh(cancel, respect_retry=True)
                except OrbitError as exc:
                    if exc.kind != TRANSIENT:
                        raise
            snapshot = self._snapshot()
            _check_cancel(cancel)
            if snapshot["access"] not in ("online", "offline"):
                with self._state_lock:
                    if self._persistent and self._credential is not None and self._transient:
                        raise error(TRANSIENT, "network_unavailable")
                raise error(DENIED, "access_unavailable")
            if not snapshot["entitlements"].get(feature, False):
                raise error(DENIED, "feature_unavailable")
            return snapshot

    def deactivate(self, idempotency_key: str, *, cancellation: Cancellation | None = None) -> None:
        with self._operation(cancellation) as cancel:
            _validate_texts(idempotency_key)
            if not 16 <= len(idempotency_key.encode()) <= 128:
                raise error(CONFIGURATION, "invalid_request")
            self._sync_storage()
            with self._state_lock:
                saved = self._credential
            if saved is None:
                raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
            generation = self._invalidate(clear_account=False)
            body = self._credential_body(saved)
            body["idempotency_key"] = idempotency_key
            try:
                result = self.transport.post(f"{CLIENT_PREFIX}activations/{saved.activation_id}/deactivate", body, True, cancel)
            except OrbitError:
                self._check_generation(generation)
                raise
            self._check_generation(generation)
            if result is not None:
                raise error(INVALID_RESPONSE, "unexpected_response_body")

    def account(self, *, cancellation: Cancellation | None = None) -> dict[str, Any] | None:
        with self._operation(cancellation) as cancel:
            _check_cancel(cancel)
            self._sync_storage()
            with self._state_lock:
                return None if self._account is None else json.loads(json.dumps(self._account.metadata))

    def customer_session_authorization(self, *, cancellation: Cancellation | None = None) -> SensitiveAuthorization:
        with self._operation(cancellation) as cancel:
            _check_cancel(cancel)
            self._sync_storage()
            with self._state_lock:
                if self._account is None:
                    raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
                value = bytearray(("Bearer " + self._account.token).encode("ascii"))
            if len(value) <= 7 or any(byte < 33 or byte > 126 for byte in value[7:]):
                _wipe(value)
                raise error(INVALID_RESPONSE, "invalid_authorization_header")
            return SensitiveAuthorization(value)

    def login(self, username: str, password: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            _validate_texts(username, password)
            if not username or len(username.encode()) > 128 or len(password.encode()) > 256:
                raise error(CONFIGURATION, "invalid_request")
            generation = self._generation_now()
            self._acquire_serial(generation, cancel)
            try:
                generation = self._invalidate(clear_account=True)
                body = self._scope_body({"username": username, "password": password})
                try:
                    data = self.transport.post(CLIENT_PREFIX + "sessions", body, False, cancel)
                    value = unique_json(data if data is not None else b"")
                    account, token = _parse_login(value)
                except OrbitError as exc:
                    self._finish_account(generation, exc, cancel)
                    raise
                self._finish_account(generation, None, cancel)
                with self._state_lock:
                    if self._generation != generation:
                        raise error(STALE_RESPONSE, "stale_response")
                    self._account = _AccountSession(token, account)
                return account
            finally:
                self._serial.release()

    def owned_licences(self, cursor: str | None = None, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            after = cursor or ""
            if after and not opaque(after):
                raise error(CONFIGURATION, "invalid_cursor")
            generation, session = self._account_request_start(cancel)
            route = self._account_path(CLIENT_PREFIX + "licences", after)
            try:
                data = self.transport.get_bearer(route, session.token, cancel)
                page = unique_json(data)
                page = fields(page, {"items": list, "next_cursor": (str, type(None))}, optional=("next_cursor",))
                if len(page["items"]) > 100 or page["next_cursor"] is not None and not opaque(page["next_cursor"]):
                    raise error(INVALID_RESPONSE, "invalid_licences")
                clean_items = [_check_licence(licence) for licence in page["items"]]
                self._finish_account(generation, None, cancel)
                return {"items": clean_items, "next_cursor": page["next_cursor"]}
            except OrbitError as exc:
                self._finish_account(generation, exc, cancel)
                raise
            finally:
                self._serial.release()

    def claim_licence(self, licence_key: str, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict[str, Any]:
        with self._operation(cancellation) as cancel:
            _validate_texts(licence_key, idempotency_key)
            if not licence_key or len(licence_key.encode()) > 256 or not 16 <= len(idempotency_key.encode()) <= 128:
                raise error(CONFIGURATION, "invalid_request")
            return self._account_post(
                CLIENT_PREFIX + "licence-claims",
                {"licence_key": licence_key, "idempotency_key": idempotency_key},
                True,
                cancel,
                validate=_check_licence,
            )

    def request_email_change(self, password: str, new_email: str, *, cancellation: Cancellation | None = None) -> None:
        with self._operation(cancellation) as cancel:
            _validate_texts(password, new_email)
            if len(password.encode()) > 256 or len(new_email.encode()) > 254:
                raise error(CONFIGURATION, "invalid_request")
            self._account_post(CLIENT_PREFIX + "email-changes", {"password": password, "email": new_email}, False, cancel, accepted=True)

    def request_password_recovery(self, email: str, *, cancellation: Cancellation | None = None) -> None:
        with self._operation(cancellation) as cancel:
            _validate_texts(email)
            if len(email.encode()) > 254:
                raise error(CONFIGURATION, "invalid_request")
            generation = self._generation_now()
            body = self._scope_body({"email": email})
            try:
                data = self.transport.post(CLIENT_PREFIX + "password-recovery", body, False, cancel)
                _accepted(data)
            except OrbitError as exc:
                self._check_response_generation(generation, cancel)
                raise
            self._check_response_generation(generation, cancel)

    def register(self, licence_key: str, username: str, email: str, password: str, *, cancellation: Cancellation | None = None) -> RegistrationResult:
        with self._operation(cancellation) as cancel:
            _validate_texts(licence_key, username, email, password)
            if not licence_key or len(licence_key.encode()) > 256 or len(username.encode()) > 128 or len(email.encode()) > 254 or len(password.encode()) > 256 or len(password) < 8:
                raise error(CONFIGURATION, "invalid_request")
            generation = self._generation_now()
            body = self._scope_body({"licence_key": licence_key, "username": username, "email": email, "password": password})
            try:
                data = self.transport.post(CLIENT_PREFIX + "registrations", body, False, cancel)
                value = unique_json(data if data is not None else b"")
                value = fields(value, {"accepted": bool, "expires_at": str, "resend_credential": str})
                if not value["accepted"] or not _bearer(value["resend_credential"]):
                    raise error(INVALID_RESPONSE, "invalid_registration")
                timestamp(value["expires_at"])
                self._check_response_generation(generation, cancel)
                pending = PendingRegistration(value["resend_credential"], self)
                return RegistrationResult(True, value["expires_at"], pending)
            except OrbitError as exc:
                self._check_response_generation(generation, cancel)
                raise

    def resend_registration(self, pending: PendingRegistration, *, cancellation: Cancellation | None = None) -> None:
        with self._operation(cancellation) as cancel:
            if not isinstance(pending, PendingRegistration):
                raise TypeError("pending must be a PendingRegistration handle")
            if pending._owner is not self or pending._application_id != self.config.application_id or pending._environment_id != self.config.environment_id:
                raise ValueError("pending registration belongs to another client")
            generation = self._generation_now()
            with pending._borrow() as credential:
                body = self._scope_body({"resend_credential": credential})
                try:
                    data = self.transport.post(CLIENT_PREFIX + "registrations/resend", body, False, cancel)
                    _accepted(data)
                except OrbitError as exc:
                    self._check_response_generation(generation, cancel)
                    raise
                self._check_response_generation(generation, cancel)

    def account_logout(self, *, cancellation: Cancellation | None = None) -> None:
        # Clear local state before checking cancellation or starting the request.
        with self._operation(cancellation) as cancel:
            self._sync_storage()
            with self._state_lock:
                session = self._account
            generation = self._invalidate(clear_account=True)
            if session is None:
                return
            route = self._account_path(CLIENT_PREFIX + "sessions/current", "")
            try:
                self.transport.delete_bearer(route, session.token, cancel)
            except OrbitError:
                self._check_generation(generation)
                raise
            self._check_generation(generation)

    def _account_request_start(self, cancel: threading.Event | None) -> tuple[int, _AccountSession]:
        generation = self._generation_now()
        self._acquire_serial(generation, cancel)
        try:
            self._check_generation(generation)
            with self._state_lock:
                session = self._account
            if session is None:
                raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
            return generation, session
        except BaseException:
            self._serial.release()
            raise

    def _account_post(self, route: str, body: dict[str, Any], retry_safe: bool, cancel: threading.Event | None, *, accepted: bool = False, validate: Any = None) -> Any:
        generation, session = self._account_request_start(cancel)
        try:
            body["customer_session"] = session.token
            data = self.transport.post(route, self._scope_body(body), retry_safe, cancel)
            value = unique_json(data if data is not None else b"")
            if accepted:
                result = _accepted(value)
                self._finish_account(generation, None, cancel)
                return result
            if validate is not None:
                value = validate(value)
            self._finish_account(generation, None, cancel)
            return value
        except OrbitError as exc:
            self._finish_account(generation, exc, cancel)
            raise
        finally:
            self._serial.release()

    def _finish_account(self, generation: int, failure: OrbitError | None, cancel: threading.Event | None) -> None:
        self._check_response_generation(generation, cancel)
        if failure is None or failure.kind in (TRANSIENT, CANCELLED) or failure.kind == DENIED and failure.code == "session_expired":
            return
        with self._state_lock:
            if self._generation != generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._clear_all_locked()
            try:
                self._storage_version = self._storage.invalidate()
            except BaseException as exc:
                raise error(STORAGE, "storage_failed") from exc

    def _check_response_generation(self, generation: int, cancel: threading.Event | None) -> None:
        self._check_generation(generation)
        _check_cancel(cancel)

    def _scope_body(self, body: dict[str, Any]) -> dict[str, Any]:
        body["application_id"] = self.config.application_id
        body["environment_id"] = self.config.environment_id
        return body

    def _account_path(self, route: str, after: str) -> str:
        result = f"{route}?application_id={self.config.application_id}&environment_id={self.config.environment_id}"
        return result + (f"&after={after}" if after else "")

    def close(self) -> None:
        thread: threading.Thread | None
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._lifecycle_stop.set()
            with self._lifecycle_condition:
                self._lifecycle_condition.notify_all()
            thread = self._lifecycle_thread
            from_lifecycle = thread is threading.current_thread()
            while self._active and not from_lifecycle:
                self._condition.wait()
            if from_lifecycle:
                self._close_deferred = True
                return
        if thread is not None:
            thread.join()
        self._finish_close()

    def _finish_close(self) -> None:
        failure: OrbitError | None = None
        try:
            if self._persistent_storage is not None:
                self._checkpoint_persistent_cache(force=True, propagate=True)
        except OrbitError as exc:
            failure = exc
        except BaseException:
            failure = error(STORAGE, "storage_failed")
        finally:
            with self._state_lock:
                self._clear_all_locked()
            close = getattr(self._storage, "close", None)
            if close is not None:
                try:
                    close()
                except OrbitError as exc:
                    if failure is None:
                        failure = exc
                except BaseException:
                    if failure is None:
                        failure = error(STORAGE, "storage_failed")
        if failure is not None:
            raise failure

    def __enter__(self) -> Client:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit client is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "Client(<redacted>)"

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class _Device:
    installation_id: str
    fingerprint: str | None
    fingerprint_provider: str | None


def _validate_config(config: Config) -> None:
    values = (config.api_origin, config.application_id, config.environment_id, config.issuer, config.installation_id, config.fingerprint, config.fingerprint_provider, config.storage_path)
    encoded = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Orbit SDK configuration values must be strings")
        try:
            raw = value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise error(CONFIGURATION, "invalid_configuration") from exc
        if len(raw) > 4096:
            raise error(CONFIGURATION, "configuration_too_large")
        encoded.append(raw)
    if sum(map(len, encoded)) > 16 * 1024:
        raise error(CONFIGURATION, "configuration_too_large")
    if not opaque(config.application_id) or not opaque(config.environment_id) or not opaque(config.installation_id) or len(config.installation_id) < 16:
        raise error(CONFIGURATION, "invalid_configuration")
    if not config.issuer:
        raise error(CONFIGURATION, "invalid_configuration")
    if bool(config.fingerprint) != bool(config.fingerprint_provider) or config.fingerprint and (not lower_hex(config.fingerprint, 64) or not valid_provider(config.fingerprint_provider)):
        raise error(CONFIGURATION, "invalid_configuration")
    _safe_origin(config.api_origin)


def _validate_app_config(config: AppConfig) -> None:
    if not isinstance(config, AppConfig):
        raise TypeError("config must be an orbit_sdk.AppConfig")
    values = (config.api_origin, config.application_id, config.environment_id, config.issuer)
    if any(not isinstance(value, str) for value in values):
        raise TypeError("Orbit SDK configuration values must be strings")
    if config.fingerprint is not None and not isinstance(config.fingerprint, str):
        raise TypeError("fingerprint must be text or None")
    if config.fingerprint_provider is not None and not isinstance(config.fingerprint_provider, str):
        raise TypeError("fingerprint_provider must be text or None")
    runtime = Config(
        api_origin=config.api_origin,
        application_id=config.application_id,
        environment_id=config.environment_id,
        issuer=config.issuer,
        installation_id="validation_installation_123",
        fingerprint=config.fingerprint or "",
        fingerprint_provider=config.fingerprint_provider or "",
    )
    _validate_config(runtime)


def _activation_input_digest(
    config: Config,
    principal_kind: str,
    licence_key: str,
    licence_id: str | None,
    previous_credential: str = "",
) -> str:
    value: dict[str, Any] = {
        "scope": canonical_scope(config),
        "installation": {
            "id": config.installation_id,
            "fingerprint": config.fingerprint or None,
            "fingerprint_provider": config.fingerprint_provider or None,
        },
        "principal_kind": principal_kind,
        "credential_mode": "persistent",
    }
    if principal_kind == "key":
        value["licence_key"] = licence_key
    else:
        value["licence_id"] = licence_id
    if previous_credential:
        value["previous_credential_sha256"] = hashlib.sha256(previous_credential.encode("ascii")).hexdigest()
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _validate_texts(*values: str) -> None:
    total = 0
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Orbit SDK text arguments must be strings")
        try:
            size = len(value.encode("utf-8", "strict"))
        except UnicodeError as exc:
            raise error(CONFIGURATION, "invalid_text") from exc
        if size > 4096:
            raise error(CONFIGURATION, "input_too_large")
        total += size
    if total > 16 * 1024:
        raise error(CONFIGURATION, "input_too_large")


def _parse_login(value: Any) -> tuple[dict[str, Any], str]:
    reply = fields(value, {"customer": dict, "session": str, "expires_at": str})
    customer = fields(reply["customer"], {"id": str, "username": str, "email": str, "suspended": bool, "created_at": str})
    username = customer["username"]
    if (
        not opaque(customer["id"])
        or customer["suspended"]
        or not 3 <= len(username) <= 32
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in username)
        or not 1 <= len(customer["email"].encode()) <= 254
        or not _bearer(reply["session"])
    ):
        raise error(INVALID_RESPONSE, "invalid_login")
    timestamp(customer["created_at"])
    timestamp(reply["expires_at"])
    clean_customer = {name: customer[name] for name in ("id", "username", "email", "suspended", "created_at")}
    return {"customer": clean_customer, "expires_at": reply["expires_at"]}, reply["session"]


def _check_licence(value: Any) -> dict[str, Any]:
    licence = fields(value, {
        "id": str,
        "policy_name": str,
        "state": str,
        "expiry_mode": str,
        "first_used_at": (str, type(None)),
        "expires_at": (str, type(None)),
        "duration_seconds": (int, type(None)),
        "device_limit": int,
        "hwid_locked": bool,
        "offline_allowed": bool,
        "offline_seconds": int,
        "entitlements": dict,
    }, optional=("first_used_at", "expires_at", "duration_seconds"))
    features = licence["entitlements"]
    if (
        not opaque(licence["id"])
        or not 1 <= licence["device_limit"] <= 100
        or len(licence["policy_name"]) > 80
        or len(features) > 64
        or any(not isinstance(name, str) or not isinstance(enabled, bool) for name, enabled in features.items())
    ):
        raise error(INVALID_RESPONSE, "invalid_licence")
    if licence["duration_seconds"] is not None and not strict_int(licence["duration_seconds"]):
        raise error(INVALID_RESPONSE, "invalid_licence")
    if not strict_int(licence["offline_seconds"], minimum=-(1 << 31), maximum=(1 << 31) - 1):
        raise error(INVALID_RESPONSE, "invalid_licence")
    for date in (licence["first_used_at"], licence["expires_at"]):
        if date is not None:
            timestamp(date)
    return {name: licence[name] for name in (
        "id", "policy_name", "state", "expiry_mode", "first_used_at", "expires_at",
        "duration_seconds", "device_limit", "hwid_locked", "offline_allowed", "offline_seconds", "entitlements",
    )}


def _accepted(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, str)):
        value = unique_json(value)
    reply = fields(value, {"accepted": bool})
    if not reply["accepted"]:
        raise error(INVALID_RESPONSE, "invalid_response")
    return reply


def _bearer(value: str) -> bool:
    return isinstance(value, str) and len(value) == 43 and value.isascii() and all(c.isalnum() or c in "_-" for c in value)


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise error(CANCELLED, "operation_cancelled")


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")
