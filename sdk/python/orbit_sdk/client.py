from __future__ import annotations

import datetime as dt
import json
import hashlib
import os
import random
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping

from .app_key import AppKey
from .clock import Anchor, Start, elapsed_ns, timestamp, wall_seconds
from .device import installation_id_new, lower_hex, native_fingerprint, opaque, valid_provider
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
    FeatureUnavailableError,
    NotActivatedError,
    OrbitError,
    error,
)
from .grants import Expected, Keys, valid_entitlements, verify
from .jsonutil import fields, strict_int, text, unique_json
from .storage import MemoryStorage, StoredCredential, WindowsStorage, SecretServiceStorage, valid_credential
from .persistent_storage import AccessState, InstallationStorage, OfflineState, PendingActivation, canonical_scope
from .offline import Expected as OfflineExpected, OfflineFile, OfflineKeys, OfflineRequest, request as offline_request, verify as verify_offline_file
from .sessions import Expected as SessionExpected, SessionGrant, SessionKeys, verify as verify_session_grant
from .transport import CLIENT_PREFIX, JWKS_PATH, Transport, _safe_origin
from . import online


class StorageMode(str, Enum):
    MEMORY = "memory"
    WINDOWS_DPAPI = "windows_dpapi"
    LINUX_SECRET_SERVICE = "linux_secret_service"


@dataclass(frozen=True)
class _Config:
    """Internal runtime settings shared by every ``Client`` instance."""

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
class _AppScope:
    """Internal trusted scope for the persistent ``Client.open`` convenience."""

    api_origin: str
    application_id: str
    environment_id: str
    issuer: str
    fingerprint: str | None = None
    fingerprint_provider: str | None = None
    environment: str = "test"


class AccessStatus(str, Enum):
    """The public, typed shape of ``Snapshot.access``."""

    ONLINE = "online"
    OFFLINE = "offline"
    REFRESH_REQUIRED = "refresh_required"
    EXPIRED = "expired"
    DENIED = "denied"


@dataclass(frozen=True)
class Snapshot:
    """A point-in-time view of installed access. Display-only; call
    ``require_access``/``ensure_access`` before protected work."""

    access: AccessStatus
    entitlements: Mapping[str, bool]
    expires_at: dt.datetime | None
    next_check_at: dt.datetime | None
    credential_expires_at: dt.datetime | None
    reauthentication_required: bool
    offline_allowed: bool
    remaining_offline: dt.timedelta
    session: SessionMetadata | None = None
    offline_file_mode: bool = False

    def has(self, feature: str) -> bool:
        """Return whether ``feature`` is a currently granted entitlement."""
        return bool(self.entitlements.get(feature, False))


@dataclass(frozen=True)
class Account:
    """Safe customer account metadata returned by ``login``/``account``."""

    id: str
    username: str
    email: str
    suspended: bool
    created_at: dt.datetime
    session_expires_at: dt.datetime


@dataclass(frozen=True)
class OwnedLicence:
    id: str
    policy_name: str
    state: str
    expiry_mode: str
    first_used_at: dt.datetime | None
    expires_at: dt.datetime | None
    duration: dt.timedelta | None
    device_limit: int
    concurrent_session_limit: int
    hwid_locked: bool
    offline_allowed: bool
    offline_duration: dt.timedelta
    offline_file_duration: dt.timedelta
    entitlements: Mapping[str, bool]
    usage_limits: Mapping[str, online.UsageLimit]
    resource_limits: Mapping[str, online.ResourceLimit]


@dataclass(frozen=True)
class SessionMetadata:
    session_id: str
    sequence: int
    expires_at: dt.datetime
    refresh_after: dt.datetime


@dataclass(frozen=True)
class OwnedLicencePage:
    items: tuple[OwnedLicence, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class RegistrationResult:
    accepted: bool
    expires_at: dt.datetime
    pending: PendingRegistration


@dataclass(frozen=True)
class DeviceBinding:
    """A caller-supplied machine fingerprint and the provider that made it."""

    fingerprint: str
    provider: str

    def __post_init__(self) -> None:
        if not lower_hex(self.fingerprint, 64) or not valid_provider(self.provider):
            raise ValueError("device binding must contain a valid fingerprint and provider")


class _CombinedCancellation:
    def __init__(self, lifecycle: Any, caller: Any) -> None:
        self.lifecycle, self.caller = lifecycle, caller

    def is_set(self) -> bool:
        return _cancelled(self.lifecycle) or _cancelled(self.caller)

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.is_set():
            remaining = 0.05 if deadline is None else min(0.05, deadline - time.monotonic())
            if remaining <= 0:
                return self.is_set()
            time.sleep(remaining)
        return True


def _cancelled(value: Any) -> bool:
    return value is not None and value.is_set()


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
    """Synchronous Orbit client. Use ``with Client.open(app_key) as orbit: ...``."""

    def __init__(self, config: _Config, transport: Any, storage: Any, *, persistent: bool = False, app_key: AppKey | None = None, offline_keys: OfflineKeys | None = None) -> None:
        self.config = config
        self.transport = transport
        self._storage = storage
        self._persistent_storage = storage if persistent and isinstance(storage, InstallationStorage) else None
        self._persistent = self._persistent_storage is not None
        device = self._device(config)
        version, credential = storage.load()
        if credential is not None and not valid_credential(credential, config, device):
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
        self._session_required = False
        self._session_keys: SessionKeys | None = None
        self._floating: tuple[SessionGrant, Anchor] | None = None
        self._pending_session_id: str | None = None
        self._session_disabled = False
        self._session_cancel = threading.Event()
        self._session_retry_deadline: float | None = None
        self._session_licence_expiry: int | None = None
        self._session_binding_mode: str | None = None
        self._session_lock = threading.Lock()
        self._transient = False
        self._retry_deadline: float | None = None
        self._last_failure: OrbitError | None = None
        self._account: _AccountSession | None = None
        self._device_value = device
        self._keys: Keys | None = None
        self._keys_lock = threading.Lock()
        self._persisted_access: AccessState | None = None
        self._app_key = app_key
        self._environment = app_key.environment if app_key is not None else "test"
        self._offline_keys = offline_keys
        self._offline_file: OfflineFile | None = None
        self._offline_state: OfflineState | None = None
        self._lifecycle_condition = threading.Condition()
        self._lifecycle_stop = threading.Event()
        self._lifecycle_thread: threading.Thread | None = None
        self._close_deferred = False
        self._last_checkpoint_elapsed = elapsed_ns() if self._persistent else 0
        if self._persistent_storage is not None:
            self._offline_state = self._persistent_storage.offline
            if self._offline_state is not None and self._offline_state.jws is not None:
                self._restore_offline_file()
            else:
                self._restore_cached_access()

    @staticmethod
    def _device(config: _Config) -> _Device:
        return _Device(
            config.installation_id,
            config.fingerprint or None,
            config.fingerprint_provider or None,
        )

    @classmethod
    def open(
        cls,
        app_key: str | AppKey,
        *,
        state_path: str | os.PathLike[str] | None = None,
        device_binding: DeviceBinding | None = None,
        machine_binding: bool = True,
        offline_keys: Mapping[str, Any] | str | bytes | None = None,
    ) -> Client:
        """Open a stable installation with private credential and grant storage.

        ``app_key`` is the public value shown on Orbit's Integration page (or
        an already-parsed :class:`AppKey`). Everything else defaults; pass
        ``state_path`` to use a dedicated directory (for a service or
        container). Machine binding uses the native identity by default;
        pass ``machine_binding=False`` for cloned containers, or provide a
        ``DeviceBinding`` when the host supplies a stable custom identity.
        """
        parsed = _parse_app_key(app_key)
        trusted_offline_keys = None if offline_keys is None else OfflineKeys.parse(offline_keys, parsed.environment)
        binding = _resolve_binding(parsed, device_binding, machine_binding)
        scope = _AppScope(
            api_origin=parsed.api_origin,
            application_id=parsed.application_id,
            environment_id=parsed.environment_id,
            issuer=parsed.issuer,
            environment=parsed.environment,
            fingerprint=None if binding is None else binding.fingerprint,
            fingerprint_provider=None if binding is None else binding.provider,
        )
        return cls._open_app(scope, state_path, transport=None, start_worker=True, app_key=parsed, offline_keys=trusted_offline_keys)

    @classmethod
    def open_with_storage(
        cls,
        app_key: str | AppKey,
        *,
        installation_id: str,
        storage_mode: StorageMode | str = StorageMode.MEMORY,
        storage_path: str | os.PathLike[str] = "",
        device_binding: DeviceBinding | None = None,
        machine_binding: bool = True,
    ) -> Client:
        """Advanced: open a client whose installation ID and storage policy
        the host manages itself, instead of the ``open()`` private
        installation record. See ``advanced.md``."""
        parsed = _parse_app_key(app_key)
        binding = _resolve_binding(parsed, device_binding, machine_binding)
        config = _Config(
            api_origin=parsed.api_origin,
            application_id=parsed.application_id,
            environment_id=parsed.environment_id,
            issuer=parsed.issuer,
            installation_id=installation_id,
            fingerprint="" if binding is None else binding.fingerprint,
            fingerprint_provider="" if binding is None else binding.provider,
            storage_mode=storage_mode,
            storage_path=storage_path,
        )
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
    def _open_for_test(
        cls,
        scope: _AppScope,
        state_path: str | os.PathLike[str],
        transport: Any,
        *,
        start_worker: bool = False,
    ) -> Client:
        """Private injection point for persistent lifecycle and storage tests."""
        return cls._open_app(scope, state_path, transport=transport, start_worker=start_worker)

    @classmethod
    def _open_app(
        cls,
        app_scope: _AppScope,
        state_path: str | os.PathLike[str] | None,
        *,
        transport: Any | None,
        start_worker: bool,
        app_key: AppKey | None = None,
        offline_keys: OfflineKeys | None = None,
    ) -> Client:
        if not isinstance(app_scope, _AppScope):
            raise TypeError("app scope must be an internal _AppScope")
        _validate_app_scope(app_scope)
        # Validate the complete trusted origin before creating private state.
        live_transport = transport if transport is not None else Transport(app_scope.api_origin)
        storage = InstallationStorage.open(state_path, app_scope)
        client = None
        try:
            config = _Config(
                api_origin=app_scope.api_origin,
                application_id=app_scope.application_id,
                environment_id=app_scope.environment_id,
                issuer=app_scope.issuer,
                installation_id=storage.installation_id,
                fingerprint=app_scope.fingerprint or "",
                fingerprint_provider=app_scope.fingerprint_provider or "",
            )
            _validate_config(config)
            if app_key is None:
                app_key_environment = app_scope.environment
            else:
                app_key_environment = app_key.environment
            client = cls(config, live_transport, storage, persistent=True, app_key=app_key, offline_keys=offline_keys)
            client._environment = app_key_environment
            if storage.pending_activation is None and not client._offline_mode():
                try:
                    client._refresh(None, respect_retry=False)
                except OrbitError as exc:
                    if exc.kind not in (TRANSIENT, REAUTHENTICATION_REQUIRED) and not (exc.kind == DENIED and exc.code == "concurrent_session_limit_reached"):
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
    def _for_test(cls, config: _Config, transport: Any, storage: Any | None = None) -> Client:
        """Private deterministic dependency injection for the SDK test suite."""
        _validate_config(config)
        return cls(config, transport, storage if storage is not None else MemoryStorage())

    def _offline_mode(self) -> bool:
        return self._offline_state is not None and self._offline_state.jws is not None

    def _offline_expected(self, now: int, sequence: int) -> OfflineExpected:
        if self._app_key is None:
            raise error(CONFIGURATION, "offline_requires_installed_client")
        return OfflineExpected(
            self._app_key, self.config.installation_id, now,
            self.config.fingerprint or None, self.config.fingerprint_provider or None, sequence,
        )

    def _restore_offline_file(self) -> None:
        state = self._offline_state
        assert state is not None and state.jws is not None
        if self._offline_keys is None:
            raise error(CONFIGURATION, "offline_keys_required")
        verified = verify_offline_file(state.jws, self._offline_keys, self._offline_expected(state.verified_at, state.sequence))
        if (verified.sequence, verified.issuance_id, verified.content_digest) != (state.sequence, state.issuance_id, state.content_digest):
            raise error(STORAGE, "storage_failed")
        self._offline_file = verified
        start = Start.capture()
        if start.wall + 30 < state.wall_high_water:
            # Preserve the renewal floor and allow a deliberate new import after
            # the clock is corrected. No authority is restored with uncertain time.
            return
        self._anchor = Anchor(max(start.wall, state.time_high_water), start)

    def offline_request(self) -> OfflineRequest:
        """Export public setup for this installation; this grants no access."""
        with self._operation():
            self._sync_storage()
            if self._persistent_storage is None or self._app_key is None:
                raise error(CONFIGURATION, "offline_requires_installed_client")
            return offline_request(self._app_key, self.config.installation_id, self.config.fingerprint or None, self.config.fingerprint_provider or None)

    def import_offline_file(self, file: str | bytes, *, cancellation: Cancellation | None = None) -> Snapshot:
        """Verify and durably import a file with the application's trusted keys."""
        with self._operation(cancellation) as cancel:
            if self._persistent_storage is None or self._app_key is None:
                raise error(CONFIGURATION, "offline_requires_installed_client")
            if self._offline_keys is None:
                raise error(CONFIGURATION, "offline_keys_required")
            generation = self._generation_now()
            self._acquire_serial(generation, cancel)
            try:
                with self._state_lock:
                    self._check_generation(generation)
                    previous = self._persistent_storage.offline
                    start = Start.capture()
                    if previous is not None and start.wall + 30 < previous.wall_high_water:
                        raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                    now = max(start.wall, previous.time_high_water if previous else 0)
                    if self._anchor is not None:
                        now = max(now, self._anchor.now())
                    verified = verify_offline_file(file, self._offline_keys, self._offline_expected(now, previous.sequence if previous else 1))
                    trusted_now = max(now, verified.issued_at)
                    saved = OfflineState(
                        verified.token, verified.sequence, verified.issuance_id, verified.content_digest,
                        now, trusted_now, max(start.wall, previous.wall_high_water if previous else 0),
                    )
                    _check_cancel(cancel)
                    try:
                        version = self._persistent_storage.save_offline(self._storage_version, saved)
                    except OrbitError as exc:
                        if exc.kind == STORAGE:
                            self._clear_all_locked()
                        raise
                    self._clear_all_locked()
                    self._storage_version = version
                    self._offline_state, self._offline_file = saved, verified
                    self._anchor = Anchor(trusted_now, start)
                    self._last_checkpoint_elapsed = start.elapsed
                    return _to_snapshot(self._snapshot_locked(trusted_now))
            finally:
                self._serial.release()

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
                allow_unbound_fingerprint=True,
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
            if self._offline_mode():
                state, anchor = self._offline_state, self._anchor
                if state is None or anchor is None:
                    self._last_checkpoint_elapsed = elapsed
                    return
                try:
                    checkpoint = replace(state, time_high_water=max(state.time_high_water, anchor.now()), wall_high_water=max(state.wall_high_water, wall_seconds()))
                    self._persistent_storage.checkpoint_offline(checkpoint)
                    self._offline_state = checkpoint
                except OrbitError as exc:
                    if exc.kind == STORAGE:
                        self._clear_all_locked()
                        raise
                    if exc.kind != CLOCK_UNCERTAIN:
                        self._clear_all_locked()
                        raise
                    # Keep the continuous-clock evidence. A later import must
                    # not restart time from an older wall clock/checkpoint.
                self._last_checkpoint_elapsed = elapsed
                return
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
                        with self._state_lock:
                            session_mode = self._session_required and not self._session_disabled and not snapshot.get("offline_file_mode", False)
                            if session_mode:
                                if self._floating is None:
                                    session_remaining = 0.0
                                else:
                                    grant, session_anchor = self._floating
                                    try:
                                        session_remaining = max(0.0, grant.refresh_after - session_anchor.now())
                                    except OrbitError:
                                        session_remaining = 0.0
                                session_retry = self._session_retry_deadline
                            else:
                                session_remaining = 60.0
                                session_retry = None
                        needs_refresh = not pending_activation and not snapshot.get("offline_file_mode", False) and snapshot["access"] in ("refresh_required", "expired", "offline") and not session_mode
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
                        session_retry_remaining = None if session_retry is None else max(0.0, session_retry - now)
                        if session_mode and session_retry_remaining is not None and session_retry_remaining > 0.0:
                            timeout = min(timeout, session_retry_remaining)
                        elif session_mode and session_remaining <= 0.0:
                            try:
                                self._advance_session(self._lifecycle_stop)
                            except OrbitError:
                                pass
                            with self._state_lock:
                                session_retry = self._session_retry_deadline
                            if session_retry is not None:
                                timeout = min(timeout, max(0.0, session_retry - time.monotonic()))
                            else:
                                timeout = min(timeout, 1.0)
                        elif session_mode:
                            timeout = min(timeout, session_remaining)
                        retry_remaining = None if retry is None else max(0.0, retry - now)
                        if needs_refresh and (retry_remaining is None or retry_remaining <= 0.0):
                            try:
                                self._refresh(self._lifecycle_stop, respect_retry=True)
                            except OrbitError:
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
                except OrbitError:
                    # OrbitError subclasses RuntimeError; only closing stops the worker.
                    timeout = min(timeout, 5.0)
                except RuntimeError:
                    return
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
        self._drop_floating_locked(release=True, clear_profile=True)
        self._generation += 1
        self._credential = None
        self._claims = None
        self._anchor = None
        self._persisted_access = None
        self._offline_file = None
        self._offline_state = None
        self._transient = False
        self._retry_deadline = None
        self._last_failure = None

    def _drop_floating_locked(self, *, release: bool, clear_profile: bool) -> None:
        current = self._floating
        session_id = current[0].session_id if current is not None else self._pending_session_id
        credential = self._credential
        self._session_cancel.set()
        self._session_cancel = threading.Event()
        self._floating = None
        self._pending_session_id = None
        self._session_retry_deadline = None
        if clear_profile:
            self._session_required = False
            self._session_disabled = False
            self._session_keys = None
            self._session_licence_expiry = None
            self._session_binding_mode = None
        if release and session_id and credential is not None:
            self._queue_session_release(session_id, credential)

    def _clear_all_locked(self) -> None:
        self._clear_access_locked()
        self._account = None

    def _invalidate(self, *, clear_account: bool = True, preserve_pending: bool = False) -> int:
        with self._state_lock:
            if self._offline_mode():
                self._checkpoint_persistent_cache(force=True)
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

    def snapshot(self) -> Snapshot:
        with self._operation():
            return _to_snapshot(self._snapshot())

    def _snapshot(self) -> dict[str, Any]:
        self._sync_storage()
        with self._state_lock:
            now = None
            if self._anchor is not None:
                try:
                    now = self._anchor.now()
                except OrbitError:
                    if self._offline_mode():
                        return self._snapshot_locked()
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
            return self._snapshot_locked(now)

    def _snapshot_locked(self, now: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "access": "refresh_required" if self._credential is not None else "denied",
            "entitlements": {},
            "expires_at": None,
            "next_check_at": None,
            "credential_expires_at": self._credential.credential_expires_at if self._credential else None,
            "reauthentication_required": self._credential is None,
            "offline_allowed": False,
            "remaining_offline_seconds": 0,
            "session": None,
        }
        if self._offline_mode():
            result["offline_file_mode"] = True
            result["reauthentication_required"] = False
            result["offline_allowed"] = True
            if self._offline_file is not None:
                result["expires_at"] = self._offline_file.expires_at
            if self._offline_file is None or self._anchor is None:
                return result
            if now is None:
                try:
                    now = self._anchor.now()
                except OrbitError:
                    return result
            remaining = self._offline_file.expires_at - now
            result["access"] = "offline" if remaining > 0 else "expired"
            if remaining > 0:
                result["entitlements"] = dict(self._offline_file.entitlements)
                result["remaining_offline_seconds"] = remaining
            return result
        if self._session_required:
            if self._floating is None:
                if self._credential is not None and self._credential.credential_expires_at is not None:
                    result["reauthentication_required"] = self._credential.credential_expires_at <= wall_seconds() + 86400
                return result
            grant, anchor = self._floating
            try:
                session_now = anchor.now()
            except OrbitError:
                self._drop_floating_locked(release=False, clear_profile=False)
                return result
            if self._credential is not None and self._credential.credential_expires_at is not None:
                result["reauthentication_required"] = self._credential.credential_expires_at <= session_now + 86400
            session = {
                "session_id": grant.session_id,
                "sequence": grant.sequence,
                "expires_at": grant.expires_at,
                "refresh_after": grant.refresh_after,
            }
            result["session"] = session
            result["expires_at"] = grant.expires_at
            result["next_check_at"] = grant.refresh_after
            if grant.expires_at > session_now:
                result["access"] = "online"
                result["entitlements"] = dict(grant.entitlements)
            else:
                result["access"] = "expired"
            return result
        if self._claims is None or self._anchor is None:
            return result
        if now is None:
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

    def logout(self) -> None:
        """Clear local activation and customer session state and schedule a
        bounded, best-effort floating-seat release. Use ``logout_account`` to
        revoke the customer session on the server."""
        with self._operation():
            self._sync_storage()
            self._invalidate(clear_account=True)

    def activate(self, licence_key: str, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> Snapshot:
        with self._operation(cancellation) as cancel:
            return _to_snapshot(self._activate("key", licence_key, None, "", idempotency_key, cancel))

    def activate_previous(self, licence_key: str, previous_credential: str | None, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> Snapshot:
        """Advanced: retry an activation while rebinding a previous credential."""
        with self._operation(cancellation) as cancel:
            return _to_snapshot(self._activate("key", licence_key, None, previous_credential or "", idempotency_key, cancel))

    def activate_account(self, licence_id: str, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> Snapshot:
        with self._operation(cancellation) as cancel:
            return _to_snapshot(self._activate("account", "", licence_id, "", idempotency_key, cancel))

    def activate_account_previous(self, licence_id: str, previous_credential: str | None, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> Snapshot:
        """Advanced: retry an account activation while rebinding a previous credential."""
        with self._operation(cancellation) as cancel:
            return _to_snapshot(self._activate("account", "", licence_id, previous_credential or "", idempotency_key, cancel))

    def _activate(self, principal: str, key: str, licence: str | None, previous: str, operation_id: str | None, cancel: threading.Event | None) -> dict[str, Any]:
        _validate_texts(key, licence or "", previous, operation_id or "")
        if principal == "key" and (not key or len(key.encode()) > 256):
            raise error(CONFIGURATION, "invalid_request")
        if principal == "account" and not opaque(licence or ""):
            raise error(CONFIGURATION, "invalid_request")
        if operation_id is not None and not 16 <= len(operation_id.encode()) <= 128 or previous and not _bearer(previous):
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
            if self._persistent_storage is not None:
                digest = _activation_input_digest(
                    self.config,
                    principal,
                    key,
                    licence,
                    previous,
                    session.metadata["customer"]["id"] if principal == "account" else None,
                )
                pending = self._persistent_storage.pending_activation
                if pending is not None:
                    now = wall_seconds()
                    if now < pending.created_at:
                        raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                    if now - pending.created_at > 86400:
                        raise error(CONFIGURATION, "pending_activation_recovery_required")
                    if pending.principal_kind != principal or pending.input_digest != digest:
                        raise error(CONFIGURATION, "pending_activation_conflict")
                    if operation_id is not None and operation_id != pending.operation_id:
                        raise error(CONFIGURATION, "pending_activation_conflict")
                    effective_operation_id = pending.operation_id
                    pending = PendingActivation(pending.operation_id, pending.principal_kind, pending.input_digest, pending.created_at)
                else:
                    effective_operation_id = operation_id or secrets.token_urlsafe(24)
                    pending = PendingActivation(effective_operation_id, principal, digest, wall_seconds())
                with self._state_lock:
                    if self._generation != original:
                        raise error(STALE_RESPONSE, "stale_response")
                    if self._offline_mode():
                        self._checkpoint_persistent_cache(force=True)
                    try:
                        version = self._persistent_storage.begin_activation(
                            self._storage_version,
                            pending,
                            preserve_credential=bool(previous),
                        )
                    except OrbitError as exc:
                        if exc.kind == STORAGE:
                            self._clear_all_locked()
                        raise
                    self._clear_access_locked()
                    generation = self._generation
                    self._storage_version = version
                    self._credential = saved_before if previous else None
                    if principal == "key":
                        self._account = None
            else:
                generation = self._invalidate(clear_account=principal == "key")
            # Idempotency IDs are optional on every mutation; generate one
            # with the SDK's existing secure random generator when omitted.
            # The persistent pending-activation path above already resolved
            # its own effective ID (and keeps it across retries); this only
            # fills the gap for callers or paths that did not.
            effective_operation_id = effective_operation_id or secrets.token_urlsafe(24)
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
            snapshot = self._accept(response, response_error, generation, None, licence if principal == "account" else None, started, cancel)
            if self._session_required and not self._session_disabled:
                self._start_session_internal(cancel, explicit=False)
                return self._snapshot()
            return snapshot
        finally:
            self._serial.release()

    def refresh(self, *, cancellation: Cancellation | None = None) -> Snapshot:
        with self._operation(cancellation) as cancel:
            return _to_snapshot(self._refresh(cancel, respect_retry=False))

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
                    last_failure = self._last_failure
                if snapshot["access"] not in ("refresh_required", "expired", "offline") or not retry_due:
                    if snapshot["access"] != "offline" and last_failure is not None:
                        raise last_failure
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
            snapshot = self._accept(response, response_error, generation, saved, None, started, cancel)
            if self._session_required and not self._session_disabled:
                self._start_session_internal(cancel, explicit=False)
                return self._snapshot()
            return snapshot
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

    def start_session(self, *, cancellation: Cancellation | None = None) -> Snapshot:
        """Acquire or reuse the current floating seat; ordinary/offline policy is a no-op."""
        with self._operation(cancellation) as cancel:
            self._sync_storage()
            if self._offline_mode():
                return _to_snapshot(self._snapshot())
            with self._state_lock:
                if self._credential is None:
                    raise NotActivatedError()
                self._session_disabled = False
                known = self._session_required or self._claims is not None
            if not known:
                self._refresh(cancel, respect_retry=False)
            if not self._session_required:
                return _to_snapshot(self._snapshot())
            return _to_snapshot(self._start_session_internal(cancel, explicit=True))

    def end_session(self, *, cancellation: Cancellation | None = None) -> Snapshot:
        """Release the current floating seat and disable automatic reacquisition."""
        with self._operation(cancellation) as cancel:
            self._sync_storage()
            if self._offline_mode():
                return _to_snapshot(self._snapshot())
            with self._state_lock:
                known = self._session_required or self._claims is not None
                if known and not self._session_required:
                    return _to_snapshot(self._snapshot_locked())
                # Preserve end intent even while the first activation is in
                # flight and its credential and policy have not arrived.
                self._session_disabled = True
                if self._credential is None:
                    return _to_snapshot(self._snapshot_locked())
            if not known:
                self._refresh(cancel, respect_retry=False)
            if not self._session_required:
                return _to_snapshot(self._snapshot())
            with self._state_lock:
                self._session_disabled = True
                self._generation += 1
                current = self._floating
                session_id = current[0].session_id if current is not None else self._pending_session_id
                credential = self._credential
                self._drop_floating_locked(release=False, clear_profile=False)
            if session_id and credential is not None:
                self._best_effort_session_release(session_id, credential, 2.0)
            return _to_snapshot(self._snapshot())

    def _start_session_internal(self, cancel: Any, *, explicit: bool) -> dict[str, Any]:
        generation = self._generation_now()
        while not self._session_lock.acquire(timeout=0.05):
            _check_cancel(cancel)
            self._check_generation(generation)
        sent = False
        session_id: str | None = None
        credential: StoredCredential | None = None
        session_cancel: threading.Event | None = None
        try:
            self._check_generation(generation)
            _check_cancel(cancel)
            self._sync_storage()
            with self._state_lock:
                if self._offline_mode():
                    return self._snapshot_locked()
                if not self._session_required:
                    return self._snapshot_locked()
                if self._session_disabled and not explicit:
                    raise error(DENIED, "session_explicitly_ended")
                credential = self._credential
                if credential is None:
                    raise NotActivatedError()
                if explicit:
                    self._session_disabled = False
                current = self._floating
                if current is not None:
                    try:
                        if current[1].now() < current[0].expires_at:
                            return self._snapshot_locked()
                    except OrbitError as exc:
                        self._drop_floating_locked(release=False, clear_profile=False)
                        raise exc
                    self._drop_floating_locked(release=False, clear_profile=False)
                if self._pending_session_id is None:
                    self._pending_session_id = secrets.token_urlsafe(24)
                session_id = self._pending_session_id
                session_cancel = self._session_cancel
            combined = _CombinedCancellation(cancel, session_cancel)
            started = Start.capture()
            route = f"{CLIENT_PREFIX}activations/{credential.activation_id}/sessions"
            sent = True
            response = self.transport.post(route, {**self._credential_body(credential), "session_id": session_id}, True, combined)
            grant, anchor = self._verify_session_reply(response, session_id, 1, credential, started, combined)
            self._check_generation(generation)
            _check_cancel(combined)
            with self._state_lock:
                if self._generation != generation or self._credential != credential or not self._session_required:
                    raise error(STALE_RESPONSE, "stale_response")
                self._floating = (grant, anchor)
                self._pending_session_id = None
                self._session_retry_deadline = None
                result = self._snapshot_locked()
            with self._lifecycle_condition:
                self._lifecycle_condition.notify_all()
            return result
        except OrbitError as exc:
            retry = exc.kind == TRANSIENT or exc.kind == DENIED and exc.code == "concurrent_session_limit_reached"
            with self._state_lock:
                if self._generation != generation or sent and self._credential != credential:
                    if sent and session_id and credential:
                        self._queue_session_release(session_id, credential)
                    if exc.kind == CANCELLED:
                        raise
                    raise error(STALE_RESPONSE, "stale_response") from exc
                if sent and session_id and credential:
                    if retry:
                        self._session_retry_deadline = time.monotonic() + random.randrange(15, 45)
                    else:
                        if self._pending_session_id == session_id:
                            self._pending_session_id = None
                        self._queue_session_release(session_id, credential)
                        if exc.code == "licence_revoked":
                            self._invalidate(clear_account=False)
                        elif exc.kind not in (CANCELLED, STALE_RESPONSE):
                            self._session_disabled = True
                            self._session_retry_deadline = None
            if sent and retry:
                with self._lifecycle_condition:
                    self._lifecycle_condition.notify_all()
            raise
        finally:
            self._session_lock.release()

    def _renew_session_internal(self, cancel: Any) -> dict[str, Any]:
        with self._state_lock:
            current = self._floating
        if current is None:
            return self._start_session_internal(cancel, explicit=False)
        generation = self._generation_now()
        while not self._session_lock.acquire(timeout=0.05):
            _check_cancel(cancel)
            self._check_generation(generation)
        sent = False
        acquired = True
        credential: StoredCredential | None = None
        try:
            self._check_generation(generation)
            _check_cancel(cancel)
            self._sync_storage()
            with self._state_lock:
                credential = self._credential
                if credential is None or not self._session_required or self._session_disabled or self._floating is not current:
                    raise error(STALE_RESPONSE, "stale_response")
                try:
                    if current[1].now() >= current[0].expires_at:
                        self._floating = None
                        self._pending_session_id = None
                        expired = True
                    else:
                        expired = False
                except OrbitError:
                    self._floating = None
                    raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                if not expired:
                    sequence = current[0].sequence + 1
                    if not strict_int(sequence, minimum=1, maximum=(1 << 53) - 1):
                        raise error(STORAGE, "storage_failed")
                    session_cancel = self._session_cancel
                    session_id = current[0].session_id
            if expired:
                self._session_lock.release()
                acquired = False
                return self._start_session_internal(cancel, explicit=False)
            combined = _CombinedCancellation(cancel, session_cancel)
            started = Start.capture()
            route = f"{CLIENT_PREFIX}activations/{credential.activation_id}/sessions/{session_id}/renew"
            sent = True
            response = self.transport.post(route, {**self._credential_body(credential), "sequence": sequence}, True, combined)
            grant, anchor = self._verify_session_reply(response, session_id, sequence, credential, started, combined)
            self._check_generation(generation)
            _check_cancel(combined)
            with self._state_lock:
                if self._generation != generation or self._credential != credential or self._floating is not current:
                    raise error(STALE_RESPONSE, "stale_response")
                self._floating = (grant, anchor)
                self._session_retry_deadline = None
                result = self._snapshot_locked()
            with self._lifecycle_condition:
                self._lifecycle_condition.notify_all()
            return result
        except OrbitError as exc:
            if sent and current[0].session_id and credential and exc.kind in (CANCELLED, STALE_RESPONSE):
                self._queue_session_release(current[0].session_id, credential)
            with self._state_lock:
                if self._generation != generation or self._credential != credential or self._floating is not current:
                    raise error(STALE_RESPONSE, "stale_response") from exc
                if exc.code == "licence_revoked":
                    revoke_credential = True
                else:
                    revoke_credential = False
                    # A terminal or malformed renewal response cannot keep
                    # authorizing the current interval or trigger a tight
                    # background retry. Explicit start_session can recover.
                    if exc.kind not in (TRANSIENT, CANCELLED, STALE_RESPONSE):
                        self._drop_floating_locked(release=False, clear_profile=False)
                        self._session_disabled = True
                        self._session_retry_deadline = None
            if revoke_credential:
                self._invalidate(clear_account=False)
                raise
            if exc.kind == TRANSIENT:
                with self._state_lock:
                    if self._generation != generation or self._credential != credential or self._floating is not current:
                        raise error(STALE_RESPONSE, "stale_response") from exc
                    self._session_retry_deadline = time.monotonic() + random.randrange(15, 45)
                    try:
                        snapshot = self._snapshot_locked()
                        if (snapshot["access"] == "online" and snapshot["session"] is not None
                                and snapshot["session"]["session_id"] == current[0].session_id
                                and snapshot["session"]["sequence"] == current[0].sequence):
                            return snapshot
                    except OrbitError:
                        pass
            raise
        finally:
            if acquired:
                self._session_lock.release()

    def _advance_session(self, cancel: Any) -> dict[str, Any]:
        self._sync_storage()
        should_start = False
        should_renew = False
        with self._state_lock:
            if self._offline_mode() or not self._session_required or self._session_disabled:
                return self._snapshot_locked()
            current = self._floating
            if self._credential is None:
                raise NotActivatedError()
            retry = self._session_retry_deadline
            if retry is not None and time.monotonic() < retry:
                return self._snapshot_locked()
            if current is None:
                should_start = True
            else:
                try:
                    if current[1].now() < current[0].refresh_after:
                        return self._snapshot_locked()
                    should_renew = True
                except OrbitError:
                    self._floating = None
                    raise error(CLOCK_UNCERTAIN, "clock_uncertain")
        if should_start:
            return self._start_session_internal(cancel, explicit=False)
        if should_renew:
            return self._renew_session_internal(cancel)
        return self._snapshot()

    def _verify_session_reply(
        self, data: bytes | None, session_id: str, sequence: int, credential: StoredCredential,
        started: Start, cancel: Any,
    ) -> tuple[SessionGrant, Anchor]:
        value = unique_json(data if data is not None else b"")
        value = fields(value, {"session_id": str, "sequence": int, "expires_at": str, "server_time": str, "grant": str}, exact=True)
        if value["session_id"] != session_id or value["sequence"] != sequence or not opaque(session_id) or len(session_id) < 16:
            raise error(INVALID_RESPONSE, "invalid_session_response")
        expires = timestamp(value["expires_at"])
        anchor = Anchor(timestamp(value["server_time"]), started)
        keys = self._session_keys
        try:
            key_known = keys is not None and keys.contains(value["grant"])
        except (AttributeError, ValueError, OrbitError):
            key_known = False
        if not key_known:
            _check_cancel(cancel)
            route = f"{JWKS_PATH}?application_id={self.config.application_id}&environment_id={self.config.environment_id}"
            raw = self.transport.get(route, cancel)
            if raw is None:
                raise error(INVALID_RESPONSE, "missing_session_jwks")
            keys = SessionKeys.parse(raw, self._environment)
            self._session_keys = keys
        expected_grant = Expected(
            issuer=self.config.issuer,
            application=self.config.application_id,
            environment=self.config.environment_id,
            licence=credential.licence_id,
            activation=credential.activation_id,
            installation=self.config.installation_id,
            fingerprint=self.config.fingerprint or None,
            fingerprint_provider=self.config.fingerprint_provider or None,
            credential_expires_at=credential.credential_expires_at,
            licence_expires_at=self._session_licence_expiry,
            now=anchor.now(),
            allow_unbound_fingerprint=True,
        )
        grant = verify_session_grant(value["grant"], keys, SessionExpected(expected_grant, session_id, sequence))
        if grant.expires_at != expires or grant.binding_mode != self._session_binding_mode:
            raise error(INVALID_RESPONSE, "invalid_session_response")
        return grant, anchor

    def _queue_session_release(self, session_id: str, credential: StoredCredential) -> None:
        def release() -> None:
            self._best_effort_session_release(session_id, credential, 2.0)
        threading.Thread(target=release, name="orbit-session-release", daemon=True).start()

    def _best_effort_session_release(self, session_id: str, credential: StoredCredential, timeout: float) -> None:
        cancelled = threading.Event()
        timer = threading.Timer(timeout, cancelled.set)
        timer.daemon = True
        timer.start()
        try:
            route = f"{CLIENT_PREFIX}activations/{credential.activation_id}/sessions/{session_id}/end"
            self.transport.post(route, self._credential_body(credential), True, cancelled)
        except BaseException:
            pass
        finally:
            timer.cancel()

    def _accept(self, response: bytes | None, response_error: OrbitError | None, generation: int, previous: StoredCredential | None, expected_licence: str | None, started: Start, cancel: threading.Event | None) -> dict[str, Any]:
        self._check_generation(generation)
        verifying = response_error is None
        result: tuple[StoredCredential, dict[str, Any] | None, Anchor | None, AccessState | None, bool, int | None, str] | None = None
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
            saved, claims, anchor, access, session_required, licence_expiry, binding_mode = result
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
                if not session_required:
                    self._drop_floating_locked(release=True, clear_profile=True)
                self._credential, self._claims, self._anchor = saved, claims, anchor
                self._persisted_access = access
                self._session_required = session_required
                self._session_licence_expiry = licence_expiry if session_required else None
                self._session_binding_mode = binding_mode if session_required else None
                if session_required and self._floating is not None and self._floating[0].activation_id != saved.activation_id:
                    self._drop_floating_locked(release=True, clear_profile=False)
                self._transient = False
                self._retry_deadline = None
                self._last_failure = None
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
        if (
            self._persistent_storage is not None
            and self._persistent_storage.pending_activation is None
            and failure.kind not in (DENIED, REAUTHENTICATION_REQUIRED)
        ):
            # A failed validation that is not an authoritative denial (TLS,
            # transport or malformed reply) drops cached authority but keeps the
            # saved credential, so a captive portal cannot force a new key prompt.
            with self._state_lock:
                if self._generation != generation:
                    raise error(STALE_RESPONSE, "stale_response")
                self._drop_floating_locked(release=False, clear_profile=True)
                self._generation += 1
                self._claims = None
                self._anchor = None
                self._persisted_access = None
                self._transient = False
                self._retry_deadline = time.monotonic() + random.randrange(15, 45)
                self._last_failure = failure
                try:
                    self._persistent_storage.clear_access()
                except BaseException as exc:
                    self._clear_all_locked()
                    raise error(STORAGE, "storage_failed") from exc
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

    def _verify_reply(self, data: bytes, previous: StoredCredential | None, expected_licence: str | None, started: Start, cancel: threading.Event | None) -> tuple[StoredCredential, dict[str, Any] | None, Anchor | None, AccessState | None, bool, int | None, str]:
        reply = unique_json(data)
        had_session_flag = isinstance(reply, dict) and "session_required" in reply
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
            "session_required": (bool, type(None)),
            "licence_id": (str, type(None)),
        }
        optional = ("credential", "grant", "fingerprint_provider", "licence_expires_at", "session_required", "licence_id")
        if not self._persistent:
            optional += ("credential_expires_at",)
        reply = fields(reply, expected_fields, optional=optional)
        if reply["secret_replay_expired"]:
            raise error(REAUTHENTICATION_REQUIRED, "secret_replay_expired")
        if (
            not opaque(reply["activation_id"])
            or reply["installation_id"] != self.config.installation_id
            or reply["fingerprint_provider"] != (self.config.fingerprint_provider or None)
            or reply["binding_mode"] not in ("hwid", "none")
            or had_session_flag and reply["session_required"] is not True
            or (reply["session_required"] is True and reply["grant"] is not None)
            or (reply["session_required"] is not True and reply["grant"] is None)
        ):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        session_required = reply["session_required"] is True
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
        licence_expiry = timestamp(reply["licence_expires_at"]) if reply["licence_expires_at"] is not None else None
        if session_required and (
            not opaque(reply["licence_id"])
            or expected_licence is not None and reply["licence_id"] != expected_licence
            or previous is not None and reply["licence_id"] != previous.licence_id
        ):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        bearer = reply["credential"] if reply["credential"] is not None else previous.credential if previous is not None else None
        if bearer is None or not _bearer(bearer):
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        if session_required:
            stored = StoredCredential(
                application_id=self.config.application_id,
                environment_id=self.config.environment_id,
                activation_id=reply["activation_id"],
                licence_id=reply["licence_id"],
                installation_id=self.config.installation_id,
                credential=bearer,
                credential_expires_at=expiry,
                fingerprint=self.config.fingerprint or None,
                fingerprint_provider=self.config.fingerprint_provider or None,
            )
            return stored, None, None, None, True, licence_expiry, reply["binding_mode"]
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
        token = reply["grant"]
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
            allow_unbound_fingerprint=True,
        )
        claims = verify(token, keys, expected)
        if claims["binding_mode"] != reply["binding_mode"]:
            raise error(INVALID_RESPONSE, "invalid_activation_response")
        credential = bearer
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
        return stored, claims, anchor, access, False, None, reply["binding_mode"]

    def require_access(self, feature: str, *, cancellation: Cancellation | None = None) -> Snapshot:
        with self._operation(cancellation) as cancel:
            _check_cancel(cancel)
            snapshot = self._snapshot()
            if snapshot.get("offline_file_mode", False):
                _check_cancel(cancel)
                if snapshot["access"] == "expired":
                    raise error(DENIED, "offline_file_expired")
                if snapshot["access"] != "offline":
                    raise error(CLOCK_UNCERTAIN, "clock_uncertain")
                if not snapshot["entitlements"].get(feature, False):
                    raise FeatureUnavailableError()
                return _to_snapshot(snapshot)
            if self._session_required:
                with self._state_lock:
                    current = self._floating
                    disabled = self._session_disabled
                if current is not None:
                    try:
                        if current[1].now() < current[0].expires_at:
                            if not current[0].entitlements.get(feature, False):
                                raise FeatureUnavailableError()
                            final = self._snapshot()
                            _check_cancel(cancel)
                            if final["access"] != "online" or not final["entitlements"].get(feature, False):
                                raise error(DENIED, "session_access_unavailable")
                            return _to_snapshot(final)
                    except OrbitError as exc:
                        if exc.kind != CLOCK_UNCERTAIN:
                            raise
                        with self._state_lock:
                            self._drop_floating_locked(release=False, clear_profile=False)
                if disabled:
                    raise error(DENIED, "session_explicitly_ended")
                _check_cancel(cancel)
                snapshot = self._start_session_internal(cancel, explicit=False)
                if snapshot["access"] == "online":
                    if not snapshot["entitlements"].get(feature, False):
                        raise FeatureUnavailableError()
                    final = self._snapshot()
                    _check_cancel(cancel)
                    if final["access"] != "online":
                        raise error(DENIED, "session_access_unavailable")
                    if not final["entitlements"].get(feature, False):
                        raise FeatureUnavailableError()
                    return _to_snapshot(final)
                raise error(DENIED, "session_access_unavailable")
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
                    if self._credential is not None and self._transient:
                        raise error(TRANSIENT, "network_unavailable")
                raise NotActivatedError()
            if not snapshot["entitlements"].get(feature, False):
                raise FeatureUnavailableError()
            return _to_snapshot(snapshot)

    def ensure_access(
        self,
        feature: str,
        ask_for_key: Callable[[], str | None],
        *,
        cancellation: Cancellation | None = None,
    ) -> Snapshot:
        """Call ``require_access``; only when there is no usable access at all
        does it call ``ask_for_key()`` and, given a non-empty key, ``activate``
        before checking access again. Any other error (including a network
        outage) propagates unchanged and never prompts."""
        try:
            return self.require_access(feature, cancellation=cancellation)
        except NotActivatedError:
            key = ask_for_key()
            if not key:
                raise
            self.activate(key, cancellation=cancellation)
            return self.require_access(feature, cancellation=cancellation)

    def deactivate(self, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> None:
        with self._operation(cancellation) as cancel:
            _validate_texts(idempotency_key or "")
            if idempotency_key is not None and not 16 <= len(idempotency_key.encode()) <= 128:
                raise error(CONFIGURATION, "invalid_request")
            effective_operation_id = idempotency_key or secrets.token_urlsafe(24)
            self._sync_storage()
            with self._state_lock:
                saved = self._credential
            if saved is None:
                raise error(REAUTHENTICATION_REQUIRED, "reauthentication_required")
            generation = self._invalidate(clear_account=False)
            body = self._credential_body(saved)
            body["idempotency_key"] = effective_operation_id
            try:
                result = self.transport.post(f"{CLIENT_PREFIX}activations/{saved.activation_id}/deactivate", body, True, cancel)
            except OrbitError:
                self._check_generation(generation)
                raise
            self._check_generation(generation)
            if result is not None:
                raise error(INVALID_RESPONSE, "unexpected_response_body")

    def check_for_update(self, installed_release_number: int, *, channel: str = "stable",
                         target: online.UpdateTarget | None = None, cancellation: Cancellation | None = None) -> online.Update | None:
        body = online.update_input(installed_release_number, channel, target)
        return self._online_request("updates", body, lambda v: online.parse_update(v, body), cancellation)

    def authorize_download(self, release_id: str, artifact_id: str, *, cancellation: Cancellation | None = None) -> online.DownloadAuthorization:
        online.require(release_id, online.identifier)
        online.require(artifact_id, online.identifier)
        return self._online_request("downloads/authorize", dict(release_id=release_id, artifact_id=artifact_id),
                                    lambda v: online.parse_authorization(v, release_id, artifact_id), cancellation)

    def download(self, authorization: online.DownloadAuthorization, destination: str | os.PathLike[str], *,
                 max_bytes: int, replace: bool = False, cancellation: Cancellation | None = None) -> Path:
        """Stream directly from the seller and atomically expose verified bytes."""
        from .download_file import download_file
        with self._operation(cancellation) as cancel:
            return download_file(authorization, destination, max_bytes=max_bytes, replace=replace, cancellation=cancel)

    def usage(self, name: str, *, cancellation: Cancellation | None = None) -> online.UsageCounter:
        online.require(name, online.name)
        return self._online_request(f"usage/{name}", {}, lambda v: online.parse_counter(v, name, True), cancellation)

    def consume(self, name: str, units: int = 1, idempotency_key: str | None = None, *,
                cancellation: Cancellation | None = None) -> online.UsageConsumption:
        online.require(name, online.name)
        online.require(units, lambda v: online.integer(v, 1))
        key = online.operation_id(idempotency_key)
        return self._online_request(f"usage/{name}/consume", dict(units=units, idempotency_key=key),
                                    lambda v: online.parse_consumption(v, name, key, units), cancellation, key)

    def resources(self, name: str, *, cancellation: Cancellation | None = None) -> online.ResourceCounter:
        online.require(name, online.name)
        return self._online_request(f"resources/{name}", {}, lambda v: online.parse_counter(v, name, False), cancellation)

    def acquire_resource(self, name: str, resource_id: str, units: int = 1, idempotency_key: str | None = None, *,
                         cancellation: Cancellation | None = None) -> online.ResourceAllocation:
        online.require(name, online.name)
        online.require(resource_id, online.identifier)
        online.require(units, lambda v: online.integer(v, 1))
        key = online.operation_id(idempotency_key)
        return self._online_request(f"resources/{name}/acquire", dict(resource_id=resource_id, units=units, idempotency_key=key),
                                    lambda v: online.parse_allocation(v, name, key, resource_id=resource_id, units=units), cancellation, key)

    def release_resource(self, name: str, allocation_id: str, idempotency_key: str | None = None, *,
                         cancellation: Cancellation | None = None) -> online.ResourceAllocation:
        online.require(name, online.name)
        online.require(allocation_id, online.identifier)
        key = online.operation_id(idempotency_key)
        return self._online_request(f"resources/{name}/allocations/{allocation_id}/release", dict(idempotency_key=key),
                                    lambda v: online.parse_allocation(v, name, key, allocation_id=allocation_id), cancellation, key)

    def _online_request(self, route: str, extra: dict[str, Any], parse: Callable[..., Any],
                        cancellation: Cancellation | None, key: str | None = None) -> Any:
        with self._operation(cancellation) as cancel:
            _check_cancel(cancel)
            generation = self._generation_now()
            with self._state_lock:
                saved = self._credential
                if saved is None or self._offline_mode():
                    raise NotActivatedError()
            try:
                response = self.transport.post(f"{CLIENT_PREFIX}activations/{saved.activation_id}/{route}",
                                               self._credential_body(saved) | extra, True, cancel)
                self._check_response_generation(generation, cancel)
                return parse(unique_json(response))
            except OrbitError as exc:
                try:
                    self._check_response_generation(generation, cancel)
                except OrbitError as changed:
                    exc = changed
                if key is not None and (exc.kind != DENIED or exc.status >= 500):
                    raise online.MutationUncertainError(key, exc) from None
                raise exc

    def account(self, *, cancellation: Cancellation | None = None) -> Account | None:
        with self._operation(cancellation) as cancel:
            _check_cancel(cancel)
            self._sync_storage()
            with self._state_lock:
                return None if self._account is None else _to_account(self._account.metadata)

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

    def login(self, username: str, password: str, *, cancellation: Cancellation | None = None) -> Account:
        with self._operation(cancellation) as cancel:
            _validate_texts(username, password)
            if not username or len(username.encode()) > 128 or len(password.encode()) > 256:
                raise error(CONFIGURATION, "invalid_request")
            generation = self._generation_now()
            self._acquire_serial(generation, cancel)
            try:
                generation = self._invalidate(clear_account=True, preserve_pending=True)
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
                return _to_account(account)
            finally:
                self._serial.release()

    def owned_licences(self, cursor: str | None = None, *, cancellation: Cancellation | None = None) -> OwnedLicencePage:
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
                clean_items = tuple(_to_owned_licence(_check_licence(licence)) for licence in page["items"])
                self._finish_account(generation, None, cancel)
                return OwnedLicencePage(clean_items, page["next_cursor"])
            except OrbitError as exc:
                self._finish_account(generation, exc, cancel)
                raise
            finally:
                self._serial.release()

    def claim_licence(self, licence_key: str, idempotency_key: str | None = None, *, cancellation: Cancellation | None = None) -> OwnedLicence:
        with self._operation(cancellation) as cancel:
            _validate_texts(licence_key, idempotency_key or "")
            if not licence_key or len(licence_key.encode()) > 256 or idempotency_key is not None and not 16 <= len(idempotency_key.encode()) <= 128:
                raise error(CONFIGURATION, "invalid_request")
            licence = self._account_post(
                CLIENT_PREFIX + "licence-claims",
                {"licence_key": licence_key, "idempotency_key": idempotency_key or secrets.token_urlsafe(24)},
                True,
                cancel,
                validate=_check_licence,
            )
            return _to_owned_licence(licence)

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
                return RegistrationResult(True, _instant(timestamp(value["expires_at"])), pending)
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

    def logout_account(self, *, cancellation: Cancellation | None = None) -> None:
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
                self._storage_version = (
                    self._persistent_storage.invalidate(preserve_pending=True)
                    if self._persistent_storage is not None
                    else self._storage.invalidate()
                )
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
        release: tuple[str, StoredCredential] | None = None
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._lifecycle_stop.set()
            with self._lifecycle_condition:
                self._lifecycle_condition.notify_all()
            thread = self._lifecycle_thread
            from_lifecycle = thread is threading.current_thread()
            with self._state_lock:
                current = self._floating
                session_id = current[0].session_id if current is not None else self._pending_session_id
                credential = self._credential
                if session_id and credential is not None:
                    release = (session_id, credential)
                self._drop_floating_locked(release=False, clear_profile=False)
            while self._active and not from_lifecycle:
                self._condition.wait()
            if from_lifecycle:
                self._close_deferred = True
        if release is not None:
            self._best_effort_session_release(release[0], release[1], 2.0)
        if from_lifecycle:
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


def _parse_app_key(value: str | AppKey) -> AppKey:
    if type(value) is AppKey:
        return AppKey.validate(value)
    if isinstance(value, AppKey):
        raise error(CONFIGURATION, "invalid_app_key")
    return AppKey.parse(value)


def _resolve_binding(app_key: AppKey, device_binding: DeviceBinding | None, machine_binding: bool) -> DeviceBinding | None:
    if not isinstance(machine_binding, bool):
        raise TypeError("machine_binding must be a bool")
    if device_binding is not None:
        if not isinstance(device_binding, DeviceBinding):
            raise TypeError("device_binding must be a DeviceBinding or None")
        # Revalidate an instance made through unusual Python object creation.
        return DeviceBinding(device_binding.fingerprint, device_binding.provider)
    if not machine_binding:
        return None
    try:
        return DeviceBinding(native_fingerprint(app_key.application_id, app_key.environment_id), "machine_v1")
    except OrbitError as exc:
        if exc.kind == DENIED and exc.code == "device_identity_unavailable":
            return None
        raise


def _instant(value: int | str) -> dt.datetime:
    seconds = timestamp(value) if isinstance(value, str) else value
    try:
        return dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise error(INVALID_RESPONSE, "invalid_timestamp") from exc


def _to_snapshot(value: dict[str, Any]) -> Snapshot:
    try:
        access = AccessStatus(value["access"])
    except (KeyError, ValueError) as exc:
        raise error(INVALID_RESPONSE, "invalid_snapshot") from exc
    entitlements = value["entitlements"]
    if not valid_entitlements(entitlements):
        raise error(INVALID_RESPONSE, "invalid_snapshot")
    return Snapshot(
        access=access,
        entitlements=MappingProxyType(dict(entitlements)),
        expires_at=None if value["expires_at"] is None else _instant(value["expires_at"]),
        next_check_at=None if value["next_check_at"] is None else _instant(value["next_check_at"]),
        credential_expires_at=None if value["credential_expires_at"] is None else _instant(value["credential_expires_at"]),
        reauthentication_required=value["reauthentication_required"],
        offline_allowed=value["offline_allowed"],
        remaining_offline=dt.timedelta(seconds=value["remaining_offline_seconds"]),
        session=None if value.get("session") is None else SessionMetadata(
            session_id=value["session"]["session_id"],
            sequence=value["session"]["sequence"],
            expires_at=_instant(value["session"]["expires_at"]),
            refresh_after=_instant(value["session"]["refresh_after"]),
        ),
        offline_file_mode=bool(value.get("offline_file_mode", False)),
    )


def _to_account(value: dict[str, Any]) -> Account:
    customer = value["customer"]
    return Account(
        id=customer["id"],
        username=customer["username"],
        email=customer["email"],
        suspended=customer["suspended"],
        created_at=_instant(customer["created_at"]),
        session_expires_at=_instant(value["expires_at"]),
    )


def _to_owned_licence(value: dict[str, Any]) -> OwnedLicence:
    return OwnedLicence(
        id=value["id"],
        policy_name=value["policy_name"],
        state=value["state"],
        expiry_mode=value["expiry_mode"],
        first_used_at=None if value["first_used_at"] is None else _instant(value["first_used_at"]),
        expires_at=None if value["expires_at"] is None else _instant(value["expires_at"]),
        duration=None if value["duration_seconds"] is None else dt.timedelta(seconds=value["duration_seconds"]),
        device_limit=value["device_limit"],
        concurrent_session_limit=value["concurrent_session_limit"],
        hwid_locked=value["hwid_locked"],
        offline_allowed=value["offline_allowed"],
        offline_duration=dt.timedelta(seconds=value["offline_seconds"]),
        offline_file_duration=dt.timedelta(seconds=value["offline_file_seconds"]),
        entitlements=MappingProxyType(dict(value["entitlements"])),
        usage_limits=online.parse_definitions(value["usage_limits"], True),
        resource_limits=online.parse_definitions(value["resource_limits"], False),
    )


@dataclass(frozen=True)
class _Device:
    installation_id: str
    fingerprint: str | None
    fingerprint_provider: str | None


def _validate_config(config: _Config) -> None:
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


def _validate_app_scope(scope: _AppScope) -> None:
    if not isinstance(scope, _AppScope):
        raise TypeError("app scope must be an internal _AppScope")
    if scope.environment not in ("test", "live"):
        raise error(CONFIGURATION, "invalid_app_key")
    values = (scope.api_origin, scope.application_id, scope.environment_id, scope.issuer)
    if any(not isinstance(value, str) for value in values):
        raise TypeError("Orbit SDK configuration values must be strings")
    if scope.fingerprint is not None and not isinstance(scope.fingerprint, str):
        raise TypeError("fingerprint must be text or None")
    if scope.fingerprint_provider is not None and not isinstance(scope.fingerprint_provider, str):
        raise TypeError("fingerprint_provider must be text or None")
    runtime = _Config(
        api_origin=scope.api_origin,
        application_id=scope.application_id,
        environment_id=scope.environment_id,
        issuer=scope.issuer,
        installation_id="validation_installation_123",
        fingerprint=scope.fingerprint or "",
        fingerprint_provider=scope.fingerprint_provider or "",
    )
    _validate_config(runtime)


def _activation_input_digest(
    config: _Config,
    principal_kind: str,
    licence_key: str,
    licence_id: str | None,
    previous_credential: str = "",
    customer_id: str | None = None,
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
        value["customer_id"] = customer_id
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
        "concurrent_session_limit": int,
        "hwid_locked": bool,
        "offline_allowed": bool,
        "offline_seconds": int,
        "offline_file_seconds": int,
        "entitlements": dict,
        "usage_limits": dict,
        "resource_limits": dict,
    }, optional=("first_used_at", "expires_at", "duration_seconds"))
    features = licence["entitlements"]
    online.parse_definitions(licence["usage_limits"], True)
    online.parse_definitions(licence["resource_limits"], False)
    if (
        not opaque(licence["id"])
        or not 1 <= licence["device_limit"] <= 100
        or not strict_int(licence["concurrent_session_limit"], minimum=0, maximum=65535)
        or len(licence["policy_name"]) > 80
        or len(features) > 64
        or any(not isinstance(name, str) or not isinstance(enabled, bool) for name, enabled in features.items())
    ):
        raise error(INVALID_RESPONSE, "invalid_licence")
    if licence["duration_seconds"] is not None and not strict_int(licence["duration_seconds"]):
        raise error(INVALID_RESPONSE, "invalid_licence")
    if not strict_int(licence["offline_seconds"], minimum=-(1 << 31), maximum=(1 << 31) - 1):
        raise error(INVALID_RESPONSE, "invalid_licence")
    file_seconds = licence["offline_file_seconds"]
    if not strict_int(file_seconds, minimum=0, maximum=31_622_400) or 0 < file_seconds < 86_400:
        raise error(INVALID_RESPONSE, "invalid_licence")
    for date in (licence["first_used_at"], licence["expires_at"]):
        if date is not None:
            timestamp(date)
    return {name: licence[name] for name in (
        "id", "policy_name", "state", "expiry_mode", "first_used_at", "expires_at",
        "duration_seconds", "device_limit", "concurrent_session_limit", "hwid_locked", "offline_allowed", "offline_seconds", "offline_file_seconds", "entitlements", "usage_limits", "resource_limits",
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
