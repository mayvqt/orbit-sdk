from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .device import installation_id_new, lower_hex, opaque, valid_provider
from .errors import STALE_RESPONSE, STORAGE, OrbitError, error
from .jsonutil import strict_int, unique_json
from .storage import MAX_GENERATION, _LinuxLease
from .transport import _safe_origin

MAX_ENVELOPE = 64 * 1024
MAX_JWS = 16 * 1024
RECORD_FILE = "orbit-storage.bin"
LOCK_FILE = "orbit-storage.lock"
MAX_TIMESTAMP = (1 << 63) - 1


@dataclass(frozen=True)
class PendingActivation:
    operation_id: str
    principal_kind: str
    input_digest: str
    created_at: int

    def __repr__(self) -> str:
        return "PendingActivation(<redacted>)"


@dataclass(frozen=True)
class AccessState:
    jws: str
    jwks: dict[str, Any]
    licence_expires_at: int | None
    received_server_time: int
    received_wall_time: int
    server_high_water: int
    wall_high_water: int

    def __repr__(self) -> str:
        return "AccessState(<redacted>)"


@dataclass(frozen=True)
class InstallationState:
    installation_id: str
    fingerprint: str | None
    fingerprint_provider: str | None
    generation: int
    credential: Any | None
    pending_activation: PendingActivation | None
    access: AccessState | None

    def __repr__(self) -> str:
        return "InstallationState(<redacted>)"


def canonical_origin(value: str) -> str:
    parsed = _safe_origin(value)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port
    authority = host if port in (None, 443) else f"{host}:{port}"
    return f"https://{authority}"


def canonical_scope(config: Any) -> dict[str, str]:
    return {
        "api_origin": canonical_origin(config.api_origin),
        "issuer": config.issuer,
        "application_id": config.application_id,
        "environment_id": config.environment_id,
    }


def scope_key(scope: dict[str, str]) -> str:
    raw = json.dumps(scope, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"orbit.installed-client.scope.v2\0" + raw).hexdigest()


def default_state_directory(config: Any) -> str:
    digest = scope_key(canonical_scope(config))
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if not base or not os.path.isabs(base):
            raise error(STORAGE, "storage_unavailable")
        return os.path.join(base, "Orbit", digest)
    if not sys.platform.startswith("linux"):
        raise error(STORAGE, "storage_unavailable")
    base = os.environ.get("XDG_STATE_HOME")
    if not base:
        home = os.path.expanduser("~")
        if not home or home == "~":
            raise error(STORAGE, "storage_unavailable")
        base = os.path.join(home, ".local", "state")
    if not os.path.isabs(base):
        raise error(STORAGE, "storage_failed")
    return os.path.join(base, "orbit", digest)


def _ensure_directory(path: str) -> str:
    if not os.path.isabs(path) or "\0" in path or ".." in Path(path).parts:
        raise error(STORAGE, "storage_failed")
    try:
        if sys.platform.startswith("linux"):
            _ensure_linux_directory(path)
        elif sys.platform == "win32":
            _ensure_windows_directory(path)
        else:
            raise error(STORAGE, "storage_unavailable")
    except OrbitError:
        raise
    except OSError as exc:
        raise error(STORAGE, "storage_failed") from exc
    return os.path.normpath(path)


def _ensure_linux_directory(path: str) -> None:
    parts = Path(path).parts
    if not parts or parts[0] != "/":
        raise error(STORAGE, "storage_failed")
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    current = "/"
    try:
        for index, part in enumerate(parts[1:]):
            if part in ("", "."):
                continue
            try:
                next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            except FileNotFoundError:
                created = False
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
                if created:
                    os.fsync(fd)
                next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = next_fd
            current = os.path.join(current, part)
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_nlink == 0:
                raise error(STORAGE, "storage_failed")
            # Existing ancestors may be shared system/user directories. The
            # dedicated leaf alone must be private; missing components are
            # created private and existing permissions are never changed.
            if index == len(parts[1:]) - 1 and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                raise error(STORAGE, "storage_failed")
    except OrbitError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise error(STORAGE, "storage_failed") from exc
    os.close(fd)


def _ensure_windows_directory(path: str) -> None:
    import ctypes
    import ntpath
    from .storage_windows import (
        _FILE_FLAG_BACKUP_SEMANTICS, _FILE_FLAG_OPEN_REPARSE_POINT,
        _GENERIC_READ, _OPEN_EXISTING, _close, _check_directory, _open_handle, _kernel32,
    )
    from .storage_windows_security import check_private, create_private_directory

    drive, tail = ntpath.splitdrive(path)
    if not drive or len(drive) != 2 or drive[1] != ":" or not tail.startswith(("\\", "/")) or "\0" in path:
        raise error(STORAGE, "storage_failed")
    current = drive.upper() + "\\"
    components = [part for part in tail.replace("/", "\\").split("\\") if part]
    if not components or any(part in (".", "..") or ":" in part or part.endswith((".", " ")) for part in components):
        raise error(STORAGE, "storage_failed")
    kernel = _kernel32()
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    if kernel.GetDriveTypeW(current) not in (2, 3, 6):
        raise error(STORAGE, "storage_failed")
    handles: list[int] = []
    try:
        # Keep ancestors pinned against replacement until the leaf is checked.
        for index, part in enumerate([None, *components]):
            if part is not None:
                current = ntpath.join(current, part)
            try:
                handle = _open_handle(current, _GENERIC_READ, 3, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)
            except OrbitError:
                if part is None or os.path.lexists(current):
                    raise
                create_private_directory(current)
                handle = _open_handle(current, _GENERIC_READ, 3, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)
            handles.append(handle)
            _check_directory(handle)
            if index == len(components):
                check_private(handle)
    finally:
        for handle in reversed(handles):
            _close(handle)


def _bearer(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 43 and value.isascii() and all(char.isalnum() or char in "_-" for char in value)


def _safe_credential(credential: Any, config: Any, installation: str, fingerprint: str | None, provider: str | None) -> bool:
    return (
        credential is not None
        and credential.application_id == config.application_id
        and credential.environment_id == config.environment_id
        and credential.installation_id == installation
        and credential.fingerprint == fingerprint
        and credential.fingerprint_provider == provider
        and opaque(credential.activation_id)
        and opaque(credential.licence_id)
        and _bearer(credential.credential)
        and (credential.credential_expires_at is None or strict_int(credential.credential_expires_at, minimum=1, maximum=MAX_TIMESTAMP))
    )


def _access_to_json(access: AccessState | None) -> Any:
    if access is None:
        return None
    return {
        "jws": access.jws,
        "jwks": access.jwks,
        "licence_expires_at": access.licence_expires_at,
        "received_server_time": access.received_server_time,
        "received_wall_time": access.received_wall_time,
        "server_high_water": access.server_high_water,
        "wall_high_water": access.wall_high_water,
    }


def _pending_to_json(pending: PendingActivation | None) -> Any:
    if pending is None:
        return None
    return {
        "operation_id": pending.operation_id,
        "principal_kind": pending.principal_kind,
        "input_digest": pending.input_digest,
        "created_at": pending.created_at,
    }


def encode_envelope(config: Any, provider: str, state: InstallationState) -> bytes:
    if provider not in ("private_file", "windows_dpapi"):
        raise error(STORAGE, "storage_failed")
    scope = canonical_scope(config)
    if (
        not opaque(state.installation_id) or len(state.installation_id) < 16
        or (state.fingerprint is None) != (state.fingerprint_provider is None)
        or state.fingerprint is not None and (not lower_hex(state.fingerprint, 64) or not valid_provider(state.fingerprint_provider))
        or not strict_int(state.generation, minimum=0, maximum=MAX_GENERATION)
        or state.credential is not None and not _safe_credential(state.credential, config, state.installation_id, state.fingerprint, state.fingerprint_provider)
    ):
        raise error(STORAGE, "storage_failed")
    pending = state.pending_activation
    if pending is not None and (
        not isinstance(pending, PendingActivation)
        or not isinstance(pending.operation_id, str) or not 16 <= len(pending.operation_id.encode("utf-8", "strict")) <= 128
        or pending.principal_kind not in ("key", "account")
        or not lower_hex(pending.input_digest, 64)
        or not strict_int(pending.created_at, minimum=0, maximum=MAX_TIMESTAMP)
    ):
        raise error(STORAGE, "storage_failed")
    access = state.access
    if access is not None:
        from .grants import Keys
        if (
            state.credential is None
            or not isinstance(access.jws, str) or not access.jws.isascii() or len(access.jws) > MAX_JWS
            or not isinstance(access.jwks, dict) or access.jwks.keys() != {"keys"}
            or access.licence_expires_at is not None and not strict_int(access.licence_expires_at, minimum=1, maximum=MAX_TIMESTAMP)
            or not strict_int(access.received_server_time, minimum=0, maximum=MAX_TIMESTAMP)
            or not strict_int(access.received_wall_time, minimum=0, maximum=MAX_TIMESTAMP)
            or not strict_int(access.server_high_water, minimum=access.received_server_time, maximum=MAX_TIMESTAMP)
            or not strict_int(access.wall_high_water, minimum=access.received_wall_time, maximum=MAX_TIMESTAMP)
            or abs((access.server_high_water - access.received_server_time) - (access.wall_high_water - access.received_wall_time)) > 30
        ):
            raise error(STORAGE, "storage_failed")
        keys = Keys.parse(access.jwks)
        if len(keys._entries) != 1:
            raise error(STORAGE, "storage_failed")
    credential = None if state.credential is None else {
        "activation_id": state.credential.activation_id,
        "licence_id": state.credential.licence_id,
        "bearer": state.credential.credential,
        "expires_at": state.credential.credential_expires_at,
    }
    value = {
        "sdk": "orbit.installed-client",
        "format": 2,
        "provider": provider,
        "scope": scope,
        "installation": {
            "id": state.installation_id,
            "fingerprint": state.fingerprint,
            "fingerprint_provider": state.fingerprint_provider,
        },
        "generation": state.generation,
        "credential": credential,
        "pending_activation": _pending_to_json(pending),
        "access": _access_to_json(access),
    }
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(raw) > MAX_ENVELOPE:
        raise error(STORAGE, "storage_failed")
    return raw


def decode_envelope(config: Any, provider: str, raw: bytes) -> InstallationState:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ENVELOPE:
        raise error(STORAGE, "storage_failed")
    try:
        value = unique_json(raw)
        names = {"sdk", "format", "provider", "scope", "installation", "generation", "credential", "pending_activation", "access"}
        if not isinstance(value, dict) or value.keys() != names:
            raise ValueError
        scope = value["scope"]
        if not isinstance(scope, dict) or scope.keys() != {"api_origin", "issuer", "application_id", "environment_id"}:
            raise ValueError
        if (
            value["sdk"] != "orbit.installed-client" or type(value["format"]) is not int or value["format"] != 2
            or value["provider"] != provider or scope != canonical_scope(config)
            or not strict_int(value["generation"], minimum=0, maximum=MAX_GENERATION)
        ):
            raise ValueError
        install = value["installation"]
        if not isinstance(install, dict) or install.keys() != {"id", "fingerprint", "fingerprint_provider"}:
            raise ValueError
        installation_id = install["id"]
        fingerprint, fingerprint_provider = install["fingerprint"], install["fingerprint_provider"]
        if (
            not opaque(installation_id) or len(installation_id) < 16
            or (fingerprint is None) != (fingerprint_provider is None)
            or fingerprint is not None and (not lower_hex(fingerprint, 64) or not valid_provider(fingerprint_provider))
            or fingerprint != (config.fingerprint or None)
            or fingerprint_provider != (config.fingerprint_provider or None)
        ):
            raise ValueError
        credential = None
        if value["credential"] is not None:
            item = value["credential"]
            if not isinstance(item, dict) or item.keys() != {"activation_id", "licence_id", "bearer", "expires_at"}:
                raise ValueError
            expiry = item["expires_at"]
            if expiry is not None and not strict_int(expiry, minimum=1, maximum=MAX_TIMESTAMP):
                raise ValueError
            if not opaque(item["activation_id"]) or not opaque(item["licence_id"]) or not _bearer(item["bearer"]):
                raise ValueError
            from .storage import StoredCredential
            credential = StoredCredential(
                application_id=config.application_id,
                environment_id=config.environment_id,
                activation_id=item["activation_id"],
                licence_id=item["licence_id"],
                installation_id=installation_id,
                credential=item["bearer"],
                credential_expires_at=expiry,
                fingerprint=fingerprint,
                fingerprint_provider=fingerprint_provider,
            )
        pending = None
        if value["pending_activation"] is not None:
            item = value["pending_activation"]
            if not isinstance(item, dict) or item.keys() != {"operation_id", "principal_kind", "input_digest", "created_at"}:
                raise ValueError
            if (
                not isinstance(item["operation_id"], str) or not 16 <= len(item["operation_id"].encode("utf-8", "strict")) <= 128
                or item["principal_kind"] not in ("key", "account")
                or not lower_hex(item["input_digest"], 64)
                or not strict_int(item["created_at"], minimum=0, maximum=MAX_TIMESTAMP)
            ):
                raise ValueError
            pending = PendingActivation(item["operation_id"], item["principal_kind"], item["input_digest"], item["created_at"])
        access = None
        if value["access"] is not None:
            item = value["access"]
            if not isinstance(item, dict) or item.keys() != {"jws", "jwks", "licence_expires_at", "received_server_time", "received_wall_time", "server_high_water", "wall_high_water"}:
                raise ValueError
            expiry = item["licence_expires_at"]
            numbers = ("received_server_time", "received_wall_time", "server_high_water", "wall_high_water")
            if (
                not isinstance(item["jws"], str) or not item["jws"].isascii() or not 1 <= len(item["jws"]) <= MAX_JWS
                or not isinstance(item["jwks"], dict) or item["jwks"].keys() != {"keys"}
                or expiry is not None and not strict_int(expiry, minimum=1, maximum=MAX_TIMESTAMP)
                or any(not strict_int(item[name], minimum=0, maximum=MAX_TIMESTAMP) for name in numbers)
                or credential is None
            ):
                raise ValueError
            from .grants import Keys
            keys = Keys.parse(item["jwks"])
            if len(keys._entries) != 1:
                raise ValueError
            access = AccessState(item["jws"], item["jwks"], expiry, *(item[name] for name in numbers))
        return InstallationState(installation_id, fingerprint, fingerprint_provider, value["generation"], credential, pending, access)
    except (ValueError, TypeError, KeyError, UnicodeError, OrbitError) as exc:
        if isinstance(exc, OrbitError) and exc.kind == STORAGE:
            raise
        raise error(STORAGE, "storage_failed") from exc


class InstallationStorage:
    """Private, leased format-2 installation state for ``Client.open``."""

    def __init__(self, directory: str, config: Any, provider: str, state: InstallationState, lease: Any, *, windows: bool = False) -> None:
        self.directory, self.config, self.provider, self._state, self._lease = directory, config, provider, state, lease
        self._windows = windows
        self._lock = threading.RLock()
        self._poisoned = False

    @classmethod
    def open(cls, directory: str | os.PathLike[str] | None, config: Any) -> InstallationStorage:
        # AppConfig is deliberately defined in client.py; validate its public
        # fields structurally here to avoid an import cycle.
        required = ("api_origin", "issuer", "application_id", "environment_id", "fingerprint", "fingerprint_provider")
        if any(not hasattr(config, name) for name in required):
            raise TypeError("config must be an orbit_sdk.AppConfig")
        target = os.fspath(directory) if directory is not None else default_state_directory(config)
        if not isinstance(target, str) or not os.path.isabs(target):
            raise error(STORAGE, "storage_failed")
        provider = "windows_dpapi" if sys.platform == "win32" else "private_file" if sys.platform.startswith("linux") else "unsupported"
        if provider == "unsupported":
            raise error(STORAGE, "storage_unavailable")
        parent = _ensure_directory(target)
        if provider == "private_file":
            return cls._open_linux(parent, config, provider)
        return cls._open_windows(parent, config, provider)

    @classmethod
    def _open_linux(cls, directory: str, config: Any, provider: str) -> InstallationStorage:
        lease = _LinuxLease(directory)
        try:
            raw = _read_linux_record(lease)
            if raw is None:
                if not lease.created:
                    raise error(STORAGE, "storage_failed")
                state = InstallationState(installation_id_new(), config.fingerprint or None, config.fingerprint_provider or None, 0, None, None, None)
                _write_linux_record(lease, encode_envelope(config, provider, state))
            else:
                state = decode_envelope(config, provider, raw)
            result = cls(directory, config, provider, state, lease)
            result._check()
            return result
        except BaseException as exc:
            lease.close()
            if isinstance(exc, OrbitError):
                raise
            raise error(STORAGE, "storage_failed") from exc

    @classmethod
    def _open_windows(cls, directory: str, config: Any, provider: str) -> InstallationStorage:
        from .storage_windows import (
            _CREATE_NEW,
            _FILE_FLAG_BACKUP_SEMANTICS,
            _FILE_FLAG_OPEN_REPARSE_POINT,
            _GENERIC_READ,
            _GENERIC_WRITE,
            _OPEN_EXISTING,
            _close,
            _check_directory,
            _check_regular,
            _open_handle,
            _DPAPI,
        )
        from .storage_windows_security import check_private
        import ntpath
        paths = [directory]
        current = directory
        while ntpath.dirname(current) != current:
            current = ntpath.dirname(current)
            paths.append(current)
        paths.reverse()
        dirs: list[tuple[str, int]] = []
        lease = None
        try:
            for path in paths:
                handle = _open_handle(path, _GENERIC_READ, 3, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)
                dirs.append((path, handle))
                _check_directory(handle)
            _check_windows_dirs(dirs)
            lock_path = ntpath.join(directory, LOCK_FILE)
            try:
                lease = _open_handle(lock_path, _GENERIC_READ | _GENERIC_WRITE, 0, _CREATE_NEW, _FILE_FLAG_OPEN_REPARSE_POINT, private=True)
                created = True
            except OrbitError:
                if not os.path.exists(lock_path):
                    raise
                lease = _open_handle(lock_path, _GENERIC_READ | _GENERIC_WRITE, 0, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT, private=True)
                created = False
            _check_windows_regular(lease, minimum_size=0, maximum_size=0)
            _check_windows_dirs(dirs)
            entropy = _windows_entropy(config)
            data_path = ntpath.join(directory, RECORD_FILE)
            raw = _read_windows_record(data_path, entropy)
            if raw is None:
                if not created:
                    raise error(STORAGE, "storage_failed")
                state = InstallationState(installation_id_new(), config.fingerprint or None, config.fingerprint_provider or None, 0, None, None, None)
                raw = encode_envelope(config, provider, state)
                _write_windows_record(directory, dirs, lease, raw, entropy)
            else:
                state = decode_envelope(config, provider, raw)
            adapter = cls(directory, config, provider, state, lease, windows=True)
            adapter._directories = dirs
            adapter._entropy = entropy
            adapter._check()
            return adapter
        except BaseException as exc:
            _close(lease)
            for _, handle in dirs:
                _close(handle)
            if isinstance(exc, OrbitError):
                raise
            raise error(STORAGE, "storage_failed") from exc

    @property
    def installation_id(self) -> str:
        return self._state.installation_id

    @property
    def fingerprint(self) -> str | None:
        return self._state.fingerprint

    @property
    def fingerprint_provider(self) -> str | None:
        return self._state.fingerprint_provider

    @property
    def pending_activation(self) -> PendingActivation | None:
        with self._lock:
            self._check()
            return self._state.pending_activation

    @property
    def access(self) -> AccessState | None:
        with self._lock:
            self._check()
            return self._state.access

    def _check(self) -> None:
        if self._poisoned:
            raise error(STORAGE, "storage_failed")
        if self._windows:
            _check_windows_dirs(self._directories)
            _check_windows_regular(self._lease, minimum_size=0, maximum_size=0)
        else:
            try:
                self._lease.verify()
            except BaseException as exc:
                self._poisoned = True
                raise error(STORAGE, "storage_failed") from exc

    def _commit(self, state: InstallationState) -> None:
        try:
            self._check()
            raw = encode_envelope(self.config, self.provider, state)
            if self._windows:
                _write_windows_record(self.directory, self._directories, self._lease, raw, self._entropy)
            else:
                _write_linux_record(self._lease, raw)
        except BaseException as exc:
            self._poisoned = True
            raise error(STORAGE, "storage_failed") from exc
        self._state = state

    def version(self) -> int:
        with self._lock:
            self._check()
            return self._state.generation

    def load(self) -> tuple[int, Any | None]:
        with self._lock:
            self._check()
            return self._state.generation, self._state.credential

    def save(self, version: int, credential: Any) -> None:
        # The installed client must commit a verified grant and credential as
        # one transaction via save_verified().
        with self._lock:
            self._check()
            if version != self._state.generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._commit(replace(self._state, credential=credential, access=None, pending_activation=None))

    def save_verified(self, version: int, credential: Any, access: AccessState) -> None:
        with self._lock:
            self._check()
            if version != self._state.generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._commit(replace(self._state, credential=credential, access=access, pending_activation=None))

    def begin_activation(self, version: int, pending: PendingActivation, *, preserve_credential: bool = False) -> int:
        with self._lock:
            self._check()
            if version != self._state.generation:
                raise error(STALE_RESPONSE, "stale_response")
            if self._state.generation == MAX_GENERATION:
                raise error(STORAGE, "storage_failed")
            next_generation = self._state.generation + 1
            credential = self._state.credential if preserve_credential else None
            self._commit(replace(self._state, generation=next_generation, credential=credential, access=None, pending_activation=pending))
            return next_generation

    def invalidate(self, *, preserve_pending: bool = False) -> int:
        with self._lock:
            self._check()
            if self._state.generation == MAX_GENERATION:
                raise error(STORAGE, "storage_failed")
            generation = self._state.generation + 1
            pending = self._state.pending_activation if preserve_pending else None
            self._commit(replace(self._state, generation=generation, credential=None, access=None, pending_activation=pending))
            return generation

    def clear_access(self) -> None:
        with self._lock:
            self._check()
            if self._state.access is not None:
                self._commit(replace(self._state, access=None))

    def checkpoint_access(self, access: AccessState) -> None:
        with self._lock:
            self._check()
            if self._state.credential is None:
                return
            self._commit(replace(self._state, access=access))

    def close(self) -> None:
        if self._windows:
            from .storage_windows import _close
            _close(getattr(self, "_lease", None))
            self._lease = None
            for _, handle in getattr(self, "_directories", []):
                _close(handle)
            self._directories = []
        else:
            self._lease.close()

    def __repr__(self) -> str:
        return "InstallationStorage(<redacted>)"


def _read_linux_record(lease: _LinuxLease) -> bytes | None:
    directory_fd = lease._dirs[-1][1]
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(RECORD_FILE, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or not 1 <= info.st_size <= MAX_ENVELOPE:
            raise error(STORAGE, "storage_failed")
        data = bytearray()
        while len(data) < info.st_size:
            chunk = os.read(fd, min(8192, info.st_size - len(data)))
            if not chunk:
                raise error(STORAGE, "storage_failed")
            data.extend(chunk)
        if os.read(fd, 1):
            raise error(STORAGE, "storage_failed")
        return bytes(data)
    finally:
        os.close(fd)


def _write_linux_record(lease: _LinuxLease, raw: bytes) -> None:
    if not raw or len(raw) > MAX_ENVELOPE:
        raise error(STORAGE, "storage_failed")
    directory_fd = lease._dirs[-1][1]
    try:
        existing = os.open(RECORD_FILE, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        try:
            info = os.fstat(existing)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise error(STORAGE, "storage_failed")
        finally:
            os.close(existing)
    temporary = f"orbit-storage-{secrets.token_hex(16)}.tmp"
    lease.begin_write()
    fd = None
    replaced = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise error(STORAGE, "storage_failed")
        os.replace(temporary, RECORD_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        replaced = True
        dir_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        lease.complete_write()
    except BaseException:
        raise
    finally:
        if fd is not None:
            os.close(fd)
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def _windows_entropy(config: Any) -> bytes:
    scope = canonical_scope(config)
    encoded = json.dumps(scope, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"orbit.installed-client.dpapi.v2\0" + encoded).digest()


def _check_windows_dirs(directories: list[tuple[str, int]]) -> None:
    from .storage_windows import _check_directory
    from .storage_windows_security import check_private
    for _, handle in directories:
        _check_directory(handle)
    check_private(directories[-1][1])


def _check_windows_regular(handle: int, *, minimum_size: int = 0, maximum_size: int | None = None) -> int:
    from .storage_windows import _check_regular, _info
    from .storage_windows_security import check_private
    size = _check_regular(handle, minimum_size=minimum_size, maximum_size=maximum_size)
    if _info(handle).links != 1:
        raise error(STORAGE, "storage_failed")
    check_private(handle)
    return size


def _read_windows_record(path: str, entropy: bytes) -> bytes | None:
    from .storage_windows import _FILE_FLAG_OPEN_REPARSE_POINT, _GENERIC_READ, _OPEN_EXISTING, _DPAPI, _check_regular, _close, _open_handle
    try:
        handle = _open_handle(path, _GENERIC_READ, 0, _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT)
    except OrbitError:
        if not os.path.lexists(path):
            return None
        raise
    try:
        size = _check_windows_regular(handle, minimum_size=1, maximum_size=MAX_ENVELOPE + 1024)
        import ctypes
        from .storage_windows import _kernel32
        kernel = _kernel32()
        kernel.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        kernel.ReadFile.restype = ctypes.c_int
        output = ctypes.create_string_buffer(size)
        read = ctypes.c_uint32()
        if not kernel.ReadFile(ctypes.c_void_p(handle), output, size, ctypes.byref(read), None) or read.value != size:
            raise error(STORAGE, "storage_failed")
        return _DPAPI.unprotect_envelope(output.raw[:size], entropy)
    finally:
        _close(handle)


def _windows_write_marker(lease: int, pending: bool) -> None:
    import ctypes
    from .storage_windows import _kernel32
    expected = 0 if pending else 1
    _check_windows_regular(lease, minimum_size=expected, maximum_size=expected)
    kernel = _kernel32()
    kernel.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_int64, ctypes.c_void_p, ctypes.c_uint32]
    kernel.SetFilePointerEx.restype = ctypes.c_int
    kernel.FlushFileBuffers.argtypes = [ctypes.c_void_p]
    kernel.FlushFileBuffers.restype = ctypes.c_int
    if not kernel.SetFilePointerEx(ctypes.c_void_p(lease), 0, None, 0):
        raise error(STORAGE, "storage_failed")
    if pending:
        kernel.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        kernel.WriteFile.restype = ctypes.c_int
        written = ctypes.c_uint32()
        marker = ctypes.create_string_buffer(b"\x01")
        if not kernel.WriteFile(ctypes.c_void_p(lease), marker, 1, ctypes.byref(written), None) or written.value != 1:
            raise error(STORAGE, "storage_failed")
    else:
        kernel.SetEndOfFile.argtypes = [ctypes.c_void_p]
        kernel.SetEndOfFile.restype = ctypes.c_int
        if not kernel.SetEndOfFile(ctypes.c_void_p(lease)):
            raise error(STORAGE, "storage_failed")
    if not kernel.FlushFileBuffers(ctypes.c_void_p(lease)):
        raise error(STORAGE, "storage_failed")


def _write_windows_record(directory: str, directories: list[tuple[str, int]], lease: int, raw: bytes, entropy: bytes) -> None:
    from .storage_windows import _DPAPI, WindowsStorage
    writer = object.__new__(WindowsStorage)
    writer._directory, writer._directories, writer._poisoned, writer._private = directory, directories, False, True
    # Flush the mutation fence first; an interrupted write cannot reopen old authority.
    _windows_write_marker(lease, True)
    ciphertext = _DPAPI.protect_envelope(raw, entropy)
    writer._write_replace(ciphertext, maximum=MAX_ENVELOPE + 1024)
    _windows_write_marker(lease, False)
