"""Standard-library Python binding for the Orbit Rust FFI."""

from __future__ import annotations

import ctypes
import json
import os
import re
import sys
import threading
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterator


_ABI_VERSION = 1
_MAX_INPUT_BYTES = 4096
_MAX_TOTAL_INPUT_BYTES = 16 * 1024
_MAX_OUTPUT_BYTES = 512 * 1024
_ERROR_KINDS = {
    0: "none",
    1: "configuration",
    2: "cancelled",
    3: "transient",
    4: "denied",
    5: "invalid_response",
    6: "transport_security",
    7: "reauthentication_required",
    8: "stale_response",
    9: "storage",
    10: "clock_uncertain",
    11: "internal",
}
_OPERATIONS = {
    "snapshot": 1,
    "activate": 2,
    "activate_previous": 3,
    "refresh": 4,
    "require_access": 5,
    "deactivate": 6,
    "local_logout": 7,
    "register": 8,
    "resend_registration": 9,
    "login": 10,
    "account": 11,
    "owned_licences": 12,
    "claim_licence": 13,
    "activate_account": 14,
    "activate_account_previous": 15,
    "account_logout": 16,
    "request_email_change": 17,
    "request_password_recovery": 18,
    "customer_session_authorization": 19,
}


class _Slice(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class _Buffer(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("len", ctypes.c_size_t)]


class _Result(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("error_kind", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("error_code", _Buffer),
        ("request_id", _Buffer),
        ("output", _Buffer),
    ]


class _ClientConfig(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("abi_version", ctypes.c_uint32),
        ("storage_mode", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
        ("api_origin", _Slice),
        ("application_id", _Slice),
        ("environment_id", _Slice),
        ("issuer", _Slice),
        ("installation_id", _Slice),
        ("fingerprint", _Slice),
        ("fingerprint_provider", _Slice),
        ("storage_path", _Slice),
    ]


class _Client(ctypes.Structure):
    pass


class _Cancellation(ctypes.Structure):
    pass


class _PendingRegistration(ctypes.Structure):
    pass


_ClientPtr = ctypes.POINTER(_Client)
_CancellationPtr = ctypes.POINTER(_Cancellation)
_PendingPtr = ctypes.POINTER(_PendingRegistration)


class StorageMode(str, Enum):
    """Credential storage selected when a client is created."""

    MEMORY = "memory"
    WINDOWS_DPAPI = "windows_dpapi"
    LINUX_SECRET_SERVICE = "linux_secret_service"


class OrbitError(RuntimeError):
    """Safe structured SDK error metadata; server messages and inputs are omitted."""

    def __init__(
        self,
        kind: str,
        code: str,
        request_id: str | None = None,
        status: int = 1,
    ) -> None:
        self.kind = kind
        self.code = code
        self.request_id = request_id
        self.status = status
        super().__init__(self.__str__())

    def __str__(self) -> str:
        detail = f"kind={self.kind}, code={self.code}"
        if self.request_id is not None:
            detail += f", request_id={self.request_id}"
        return f"Orbit SDK operation failed ({detail})"


@dataclass(frozen=True)
class Config:
    """Public runtime settings for ``Client.connect``.

    Persist ``installation_id`` in the host application and reuse it after
    restarts. Protected storage requires a dedicated existing absolute folder.
    """

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
        path = os.fspath(self.storage_path)
        if not isinstance(path, str):
            raise TypeError("storage_path must be a text path")
        object.__setattr__(self, "storage_path", path)
        if mode is StorageMode.MEMORY:
            if path:
                raise ValueError("memory storage does not use storage_path")
        else:
            if not path or not os.path.isabs(path) or not os.path.isdir(path):
                raise ValueError("protected storage needs an existing absolute directory")
            if mode is StorageMode.WINDOWS_DPAPI and sys.platform != "win32":
                raise ValueError("Windows DPAPI storage is available only on Windows")
            if mode is StorageMode.LINUX_SECRET_SERVICE and not sys.platform.startswith("linux"):
                raise ValueError("Linux Secret Service storage is available only on Linux")


@dataclass(frozen=True)
class RegistrationResult:
    """Registration acceptance metadata and its opaque resend handle."""

    accepted: bool
    expires_at: str | None
    pending: PendingRegistration


class SensitiveAuthorization:
    """A redacted, clearable customer Authorization header held in a bytearray.

    Call ``reveal()`` only when sending it to your trusted HTTPS backend. The
    returned bytes are a caller-owned copy; clear that copy when practical.
    """

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


def _safe_error_text(buffer: _Buffer, limit: int, pattern: re.Pattern[str]) -> str | None:
    if buffer.len == 0:
        return None
    if buffer.len > limit or not buffer.data:
        return None
    try:
        text = ctypes.string_at(buffer.data, buffer.len).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if pattern.fullmatch(text) else None


_CODE_PATTERN = re.compile(r"[a-z0-9_]{1,128}")
_REQUEST_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _read_output(buffer: _Buffer, *, sensitive: bool = False) -> bytes | bytearray:
    if buffer.len > _MAX_OUTPUT_BYTES or (buffer.len and not buffer.data):
        raise OrbitError("invalid_response", "output_too_large")
    if sensitive:
        value = bytearray(buffer.len)
        if buffer.len:
            destination = (ctypes.c_uint8 * buffer.len).from_buffer(value)
            ctypes.memmove(destination, buffer.data, buffer.len)
        return value
    if not buffer.len:
        return b""
    return ctypes.string_at(buffer.data, buffer.len)


def _result_value(library: ctypes.CDLL, result: _Result, *, sensitive: bool = False) -> bytes | bytearray:
    if result.abi_version != _ABI_VERSION:
        raise OrbitError("internal", "abi_mismatch", status=int(result.status))
    if result.status != 0:
        kind = _ERROR_KINDS.get(int(result.error_kind), "unknown")
        code = _safe_error_text(result.error_code, 128, _CODE_PATTERN) or "operation_failed"
        request_id = _safe_error_text(result.request_id, 64, _REQUEST_PATTERN)
        raise OrbitError(kind, code, request_id, int(result.status))
    return _read_output(result.output, sensitive=sensitive)


def _bind_functions(library: ctypes.CDLL) -> None:
    library.orbit_ffi_abi_version.argtypes = []
    library.orbit_ffi_abi_version.restype = ctypes.c_uint32
    library.orbit_client_create.argtypes = [
        ctypes.POINTER(_ClientConfig),
        ctypes.POINTER(_ClientPtr),
    ]
    library.orbit_client_create.restype = _Result
    library.orbit_client_call.argtypes = [
        _ClientPtr,
        ctypes.c_uint32,
        ctypes.POINTER(_Slice),
        ctypes.c_size_t,
        _CancellationPtr,
        _PendingPtr,
        ctypes.POINTER(_PendingPtr),
    ]
    library.orbit_client_call.restype = _Result
    library.orbit_cancellation_create.argtypes = []
    library.orbit_cancellation_create.restype = _CancellationPtr
    library.orbit_cancellation_cancel.argtypes = [_CancellationPtr]
    library.orbit_cancellation_cancel.restype = None
    library.orbit_cancellation_free.argtypes = [_CancellationPtr]
    library.orbit_cancellation_free.restype = None
    library.orbit_client_free.argtypes = [_ClientPtr]
    library.orbit_client_free.restype = None
    library.orbit_pending_registration_free.argtypes = [_PendingPtr]
    library.orbit_pending_registration_free.restype = None
    library.orbit_ffi_result_free.argtypes = [ctypes.POINTER(_Result)]
    library.orbit_ffi_result_free.restype = None
    for name, count in (("orbit_installation_id_new", 0), ("orbit_native_fingerprint", 2), ("orbit_machine_fingerprint", 4)):
        function = getattr(library, name)
        function.argtypes = [] if count == 0 else [_Slice] * count
        function.restype = _Result


_LIBRARIES: dict[str, ctypes.CDLL] = {}
_LIBRARIES_LOCK = threading.Lock()


def _library_name() -> str:
    if sys.platform == "win32":
        return "orbit_sdk_ffi.dll"
    if sys.platform.startswith("linux"):
        return "liborbit_sdk_ffi.so"
    raise RuntimeError("Orbit FFI supports Linux and Windows")


def _load_library(library_path: str | os.PathLike[str] | None) -> tuple[ctypes.CDLL, str]:
    candidate = Path(library_path) if library_path is not None else Path(__file__).resolve().with_name(_library_name())
    path = str(candidate.expanduser().resolve())
    with _LIBRARIES_LOCK:
        library = _LIBRARIES.get(path)
        if library is None:
            if not os.path.isfile(path):
                raise FileNotFoundError(f"Orbit FFI library not found: {path}")
            try:
                library = ctypes.CDLL(path)
            except OSError as exc:
                raise OSError(f"Could not load Orbit FFI library at {path}") from exc
            _bind_functions(library)
            version = int(library.orbit_ffi_abi_version())
            if version != _ABI_VERSION:
                raise RuntimeError(f"Unsupported Orbit FFI ABI version {version}; expected {_ABI_VERSION}")
            _LIBRARIES[path] = library
    return library, path


def _encode(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Orbit SDK text arguments must be strings")
    encoded = value.encode("utf-8")
    if len(encoded) > _MAX_INPUT_BYTES:
        raise ValueError("Orbit SDK text argument exceeds 4096 UTF-8 bytes")
    return encoded


def _slice(value: bytes) -> tuple[ctypes.Array[ctypes.c_char], _Slice]:
    storage = ctypes.create_string_buffer(value)
    return storage, _Slice(ctypes.cast(storage, ctypes.POINTER(ctypes.c_uint8)), len(value))


def _slices(values: tuple[str, ...]) -> tuple[list[ctypes.Array[ctypes.c_char]], object]:
    encoded = [_encode(value) for value in values]
    if sum(map(len, encoded)) > _MAX_TOTAL_INPUT_BYTES:
        raise ValueError("combined Orbit SDK text arguments exceed 16384 UTF-8 bytes")
    holders: list[ctypes.Array[ctypes.c_char]] = []
    entries: list[_Slice] = []
    for value in encoded:
        holder, item = _slice(value)
        holders.append(holder)
        entries.append(item)
    if not entries:
        return holders, None
    array_type = _Slice * len(entries)
    return holders, array_type(*entries)


def _config_record(config: Config) -> tuple[_ClientConfig, list[ctypes.Array[ctypes.c_char]]]:
    names = (
        config.api_origin,
        config.application_id,
        config.environment_id,
        config.issuer,
        config.installation_id,
        config.fingerprint,
        config.fingerprint_provider,
        config.storage_path,
    )
    encoded = [_encode(value) for value in names]
    if sum(map(len, encoded)) > _MAX_TOTAL_INPUT_BYTES:
        raise ValueError("combined Orbit SDK configuration exceeds 16384 UTF-8 bytes")
    holders: list[ctypes.Array[ctypes.c_char]] = []
    fields: list[_Slice] = []
    for value in encoded:
        holder, item = _slice(value)
        holders.append(holder)
        fields.append(item)
    storage_mode = {
        StorageMode.MEMORY: 0,
        StorageMode.WINDOWS_DPAPI: 1,
        StorageMode.LINUX_SECRET_SERVICE: 2,
    }[config.storage_mode]
    record = _ClientConfig(
        ctypes.sizeof(_ClientConfig), _ABI_VERSION, storage_mode, 0, *fields
    )
    return record, holders


def _take_result(library: ctypes.CDLL, result: _Result) -> bytes:
    try:
        value = _result_value(library, result)
        if isinstance(value, bytearray):
            return bytes(value)
        return value
    finally:
        library.orbit_ffi_result_free(ctypes.byref(result))


def _identity_result(library: ctypes.CDLL, result: _Result) -> str:
    output = _take_result(library, result)
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OrbitError("invalid_response", "invalid_utf8") from exc


class _OpaqueHandle:
    def _init_handle(self, library: ctypes.CDLL, pointer: object, free_function: str) -> None:
        self._library = library
        self._pointer = pointer
        self._condition = threading.Condition()
        self._active = 0
        self._closed = False
        self._finalizer = weakref.finalize(self, getattr(library, free_function), pointer)

    @contextmanager
    def _borrow(self) -> Iterator[object]:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit SDK handle is closed")
            self._active += 1
            pointer = self._pointer
        try:
            yield pointer
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
        self._finalizer()

    def __enter__(self):
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit SDK handle is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class Cancellation(_OpaqueHandle):
    """A shareable cancellation signal for an operation in progress."""

    @classmethod
    def create(cls, library_path: str | os.PathLike[str] | None = None) -> Cancellation:
        library, _ = _load_library(library_path)
        pointer = library.orbit_cancellation_create()
        if not pointer:
            raise MemoryError("Could not create Orbit cancellation handle")
        value = cls()
        try:
            value._init_handle(library, pointer, "orbit_cancellation_free")
        except BaseException:
            library.orbit_cancellation_free(pointer)
            raise
        return value

    def cancel(self) -> None:
        with self._condition:
            if self._closed:
                raise RuntimeError("Orbit cancellation handle is closed")
            self._library.orbit_cancellation_cancel(self._pointer)

    def __repr__(self) -> str:
        return "Cancellation(<opaque>)"


class PendingRegistration(_OpaqueHandle):
    """Opaque in-memory resend proof returned by ``Client.register``."""

    _owner: Client | None = None

    def __repr__(self) -> str:
        return "PendingRegistration(<opaque>)"


class Client(_OpaqueHandle):
    """Synchronous client over the Rust SDK. Use ``with Client.connect(...)``."""

    @classmethod
    def connect(
        cls,
        config: Config,
        library_path: str | os.PathLike[str] | None = None,
    ) -> Client:
        if not isinstance(config, Config):
            raise TypeError("config must be an orbit_sdk.Config")
        library, _ = _load_library(library_path)
        record, keepalive = _config_record(config)
        pointer = _ClientPtr()
        result = library.orbit_client_create(ctypes.byref(record), ctypes.byref(pointer))
        try:
            _take_result(library, result)
            if not pointer:
                raise OrbitError("internal", "missing_client")
            value = cls()
            value._init_handle(library, pointer, "orbit_client_free")
            pointer = _ClientPtr()
            return value
        except BaseException:
            if pointer:
                library.orbit_client_free(pointer)
            raise
        finally:
            del keepalive

    def _call(
        self,
        operation: int,
        arguments: tuple[str, ...] = (),
        *,
        cancellation: Cancellation | None = None,
        pending: PendingRegistration | None = None,
        register: bool = False,
        sensitive: bool = False,
    ):
        if cancellation is not None and not isinstance(cancellation, Cancellation):
            raise TypeError("cancellation must be a Cancellation handle")
        if pending is not None and not isinstance(pending, PendingRegistration):
            raise TypeError("pending must be a PendingRegistration handle")
        holders, array = _slices(arguments)
        arg_pointer = None if array is None else ctypes.cast(array, ctypes.POINTER(_Slice))
        pending_out = _PendingPtr()
        cancellation_context = cancellation._borrow() if cancellation is not None else _null_handle()
        pending_context = pending._borrow() if pending is not None else _null_handle()
        raw_pending = None
        with self._borrow() as client_pointer, cancellation_context as cancellation_pointer, pending_context as pending_pointer:
            if pending is not None and pending._library is not self._library:
                raise ValueError("pending registration belongs to another FFI library")
            if pending is not None and pending._owner is not self:
                raise ValueError("pending registration belongs to another client")
            if not register and pending is not None and operation != _OPERATIONS["resend_registration"]:
                raise ValueError("pending handle is valid only for resend_registration")
            result = self._library.orbit_client_call(
                client_pointer,
                operation,
                arg_pointer,
                len(arguments),
                cancellation_pointer,
                pending_pointer,
                ctypes.byref(pending_out) if register else None,
            )
            raw_pending = pending_out if pending_out else None
            try:
                output = _result_value(self._library, result, sensitive=sensitive)
                if sensitive:
                    if (
                        len(output) <= len(b"Bearer ")
                        or not output.startswith(b"Bearer ")
                        or any(byte < 0x21 or byte > 0x7E for byte in output[len(b"Bearer ") :])
                    ):
                        if isinstance(output, bytearray):
                            for index in range(len(output)):
                                output[index] = 0
                            output.clear()
                        raise OrbitError("invalid_response", "invalid_authorization_header")
                    return SensitiveAuthorization(output), None
                try:
                    value = json.loads(output.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise OrbitError("invalid_response", "invalid_json") from exc
                if register:
                    if raw_pending is None:
                        raise OrbitError("invalid_response", "missing_pending_registration")
                    handle = PendingRegistration()
                    handle._init_handle(self._library, raw_pending, "orbit_pending_registration_free")
                    handle._owner = self
                    raw_pending = None
                    return value, handle
                return value
            finally:
                self._library.orbit_ffi_result_free(ctypes.byref(result))
                if raw_pending is not None:
                    self._library.orbit_pending_registration_free(raw_pending)
                del holders

    def snapshot(self, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["snapshot"], cancellation=cancellation)

    def activate(self, licence_key: str, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["activate"], (licence_key, idempotency_key), cancellation=cancellation)

    def activate_previous(
        self,
        licence_key: str,
        previous_credential: str | None,
        idempotency_key: str,
        *,
        cancellation: Cancellation | None = None,
    ) -> dict:
        return self._call(
            _OPERATIONS["activate_previous"],
            (licence_key, previous_credential or "", idempotency_key),
            cancellation=cancellation,
        )

    def refresh(self, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["refresh"], cancellation=cancellation)

    def require_access(self, feature: str, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["require_access"], (feature,), cancellation=cancellation)

    def deactivate(self, idempotency_key: str, *, cancellation: Cancellation | None = None) -> None:
        self._call(_OPERATIONS["deactivate"], (idempotency_key,), cancellation=cancellation)

    def local_logout(self) -> None:
        self._call(_OPERATIONS["local_logout"])

    def register(
        self,
        licence_key: str,
        username: str,
        email: str,
        password: str,
        *,
        cancellation: Cancellation | None = None,
    ) -> RegistrationResult:
        value, pending = self._call(
            _OPERATIONS["register"],
            (licence_key, username, email, password),
            cancellation=cancellation,
            register=True,
        )
        if not isinstance(value, dict) or not isinstance(value.get("accepted"), bool):
            pending.close()
            raise OrbitError("invalid_response", "invalid_registration")
        expires_at = value.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            pending.close()
            raise OrbitError("invalid_response", "invalid_registration")
        return RegistrationResult(value["accepted"], expires_at, pending)

    def resend_registration(
        self,
        pending: PendingRegistration,
        *,
        cancellation: Cancellation | None = None,
    ) -> None:
        self._call(
            _OPERATIONS["resend_registration"],
            cancellation=cancellation,
            pending=pending,
        )

    def login(self, username: str, password: str, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["login"], (username, password), cancellation=cancellation)

    def account(self, *, cancellation: Cancellation | None = None) -> dict | None:
        return self._call(_OPERATIONS["account"], cancellation=cancellation)

    def owned_licences(self, cursor: str | None = None, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["owned_licences"], (cursor or "",), cancellation=cancellation)

    def claim_licence(self, licence_key: str, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["claim_licence"], (licence_key, idempotency_key), cancellation=cancellation)

    def activate_account(self, licence_id: str, idempotency_key: str, *, cancellation: Cancellation | None = None) -> dict:
        return self._call(_OPERATIONS["activate_account"], (licence_id, idempotency_key), cancellation=cancellation)

    def activate_account_previous(
        self,
        licence_id: str,
        previous_credential: str | None,
        idempotency_key: str,
        *,
        cancellation: Cancellation | None = None,
    ) -> dict:
        return self._call(
            _OPERATIONS["activate_account_previous"],
            (licence_id, previous_credential or "", idempotency_key),
            cancellation=cancellation,
        )

    def account_logout(self, *, cancellation: Cancellation | None = None) -> None:
        self._call(_OPERATIONS["account_logout"], cancellation=cancellation)

    def request_email_change(
        self,
        password: str,
        new_email: str,
        *,
        cancellation: Cancellation | None = None,
    ) -> None:
        self._call(_OPERATIONS["request_email_change"], (password, new_email), cancellation=cancellation)

    def request_password_recovery(self, email: str, *, cancellation: Cancellation | None = None) -> None:
        self._call(_OPERATIONS["request_password_recovery"], (email,), cancellation=cancellation)

    def customer_session_authorization(
        self,
        *,
        cancellation: Cancellation | None = None,
    ) -> SensitiveAuthorization:
        value, _ = self._call(
            _OPERATIONS["customer_session_authorization"],
            cancellation=cancellation,
            sensitive=True,
        )
        return value


@contextmanager
def _null_handle() -> Iterator[None]:
    yield None


def installation_id_new(library_path: str | os.PathLike[str] | None = None) -> str:
    """Generate a random installation ID using the SDK's operating system RNG."""

    library, _ = _load_library(library_path)
    return _identity_result(library, library.orbit_installation_id_new())


def native_fingerprint(
    application_id: str,
    environment_id: str,
    library_path: str | os.PathLike[str] | None = None,
) -> str:
    """Derive a scoped machine_v1 fingerprint on a supported OS."""

    library, _ = _load_library(library_path)
    holders, args = _slices((application_id, environment_id))
    try:
        return _identity_result(library, library.orbit_native_fingerprint(*args))
    finally:
        del holders


def machine_fingerprint(
    application_id: str,
    environment_id: str,
    family: str,
    identity: str,
    library_path: str | os.PathLike[str] | None = None,
) -> str:
    """Normalize and scope a host-provided identity; never send raw identity."""

    library, _ = _load_library(library_path)
    holders, args = _slices((application_id, environment_id, family, identity))
    try:
        return _identity_result(library, library.orbit_machine_fingerprint(*args))
    finally:
        del holders


__all__ = [
    "Cancellation",
    "Client",
    "Config",
    "OrbitError",
    "PendingRegistration",
    "RegistrationResult",
    "SensitiveAuthorization",
    "StorageMode",
    "installation_id_new",
    "machine_fingerprint",
    "native_fingerprint",
]
