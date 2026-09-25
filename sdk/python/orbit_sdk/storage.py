from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .device import lower_hex, opaque, valid_provider
from .errors import STALE_RESPONSE, STORAGE, OrbitError, error
from .jsonutil import MAX_JSON_BYTES, strict_int, unique_json

MAX_PLAINTEXT = 32 * 1024
MAX_CIPHERTEXT = 64 * 1024
MAX_GENERATION = (1 << 63) - 1


@dataclass(frozen=True)
class StoredCredential:
    application_id: str
    environment_id: str
    activation_id: str
    licence_id: str
    installation_id: str
    credential: str
    credential_expires_at: int
    fingerprint: str | None = None
    fingerprint_provider: str | None = None

    def __repr__(self) -> str:
        return "StoredCredential(<redacted>)"


def valid_credential(value: StoredCredential, config: Any, device: Any) -> bool:
    return (
        value.application_id == config.application_id
        and value.environment_id == config.environment_id
        and value.installation_id == device.installation_id
        and value.fingerprint == device.fingerprint
        and value.fingerprint_provider == device.fingerprint_provider
        and opaque(value.activation_id)
        and opaque(value.licence_id)
        and len(value.credential) == 43
        and value.credential.isascii()
        and all(c.isalnum() or c in "_-" for c in value.credential)
        and 0 < value.credential_expires_at <= (1 << 63) - 1
    )


def _configuration(config: Any, device: Any) -> bool:
    return (
        opaque(config.application_id)
        and opaque(config.environment_id)
        and isinstance(config.issuer, str)
        and bool(config.issuer)
        and len(config.issuer.encode("utf-8", "strict")) <= MAX_PLAINTEXT
        and opaque(device.installation_id)
        and len(device.installation_id) >= 16
        and (device.fingerprint is None) == (device.fingerprint_provider is None)
        and (device.fingerprint is None or lower_hex(device.fingerprint, 64))
        and (device.fingerprint_provider is None or valid_provider(device.fingerprint_provider))
    )


def storage_entropy(config: Any, device: Any) -> bytes:
    if not _configuration(config, device):
        raise error(STORAGE, "storage_failed")
    digest = hashlib.sha256()
    digest.update(b"orbit.sdk.storage.v1\0")
    for value in (config.issuer, config.application_id, config.environment_id, device.installation_id):
        encoded = value.encode("utf-8", "strict")
        if len(encoded) > MAX_PLAINTEXT:
            raise error(STORAGE, "storage_failed")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return digest.digest()


def encode_record(config: Any, device: Any, generation: int, credential: StoredCredential | None) -> bytes:
    storage_entropy(config, device)
    if not strict_int(generation, minimum=0, maximum=MAX_GENERATION) or credential is not None and not valid_credential(credential, config, device):
        raise error(STORAGE, "storage_failed")
    record = {
        "sdk": "orbit.rust.storage",
        "format": 1,
        "generation": generation,
        "issuer": config.issuer,
        "application_id": config.application_id,
        "environment_id": config.environment_id,
        "installation_id": device.installation_id,
        "fingerprint": device.fingerprint,
        "fingerprint_provider": device.fingerprint_provider,
        "credential": None if credential is None else {
            "activation_id": credential.activation_id,
            "licence_id": credential.licence_id,
            "bearer": credential.credential,
            "expires_at": credential.credential_expires_at,
        },
    }
    raw = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > MAX_PLAINTEXT:
        raise error(STORAGE, "storage_failed")
    return raw


def decode_record(config: Any, device: Any, raw: bytes) -> tuple[int, StoredCredential | None]:
    storage_entropy(config, device)
    if not isinstance(raw, bytes) or len(raw) > MAX_PLAINTEXT:
        raise error(STORAGE, "storage_failed")
    try:
        record = unique_json(raw)
        names = {"sdk", "format", "generation", "issuer", "application_id", "environment_id", "installation_id", "fingerprint", "fingerprint_provider", "credential"}
        if not isinstance(record, dict) or record.keys() != names:
            raise ValueError
        if (
            record["sdk"] != "orbit.rust.storage"
            or type(record["format"]) is not int or record["format"] != 1
            or not strict_int(record["generation"], minimum=0, maximum=MAX_GENERATION)
            or record["issuer"] != config.issuer
            or record["application_id"] != config.application_id
            or record["environment_id"] != config.environment_id
            or record["installation_id"] != device.installation_id
            or record["fingerprint"] != device.fingerprint
            or record["fingerprint_provider"] != device.fingerprint_provider
        ):
            raise ValueError
        credential_value = record["credential"]
        credential = None
        if credential_value is not None:
            fields = {"activation_id", "licence_id", "bearer", "expires_at"}
            if not isinstance(credential_value, dict) or credential_value.keys() != fields:
                raise ValueError
            if not all(isinstance(credential_value[name], str) for name in ("activation_id", "licence_id", "bearer")):
                raise ValueError
            if not strict_int(credential_value["expires_at"], minimum=1, maximum=MAX_GENERATION):
                raise ValueError
            credential = StoredCredential(
                application_id=record["application_id"],
                environment_id=record["environment_id"],
                activation_id=credential_value["activation_id"],
                licence_id=credential_value["licence_id"],
                installation_id=record["installation_id"],
                credential=credential_value["bearer"],
                credential_expires_at=credential_value["expires_at"],
                fingerprint=record["fingerprint"],
                fingerprint_provider=record["fingerprint_provider"],
            )
            if not valid_credential(credential, config, device):
                raise ValueError
        return record["generation"], credential
    except (ValueError, TypeError, KeyError, OrbitError) as exc:
        if isinstance(exc, OrbitError) and exc.kind == STORAGE:
            raise
        raise error(STORAGE, "storage_failed") from exc


class MemoryStorage:
    """Process-local credential storage. Its contents disappear at exit."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0
        self._credential: StoredCredential | None = None

    def version(self) -> int:
        with self._lock:
            return self._generation

    def load(self) -> tuple[int, StoredCredential | None]:
        with self._lock:
            return self._generation, self._credential

    def save(self, version: int, credential: StoredCredential) -> None:
        with self._lock:
            if version != self._generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._credential = credential

    def invalidate(self) -> int:
        with self._lock:
            if self._generation == MAX_GENERATION:
                raise error(STORAGE, "storage_failed")
            self._generation += 1
            self._credential = None
            return self._generation


class _LinuxLease:
    NAME = "orbit-storage.lock"
    PENDING = b"\x01"

    def __init__(self, directory: str) -> None:
        import fcntl
        import stat

        path = Path(directory)
        if not path.is_absolute() or ".." in path.parts:
            raise error(STORAGE, "storage_failed")
        self.directory = "/"
        self._dirs: list[tuple[str, int]] = []
        root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        self._dirs.append(("/", root_fd))
        try:
            for part in path.parts[1:]:
                if part in ("", "."):
                    continue
                fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=self._dirs[-1][1])
                self.directory = os.path.join(self.directory, part)
                self._dirs.append((self.directory, fd))
            self.path = os.path.join(self.directory, self.NAME)
            directory_info = os.fstat(self._dirs[-1][1])
            if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o077 or directory_info.st_nlink == 0:
                raise error(STORAGE, "storage_failed")
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            created = False
            try:
                self.fd = os.open(self.NAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self._dirs[-1][1])
                created = True
            except FileExistsError:
                self.fd = os.open(self.NAME, flags, dir_fd=self._dirs[-1][1])
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise error(STORAGE, "storage_failed")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.created = created
            self._verify(b"")
            if created:
                os.fsync(self.fd)
                directory_fd = os.open(".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=self._dirs[-1][1])
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                self._verify(b"")
        except BaseException:
            self.close()
            raise error(STORAGE, "storage_failed")

    def _verify(self, marker: bytes) -> None:
        import stat

        for index, (path, fd) in enumerate(self._dirs):
            opened = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(opened.st_mode) or not stat.S_ISDIR(current.st_mode) or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino) or opened.st_nlink == 0 or current.st_nlink == 0:
                raise error(STORAGE, "storage_failed")
            if index == len(self._dirs) - 1 and (opened.st_uid != os.geteuid() or current.st_uid != os.geteuid() or opened.st_mode & 0o077 or current.st_mode & 0o077):
                raise error(STORAGE, "storage_failed")
        opened = os.fstat(self.fd)
        current = os.stat(self.path, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(current.st_mode)
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_uid != os.geteuid() or current.st_uid != os.geteuid()
            or opened.st_mode & 0o077 or current.st_mode & 0o077
            or opened.st_nlink != 1 or current.st_nlink != 1
            or opened.st_size != len(marker) or current.st_size != len(marker)
            or os.pread(self.fd, 2, 0) != marker
        ):
            raise error(STORAGE, "storage_failed")

    def verify(self) -> None:
        self._verify(b"")

    def begin_write(self) -> None:
        self.verify()
        os.pwrite(self.fd, self.PENDING, 0)
        os.fsync(self.fd)
        self._verify(self.PENDING)

    def complete_write(self) -> None:
        self._verify(self.PENDING)
        try:
            os.ftruncate(self.fd, 0)
            os.fsync(self.fd)
            self.verify()
        except BaseException:
            try:
                os.pwrite(self.fd, self.PENDING, 0)
                os.fsync(self.fd)
            except OSError:
                pass
            raise

    def close(self) -> None:
        fd = getattr(self, "fd", None)
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass
            self.fd = None
        for _, directory_fd in getattr(self, "_dirs", []):
            try:
                os.close(directory_fd)
            except OSError:
                pass
        self._dirs = []


class _SecretTool:
    EXECUTABLE = "/usr/bin/secret-tool"
    MAX_STDOUT = 5465
    MAX_STDERR = 4096

    def lookup(self, scope: str) -> bytes | None:
        status, out, err = self._run(["lookup"], scope, b"")
        if err:
            raise error(STORAGE, "storage_failed")
        if status == 0:
            return out
        if status == 1 and not out:
            return None
        raise error(STORAGE, "storage_failed")

    def store(self, scope: str, record: bytes) -> None:
        if len(record) > 5464:
            raise error(STORAGE, "storage_failed")
        status, out, err = self._run(["store", "--label=Orbit Rust SDK activation", "--collection=default"], scope, record)
        if status != 0 or out or err:
            raise error(STORAGE, "storage_failed")

    def _run(self, operation: list[str], scope: str, stdin: bytes) -> tuple[int, bytes, bytes]:
        import selectors
        import subprocess
        import time

        args = [self.EXECUTABLE, *operation, "application", "orbit-sdk", "sdk", "rust", "scope", scope]
        try:
            proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        except OSError as exc:
            raise error(STORAGE, "storage_failed") from exc
        out, err = bytearray(), bytearray()
        offset = 0
        deadline = time.monotonic() + 5.0
        selector = selectors.DefaultSelector()
        streams = (proc.stdin, proc.stdout, proc.stderr)
        try:
            assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
            for stream in streams:
                os.set_blocking(stream.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map() or proc.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise error(STORAGE, "storage_failed")
                for key, _ in selector.select(min(0.05, remaining)):
                    stream, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            written = os.write(stream.fileno(), stdin[offset:offset + 1024]) if offset < len(stdin) else 0
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as exc:
                            raise error(STORAGE, "storage_failed") from exc
                        offset += written
                        if offset >= len(stdin):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        limit = self.MAX_STDOUT if name == "stdout" else self.MAX_STDERR
                        target = out if name == "stdout" else err
                        try:
                            data = os.read(stream.fileno(), min(1024, limit - len(target) + 1))
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            target.extend(data)
                            if len(target) > limit:
                                raise error(STORAGE, "storage_failed")
                if proc.poll() is not None and not selector.get_map():
                    break
            if offset != len(stdin):
                raise error(STORAGE, "storage_failed")
            status = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            return status, bytes(out), bytes(err)
        except BaseException:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            raise
        finally:
            selector.close()
            for stream in streams:
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


class SecretServiceStorage:
    def __init__(self, config: Any, device: Any, lease: _LinuxLease, helper: Any, scope: str, generation: int, credential: StoredCredential | None) -> None:
        self._config, self._device, self._lease, self._helper, self._scope = config, device, lease, helper, scope
        self._generation, self._credential = generation, credential
        self._poisoned = False
        self._lock = threading.Lock()

    @classmethod
    def open(cls, directory: str, config: Any, device: Any, *, _helper: Any = None) -> SecretServiceStorage:
        if not sys.platform.startswith("linux"):
            raise error(STORAGE, "storage_unavailable")
        encode_record(config, device, 0, None)
        lease = _LinuxLease(directory)
        helper = _helper or _SecretTool()
        try:
            scope = secret_service_scope(config, device, lease.directory)
            storage = cls(config, device, lease, helper, scope, 0, None)
            output = helper.lookup(scope)
            if output is not None:
                storage._generation, storage._credential = decode_secret_record(config, device, output)
            elif lease.created:
                storage._commit(0, None)
            else:
                raise error(STORAGE, "storage_failed")
            storage._check()
            return storage
        except BaseException:
            lease.close()
            raise

    def _check(self) -> None:
        if self._poisoned:
            raise error(STORAGE, "storage_failed")
        try:
            self._lease.verify()
        except BaseException as exc:
            self._poison()
            raise error(STORAGE, "storage_failed") from exc

    def _poison(self) -> None:
        self._poisoned = True
        self._credential = None

    def _commit(self, generation: int, credential: StoredCredential | None) -> None:
        try:
            self._check()
            record = encode_record(self._config, self._device, generation, credential)
            if len(record) > 4096:
                raise error(STORAGE, "storage_failed")
            self._lease.begin_write()
            self._helper.store(self._scope, base64.b64encode(record))
            self._lease.complete_write()
        except BaseException as exc:
            self._poison()
            raise error(STORAGE, "storage_failed") from exc
        self._generation, self._credential = generation, credential

    def version(self) -> int:
        with self._lock:
            self._check()
            return self._generation

    def load(self) -> tuple[int, StoredCredential | None]:
        with self._lock:
            self._check()
            return self._generation, self._credential

    def save(self, version: int, credential: StoredCredential) -> None:
        with self._lock:
            self._check()
            if version != self._generation:
                raise error(STALE_RESPONSE, "stale_response")
            self._commit(version, credential)

    def invalidate(self) -> int:
        with self._lock:
            self._check()
            if self._generation == MAX_GENERATION:
                self._poison()
                raise error(STORAGE, "storage_failed")
            next_generation = self._generation + 1
            self._commit(next_generation, None)
            return next_generation

    def close(self) -> None:
        self._lease.close()

    def __repr__(self) -> str:
        return "SecretServiceStorage(<redacted>)"


def secret_service_scope(config: Any, device: Any, directory: str) -> str:
    entropy = storage_entropy(config, device)
    encoded = directory.encode("utf-8", "strict")
    digest = hashlib.sha256()
    digest.update(b"orbit.sdk.secret-service.v1\0")
    digest.update(struct.pack(">I", 4))
    digest.update(b"rust")
    digest.update(entropy)
    digest.update(struct.pack(">I", len(encoded)))
    digest.update(encoded)
    return digest.hexdigest()


def encode_secret_record(config: Any, device: Any, generation: int, credential: StoredCredential | None) -> bytes:
    record = encode_record(config, device, generation, credential)
    if len(record) > 4096:
        raise error(STORAGE, "storage_failed")
    return base64.b64encode(record)


def decode_secret_record(config: Any, device: Any, output: bytes) -> tuple[int, StoredCredential | None]:
    if not isinstance(output, bytes) or len(output) > 5465:
        raise error(STORAGE, "storage_failed")
    encoded = output[:-1] if output.endswith(b"\n") else output
    if not encoded or len(encoded) > 5464:
        raise error(STORAGE, "storage_failed")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise error(STORAGE, "storage_failed") from exc
    if len(decoded) > 4096 or base64.b64encode(decoded) != encoded:
        raise error(STORAGE, "storage_failed")
    return decode_record(config, device, decoded)


class WindowsStorage:
    @classmethod
    def open(cls, directory: str, config: Any, device: Any) -> Any:
        if sys.platform != "win32":
            raise error(STORAGE, "storage_unavailable")
        from .storage_windows import WindowsStorage as NativeWindowsStorage
        return NativeWindowsStorage.open(directory, config, device)
