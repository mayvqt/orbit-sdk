from __future__ import annotations

import errno
import http.client
import json
import random
import select
import socket
import ssl
import threading
import time
import urllib.parse
from collections import deque
from typing import Any, Callable

from .errors import (
    CANCELLED,
    CONFIGURATION,
    DENIED,
    INVALID_RESPONSE,
    TRANSIENT,
    TRANSPORT_SECURITY,
    OrbitError,
    error,
)
from .jsonutil import unique_json, fields, text

MAX_BYTES = 64 * 1024
OPERATION_TIMEOUT = 30.0
CLIENT_PREFIX = "/api/client/v1/"
JWKS_PATH = "/.well-known/orbit-jwks.json"
MAX_DNS_RESULTS = 16


class _ResolveJob:
    __slots__ = ("host", "port", "deadline", "ready", "state", "cancelled", "result", "failure")

    def __init__(self, host: str, port: int, deadline: float) -> None:
        self.host, self.port, self.deadline = host, port, deadline
        self.ready = threading.Event()
        self.state = "queued"
        self.cancelled = False
        self.result: list[tuple[Any, ...]] | None = None
        self.failure: BaseException | None = None


class _ResolverBusy(Exception):
    pass


class _ResolverPool:
    """Fixed daemon workers with a bounded, cancellable queue for DNS only."""

    def __init__(self, *, getaddrinfo: Callable[..., Any] = socket.getaddrinfo, workers: int = 2, queue_limit: int = 8) -> None:
        self._getaddrinfo = getaddrinfo
        self._worker_count, self._queue_limit = workers, queue_limit
        self._condition = threading.Condition()
        self._pending: deque[_ResolveJob] = deque()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._closed = False

    def _start_locked(self) -> None:
        if self._started:
            return
        self._started = True
        for index in range(self._worker_count):
            thread = threading.Thread(target=self._worker, name=f"orbit-sdk-dns-{id(self):x}-{index}", daemon=True)
            self._threads.append(thread)
            thread.start()

    def _worker(self) -> None:
        while True:
            with self._condition:
                while not self._pending and not self._closed:
                    self._condition.wait()
                if self._closed and not self._pending:
                    return
                job = self._pending.popleft()
                if job.cancelled:
                    continue
                job.state = "running"
            result = None
            failure = None
            try:
                result = self._getaddrinfo(
                    job.host, job.port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
                )[:MAX_DNS_RESULTS]
            except BaseException as exc:
                failure = exc
            with self._condition:
                if not job.cancelled:
                    if time.monotonic() >= job.deadline:
                        job.failure = socket.timeout("DNS resolution timed out")
                    else:
                        job.result, job.failure = result, failure
                    job.state = "done"
                    job.ready.set()

    def resolve(self, host: str, port: int, deadline: float, cancel: Any = None) -> list[tuple[Any, ...]]:
        if _cancelled(cancel):
            raise _AttemptError(error(CANCELLED, "operation_cancelled"))
        if time.monotonic() >= deadline:
            raise socket.timeout("DNS resolution timed out")
        job = _ResolveJob(host, port, deadline)
        with self._condition:
            if self._closed:
                raise _ResolverBusy
            self._start_locked()
            if len(self._pending) >= self._queue_limit:
                raise _ResolverBusy
            self._pending.append(job)
            self._condition.notify()
        while True:
            if _cancelled(cancel):
                self._cancel(job)
                raise _AttemptError(error(CANCELLED, "operation_cancelled"))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._cancel(job)
                raise socket.timeout("DNS resolution timed out")
            if job.ready.wait(min(remaining, 0.05)):
                if job.failure is not None:
                    raise job.failure
                if job.result is None:
                    raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "DNS resolution returned no addresses")
                return job.result

    def _cancel(self, job: _ResolveJob) -> None:
        with self._condition:
            if job.state == "queued":
                try:
                    self._pending.remove(job)
                except ValueError:
                    pass
            job.cancelled = True
            if job.state == "queued":
                job.state = "cancelled"
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            while self._pending:
                job = self._pending.popleft()
                job.cancelled = True
                job.state = "cancelled"
            self._condition.notify_all()
        for thread in self._threads:
            thread.join()


_DNS_RESOLVER = _ResolverPool()


_IO_POLL_INTERVAL = 0.05


def _check_io(deadline: float, cancel: Any, operation: str) -> None:
    if _cancelled(cancel):
        raise _AttemptError(error(CANCELLED, "operation_cancelled"))
    if time.monotonic() >= deadline:
        raise socket.timeout(f"{operation} timed out")


def _wait_ready(sock: socket.socket, deadline: float, cancel: Any, *, read: bool) -> None:
    while True:
        _check_io(deadline, cancel, "socket I/O")
        remaining = deadline - time.monotonic()
        try:
            readable, writable, exceptional = select.select(
                [sock] if read else [], [] if read else [sock], [sock], min(remaining, _IO_POLL_INTERVAL)
            )
        except InterruptedError:
            continue
        if readable or writable or exceptional:
            return


class _BoundedSSLSocket(ssl.SSLSocket):
    """Nonblocking TLS socket whose public I/O waits honor request limits."""

    def _configure(self, deadline: float, cancel: Any) -> None:
        self._deadline = deadline
        self._cancel = cancel
        self.setblocking(False)

    def _perform(self, operation: Callable[[], Any]) -> Any:
        while True:
            _check_io(self._deadline, self._cancel, "TLS I/O")
            try:
                result = operation()
            except ssl.SSLWantReadError:
                _wait_ready(self, self._deadline, self._cancel, read=True)
                continue
            except ssl.SSLWantWriteError:
                _wait_ready(self, self._deadline, self._cancel, read=False)
                continue
            _check_io(self._deadline, self._cancel, "TLS I/O")
            return result

    def recv_into(self, buffer: Any, nbytes: int | None = None, flags: int = 0) -> int:
        return self._perform(lambda: ssl.SSLSocket.recv_into(self, buffer, nbytes, flags))

    def send(self, data: Any, flags: int = 0) -> int:
        return self._perform(lambda: ssl.SSLSocket.send(self, data, flags))

    def do_handshake(self, block: bool = False) -> None:
        self._perform(lambda: ssl.SSLSocket.do_handshake(self, block=False))


class _BoundedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, timeout: float, context: ssl.SSLContext,
                 addresses: list[tuple[Any, ...]], deadline: float, cancel: Any) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._addresses = addresses
        self._deadline = deadline
        self._cancel = cancel

    def _connect_nonblocking(self, sock: socket.socket, address: Any) -> None:
        _check_io(self._deadline, self._cancel, "connection")
        result = sock.connect_ex(address)
        _check_io(self._deadline, self._cancel, "connection")
        connected = {0}
        pending: set[int] = set()
        for source in (errno, socket):
            for name in ("EISCONN", "WSAEISCONN"):
                value = getattr(source, name, None)
                if isinstance(value, int):
                    connected.add(value)
            for name in (
                "EINPROGRESS", "EWOULDBLOCK", "EALREADY", "EINTR",
                "WSAEWOULDBLOCK", "WSAEINPROGRESS", "WSAEALREADY",
            ):
                value = getattr(source, name, None)
                if isinstance(value, int):
                    pending.add(value)
        if result in connected:
            return
        if result not in pending:
            raise OSError(result, "socket connection failed")
        while True:
            _wait_ready(sock, self._deadline, self._cancel, read=False)
            result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            _check_io(self._deadline, self._cancel, "connection")
            if result in connected:
                return
            if result not in pending:
                raise OSError(result, "socket connection failed")

    def connect(self) -> None:
        last_failure: OSError | None = None
        for family, kind, protocol, _canonical, address in self._addresses:
            if _cancelled(self._cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled"))
            if time.monotonic() >= self._deadline:
                raise socket.timeout("connection attempt timed out")
            sock = socket.socket(family, kind, protocol)
            self.sock = sock
            try:
                sock.setblocking(False)
                self._connect_nonblocking(sock, address)
                if self._tunnel_host:
                    self._tunnel()
                _check_io(self._deadline, self._cancel, "TLS connection")
                self._context.sslsocket_class = _BoundedSSLSocket
                tls = self._context.wrap_socket(
                    sock,
                    server_hostname=self._tunnel_host or self.host,
                    do_handshake_on_connect=False,
                )
                self.sock = tls
                tls._configure(self._deadline, self._cancel)
                tls.do_handshake()
                return
            except _AttemptError:
                self.close()
                raise
            except OSError as exc:
                self.close()
                if _cancelled(self._cancel):
                    raise _AttemptError(error(CANCELLED, "operation_cancelled")) from exc
                if time.monotonic() >= self._deadline:
                    raise socket.timeout("connection attempt timed out") from exc
                last_failure = exc
        if last_failure is not None:
            raise last_failure
        raise socket.gaierror(getattr(socket, "EAI_NONAME", -2), "DNS resolution returned no addresses")


def _opaque(value: str) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and value.isascii() and all(c.isalnum() or c in "_-" for c in value)


def _safe_origin(origin: str) -> urllib.parse.SplitResult:
    if not isinstance(origin, str) or not origin or any(ord(c) <= 32 or ord(c) == 127 for c in origin):
        raise error(CONFIGURATION, "invalid_api_origin")
    try:
        parsed = urllib.parse.urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise error(CONFIGURATION, "invalid_api_origin") from exc
    authority = origin[8:] if origin.startswith("https://") else ""
    authority = authority[:-1] if authority.endswith("/") else authority
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not authority
        or any(char in authority for char in "/\\@?#")
        or port is not None and not 1 <= port <= 65535
    ):
        raise error(CONFIGURATION, "invalid_api_origin")
    return parsed


class Transport:
    """Fixed-origin HTTPS transport with bounded bodies and explicit retries."""

    def __init__(self, origin: str, *, _connection_factory: Callable[..., Any] | None = None,
                 _resolver: _ResolverPool | None = None) -> None:
        self._base = _safe_origin(origin)
        self._factory = _connection_factory
        self._resolver = _resolver
        self._ssl = ssl.create_default_context()

    def _endpoint(self, route: str) -> str:
        if (
            not isinstance(route, str)
            or len(route) > 2048
            or "//" in route
            or "\\" in route
            or "#" in route
            or any(ord(c) <= 32 or ord(c) == 127 for c in route)
        ):
            raise error(CONFIGURATION, "invalid_route")
        path, sep, query = route.partition("?")
        if not (path.startswith(CLIENT_PREFIX) or path == JWKS_PATH) or "%" in path:
            raise error(CONFIGURATION, "invalid_route")
        if path.rstrip("/") != path or any(part in (".", "..") for part in path.split("/")):
            raise error(CONFIGURATION, "invalid_route")
        if sep:
            if path not in (JWKS_PATH, CLIENT_PREFIX + "licences", CLIENT_PREFIX + "sessions/current"):
                raise error(CONFIGURATION, "invalid_route")
            pairs = query.split("&")
            names = ["application_id", "environment_id"]
            if path == CLIENT_PREFIX + "licences" and len(pairs) == 3:
                names.append("after")
            if len(pairs) != len(names):
                raise error(CONFIGURATION, "invalid_route")
            for pair, name in zip(pairs, names):
                key, equals, value = pair.partition("=")
                if not equals or key != name or not _opaque(value):
                    raise error(CONFIGURATION, "invalid_route")
        elif path in (CLIENT_PREFIX + "licences", CLIENT_PREFIX + "sessions/current"):
            # These routes are scoped by required query parameters.
            raise error(CONFIGURATION, "invalid_route")
        return path + (("?" + query) if sep else "")

    def get(self, route: str, cancel: Any = None) -> bytes:
        return self._request("GET", route, None, "", True, cancel)

    def get_bearer(self, route: str, token: str, cancel: Any = None) -> bytes:
        if route.partition("?")[0] != CLIENT_PREFIX + "licences":
            raise error(CONFIGURATION, "invalid_route")
        return self._request("GET", route, None, token, True, cancel)

    def delete_bearer(self, route: str, token: str, cancel: Any = None) -> None:
        if route.partition("?")[0] != CLIENT_PREFIX + "sessions/current":
            raise error(CONFIGURATION, "invalid_route")
        if self._request("DELETE", route, None, token, False, cancel) is not None:
            raise error(INVALID_RESPONSE, "unexpected_response_body")

    def post(self, route: str, body: Any, retry_safe: bool, cancel: Any = None) -> bytes | None:
        if _cancelled(cancel):
            raise error(CANCELLED, "operation_cancelled")
        try:
            data = __import__("json").dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise error(CONFIGURATION, "invalid_request") from exc
        if len(data) > MAX_BYTES:
            raise error(CONFIGURATION, "request_too_large")
        return self._request("POST", route, data, "", retry_safe, cancel)

    def _request(self, method: str, route: str, body: bytes | None, token: str, safe: bool, cancel: Any) -> bytes | None:
        endpoint = self._endpoint(route)
        if token and (len(token) > 256 or not _opaque(token)):
            raise error(CONFIGURATION, "invalid_authorization")
        if (method == "DELETE" or method == "GET" and route.partition("?")[0] == CLIENT_PREFIX + "licences") and not token:
            raise error(CONFIGURATION, "invalid_authorization")
        started = time.monotonic()
        deadline = started + OPERATION_TIMEOUT
        for attempt in range(3):
            if _cancelled(cancel):
                raise error(CANCELLED, "operation_cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise error(TRANSIENT, "request_timeout")
            try:
                result, retry_after = self._attempt(method, endpoint, body, token, min(10.0, remaining), cancel)
                if _cancelled(cancel):
                    raise error(CANCELLED, "operation_cancelled")
                if time.monotonic() >= deadline:
                    raise error(TRANSIENT, "request_timeout")
                return result
            except _AttemptError as failure:
                if _cancelled(cancel):
                    raise error(CANCELLED, "operation_cancelled")
                if not safe or attempt == 2 or failure.error.kind != TRANSIENT:
                    raise failure.error
                delay = random.uniform(0.250, 0.505) * (2**attempt)
                if failure.retry_after is not None:
                    delay = max(delay, failure.retry_after)
                if delay >= deadline - time.monotonic():
                    raise failure.error
                if _wait_cancel(cancel, delay):
                    raise error(CANCELLED, "operation_cancelled")
        raise error(TRANSIENT, "request_timeout")

    def _connection(self, timeout: float, deadline: float, cancel: Any) -> Any:
        if self._factory is not None and self._resolver is None:
            return self._factory(self._base.hostname, self._base.port or 443, timeout=timeout, context=self._ssl)
        resolver = self._resolver or _DNS_RESOLVER
        try:
            addresses = resolver.resolve(self._base.hostname, self._base.port or 443, deadline, cancel)
        except _ResolverBusy as exc:
            raise _AttemptError(error(TRANSIENT, "network_unavailable")) from exc
        if _cancelled(cancel):
            raise _AttemptError(error(CANCELLED, "operation_cancelled"))
        if time.monotonic() >= deadline:
            raise socket.timeout("DNS resolution timed out")
        if self._factory is not None:
            return self._factory(self._base.hostname, self._base.port or 443, timeout=timeout, context=self._ssl)
        return _BoundedHTTPSConnection(
            self._base.hostname,
            self._base.port or 443,
            timeout,
            self._ssl,
            addresses,
            deadline,
            cancel,
        )

    def _attempt(self, method: str, target: str, body: bytes | None, token: str, timeout: float, cancel: Any) -> tuple[bytes | None, float | None]:
        connection = None
        response = None
        deadline = time.monotonic() + timeout

        try:
            connection = self._connection(timeout, deadline, cancel)
            if time.monotonic() >= deadline:
                raise _AttemptError(error(TRANSIENT, "request_timeout"))
            if _cancelled(cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled"))
            headers = {"Accept": "application/json"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            if token:
                headers["Authorization"] = "Bearer " + token
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            if content_length is not None and content_length.isdigit() and int(content_length) > MAX_BYTES:
                raise _AttemptError(error(INVALID_RESPONSE, "response_too_large"))
            chunks = bytearray()
            while len(chunks) <= MAX_BYTES:
                if _cancelled(cancel):
                    raise _AttemptError(error(CANCELLED, "operation_cancelled"))
                chunk = response.read(min(8192, MAX_BYTES + 1 - len(chunks)))
                if time.monotonic() >= deadline:
                    raise _AttemptError(error(TRANSIENT, "request_timeout"))
                if _cancelled(cancel):
                    raise _AttemptError(error(CANCELLED, "operation_cancelled"))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) > MAX_BYTES:
                raise _AttemptError(error(INVALID_RESPONSE, "response_too_large"))
            data = bytes(chunks)
            status = response.status
            retry_after = _retry_after(response.getheader("Retry-After"))
            if status == 204:
                if data:
                    raise _AttemptError(error(INVALID_RESPONSE, "invalid_response"))
                return None, None
            if 200 <= status < 300:
                unique_json(data)
                return data, None
            if status in (502, 503, 504):
                if not _has_orbit_error_member(data):
                    raise _AttemptError(error(TRANSIENT, "service_unavailable"), retry_after)
            if status not in (401, 403, 404, 409, 422, 429) and not 500 <= status <= 599:
                raise _AttemptError(error(INVALID_RESPONSE, "unexpected_status"))
            envelope = unique_json(data)
            if not isinstance(envelope, dict) or "error" not in envelope:
                raise _AttemptError(error(INVALID_RESPONSE, "invalid_error_response"))
            failure = fields(envelope["error"], {"code": str, "message": str, "request_id": str})
            if not text(failure["code"], minimum=1, maximum=128, ascii_only=True) or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in failure["code"]):
                raise _AttemptError(error(INVALID_RESPONSE, "invalid_error_response"))
            if not failure["message"] or not text(failure["request_id"], minimum=1, maximum=64, ascii_only=True) or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in failure["request_id"]):
                raise _AttemptError(error(INVALID_RESPONSE, "invalid_error_response"))
            if (
                status == 429 and failure["code"] == "rate_limited"
                or status == 503 and failure["code"] == "service_unavailable"
            ):
                raise _AttemptError(error(TRANSIENT, failure["code"], failure["request_id"]), retry_after)
            raise _AttemptError(error(DENIED, failure["code"], failure["request_id"]))
        except _AttemptError:
            raise
        except ssl.SSLError as exc:
            if _cancelled(cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled")) from exc
            if time.monotonic() >= deadline:
                raise _AttemptError(error(TRANSIENT, "request_timeout")) from exc
            raise _AttemptError(error(TRANSPORT_SECURITY, "tls_failure")) from exc
        except (socket.timeout, TimeoutError) as exc:
            if _cancelled(cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled")) from exc
            raise _AttemptError(error(TRANSIENT, "request_timeout")) from exc
        except OSError as exc:
            if _cancelled(cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled")) from exc
            if time.monotonic() >= deadline:
                raise _AttemptError(error(TRANSIENT, "request_timeout")) from exc
            if _transient_os_error(exc):
                raise _AttemptError(error(TRANSIENT, "network_unavailable")) from exc
            raise _AttemptError(error(TRANSPORT_SECURITY, "transport_failure")) from exc
        except (http.client.HTTPException, ValueError) as exc:
            if _cancelled(cancel):
                raise _AttemptError(error(CANCELLED, "operation_cancelled")) from exc
            if time.monotonic() >= deadline:
                raise _AttemptError(error(TRANSIENT, "request_timeout")) from exc
            raise _AttemptError(error(TRANSPORT_SECURITY, "transport_failure")) from exc
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass


class _AttemptError(Exception):
    def __init__(self, error_value: OrbitError, retry_after: float | None = None) -> None:
        self.error = error_value
        self.retry_after = retry_after
        super().__init__(str(error_value))


def _cancelled(cancel: Any) -> bool:
    return cancel is not None and cancel.is_set()


def _has_orbit_error_member(data: bytes) -> bool:
    """Detect an error envelope loosely; strict decoding below rejects duplicates."""
    try:
        value = json.loads(data.decode("utf-8", "strict"))
    except (UnicodeError, ValueError, RecursionError):
        return False
    return isinstance(value, dict) and "error" in value


def _wait_cancel(cancel: Any, duration: float) -> bool:
    return bool(cancel.wait(duration)) if cancel is not None else (time.sleep(duration) or False)


def _retry_after(value: str | None) -> float | None:
    if value is None or not value or not value.isascii() or not value.isdecimal():
        return None
    try:
        return min(float(int(value)), OPERATION_TIMEOUT)
    except ValueError:
        return OPERATION_TIMEOUT


def _transient_os_error(exc: OSError) -> bool:
    transient = {
        getattr(errno, name)
        for name in ("ECONNREFUSED", "ECONNRESET", "ENETUNREACH", "EHOSTUNREACH", "EPIPE", "ETIMEDOUT")
        if hasattr(errno, name)
    }
    transient.update((10051, 10053, 10054, 10060, 10061, 10065, 11002))
    return exc.errno in transient or getattr(exc, "winerror", None) in transient or exc.errno == -3
