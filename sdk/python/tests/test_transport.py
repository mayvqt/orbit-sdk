from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import ssl
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID

from orbit_sdk import Cancellation
from orbit_sdk.errors import CANCELLED, TRANSIENT
from orbit_sdk.errors import OrbitError
from orbit_sdk.transport import MAX_BYTES, Transport, _ResolverPool, _transient_os_error


class _Response:
    def __init__(self, status: int, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._data = data
        self._headers = headers or {}
        self._offset = 0

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._data)
        value = self._data[self._offset : self._offset + size]
        self._offset += len(value)
        return value

    def close(self) -> None:
        pass


class _Connection:
    def __init__(self, response: _Response, requests: list[tuple[str, str, dict[str, str]]]) -> None:
        self.response = response
        self.requests = requests
        self.sock = None

    def request(self, method: str, route: str, *, body: bytes | None, headers: dict[str, str]) -> None:
        self.requests.append((method, route, headers))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        pass


@contextmanager
def _trusted_tls_server(handler: type[http.server.BaseHTTPRequestHandler]):
    with tempfile.TemporaryDirectory(prefix="orbit-python-tls-ca-") as directory:
        root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Orbit synthetic test CA")])
        now = dt.datetime.now(dt.timezone.utc)
        root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(root_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        ca_path = Path(directory, "ca.pem")
        cert_path, key_path = Path(directory, "server.pem"), Path(directory, "server-key.pem")
        ca_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
        cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)

        def discard_handler_error(*_: Any) -> None:
            pass

        server.handle_error = discard_handler_error
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client_context = ssl.create_default_context(cafile=str(ca_path))
            yield f"https://127.0.0.1:{server.server_address[1]}", client_context
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


class TransportTests(unittest.TestCase):
    def test_origin_and_route_are_fixed_trusted_https_scope(self) -> None:
        for bad in (
            "http://orbit.example.test",
            "https://user:password@orbit.example.test",
            "https://orbit.example.test/path",
            "https://orbit.example.test?next=https://attacker.example",
            "https://orbit.example.test/#fragment",
            "https://orbit.example.test:0",
        ):
            with self.assertRaises(OrbitError):
                Transport(bad)
        transport = Transport("https://orbit.example.test")
        for route in (
            "https://attacker.example/api/client/v1/sessions",
            "/api/client/v1/../sessions",
            "/api/client/v1/sessions?application_id=app&environment_id=test",
            "/api/client/v1/licences?environment_id=test&application_id=app",
            "/api/client/v1/licences?application_id=app&environment_id=test&after=bad%2Fcursor",
        ):
            with self.assertRaises(OrbitError):
                transport._endpoint(route)

    def test_redirect_is_not_followed_and_authorization_is_not_forwarded(self) -> None:
        requests: list[tuple[str, str, dict[str, str]]] = []
        connections: list[_Connection] = []

        def factory(*_: Any, **__: Any) -> _Connection:
            connection = _Connection(_Response(302, b"redirect", {"Location": "https://attacker.example/collect"}), requests)
            connections.append(connection)
            return connection

        transport = Transport("https://orbit.example.test", _connection_factory=factory)
        with self.assertRaises(OrbitError) as raised:
            transport.get_bearer("/api/client/v1/licences?application_id=app&environment_id=test", "s" * 43)
        self.assertEqual(raised.exception.kind, "invalid_response")
        self.assertEqual(len(connections), 1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][2]["Authorization"], "Bearer " + "s" * 43)
        self.assertNotIn("s" * 43, str(raised.exception))

    def test_response_body_limit_is_enforced_before_json_decoding(self) -> None:
        requests: list[tuple[str, str, dict[str, str]]] = []
        transport = Transport(
            "https://orbit.example.test",
            _connection_factory=lambda *_args, **_kwargs: _Connection(_Response(200, b"{}", {"Content-Length": str(MAX_BYTES + 1)}), requests),
        )
        with self.assertRaises(OrbitError) as raised:
            transport.get("/api/client/v1/status")
        self.assertEqual(raised.exception.kind, "invalid_response")

    def test_only_safe_reads_retry_valid_transient_envelopes(self) -> None:
        requests: list[tuple[str, str, dict[str, str]]] = []
        queue = [
            _Response(503, b'{"error":{"code":"service_unavailable","message":"busy","request_id":"synthetic-1"}}'),
            _Response(200, b"{}"),
        ]

        def factory(*_: Any, **__: Any) -> _Connection:
            return _Connection(queue.pop(0), requests)

        transport = Transport("https://orbit.example.test", _connection_factory=factory)
        self.assertEqual(transport.get("/api/client/v1/status"), b"{}")
        self.assertEqual(len(requests), 2)

        requests.clear()
        queue[:] = [_Response(503, b'{"error":{"code":"service_unavailable","message":"busy","request_id":"synthetic-2"}}')]
        with self.assertRaises(OrbitError) as raised:
            transport.post("/api/client/v1/activations", {"idempotency_key": "synthetic"}, False)
        self.assertEqual(raised.exception.kind, "transient")
        self.assertEqual(len(requests), 1)

    def test_valid_server_errors_are_denied_except_exact_transient_envelopes(self) -> None:
        cases = (
            (500, "internal_error", "denied"),
            (429, "unexpected_code", "denied"),
            (429, "rate_limited", "transient"),
            (503, "service_unavailable", "transient"),
        )
        for status, code, kind in cases:
            requests: list[tuple[str, str, dict[str, str]]] = []
            body = (
                '{"error":{"code":"'
                + code
                + '","message":"private server message","request_id":"safe-request-1"}}'
            ).encode()
            transport = Transport(
                "https://orbit.example.test",
                _connection_factory=lambda *_args, value=body, response_status=status, **_kwargs:
                    _Connection(_Response(response_status, value), requests),
            )
            with self.assertRaises(OrbitError) as raised:
                transport.post("/api/client/v1/activations", {"operation": "synthetic"}, False)
            self.assertEqual(raised.exception.kind, kind)
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(raised.exception.request_id, "safe-request-1")
            self.assertNotIn("private server message", str(raised.exception))

    def test_windows_socket_outages_are_transient(self) -> None:
        for code in (10051, 10053, 10054, 10060, 10061, 10065, 11002):
            self.assertTrue(_transient_os_error(OSError(code, "synthetic network failure")), code)

    def test_proxy_errors_are_transient_but_duplicate_orbit_envelopes_fail_closed(self) -> None:
        requests: list[tuple[str, str, dict[str, str]]] = []
        cases = (
            b'{"error":{"code":"service_unavailable","code":"service_unavailable","message":"busy","request_id":"synthetic-1"}}',
            b'{"error":{"code":"service_unavailable","message":"busy","request_id":"synthetic-2"},"error":{}}',
        )
        for body in cases:
            transport = Transport(
                "https://orbit.example.test",
                _connection_factory=lambda *_args, value=body, **_kwargs: _Connection(_Response(503, value), requests),
            )
            before = len(requests)
            with self.assertRaises(OrbitError) as raised:
                transport.get("/api/client/v1/status")
            self.assertEqual(raised.exception.kind, "invalid_response")
            self.assertEqual(len(requests), before + 1)

        for body in (b'{"error":{"code":"service_unavailable"', b"<html>temporary proxy failure</html>"):
            queue = [_Response(503, body), _Response(200, b"{}")]

            def factory(*_: Any, **__: Any) -> _Connection:
                return _Connection(queue.pop(0), requests)

            transport = Transport("https://orbit.example.test", _connection_factory=factory)
            before = len(requests)
            self.assertEqual(transport.get("/api/client/v1/status"), b"{}")
            self.assertEqual(len(requests), before + 2)

    def test_absolute_deadline_aborts_slow_headers_and_body_with_trusted_tls(self) -> None:
        for slow_body in (False, True):
            entered = threading.Event()
            release = threading.Event()

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    entered.set()
                    if slow_body:
                        self.send_response(200)
                        self.send_header("Content-Length", "7")
                        self.end_headers()
                        for byte in b'{"x":1}':
                            try:
                                self.wfile.write(bytes((byte,)))
                                self.wfile.flush()
                            except OSError:
                                return
                            if release.wait(0.12):
                                return
                    release.wait(2)
                    if not slow_body:
                        self.send_response(200)
                        self.send_header("Content-Length", "2")
                        self.end_headers()
                    try:
                        self.wfile.write(b"}")
                        self.wfile.flush()
                    except OSError:
                        pass

                def log_message(self, *_: object) -> None:
                    pass

            with _trusted_tls_server(Handler) as (origin, context):
                transport = Transport(origin)
                transport._ssl = context
                started = time.monotonic()
                with patch("orbit_sdk.transport.OPERATION_TIMEOUT", 0.25):
                    with self.assertRaises(OrbitError) as raised:
                        transport.get("/api/client/v1/status")
                elapsed = time.monotonic() - started
                release.set()
                self.assertEqual(raised.exception.kind, TRANSIENT)
                self.assertLess(elapsed, 0.45 if slow_body else 1.0)
                self.assertTrue(entered.is_set())

    def test_cancellation_shuts_down_an_inflight_trusted_tls_read(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                try:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{")
                    self.wfile.flush()
                    entered.set()
                    release.wait(2)
                    self.wfile.write(b"}")
                except OSError:
                    pass

            def log_message(self, *_: object) -> None:
                pass

        with _trusted_tls_server(Handler) as (origin, context):
            transport = Transport(origin)
            transport._ssl = context
            cancellation = Cancellation.create()
            result: list[BaseException | bytes] = []

            def request() -> None:
                try:
                    result.append(transport.get("/api/client/v1/status", cancellation))
                except BaseException as exc:
                    result.append(exc)

            thread = threading.Thread(target=request)
            started = time.monotonic()
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                cancellation.cancel()
                thread.join(1)
            finally:
                release.set()
                cancellation.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(result), 1)
            self.assertIsInstance(result[0], OrbitError)
            self.assertEqual(result[0].kind, CANCELLED)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_slow_dns_deadline_and_cancellation_do_not_start_http_requests(self) -> None:
        original_getaddrinfo = __import__("socket").getaddrinfo
        for cancel_request in (False, True):
            entered = threading.Event()
            release = threading.Event()
            completed = threading.Event()
            connection_calls: list[bool] = []

            def slow_lookup(host: str, port: int, **kwargs: Any) -> Any:
                entered.set()
                release.wait(2)
                completed.set()
                return original_getaddrinfo(host, port, **kwargs)

            resolver = _ResolverPool(getaddrinfo=slow_lookup, workers=1, queue_limit=1)
            transport = Transport(
                "https://orbit.example.test",
                _resolver=resolver,
                _connection_factory=lambda *_args, **_kwargs: connection_calls.append(True),
            )
            cancellation = Cancellation.create() if cancel_request else None
            result: list[BaseException | bytes] = []

            def request() -> None:
                try:
                    result.append(transport.get("/api/client/v1/status", cancellation))
                except BaseException as exc:
                    result.append(exc)

            thread = threading.Thread(target=request)
            try:
                with patch("orbit_sdk.transport.OPERATION_TIMEOUT", 0.25):
                    started = time.monotonic()
                    thread.start()
                    self.assertTrue(entered.wait(1))
                    if cancellation is not None:
                        cancellation.cancel()
                    thread.join(1)
                    self.assertFalse(thread.is_alive())
                    self.assertLess(time.monotonic() - started, 0.8)
                self.assertEqual(len(result), 1)
                self.assertIsInstance(result[0], OrbitError)
                self.assertEqual(result[0].kind, CANCELLED if cancel_request else TRANSIENT)
                self.assertEqual(connection_calls, [])
            finally:
                release.set()
                if cancellation is not None:
                    cancellation.close()
                self.assertTrue(completed.wait(1))
                resolver.close()

    def test_default_tls_context_rejects_an_isolated_self_signed_server(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with tempfile.TemporaryDirectory(prefix="orbit-python-tls-") as directory:
            cert_path, key_path = Path(directory, "cert.pem"), Path(directory, "key.pem")
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")

                def log_message(self, *_: object) -> None:
                    pass

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                transport = Transport(f"https://127.0.0.1:{server.server_address[1]}")
                with self.assertRaises(OrbitError) as raised:
                    transport.get("/api/client/v1/status")
                self.assertEqual(raised.exception.kind, "transport_security")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
