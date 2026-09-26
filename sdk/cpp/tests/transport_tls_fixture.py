#!/usr/bin/env python3
"""Loopback TLS fixture for the native transport regression driver."""

from __future__ import annotations

import argparse
import collections
import contextlib
import http.server
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from typing import Iterator
from urllib.parse import urlsplit


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts: collections.Counter[str] = collections.Counter()
        self.authorizations: dict[str, list[str]] = collections.defaultdict(list)

    def record(self, path: str, authorization: str) -> None:
        with self.lock:
            self.counts[path] += 1
            self.authorizations[path].append(authorization)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _handle(self) -> None:
        route = urlsplit(self.path).path
        state: State = self.server.state  # type: ignore[attr-defined]
        state.record(route, self.headers.get("Authorization", ""))
        if self.command == "POST":
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)

        if route == "/capture":
            self._respond(200, b'{"captured":true}')
        elif route == "/api/client/v1/sessions/current":
            host, port = self.server.server_address  # type: ignore[attr-defined]
            self._respond(
                302,
                b"redirect",
                headers={"Location": f"https://{host}:{port}/capture"},
            )
        elif route.endswith("/success"):
            self._respond(200, b'{"ok":true}')
        elif route.endswith("/body-limit"):
            self.send_response(200)
            self.send_header("Content-Length", str(64 * 1024 + 1))
            self.end_headers()
            try:
                for offset in range(0, 64 * 1024 + 1, 4096):
                    self.wfile.write(b"x" * min(4096, 64 * 1024 + 1 - offset))
                    self.wfile.flush()
            except OSError:
                pass
        elif route.endswith("/header-limit"):
            self.send_response(200)
            for index in range(5):
                self.send_header(f"X-Fill-{index}", "x" * 7900)
            self.send_header("Content-Length", "2")
            self.end_headers()
            try:
                self.wfile.write(b"{}")
                self.wfile.flush()
            except OSError:
                pass
        elif route.endswith("/stall"):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            try:
                self.wfile.write(b"{")
                self.wfile.flush()
                time.sleep(2)
                self.wfile.write(b"}")
                self.wfile.flush()
            except OSError:
                pass
        elif route.endswith("/stalled-deadline"):
            time.sleep(11)
            self._respond(200, b"{}")
        elif route.endswith("/deadline"):
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            try:
                for index, chunk in enumerate((b"{", b"}", b" ", b" ")):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if index != 3:
                        time.sleep(3.5)
            except OSError:
                pass
        elif route.endswith("/duplicate-field"):
            self._respond(
                503,
                b'{"error":{"code":"service_unavailable","code":"other",'
                b'"message":"busy","request_id":"fixture"}}',
            )
        elif route.endswith("/duplicate-member"):
            self._respond(
                503,
                b'{"error":{"code":"service_unavailable","message":"busy",'
                b'"request_id":"fixture"},"error":{}}',
            )
        elif route.endswith("/proxy-html"):
            self._respond(503, b"<html>temporary proxy failure</html>", "text/html")
        elif route.endswith("/valid-bounds"):
            body = json.dumps(
                {"error": {"code": "a" * 128, "message": "busy", "request_id": "R" * 64}},
                separators=(",", ":"),
            ).encode("ascii")
            self._respond(403, body)
        elif route.endswith("/code-too-long"):
            body = json.dumps(
                {"error": {"code": "a" * 129, "message": "busy", "request_id": "fixture"}},
                separators=(",", ":"),
            ).encode("ascii")
            self._respond(403, body)
        elif route.endswith("/request-id-too-long"):
            body = json.dumps(
                {"error": {"code": "licence_revoked", "message": "busy", "request_id": "R" * 65}},
                separators=(",", ":"),
            ).encode("ascii")
            self._respond(403, body)
        elif route.endswith("/nonfinite"):
            self._respond(200, b'{"value":1e999}')
        elif route.endswith("/surrogate-value"):
            self._respond(200, br'{"value":"\ud800"}')
        elif route.endswith("/surrogate-key"):
            self._respond(200, br'{"\ud800":"value"}')
        else:
            self._respond(404, b"not found", "text/plain")

    def _respond(
        self,
        status: int,
        body: bytes,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except OSError:
            pass

    def log_message(self, *_: object) -> None:
        pass


class TLSHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, certificate: str, key: str) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.state = State()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)


@contextlib.contextmanager
def running_server(certificate: str, key: str) -> Iterator[TLSHTTPServer]:
    server = TLSHTTPServer(certificate, key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def origin(server: TLSHTTPServer) -> str:
    return f"https://127.0.0.1:{server.server_address[1]}"


def run_driver(
    driver: str, scenario: str, endpoint: str, ca: str, timeout: float = 8
) -> None:
    environment = os.environ.copy()
    no_proxy = "127.0.0.1,localhost"
    environment["NO_PROXY"] = no_proxy
    environment["no_proxy"] = no_proxy
    completed = subprocess.run(
        [driver, scenario, endpoint, ca],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"scenario {scenario!r} failed with exit {completed.returncode}:\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--server-cert", required=True)
    parser.add_argument("--server-key", required=True)
    parser.add_argument("--mismatch-cert", required=True)
    parser.add_argument("--mismatch-key", required=True)
    args = parser.parse_args()

    with running_server(args.server_cert, args.server_key) as server, running_server(
        args.mismatch_cert, args.mismatch_key
    ) as mismatch_server:
        endpoint = origin(server)
        run_driver(args.driver, "routes", endpoint, args.ca)
        run_driver(args.driver, "success", endpoint, args.ca)
        run_driver(args.driver, "untrusted", endpoint, args.ca)
        run_driver(args.driver, "hostname", origin(mismatch_server), args.ca)

        run_driver(args.driver, "redirect", endpoint, args.ca)
        session_route = "/api/client/v1/sessions/current"
        if server.state.counts[session_route] != 1 or server.state.counts["/capture"] != 0:
            raise AssertionError("redirect was followed or the bearer reached its target")
        authorization = server.state.authorizations[session_route]
        if authorization != ["Bearer synthetic_bearer_123"]:
            raise AssertionError("the synthetic bearer was not attached to the initial request")

        for scenario in (
            "body-limit",
            "header-limit",
            "duplicate-field",
            "duplicate-member",
            "valid-bounds",
            "code-too-long",
            "request-id-too-long",
            "nonfinite",
            "surrogate-value",
            "surrogate-key",
        ):
            run_driver(args.driver, scenario, endpoint, args.ca)
        for duplicate in ("duplicate-field", "duplicate-member"):
            route = f"/api/client/v1/status/{duplicate}"
            if server.state.counts[route] != 1:
                raise AssertionError(f"malformed Orbit envelope {duplicate} was retried")

        run_driver(args.driver, "proxy-html", endpoint, args.ca)
        if server.state.counts["/api/client/v1/status/proxy-html"] != 3:
            raise AssertionError("an HTML proxy failure did not remain transient")
        run_driver(args.driver, "cancel", endpoint, args.ca)
        run_driver(args.driver, "owner-cancel", endpoint, args.ca)
        if server.state.counts["/api/client/v1/status/stall"] != 2:
            raise AssertionError("cancelled trusted TLS request did not reach the fixture")
        run_driver(args.driver, "stalled-deadline", endpoint, args.ca, timeout=20)
        run_driver(args.driver, "deadline", endpoint, args.ca, timeout=20)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        refused_port = reservation.getsockname()[1]
    run_driver(args.driver, "refused", f"https://127.0.0.1:{refused_port}", args.ca)

    print("TLS transport checks passed: 21 driver scenarios plus retry/redirect assertions")


if __name__ == "__main__":
    main()
