"""Isolated synthetic HTTPS fixture for Rust download tests; no external traffic."""
import http.server
import ssl
import sys
import time

PAYLOAD = b"verified seller bytes"

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass

    def do_GET(self):
        bearer = self.headers.get("Authorization", "")
        expected = "Bearer synthetic.ticket.proof" if self.path == "/start" else ""
        if bearer != expected or self.headers.get("Cookie") or self.headers.get("Accept-Encoding") != "identity":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path in ("/start", "/loop", "/http"):
            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.send_header("Location", {"/start": "/file", "/loop": "/loop", "/http": "http://localhost/file"}[self.path])
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        if self.path == "/encoded":
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        if self.path == "/blocked":
            time.sleep(2)
        payload = {"/wrong": b"x" * len(PAYLOAD), "/short": b"bad", "/oversize": PAYLOAD + b"x"}.get(self.path, PAYLOAD)
        try:
            self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
