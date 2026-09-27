"""Direct, bounded HTTPS downloads. Never executes or unpacks an artifact."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
from urllib.parse import urljoin, urlsplit

from .errors import CANCELLED, CONFIGURATION, INVALID_RESPONSE, STORAGE, TRANSIENT, TRANSPORT_SECURITY, OrbitError, error
from .online import DownloadAuthorization, delivery_url, integer, parse_artifact, require
from .transport import _AttemptError, _BoundedHTTPSConnection, _DNS_RESOLVER


def download_file(authorization: DownloadAuthorization, destination: str | os.PathLike[str], *,
                  max_bytes: int, replace: bool = False, cancellation=None) -> Path:
    """Write only length- and SHA-256-verified bytes; preserve old files on failure."""
    return _download_file(authorization, destination, max_bytes=max_bytes, replace=replace, cancellation=cancellation)


def _download_file(authorization, destination, *, max_bytes, replace=False, cancellation=None, _context=None):
    require(authorization, lambda v: isinstance(v, DownloadAuthorization))
    require(max_bytes, lambda v: integer(v, 1))
    require(replace, lambda v: isinstance(v, bool))
    artifact = parse_artifact(vars(authorization.artifact))
    if artifact.byte_length > max_bytes:
        raise error(CONFIGURATION, "download_size_limit")
    if artifact.delivery_mode == "protected":
        from .online import parse_authorization
        parse_authorization(dict(artifact=vars(artifact), ticket=authorization.ticket,
                                 expires_at=authorization.expires_at.isoformat().replace("+00:00", "Z") if authorization.expires_at else None), artifact.release_id, artifact.id)
    elif authorization.ticket is not None or authorization.expires_at is not None:
        raise error(CONFIGURATION, "invalid_download_authorization")
    target = Path(destination).absolute()
    if not replace and os.path.lexists(target):
        raise error(STORAGE, "destination_exists")
    deadline = time.monotonic() + 300
    temporary = None
    connection = response = None

    def check():
        if cancellation is not None and cancellation.is_set():
            raise error(CANCELLED, "operation_cancelled")
        if time.monotonic() >= deadline:
            raise error(TRANSIENT, "download_timeout")

    try:
        check()
        context = _context or ssl.create_default_context()
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise error(TRANSPORT_SECURITY, "tls_verification_required")
        current = artifact.url
        for redirects in range(6):
            check()
            delivery_url(current)
            endpoint = urlsplit(current)
            addresses = _DNS_RESOLVER.resolve(endpoint.hostname, endpoint.port or 443, deadline, cancellation)
            connection = _BoundedHTTPSConnection(endpoint.hostname, endpoint.port or 443, 300, context, addresses, deadline, cancellation)
            headers = {"Accept": "application/octet-stream", "Accept-Encoding": "identity"}
            if redirects == 0 and authorization.ticket is not None:
                headers["Authorization"] = "Bearer " + authorization.ticket
            connection.request("GET", (endpoint.path or "/") + ("?" + endpoint.query if endpoint.query else ""), headers=headers)
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                locations = response.headers.get_all("Location", [])
                if redirects == 5 or len(locations) != 1:
                    raise error(INVALID_RESPONSE, "invalid_download_redirect")
                location = locations[0]
                if (not location or not location.isascii() or any(ord(c) <= 32 or ord(c) == 127 or c in '\\#<>"{}|^`' for c in location)
                        or re.search(r"%(?![0-9A-Fa-f]{2})", location)):
                    raise error(INVALID_RESPONSE, "invalid_download_redirect")
                if location.startswith("//"):
                    delivery_url("https:" + location)
                elif urlsplit(location).scheme:
                    delivery_url(location)
                next_url = urljoin(current, location)
                delivery_url(next_url)
                response.close()
                connection.close()
                response = connection = None
                current = next_url
                continue
            if response.status != 200:
                raise error(INVALID_RESPONSE, "download_http_error")
            encodings = response.headers.get_all("Content-Encoding", [])
            if encodings and encodings != ["identity"]:
                raise error(INVALID_RESPONSE, "unexpected_content_encoding")
            lengths = response.headers.get_all("Content-Length", [])
            if lengths and (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or int(lengths[0]) != artifact.byte_length):
                raise error(INVALID_RESPONSE, "download_length_mismatch")
            if lengths and response.getheader("Transfer-Encoding") is not None:
                raise error(INVALID_RESPONSE, "invalid_download_framing")
            fd, temporary = tempfile.mkstemp(prefix=".orbit-download-", dir=target.parent)
            digest, count = hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    check()
                    chunk = response.read(min(65536, min(max_bytes, artifact.byte_length) - count + 1))
                    check()
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > max_bytes or count > artifact.byte_length:
                        raise error(INVALID_RESPONSE, "download_size_limit")
                    digest.update(chunk)
                    output.write(chunk)
                if count != artifact.byte_length or digest.hexdigest() != artifact.sha256:
                    raise error(INVALID_RESPONSE, "download_integrity_mismatch")
                output.flush()
                os.fsync(output.fileno())
            check()
            if replace:
                os.replace(temporary, target)
            else:
                # link is atomic and cannot overwrite a destination created during transfer.
                os.link(temporary, target)
                os.unlink(temporary)
            temporary = None
            return target
        raise error(INVALID_RESPONSE, "invalid_download_redirect")
    except _AttemptError as exc:
        raise exc.error from None
    except OrbitError:
        raise
    except ssl.SSLError:
        raise error(TRANSPORT_SECURITY, "tls_failure") from None
    except (TimeoutError, http.client.HTTPException):
        check()
        raise error(TRANSIENT, "download_incomplete") from None
    except OSError:
        check()
        raise error(STORAGE, "download_failed") from None
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
