"""Seller-owned endpoint: exchange an Orbit ticket for a short private S3 URL."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from flask import Flask, Response, request
from orbit_sdk import DownloadTicketVerifier, OrbitError


def create_app(configuration=None, *, storage=None, clock=None):
    if configuration is None:
        configuration = {
            "app_key": os.environ["ORBIT_APP_KEY"],
            "endpoint": os.environ["ORBIT_DOWNLOAD_ENDPOINT"],
            "public_keys": Path(os.environ["ORBIT_PUBLIC_KEYS_FILE"]).read_bytes(),
            "artifacts": json.loads(Path(os.environ["ORBIT_ARTIFACTS_FILE"]).read_text()),
        }
    endpoint = configuration["endpoint"]
    verifier = DownloadTicketVerifier(configuration["app_key"], endpoint, configuration["public_keys"])
    artifacts = {key: dict(value) for key, value in configuration["artifacts"].items()}
    now = clock or (lambda: datetime.now(timezone.utc))
    if storage is None:
        storage_endpoint = os.environ.get("S3_ENDPOINT_URL")
        if storage_endpoint and not storage_endpoint.startswith("https://"):
            raise ValueError("S3_ENDPOINT_URL must use HTTPS")
        storage = boto3.client(
            "s3", endpoint_url=storage_endpoint,
            config=Config(signature_version="s3v4", connect_timeout=5, read_timeout=5),
        )
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 0

    @app.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def download():
        if request.method != "GET":
            return Response(status=405)
        authorization = request.headers.get("Authorization", "")
        if request.query_string or not authorization.startswith("Bearer ") or len(authorization) > 16391:
            return Response(status=401)
        try:
            ticket = verifier.verify(authorization[7:], now=now())
        except OrbitError:
            return Response(status=401)
        artifact = artifacts.get(ticket.artifact_id)
        if artifact is None or any(artifact.get(name) != getattr(ticket, name) for name in (
            "release_id", "sha256", "byte_length",
        )):
            return Response(status=403)
        remaining = int((ticket.expires_at - now()).total_seconds())
        if remaining < 1:
            return Response(status=401)
        try:
            url = storage.generate_presigned_url(
                "get_object", Params={"Bucket": artifact["bucket"], "Key": artifact["object_key"]},
                ExpiresIn=min(60, remaining), HttpMethod="GET",
            )
            # SigV4 URL expiry must not extend the ticket after a slow signing
            # operation or credential refresh. Neither URL nor bearer is logged.
            parsed = urlsplit(url)
            values = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
            dates, durations = values.get("X-Amz-Date", []), values.get("X-Amz-Expires", [])
            if (
                parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or len(url) > 16384
                or any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url)
                or len(dates) != 1 or len(durations) != 1 or not durations[0].isascii()
                or not durations[0].isdigit() or not 1 <= int(durations[0]) <= 60
            ):
                return Response(status=503)
            signed_at = datetime.strptime(dates[0], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            storage_expiry = signed_at + timedelta(seconds=int(durations[0]))
            if not now() < storage_expiry <= ticket.expires_at:
                return Response(status=503)
        except (BotoCoreError, ClientError, ValueError, KeyError, TypeError, OverflowError):
            return Response(status=503)
        return Response(status=302, headers={"Location": url})

    app.add_url_rule(urlsplit(endpoint).path or "/", view_func=download, methods=["GET"], provide_automatic_options=False)
    return app
