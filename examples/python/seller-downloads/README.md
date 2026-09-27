# Seller-hosted protected downloads

This Flask endpoint verifies an Orbit download ticket and redirects to a
private S3-compatible object you own. Orbit never receives your storage
credentials or file bytes; configure this endpoint's URL on the artifact in
Orbit.

## Set up

From the repository root:

```sh
python3 -m venv build/seller-downloads-venv
build/seller-downloads-venv/bin/python -m pip install ./sdk/python -r examples/python/seller-downloads/requirements.txt
```

Set these environment variables on the server:

* `ORBIT_APP_KEY`: the application's public app key.
* `ORBIT_DOWNLOAD_ENDPOINT`: this endpoint's exact HTTPS URL, for example
  `https://downloads.your-domain.com/file`.
* `ORBIT_PUBLIC_KEYS_FILE`: trusted public keys from your Orbit environment.
  Update the file when keys rotate.
* `ORBIT_ARTIFACTS_FILE`: a copy of [artifacts.example.json](artifacts.example.json)
  mapping Orbit artifact IDs to your objects, with each file's exact SHA-256 and
  byte count. Keep published objects immutable.
* Your provider's normal Boto3 credentials and region, plus `S3_ENDPOINT_URL`
  for a non-AWS HTTPS endpoint.

## Run

```sh
build/seller-downloads-venv/bin/python -m flask --app examples/python/seller-downloads/server.py run --host 127.0.0.1 --port 8090
```

This starts Flask's development server. In production, host the app with a
WSGI server behind HTTPS, apply request and header size limits at the front
end and keep debug mode off.

## What it does

The client sends the ticket in `Authorization: Bearer …`. The endpoint checks
its signature, audience, scope and expiry, then matches the artifact ID,
release, digest and byte count against your registry; a ticket can never choose
a bucket, path or URL. It answers with a `302` to a presigned
[storage URL](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/generate_presigned_url.html)
that lasts at most 60 seconds and never outlives the ticket, and forbids
caching.

Tickets and storage URLs are replayable until they expire, and a downloaded file
can still be copied. Keep the `Authorization` and `Location` headers out of
logs and telemetry.
