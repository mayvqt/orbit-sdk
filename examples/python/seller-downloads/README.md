# Seller-hosted protected downloads

This example verifies an Orbit download ticket and redirects to a private
S3-compatible object owned by the seller. It does not create a bucket, upload a
file or send storage credentials to Orbit. Configure Orbit with this endpoint's
URL; Orbit supplies the authorization ticket and your backend controls delivery.

From the SDK checkout root, install into a local environment:

```sh
python3 -m venv build/seller-downloads-venv
build/seller-downloads-venv/bin/python -m pip install ./sdk/python -r examples/python/seller-downloads/requirements.txt
```

Configure your server's environment with `ORBIT_APP_KEY`,
`ORBIT_DOWNLOAD_ENDPOINT` (for example `https://downloads.your-domain.com/file`),
`ORBIT_PUBLIC_KEYS_FILE` and `ORBIT_ARTIFACTS_FILE`. The first file contains
trusted public keys obtained from your configured Orbit environment. Update it
when keys rotate. The second maps Orbit artifact IDs to your own object records;
copy [artifacts.example.json](artifacts.example.json) and replace every placeholder,
including the exact SHA-256 and byte count of your file. Keep published objects
immutable. A ticket cannot supply a bucket, path or arbitrary URL.

Use your provider's normal Boto3 credential configuration on this backend.
`S3_ENDPOINT_URL` optionally selects an HTTPS S3-compatible endpoint; configure the
appropriate region too. Keep these credentials out of installed software, Orbit
and source control. The seller's existing storage account bears its storage and
delivery charges. See the provider's
[presigned URL API](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/generate_presigned_url.html).

Run a local development endpoint after setting those values:

```sh
build/seller-downloads-venv/bin/python -m flask --app examples/python/seller-downloads/server.py run --host 127.0.0.1 --port 8090
```

This command starts Flask's local development server. For an actual seller
service, use its normal WSGI hosting behind HTTPS, route the configured endpoint
path to this app, and apply request/header size limits at that front end. Keep
debug mode off. Exclude authorization and `Location` response headers from logs;
the latter contains a temporary storage capability.

The client sends an Orbit ticket in `Authorization: Bearer …`. The endpoint
checks its signature, exact configured audience, scope, expiry, artifact ID,
release, digest and byte count. It returns a 302 with a storage URL lasting at
most 60 seconds and no longer than the ticket. Responses forbid caching. Never
forward the Orbit authorization header when following the storage redirect.
Keep both URLs and tickets out of telemetry. A valid ticket or storage URL is
replayable until its deadline; a downloaded file can still be copied.

Run the local example checks:

```sh
build/seller-downloads-venv/bin/python -m unittest discover -s examples/python/seller-downloads -p 'test_*.py'
```

These tests exercise the real public verifier and Boto3 signing using synthetic
credentials; they never contact a bucket. Test your provider integration and
the complete TLS download flow separately before accepting user traffic.
