# Shared SDK security vectors

These Orbit-authored shared SDK fixtures are available under the
[MIT licence](../../sdk/LICENSE).

[grants.json](grants.json) contains fixed ES256 tokens signed with the existing
synthetic key in `sdk/rust/tests/fixtures`. This is public test material, never a
production signing key. Twelve valid and 92 invalid cases cover scope, claim types,
time/lifetime limits, negotiated refresh timing, binding, duplicate fields, boolean entitlements, JOSE headers,
signature/encoding rejection and bounded trusted JWKS handling.

The grant-verifying Rust, Go, C#, C++, and Python SDKs consume the same bytes
with a fixed clock. `expected` supplies
the trusted verification context; a case's optional `expected` object overrides
only those fields. A case's optional `jwks` replaces the whole trusted key set.
`valid` is the expected result of key parsing followed by grant verification.
Malformed input must return rejection without crashing or accepting access.
For `binding_mode=none`, fingerprint claims must be absent; explicit JSON null
values are rejected as well as populated fingerprint claims.

The corpus uses format version 1. Its tokens were generated with the workstation's
existing Python cryptography ECDSA implementation and the checked-in synthetic
private key; no runtime or check dependency on that generator is required.
The Rust unit test accepts `ORBIT_SDK_GRANT_VECTORS` to locate the same corpus
when testing an unpacked SDK outside the source tree.

This covers grant acceptance. Transport, account/device concurrency, offline
state transitions and native suspend behavior need separate integration and
platform checks.

## Long-term offline files

[offline.md](offline.md) defines the separate signed-file and renewal contract.
[offline-files.json](offline-files.json) supplies 13 valid and 91 invalid synthetic
ES256 cases, using the fixture key named above and a second synthetic key for
trusted rotation. These files
are distinct from short-lived connected access grants. `expected` contains the
app key, installation, optional binding, verification time and minimum accepted
renewal sequence; per-case overrides and replacement trusted `jwks` work like the
connected corpus. The Python verifier consumes the corpus, with installed import,
renewal and restart behavior covered separately. Other SDK consumers and the
server issuance workflow are still being implemented.

Do not treat a passing file-verification corpus as evidence that issuance,
durable renewal or reboot behavior is complete. Those require the behavioral
checks in the contract. The configured keys are trusted inputs; no case authorizes
discovering a key from the file being verified.

## Licensed downloads

The pending seller-hosted delivery feature is defined in
[downloads.md](downloads.md). Its contract does not imply that release discovery,
download authorization or SDK helpers are implemented.

## App keys

[app-keys.json](app-keys.json) fixes how every SDK parses the public app key
shown on Orbit's **Integration** page. An app key is not a secret; it only
names the API origin, application and environment:

```text
orbit_app_{test|live}_{base64url(api_origin)}.{application_id}.{environment_id}
```

Parsing trims surrounding whitespace, then requires at most 512 characters,
the exact lowercase `orbit_app_test_` or `orbit_app_live_` prefix and exactly
three `.`-separated parts. Customer licence keys use the application's chosen
prefix and are separate from this public configuration. The origin uses the
unpadded URL-safe base64 alphabet and
must decode to UTF-8 that passes the SDK's ordinary HTTPS origin rules. Both IDs
are 1–128 ASCII letters, digits, `_` or `-`. The grant issuer is the API origin.
Any other input is a configuration error. Valid cases list the parsed values.
