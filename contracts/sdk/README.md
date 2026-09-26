# Shared SDK security vectors

These Orbit-authored shared SDK fixtures are available under the
[MIT licence](../../sdk/LICENSE).

[grants.json](grants.json) contains fixed ES256 tokens signed with the existing
synthetic key in `sdk/rust/tests/fixtures`. This is public test material, never a
production signing key. Twelve valid and 89 invalid cases cover scope, claim types,
time/lifetime limits, negotiated refresh timing, binding, duplicate fields, boolean entitlements, JOSE headers,
signature/encoding rejection and bounded trusted JWKS handling.

The grant-verifying Rust, Go, C#, C++, and Python SDKs consume the same bytes
with a fixed clock. `expected` supplies
the trusted verification context; a case's optional `expected` object overrides
only those fields. A case's optional `jwks` replaces the whole trusted key set.
`valid` is the expected result of key parsing followed by grant verification.
Malformed input must return rejection without crashing or accepting access.

The corpus uses format version 1. Its tokens were generated with the workstation's
existing Python cryptography ECDSA implementation and the checked-in synthetic
private key; no runtime or check dependency on that generator is required.
The Rust unit test accepts `ORBIT_SDK_GRANT_VECTORS` to locate the same corpus
when testing an unpacked SDK outside the source tree.

This covers grant acceptance. Transport, account/device concurrency, offline
state transitions and native suspend behavior need separate integration and
platform checks.

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
