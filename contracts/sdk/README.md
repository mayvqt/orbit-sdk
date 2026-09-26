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
connected corpus. Python, Go, Rust, C# and C++ verifiers consume the corpus.
Python, Go and Rust installed import, renewal and restart behavior is covered
separately. The matching private Orbit candidate includes authenticated issuance,
dashboard export and recovery handling; real Python interoperability and
desktop/mobile browser checks pass. C#/C++, installed TypeScript and embedded
lifecycle work remains in progress. Neither candidate has been released or deployed.

Do not treat a passing file-verification corpus as evidence that issuance,
durable renewal or reboot behavior is complete. Those require the behavioral
checks in the contract. The configured keys are trusted inputs; no case authorizes
discovering a key from the file being verified.

## Licensed downloads

The pending seller-hosted delivery feature is defined in
[downloads.md](downloads.md). Its contract does not imply that release discovery,
download authorization or SDK helpers are implemented.

[download-tickets.json](download-tickets.json) has 110 synthetic cases (10 valid,
100 invalid), consumed by the Python, C# and C++ seller-endpoint verifiers.
`expected` pins the public app key, exact endpoint and verification time. Each
case may override that context or the trusted JWKS. The fixture signing keys are the same public test
material described above. These checks cover ticket verification; server
issuance, storage redirects and verified streaming need separate integration
evidence.

## Floating sessions

[floating.md](floating.md) defines seat acquisition, renewal, release and the
separate session-grant purpose. It is an implementation baseline; ordinary
activation grants do not provide concurrent-session enforcement.

[session-grants.json](session-grants.json) supplies 184 signed cases (23 valid,
161 invalid), consumed by the internal Python and C# verifiers. Its expected
context extends the connected corpus with `session_id`, exact `sequence` and
the configured Test/Live `key_environment`. Cases cover process/sequence binding,
120-second intervals, active retries without deadline extension, exact expiry,
refresh timing, credential/purchased caps, scope and machine binding, purpose
separation, strict encodings and retained-key validation. The fixture key is the
same public test material, with an additional synthetic rotation key. These cases
do not establish automatic acquisition, renewal, release or durable seat accounting.

## Usage and resource limits

[limits.md](limits.md) defines online usage consumption and persistent resource
allocations, including retries and the trust boundary for customer-controlled
applications. Implementation and behavioral tests remain pending.

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
