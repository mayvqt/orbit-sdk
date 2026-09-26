# Seller-hosted releases and licensed downloads

Implementation contract for the candidate feature; no release or deployment is
implied. Sellers host their files. Orbit stores release metadata and authorizes
access; it does not upload, store, scan or proxy the file contents.

## Release metadata

A release belongs to one application/environment and channel. It has a seller's
display version, an immutable increasing release number, release notes and one
or more artifacts identified by platform and architecture. Publish a complete
release atomically. Never replace an artifact's bytes under its published ID;
publish another release when the payload changes. Drafts are not discoverable
by installed clients, and unpublishing prevents new authorization.

Each artifact records its byte length, SHA-256 digest, filename, HTTPS delivery
URL and optional required boolean feature. A valid, current licence is always
required for licensed discovery and authorization. A required feature adds to
that requirement. Ordinary licence expiry and suspension/revocation rules apply;
this feature does not extend purchased access or create a separate maintenance
term. The dashboard must keep Test and Live releases separate.

Update discovery takes the channel, platform, architecture and installed release
number. It returns the newest eligible published release with a greater number,
or no update. The number is an ordering mechanism; display-version text must not
be compared lexically. Clients never choose an artifact for another target as an
automatic fallback.

## Delivery choices

The seller chooses one of two clearly labelled delivery modes:

- **Public URL:** Orbit authorizes disclosure of the URL. Anyone who obtains the
  permanent URL can share it; Orbit cannot enforce subsequent access to that
  public host.
- **Protected seller endpoint:** the endpoint verifies a short-lived Orbit
  download ticket, then serves the file or redirects to an expiring URL from the
  seller's private storage. A protected endpoint that ignores the ticket does not
  enforce licensing.

Do not provision Orbit-owned storage or request a seller's storage credentials.
Orbit must not fetch arbitrary delivery URLs for validation, previews or a
download. Validate URL syntax when saving metadata, and use the seller's declared
length and digest when verifying the downloaded bytes. An HTTPS URL has no user
information or fragment. Protected endpoint URLs also have no query string;
credentials and tickets never belong in a URL.

## Download tickets

Tickets use the existing environment-specific connected signing ring, with
`alg=ES256`, `typ=orbit-download+jwt` and its trusted `kid`. Their lifetime is at
most 120 seconds and is capped by current licence and workspace access expiry.
The separate long-term offline signer must not issue them. Ordinary access-grant
and offline-file verifiers reject this ticket type.

Required claims identify the exact issuer, application/environment, licence,
release and artifact, plus `jti`, `iat`, `nbf`, `exp`, artifact SHA-256 and byte
length. `aud` is the exact configured protected endpoint. The seller verifier
pins that audience and configured Orbit origin/scope, validates all required
types and time bounds, rejects duplicate/unknown claims and JOSE fields, and
uses only the trusted scoped JWKS endpoint or bundled keys. It never discovers
a key from the ticket. Allow at most 30 seconds of issuance skew and no expiry
grace.

The installed client sends the ticket only to the configured protected endpoint,
in an `Authorization: Bearer` header. Do not forward it to a storage redirect or
another origin. Tickets and authorization responses are not cached or logged.
A ticket can be replayed until it expires; this is an intentionally bounded
download capability, not a claim of single-use or copy protection.

## SDK and onboarding behavior

Expose typed release/artifact/update results. Authentication uses the ordinary
current activation principal or a scoped trusted-backend decision; installed
applications never receive management credentials. Check current scope,
ownership, licence status and required feature at authorization time, even if
discovery metadata was obtained earlier.

Downloads go directly from the seller's host to the caller. A streaming helper
uses an explicit destination and size limit, bounds redirects, uses verified
HTTPS, checks the exact length and SHA-256, and atomically exposes the completed
file only after verification. It must not execute an installer, unpack archives
or apply an update. A cancelled, oversized, truncated or mismatched download
leaves no completed artifact at the destination. Caller-owned streaming callbacks
are appropriate for embedded targets where a filesystem helper is unavailable.

Provide a minimal seller backend example that verifies tickets using configured
public keys and returns an expiring storage URL. Keep private storage secrets on
that backend. The dashboard flow is: add release, add seller URL and artifact
details, choose delivery mode, publish metadata. Explain the public-URL sharing
limitation at that choice. Metadata publication and the product's code releases
remain separate operations.

## Acceptance

Cover cross-application/environment/target isolation, licence and feature denial,
unpublished releases, channel ordering, ticket purpose/audience confusion,
unknown keys, key rotation, exact expiry, malformed URLs, redirect header leakage,
stream cancellation, size/digest mismatches and atomic destination writes. Exercise
the seller example end to end against local TLS fixtures. Show that Orbit never
receives file bytes or storage credentials. Public URLs must be documented as
shareable rather than advertised as protected downloads.
