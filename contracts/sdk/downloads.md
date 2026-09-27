# Seller-hosted releases and licensed downloads

Sellers host their files. Orbit stores release metadata and authorizes
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

The exact header fields are `alg`, `typ` and `kid`. Connected-ring key IDs start
with `test-` or `live-` according to the configured app key, with a nonempty opaque
suffix; reject offline-purpose or mixed-environment keys. The trusted JWKS has
only `keys`, contains 1–8 strict public P-256 signing keys, and is at most 16 KiB.

The exact required claims are `ver=1`, `iss`, `aud`, `sub`, `jti`, `iat`, `nbf`,
`exp`, `application_id`, `environment_id`, `release_id`, `artifact_id`, `sha256`
and `byte_length`. `sub` is the licence ID. Identifiers are 1–128 ASCII letters,
digits, `_` or `-`; the SHA-256 value is 64 lowercase hexadecimal characters.
Byte length is an integer from 1 through `2^53-1`. All timestamps are integers
from zero through 253402300799, with `nbf=iat` and `iat < exp <= iat+120`.
Reject boolean/fractional numeric values, explicit nulls, duplicates and unknown
claims. The compact ticket is ASCII, at most 16 KiB, with canonical unpadded
base64url segments and a 64-byte ES256 signature; surrounding whitespace is not
part of a valid HTTP bearer token.

The protected endpoint is a configured, exact HTTPS URL of at most 2048 ASCII
characters, without credentials, query, fragment, whitespace or backslashes.
Validate the raw authority before a URL parser can normalize it: require a
nonempty host, reject any user-info delimiter (including an empty `@`) and
percent encoding in the authority, and allow a port only as decimal digits
from 1 through 65535. An explicit empty port is invalid. IPv6 addresses must
use brackets, with only an optional port after the closing bracket. Use an
ASCII hostname (Punycode for international names); valid percent encoding is
allowed in the path. Preserve the exact configured URL for audience matching.
A seller verifier returns
verified artifact metadata, which the seller matches against its own artifact
registry before selecting a file or storage object. It must not use an artifact
ID directly as an unchecked filesystem path or fetch a URL supplied by a ticket.

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
limitation at that choice.

## Metadata and HTTP profile

Management routes use `/api/management/v1/releases`, the ordinary explicit
application/environment query scope, and `releases:read` or `releases:write`
permissions. Dashboard routes use the same services after workspace RBAC and
CSRF checks. All mutations use the service's existing idempotency key and replay
contract.

- `POST /releases` creates a draft from `channel`, `version`, `notes` and
  `idempotency_key`. `GET /releases` lists bounded, cursor-paginated releases
  within the scope, optionally filtered by channel; `GET /releases/{id}` reads
  one. Pagination uses `after` and `limit`; default page size is 50, maximum
  100. A non-null `next_cursor` is opaque ASCII, 1–256 characters from letters,
  digits, `_`, `-` and `.`. Pass it unchanged as `after`; it is bound to the
  application/environment and channel filter, and is not a release ID.
- `PATCH /releases/{id}` changes draft metadata. Artifact create/update/delete
  uses `/releases/{id}/artifacts` and `/releases/{id}/artifacts/{artifact_id}`.
  Only drafts that have never been published are editable.
- `POST /releases/{id}/publish` publishes a complete draft with at least one
  artifact. Allocate its increasing `release_number` atomically on first
  publication, scoped to application/environment/channel. A draft has no number.
  `POST /releases/{id}/unpublish` stops discovery and new authorization. Repeating
  either action is a no-op; republishing preserves its original number and bytes.
  Unpublishing a never-published draft returns the unchanged draft, with null
  publication number and time; it remains editable.

Creation returns HTTP 201 with the created release or artifact. Release reads,
metadata edits, publication and unpublication return HTTP 200 with the release;
artifact edits return HTTP 200 with the artifact. Release lists return `items`
and nullable `next_cursor`.

Draft metadata edits use `PATCH` with the complete `channel`, `version`, `notes`
and `idempotency_key` fields. Artifact creation uses `POST`; artifact edits use
`PATCH`. Both take the complete artifact input below plus `idempotency_key`.
Artifact deletion uses `DELETE` with an `idempotency_key` JSON body and returns
HTTP 204. Publish and unpublish bodies contain only `idempotency_key`. Reject
unknown or duplicate input fields. Identical mutation retries retain the original
result and publication number, with current authorization checked first.

Channel, platform and architecture are 1–32 ASCII lowercase letters, digits,
`_` or `-`, beginning with a letter. Display versions are nonempty plain text
of at most 64 UTF-8 bytes. Notes are plain text of at most 8192 UTF-8 bytes and
must be rendered as text, not executable markup. Bound each release to 32
artifacts and require unique platform/architecture pairs. Standard desktop
platform names are `windows`, `macos` and `linux`; standard architectures include
`x64`, `arm64`, `x86` and `armv7`. Embedded boards may use their own explicit
target names under the same grammar.

Artifact input contains `platform`, `architecture`, `filename`, `byte_length`,
`sha256`, `delivery_mode`, `url` and `required_feature`. The latter is null or a
valid entitlement name. Delivery modes are `public` and `protected`. Require the
byte-length and digest bounds from the ticket profile. The URL is at most 2048
ASCII characters and obeys the delivery-mode rules above. The filename is a
nonempty basename of at most 255 UTF-8 bytes, without slash, backslash or control
characters, and is neither `.` nor `..`. It is display metadata; it must not
choose a local destination path implicitly. The service creates artifact IDs.

An artifact result adds `id` and `release_id`. A release result contains `id`,
`channel`, `version`, `notes`, nullable `release_number`, `state` (`draft`,
`published` or `unpublished`), `created_at`, nullable `published_at`, and its
artifact list. Identifiers use the service's opaque-ID grammar. Number values are
positive integers no greater than `2^53-1`; timestamps use RFC3339 UTC. Once first
published, metadata and artifact definitions are immutable, including URLs.
Change them by publishing a new release. Unpublishing does not downgrade software
already installed, and discovery never silently returns a lower release number.

Installed routes use the prefix
`/api/client/v1/activations/{activation_id}` and `POST` bodies with the ordinary
activation proof (`application_id`, `environment_id`, `credential`,
`installation_id`, `fingerprint`, `fingerprint_provider`):

- `/updates` additionally takes `channel`, `platform`, `architecture` and
  `installed_release_number` (zero through `2^53-1`). It returns
  `{"release": null, "artifact": null}` when no eligible update exists, or
  the matching published release and exact target artifact. At most one artifact
  is selected. Filter by licence/feature eligibility before choosing the newest
  release; another target is never a fallback. In this discovery result,
  `release.artifacts` contains only that selected artifact. Do not disclose other
  targets' URLs or feature-restricted artifacts through the nested release.
- `/downloads/authorize` additionally takes `release_id` and `artifact_id`.
  It returns `artifact`, `ticket` and `expires_at`. Public delivery has null
  ticket and expiry. Protected delivery contains the short ticket and its
  RFC3339 expiry. The artifact's configured URL is the initial destination.

Both operations authenticate the current activation proof and licence each time.
They do not acquire a floating seat, extend an offline file or consume a usage
unit implicitly. Scope admission/rate limiting occurs before database work,
using ordinary client capacity, not the separate validation capacity. Responses
are `Cache-Control: no-store`; delivery URLs and tickets are omitted from logs.

Trusted backends use `GET /api/management/v1/licences/{id}/updates` with those
target/filter parameters, and `POST .../licences/{id}/downloads/authorize` with
the release/artifact IDs. Both require scoped `licences:read` and `releases:read`.
They apply the same current eligibility rules; management authorization does not
make a revoked licence eligible. There is no unauthenticated release directory
or app-key-only URL disclosure endpoint.

SDK update checks take the installed release number, default channel `stable`,
and optional explicit target. Desktop SDKs may default to their actual runtime
OS/architecture using the standard names; an unknown target requires explicit
configuration. Embedded callers supply the board target. Return typed optional
update metadata. Download authorization is separate from downloading bytes.
Streaming requires a caller-chosen destination and maximum size, allows at most
five HTTPS redirects, and forwards no Orbit bearer on any redirect, including
one to the same origin. Do not use ambient cookies or caller-global credentials.
Apply the byte limit while streaming, even when `Content-Length` is absent or
false. Hash the exact artifact bytes; request identity encoding and reject an
unexpected content encoding instead of silently hashing decompressed output.
Use a temporary file in the destination's directory and expose it atomically
only after length and digest validation. Refuse an existing destination unless
the caller explicitly opts into replacement; a failed download preserves any
existing file. Embedded callbacks must stage bytes separately and acknowledge
completion only after verification, with an abort path for incomplete data.

Store only metadata in Orbit. Use scoped indexes for release discovery and
artifact lookup, and serialize publication numbering within its own channel.
Include metadata/numbering in scoped recovery, export, app purge and reset
inventory. Restoring a release must preserve its immutable number and target
definitions or fail. Application deletion removes release metadata while leaving
the seller's external storage untouched. No cleanup job contacts that storage.

## Acceptance

Cover cross-application/environment/target isolation, licence and feature denial,
unpublished releases, channel ordering, ticket purpose/audience confusion,
unknown keys, key rotation, exact expiry, malformed URLs, redirect header leakage,
stream cancellation, size/digest mismatches and atomic destination writes. Exercise
the seller example end to end against local TLS fixtures. Show that Orbit never
receives file bytes or storage credentials. Public URLs must be documented as
shareable rather than advertised as protected downloads.
