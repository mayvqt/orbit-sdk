# Floating seats and concurrent sessions

Implementation contract for the candidate feature; this document is not evidence
that the server or SDKs implement it. Floating seats count active application
sessions. The existing device limit continues to count registered installations.
Neither limit silently changes the other.

## Policy and authorization

An immutable policy version has `concurrent_session_limit`: zero disables floating
sessions; a value from 1 through 65535 enables that many concurrent sessions per
licence. Floating policies require `offline_allowed=false`, `offline_seconds=0`
and `offline_file_seconds=0`. Reject incompatible policy input rather than
silently disabling one of its settings. Ordinary policies keep their current
activation and grant behavior.

Every start and renewal authenticates the current activation credential and
checks application/environment, installation, optional machine binding, customer
ownership/session validity, licence status and workspace access. A licence key
alone does not renew a session. Management credentials never enter installed
applications. A first-use licence still starts its term on activation; acquiring
or renewing a seat does not restart that term.

For a floating licence, activation and ordinary activation validation return
their usual metadata and credential fields, plus `session_required=true` and
`grant=null`. They issue no ordinary access grant. SDKs recognize this explicit
response profile, durably save the activation credential, and then acquire a
seat. An older SDK that cannot handle the profile cannot obtain local access.
Ordinary responses omit `session_required` and retain the existing grant shape.
A device registration can succeed while seat acquisition is denied: the SDK
keeps the credential and reports `concurrent_session_limit_reached`, so a later
attempt does not prompt for a key or consume another device slot.

## Session API

Use the client route prefix
`/api/client/v1/activations/{activation_id}/sessions`. Request bodies use the
existing activation proof: `application_id`, `environment_id`, `credential`,
`installation_id`, `fingerprint` and `fingerprint_provider`. Validate the same
scope, credential bounds and paired binding fields as activation validation.
Unknown and duplicate fields are errors. All endpoints require verified HTTPS.

- `POST` at the prefix starts a session, with an additional `session_id`. The
  SDK generates at least 128 random bits, encoded as 16–128 ASCII letters,
  digits, `_` or `-`. One client instance uses one current session. It never
  derives the session ID from a device ID, time, PID or a saved access file.
- `POST /{session_id}/renew` takes an additional `sequence`, the last confirmed
  sequence plus one. Sequence values are integers from 1 through `2^53-1`;
  a start issues sequence 1. Only one renewal may be outstanding per client.
- `POST /{session_id}/end` ends that session. Repeating a completed end is an
  authenticated no-op. It does not deactivate the registered installation.

Start and renewal return `session_id`, `sequence`, `expires_at`, `server_time`
and `grant`. Response timestamps are RFC3339 UTC; signed timestamps are integer
Unix seconds. End returns the service's ordinary empty success response. Scope
and session ownership are immutable. A session ID already belonging to another
activation must not disclose its owner or authorize any operation.

The start retry key is the session ID itself. A repeated start returns the same
active session and signed decision interval; it neither extends the deadline
nor consumes another seat. A repeated renewal with the last accepted sequence
returns that renewal's decision interval without extending it. A lower sequence
or a jump ahead is a conflict. Request binding must still match. Current
authorization is checked before returning a saved decision. An expired or ended
session cannot be renewed or revived; acquiring another seat needs a new session
ID. Retain closed/expired retry records for 24 hours. Beyond that retry window,
callers must create a new ID rather than retry an old operation.

Persist only the latest renewal interval and bounded signed-claim payload for
each session, rather than appending a replay row or audit event for each
heartbeat. A repeated response may have another valid signature, but its claims,
sequence and authorization deadline must be unchanged. Do not log credentials
or compact signed grants. Audit starts, ends and operator actions; aggregate
renewal diagnostics without generating an unbounded event stream.

## Lease and signing rules

A new interval ends at the earliest of database time plus 120 seconds, licence
expiry, activation-credential expiry and workspace access expiry. No expiry grace
or offline fallback extends that deadline. Set `refresh_after` to database time
plus a random 45–75 seconds, capped by the interval deadline. When the remaining
term is shorter, the original shorter deadline remains authoritative.

The connected Test/Live signing rings issue ES256 grants with
`typ=orbit-session+jwt`. Long-term offline keys never issue them. The audience is
`orbit-session:<application_id>:<environment_id>`. Use the connected grant's
strict claims, adding `session_id` and `session_sequence`, with
`offline_allowed=false`. Require `iat=nbf`, `iat < exp <= iat+120`,
`iat < refresh_after <= exp`, and the existing scope, policy, boolean-entitlement,
optional purchased-expiry and binding rules. An unbound grant omits fingerprint
claims entirely. Keys and JOSE fields keep the connected contract's bounds.

A verifier requires the exact in-memory session ID and expected sequence, not
merely the activation ID. Use bounded trusted scoped JWKS, at most 30 seconds of
issuance skew and no expiry grace. Ordinary connected, offline and download
verifiers reject this purpose. A session grant cannot be converted into a
cached ordinary grant or imported as an offline file.

Seat accounting and deadline changes commit durably. Serialize capacity-changing
operations by licence, using the established principal-before-licence lock order.
Count only that licence's unended sessions whose deadline is later than database
time, and reject a start when its limit is reached. Start, renewal and end use a
consistent lock order. No workspace-wide write lock is needed. Expired seats are
available immediately in the query, independently of background cleanup.

Ending a seat stops future renewals and releases its server-side capacity.
Credential replacement, deactivation, device reset, key replacement and relevant
customer recovery terminate the affected sessions. Revocation, suspension and
workspace denial prevent further grants. Operator views may list and end sessions
only within their authorized application/environment; use `devices:read` and
`devices:write` for management tokens and the existing dashboard RBAC/CSRF rules.

Already issued local grants remain usable until their deadline unless the SDK
receives and acts on the denial sooner. Ending a seat remotely cannot recall a
signed grant held by an offline or modified client. Describe this bounded delay
plainly; do not promise instantaneous remote revocation or copy protection.

## SDK lifecycle

Ordinary setup stays `Client.open(app_key)` followed by `ensure_access`. The SDK
starts and renews a floating session when the server requires one. Expose typed
session metadata and `start_session`/`end_session` for applications that explicitly
release seats while idle. `end_session` first clears local authority and cancels
renewals, then sends the release request. A failed release does not restore
authority; the server reservation expires naturally. Ending explicitly disables
automatic reacquisition until the caller invokes `start_session` again.

Use existing generation fencing around network awaits: a late start or renewal
cannot restore access after end, logout, close, credential change or cancellation.
If a cancelled start may have reached the service, best-effort end its known ID;
never treat failure to release as permission to use it. `close` clears authority,
stops renewal, and attempts a bounded release without deleting the installed
credential. Restart creates a fresh session ID and acquires online. A crash can
leave the old reservation occupied for at most its remaining 120-second term.

Never persist a session grant or ID as restorable access. Persist only the normal
installation/credential state. During an outage, a running process may finish
using its verified current interval until its exact deadline; it cannot mint a
new interval or fall back to another access mode. After expiry, require a new
online acquisition. No new licence-key prompt is appropriate for a seat limit,
outage, expired seat or missing feature.

Warm access checks remain local and inspect the private-storage lease plus a
fresh sleep-inclusive clock. Background renewal does not force a network round
trip for every protected operation. Embedded callers may drive the same bounded
renewal state machine with an explicit poll function. Make that obligation clear
in the board example, with no access past expiry if polling stops.

## Acceptance

Exercise concurrent starts at the limit, repeated/lost starts and renewals,
duplicate and out-of-order sequences, exact expiry without cleanup, Test/Live
and cross-licence isolation, activation/credential replacement, customer recovery,
operator RBAC and revocation. Verify durable recovery never resurrects an ended
session or grants more capacity from stale counters. Application purge and
customer erasure must cover session metadata; scoped restore must invalidate
sessions rather than restore live access from a backup.

Share signed acceptance/rejection vectors for the new purpose. SDK behavior tests
must cover auto-acquisition, no repeated prompts, background renewal, process
restart, crash leftovers, sleep/clock rollback, cancellation and every late-result
race around end/close/logout. Test that no session authority is restored from
disk, that expiry is never shifted by response delay, and that ordinary/offline
licences retain their prior behavior.
