# Long-term offline licence files, version 1

This is the implementation contract for the next offline-file batch. It does not
mean the feature is implemented or released. Ordinary connected access grants
retain their existing lifetime and refresh rules.

## Setup and requests

Keep the normal installed `Client.open(app_key)` flow. Offline applications also
configure `offline_keys`, a trusted public JWK set distributed with the application
or obtained from the app key's origin over verified HTTPS. This option never
contains private signing material. Do not extract trusted keys from a licence file
or accept keys supplied by the person importing it.

`client.offline_request()` returns a typed, serializable request for the existing
stable installation. It does not contact Orbit or consume an installation slot.
The JSON shape is:

```json
{
  "format": "orbit-offline-request",
  "version": 1,
  "app_key": "orbit_app_test_...",
  "installation_id": "stable-installation-id",
  "fingerprint": null,
  "fingerprint_provider": null
}
```

The request is public configuration, not proof of ownership. Its app key must
parse normally. Installation IDs and binding values obey the existing activation
contract. Reject duplicate/unknown fields, unsupported versions, partial binding
pairs and requests over 4 KiB. A seller or customer transfers the request to an
online machine and authenticates there to issue the file. Licence keys, passwords,
customer sessions and activation credentials are not part of the request.

## Issuance

Issuance accepts the request, an explicit requested duration and an idempotency
key. Customer issuance requires the same fresh principal authentication and
licence ownership as activation. Seller issuance requires scoped licence/device
write authority. An ID or a machine fingerprint alone does not authorize issuance.

The policy's `offline_file_seconds` is separate from the connected grant's
`offline_seconds`: zero disables files; otherwise it bounds the requested duration
between one day and 366 days. Six-month and annual commercial terms do not enable
offline files automatically. A file expires at the earliest of requested duration,
the policy maximum and purchased licence expiry. Perpetual licences may issue
bounded files. Issuing or renewing never extends purchased access.

Use the existing installation-slot limit and stable activation identity. Identical
retries return the same issuance, expiry and renewal sequence without consuming
another slot. Reusing an idempotency key with different input is a conflict.
Renewing the same installation retains its activation ID and increments its signed
sequence under the licence and scoped installation's concurrency locks. The
sequence belongs to the installation within its application/environment, including
when it changes licences, so importing another licence cannot reset its renewal
floor. A changed machine follows the
existing binding and transfer rules; offline issuance is not a bypass.

Issuance requires current seller workspace access, but an already-issued file is
not capped by the seller's Orbit subscription expiry. It remains usable for its
agreed term if that subscription later ends. Expiry, refund, revocation and policy
changes cannot immediately revoke a disconnected file. Show that property before
issuance. Reject policies that combine long-term offline files with centrally
enforced concurrent seats.

Record issuance/renewal, actor, scope, installation, sequence and expiry in audit
history. Do not log the file, raw request fingerprint or authentication secrets.

## Signed file

The file is a UTF-8 compact JWS, at most 16 KiB, with no surrounding JSON envelope.
Outer ASCII whitespace may be trimmed before parsing. Use ES256 with a fixed-width
64-byte signature and canonical unpadded base64url encoding. Require the exact
header fields `alg`, `typ`, `kid`, with `alg=ES256` and
`typ=orbit-offline+jwt`. No embedded key, key URL, certificate URL or critical
header is permitted. Reject duplicate fields before interpreting JSON.

Required claims:

| Claim | Meaning |
| --- | --- |
| `ver` | Integer `1` |
| `iss` | Exact issuer from the app key |
| `aud` | Exact `orbit-offline:<application_id>:<environment_id>` |
| `sub` | Licence ID |
| `jti` | Unique issuance ID, preserved on retries |
| `iat`, `nbf`, `exp` | Whole UTC epoch seconds; `nbf = iat < exp` |
| `application_id`, `environment_id` | Exact configured scope |
| `activation_id`, `installation_id` | Exact issued activation and target installation |
| `sequence` | Scoped installation integer, from 1 through 9,007,199,254,740,991 |
| `binding_mode` | `none` or `hwid` |
| `policy_version` | Positive signed 32-bit integer |
| `entitlements` | Existing bounded map of named boolean features |

`licence_expires_at` is present for a finite purchased term and must be an integer
at or after `exp`. Under `hwid`, both `fingerprint` and `fingerprint_provider` are
required and must match the installation. Under `none`, both claims must be
absent, including no explicit nulls. No other claims are accepted in version 1.
Enforce `exp - iat <= 366 * 86,400`; accept at most 30 seconds of issuance/start
skew, with no access at or after `exp`. Timestamps use the existing maximum
9999-12-31T23:59:59Z. Booleans and floating-point numbers are not integers.

Offline-file signing uses keys separate from connected access grants, with
separate Test and Live rings. Public key IDs use the purpose prefix
`offline-test-` or `offline-live-`. An ordinary access grant or JWKS must not become
offline-file authority. Retain public verification material through the longest
outstanding file plus clock skew. Applications deployed without connectivity must
receive new trusted keys through their trusted software/configuration update
process before importing files signed by those keys. Removing a public key from
Orbit cannot erase a previously distributed key.

## Import, persistence and access

`client.import_offline_file(file)` verifies the signature with configured trusted
keys, exact scope, installation, binding, claims, time bounds and sequence. Reject
unknown keys offline; importing a file must not trigger discovery at an untrusted
location or silently add a verification key. Keep errors typed and redact file
contents from diagnostics.

After successful durable import, the existing `require_access(feature)` and
`ensure_access(feature, ask_for_key)` guard the offline installation. A valid file
uses local access checks and does not trigger background validation or a key
prompt. Expose offline status and absolute expiry in the ordinary typed snapshot.
Always recheck storage ownership/lease, clock state, expiry and the requested
feature before returning access. A startup boolean is not sufficient.

Persist the original signed file, its trusted key identity, highest accepted
sequence, issuance identity and clock high-water values atomically, using the
installed client's private leased storage and stable installation ID. Verification
after restart uses the configured trusted keys again. Never reconstruct a fresh
term from a stored duration. An equal sequence is idempotent only for the same
issuance and claims; a lower sequence or an equal sequence with different content
is rejected. A rejected import cannot reduce persisted sequence/time high-water
values. Never expose new authority before durable persistence succeeds.

Do not combine cached online and offline authority. Explicit offline import
selects the file's signed features and expiry. Explicit online activation selects
the normal connected flow. Preserve renewal/time high-water values across those
mode changes. Local logout removes access without claiming to free the remote
installation slot. Re-importing the same still-valid file is a deliberate local
action; it does not renew its term.

Within a running process, use the platform's continuous clock including sleep and
the existing bounded wall-clock drift checks. Across restart, re-verify the file
and require wall time to be consistent with signed issuance time and persisted
high-water values; never move time backward. Persist checkpoints periodically and
on clean close, with the same failure-closed behavior as installed grants. Clock
uncertainty must deny access, not start another offline interval.

A user controlling the machine can restore an entire old state/clock snapshot,
clone an unbound installation or patch the program. Ordinary files cannot prove
that this happened. Do not promise complete rollback resistance without a trusted
hardware counter or online authority. Retaining the signed absolute expiry and
checking available clock evidence remains mandatory.

## Acceptance

Use shared signed vectors across every verifying SDK: valid six-/twelve-month
files; exact expiry and skew edges; wrong issuer, audience, product, environment,
installation or binding; wrong purpose/algorithm; unknown keys; invalid signature;
duplicate fields; malformed types; overlong lifetime; malformed key sets; and
sequence limits. Test with the same bytes and fixed verification context.

Behavior checks cover offline restart/reboot, suspend across expiry, wall-clock
rollback, partial writes/corruption, old renewal replay, equal-sequence conflicts,
duplicate issuance and concurrent renewals, slot exhaustion, seller subscription
expiry and trusted key rotation. Restoring older state must never create a new
term; document the unavoidable full-machine-rollback limitation. Exercise both
desktop prompt/import and unattended file-import examples. Physical platform
coverage must be reported separately from simulated clocks/filesystems.
