# Usage quotas and resource limits

Usage quotas limit work consumed during a period. Resource limits bound the units
held by active allocations. Floating sessions have their own short-lived lease
contract in [floating.md](floating.md).

## Policy model

Keep numeric limits separate from boolean `entitlements`. An immutable policy
version may define up to 32 `usage_limits` and 32 `resource_limits`. Names use
the entitlement grammar: 1–64 ASCII characters, starting with a lowercase letter,
then lowercase letters, digits or `_`. A definition may name one optional
`required_feature`; when present, that boolean entitlement must also be true.

A usage definition contains `limit` and `period`. A resource definition contains
`limit`. Limits are integers from zero through `2^53-1`; zero permits no new units.
Periods are `day`, `month` or `lifetime`. Reject duplicate names, unknown fields,
fractional numbers, booleans used as numbers and arithmetic overflow. An absent
definition is `unknown_limit`, not an implicit unlimited allowance. The same name
may exist in each map because their API routes and counters are distinct.

Policy create/version bodies and policy/licence/owned-licence results use JSON
objects keyed by the limit name. A usage value is
`{"limit": 100, "period": "day", "required_feature": "export"}`; a resource
value is `{"limit": 5, "required_feature": null}`. Omitted input maps default
to empty objects and an omitted `required_feature` defaults to null. Responses
include both maps and the explicit nullable feature. Definitions are immutable
with the rest of the pinned policy, and grants retain boolean entitlements only;
numeric metadata is never evidence of available quota without an online result.

Periods use database time in UTC: day boundaries are midnight; month boundaries
are the first day of the calendar month. Lifetime usage does not reset. Never
accept a period boundary or authoritative usage total from the caller. Changing
a policy definition requires the existing explicit new-version flow; it does
not rewrite an issued licence's pinned policy or erase its counters.

## Authorization and trust

Installed clients authenticate using their current activation proof, including
the ordinary scope, installation and optional binding fields. A customer session
or licence key alone is not that proof. Trusted backends use scoped management
tokens with dedicated `usage:read`, `usage:write`, `resources:read` and
`resources:write` permissions. A write permission authorizes that mutation and
its result, not unrelated reads or another application's records. Dashboard
controls retain the existing environment scoping, workspace RBAC and CSRF rules.

Every read, consume and acquire checks current licence/customer/workspace access
and the optional required feature. Release may clean up an allocation after
licence expiry without granting access or returning a refund; it still requires
a currently authenticated owner or authorized operator. Offline files cannot
authorize these operations. Reject disconnected attempts without modifying a
local counter as though it were authoritative.

Orbit can enforce reported usage and allocations atomically. It cannot prove
that software controlled by a customer reported every export, request or created
resource. Sellers that require authoritative metering must gate the actual work
on their trusted backend. The SDK documentation must explain where to perform
that check, without promising tamper-proof metering in an installed executable.

## Client and management routes

Client routes are under
`/api/client/v1/activations/{activation_id}`. Each uses `POST` and the existing
activation-proof body so credentials stay out of URLs and caches:

- `/usage/{name}` reads the current period's counter.
- `/usage/{name}/consume` additionally takes positive integer `units` and
  `idempotency_key`.
- `/resources/{name}` reads active allocated units and remaining capacity.
- `/resources/{name}/acquire` additionally takes `resource_id`, positive integer
  `units` and `idempotency_key`.
- `/resources/{name}/allocations/{allocation_id}/release` additionally takes
  `idempotency_key`.

Use the existing idempotency-key grammar and a 24-hour replay window. Unit values
are at most `2^53-1`. A resource ID is an application-supplied opaque 1–128 ASCII
letters/digits/`_`/`-` identifier; it is not a path, URL, secret or arbitrary JSON
metadata. The server creates the allocation ID. Requests reject unknown and
duplicate fields and stay within the service's existing bounded body limits.

Management routes mirror these actions under
`/api/management/v1/licences/{licence_id}`, with existing application/environment
query scope and bearer authentication. Management reads use `GET`; mutation
bodies contain only the extra operation fields, never an activation proof.
Dashboard actions call the same authoritative services after cookie/RBAC/CSRF
authorization. Do not provide an unauthenticated licence-ID lookup.

Successful reads, consumes, acquires and releases return HTTP 200, including
successful mutation replays and acquisition of an already-active resource.
All responses use `Cache-Control: no-store`.

Management and dashboard allocation lists use
`GET .../licences/{licence_id}/resources/{name}/allocations` and `resources:read`
or the equivalent dashboard read permission. Return `items` and nullable
`next_cursor`, with default page size 50 and maximum 100. Optional `state` is
`active` or `released`; omission includes both retained states. Order by creation
time and allocation ID descending, with cursors bound to licence, limit and
filter. Items contain `allocation_id`, `resource_id`, `units`, `state`,
`created_at` and nullable `released_at`, without activation credentials or tokens.

## Usage consumption

Read results contain `name`, `period`, `limit`, `used`, `remaining`,
`period_started_at` and `resets_at`. Timestamps use RFC3339 UTC; lifetime
`period_started_at` and `resets_at` are null. The definition and result belong to
the authenticated licence and current pinned policy. Do not merge totals from
different licences or Test/Live environments.

Consume adds the requested units exactly once only when the resulting total
does not exceed the limit. Success returns the counter after that operation,
plus `idempotency_key` and `consumed_units`. A rejected consume returns the typed
`usage_limit_reached` error with the same bounded counter details; it changes
no total. Check `units <= limit - used` instead of overflowing an addition.

Capacity denials use HTTP 409 and the ordinary safe `code`, plus a typed
`counter` containing the read result, the `idempotency_key` and `requested_units`.
Resource-capacity denials use the same envelope with `resource_limit_reached`
and the resource counter shape. Other errors keep the existing error envelope;
never place arbitrary request bodies or database diagnostics into these details.

The counter and operation fields are inside `error`, alongside the service's
safe message and request ID. For example, a usage-capacity denial has this shape:

```json
{
  "error": {
    "code": "usage_limit_reached",
    "message": "The request conflicts with current state.",
    "request_id": "request_example",
    "counter": {
      "name": "exports",
      "period": "day",
      "limit": 100,
      "used": 100,
      "remaining": 0,
      "period_started_at": "2026-09-27T00:00:00Z",
      "resets_at": "2026-09-28T00:00:00Z"
    },
    "idempotency_key": "export_job_example",
    "requested_units": 1
  }
}
```

SDKs expose these details only after validating the expected counter kind and
name, safe-integer bounds, `used <= limit`, `remaining = limit - used`, and the
request's operation ID and units. A mismatched or malformed denial is an invalid
response with an uncertain mutation outcome, so the caller retains the same
operation ID for recovery. Do not present unvalidated error fields as counters
or treat an invalid response as a new operation.

Save both accepted and limit-denied outcomes for the replay window. Reusing an
operation ID with different normalized input is a conflict. An identical retry
returns the original outcome, period and totals, even if another consume ran or
a UTC boundary passed in the meantime. A denial just before midnight cannot
turn into a new debit after midnight merely because its reply was lost. Current
authentication/ownership/access still precedes replay disclosure. Operation
identity is scoped to the licence and action, so changing an otherwise authorized
management token cannot debit the same operation a second time.

Consumption reserves quota before the application performs the work. A later
business-operation failure does not automatically refund units. Orbit's counter
transaction is not atomic with an unrelated seller database or external API.
The seller should use its job ID as the idempotency key and record the result
with that job when restart-safe workflow coordination is required.

## Resource allocations

Read results contain `name`, `limit`, `used` and `remaining`, where `used` is the
sum of units in active allocations. Acquire returns those fields plus
`allocation_id`, `resource_id`, `units` and `state=active`. Allocation units are
immutable. If the same resource is already active with identical units, return
that allocation without charging again; different units are a conflict.

Successful acquire and release responses also include the operation's
`idempotency_key`. Release contains the same allocation fields as acquire, with
`state=released` and the current resource counter.

If acquiring would exceed capacity, return `resource_limit_reached` with bounded
counter details and create no allocation. Save its outcome like a usage denial.
Release identifies the server allocation ID, decrements its units once and
returns `state=released` with the resulting counter. Repeating release is a
no-op. It must not release a later allocation that reused the same resource ID.

After release, another deliberate acquire with a new operation ID may reuse the
resource ID and gets a new allocation ID. An old acquire retry must never
reactivate a released allocation. If its saved result describes an allocation
that has since been released, return that ID with `state=released`, preserving
the original charged units and without a new charge. Document this current-state
qualification separately from usage's fixed debit outcome.

Successful resource replays include the current resource counter, because the
allocation's current state may have changed. They preserve allocation identity
and the original operation's unit count, never repeat its mutation, and do not
present an old active total as the counter after a release. Capacity-denied
acquire replays retain their original denial and do not become new attempts.

Allocations do not expire automatically and are not tied to a process heartbeat.
Close, logout or a network outage cannot silently delete the seller's tracked
resource. Release explicitly when the actual resource is removed. The dashboard
provides a scoped list and deliberate release action for stranded allocations.
Use floating sessions for temporary concurrent seats instead.

## Concurrency, storage and SDK behavior

Check authorization under the existing principal/licence lock order, then lock
the relevant counter. Serialize replay identity before mutating that counter.
Enforce a unique active allocation per licence/name/resource ID in the database.
Atomic database counters and constraints, not read-modify-write application
caches, enforce limits. Independent licences and unrelated meters must not
require a workspace-wide write lock. These mutations commit durably; they are
not advisory last-seen telemetry.

Keep old period totals for 90 days after their period ends, then clean them up
only after their operation replay window has also expired. Lifetime totals and
active allocations remain until their owning data is deleted. Bounded pagination
is required for allocation lists. Do not log credentials, signed grants or
unbounded caller metadata in diagnostic events.

Retain released allocation metadata for 90 days after release and at least
through every associated replay's expiry. A cleanup cannot remove an allocation
needed to qualify a still-valid acquire retry as released. Meter time is read
after its serialization lock, so waiting across midnight selects the new period;
an already-recorded operation keeps its original outcome under the replay rule.

Include definitions, counters, allocations and replay records in scoped export,
backup, recovery and app/customer purge handling. Recovery must preserve quota
totals and active allocations or explicitly fail; it must not silently reset
usage to zero. Invalidate authorization according to the normal recovery rules.
Application deletion removes this app-owned data without changing operator
accounts or billing records.

SDKs expose typed `usage`, `consume`, `resources`, `acquire_resource` and
`release_resource` operations with idiomatic names, cancellation and optional
operation IDs. An auto-generated ID is reused for all retries of that invocation.
An uncertain mutation reports its operation ID so the caller can deliberately
resume it; a new invocation without that ID is a new intent. Caller-provided job
IDs are the simple documented path for retries across process restarts.

These are explicit online operations. Ordinary `require_access` stays a local
feature check and never consumes units, acquires a resource or hides another
network request. SDKs must not automatically retry a denied mutation as a new
operation or convert an unknown outcome into a successful local deduction.

## Acceptance

Test simultaneous consumes/acquires at the boundary, cross-scope isolation,
unknown/zero limits, invalid units and overflow, identical/conflicting IDs,
current authorization before replay, UTC day/month transitions including leap
years, lifetime totals, and retries crossing those boundaries. Exercise lost
replies, cancellation after commit, resource reuse after release, duplicate
releases and old releases racing a new allocation.

Verify exact permission checks, bounded lists, real database constraints,
durable backup/recovery totals, erasure and app purge. Public SDK examples must
show both an installed caller and a trusted backend gating a concrete operation,
with no management credential in the installed application. Load tests should
measure contention on one meter and independence across different licences.
