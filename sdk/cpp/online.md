# Floating seats, updates and online limits

Use the same `orbit::Client` opened with your app key. Operations accept an
optional trailing `const orbit::Cancellation*`. Metering and download discovery
use the current activation proof and require an online connection.

## Floating seats

A floating policy automatically acquires a process session after the activation
credential is saved. The worker renews it, with one renewal in flight. The
snapshot's optional `session` contains the verified ID and sequence. Session
grants are never cached across restart. Uncertain starts/renewals reuse their
original session ID/sequence; transient renewal failures retain only the original
signed interval. Authoritative denial clears local authority. Seat limits,
expired seats and outages never ask for another licence key.

`client.end_session()` clears local floating access before waiting for a release.
It suppresses automatic acquisition until `client.start_session()`. Both methods
leave ordinary and offline-file access unchanged. `close()` tries a bounded seat
release while preserving activation; an unreachable server retains the seat until
its lease expires. A remote operator end is observed at renewal or signed expiry,
so disconnected revocation has a bounded delay.

## Updates and downloads

```cpp
#include <orbit_sdk.hpp>
#include <string_view>

void download_update(const orbit::Client& client, std::int64_t installed_release,
                     std::string_view destination, const orbit::Cancellation* cancellation = nullptr) {
    const auto update = client.check_for_update(installed_release, "stable", std::nullopt, cancellation);
    if (!update) return;
    const auto authorization = client.authorize_download(update->release.id, update->artifact.id, cancellation);
    authorization.download(destination, 64 * 1024 * 1024, false, cancellation);
}
```

Discovery defaults to `stable` and the current process platform/architecture.
Supply an `orbit::UpdateTarget{"windows", "arm64"}` for a different target;
unknown runtime targets require it. Increasing release numbers determine ordering,
not display-version strings. A result exposes only the selected artifact and
never substitutes another target.

Authorization is a separate fresh request. Its URLs and ticket are sensitive:
do not log or cache them. The streaming helper uses verified HTTPS without cookies
or ambient credentials, requests identity encoding, and checks exact length,
streaming size and SHA-256. At most five HTTPS redirects are followed, with the
Orbit bearer stripped from every redirected request, including same-host redirects.

Choose the destination and size limit explicitly; the remote filename never
selects a path. A staged file in the same directory is exposed atomically only
after verification. Existing files are refused unless `replace=true` is explicit;
failed or cancelled transfers preserve them and clean up their staging file.
The destination filesystem must support atomic rename and hard links (used for
no-overwrite exposure). The helper never executes or unpacks a download. Sellers host the file bytes;
Orbit stores metadata and authorizes discovery. Public URLs remain shareable.
Protected endpoints use the [seller verifier](advanced.md#seller-hosted-downloads).

## Usage and resources

```cpp
#include <orbit_sdk.hpp>
#include <iostream>
#include <string_view>

void export_report(const orbit::Client& client, std::string_view job_id) {
    client.require_access("export");
    const auto debit = client.consume("exports", 1, job_id);
    std::cout << "Report: rows=3, total=42. Exports remaining: " << debit.counter.remaining << '\n';
}
```

Configure an `exports` usage limit, optionally requiring the `export` feature.
`usage("exports")` reads the current counter. `resources("projects")` reads
allocated capacity. `acquire_resource("projects", project_id, 1, job_id)` reserves
an allocation; retain its `allocation_id`, and call
`release_resource("projects", allocation_id)` when that actual project is removed.
Resource IDs use 1–128 ASCII letters, digits, `_` or `-`. Units must be positive
integers no greater than `2^53-1`.

These are explicit online calls. Feature guards never consume units or allocate
resources. `OwnedLicence::usage_limits`, `resource_limits` and
`concurrent_session_limit` describe policy, not current capacity. Offline files
cannot authorize meter changes and failures never change a local counter.

Mutation IDs are optional secure random values reused across the invocation's
transport retries. Supply your job ID (16–128 ASCII letters, digits, `_` or `-`)
for restart-safe coordination. Catch `orbit::OperationError`: its `operation_id()`
identifies the intent even after cancellation, a lost reply or malformed data.
Reuse it with the same inputs to recover an uncertain operation. Another call
without that ID is a new intent.

Capacity denials use `usage_limit_reached` or `resource_limit_reached`; the
exception's `requested_units()`, `usage_counter()` or `resource_counter()` contains only validated,
bounded details. A usage replay preserves its original outcome, period and totals,
even after midnight. Resource replays preserve allocation identity and units but
return the current allocation state and resource counter. An old acquire can
return `AllocationState::released`: it never reactivates the allocation. A new
intent needs a new ID. Limit-denied retries preserve their original denial.

Consumption reserves units before work; failure of that work does not refund
units. Allocations persist through close, logout and outages until explicit
release. Use floating sessions for temporary process occupancy. Installed code
cannot prove that every operation was reported. Gate authoritative metering on
your trusted backend immediately before doing the actual work, using the
scoped management routes in the [OpenAPI document](https://orbit.mayvie.dev/api/openapi.json).
Keep management tokens there and store operation IDs with your jobs. Orbit's
transaction is separate from your own database or external API.
