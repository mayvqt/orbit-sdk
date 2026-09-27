# Advanced C++ usage

## Installation storage and device identity

`Client::open(app_key, options)` accepts an optional absolute
`state_directory`. The default is `$XDG_STATE_HOME/orbit/<scope>` (or
`~/.local/state/orbit/<scope>`) on Linux and `%LOCALAPPDATA%/Orbit/<scope>` on
Windows, and `~/Library/Application Support/Orbit/<scope>` on macOS. Keep the
directory on persistent storage when an installation must survive restarts.

By default, the SDK uses its native `machine_v1` fingerprint. Set
`disable_machine_binding = true` to omit it, or supply one `Fingerprint{value,
provider}` for an application with its own stable identity source. The value
must be a lowercase SHA-256 digest; never provide a raw hardware identifier. A
changed or unavailable identity starts a new installation ID and clears the old
credential, pending activation, and cached grant before it can be used offline.

Linux stores a private file in a `0700` directory with `0600` files. Windows
uses current-user DPAPI and a private ACL for the user, SYSTEM and
Administrators. macOS uses private POSIX files in an owner-only directory and
uses `F_FULLFSYNC` for file data plus a parent-directory sync after replacement;
this is not Keychain encryption. Unsafe existing directories are rejected
without changing their permissions. Windows impersonating threads are
unsupported. A lease allows one client to own an installation; share copies of
that client within a process instead of opening the same directory twice.

On macOS, the default device identity comes from IOKit's `IOPlatformUUID`,
normalized and scoped before hashing. Only the derived fingerprint leaves the
process. The SDK uses `mach_continuous_time` so sleep counts toward access
expiry. If native identity is unavailable, setup follows the normal best-effort
unbound path; server machine-lock policy still decides whether activation is
allowed.

On restart, the client validates online first. A temporary failure may use the
original verified offline grant until its signed deadline; strict-online
policies require a connection. Local storage and clock checks cannot protect
against an attacker who controls the user's account or restores the entire
machine to an old snapshot.

## Optional username/password accounts

These are accounts for your application's customers, separate from Orbit
dashboard accounts. Enable Account or Both authentication for the application.
Call `login`, choose a licence from `owned_licences`, then call
`activate_account`. Login alone does not grant access. The SDK does not save
passwords or customer sessions. `logout_account` revokes the server session;
`logout` clears local licensed access; `deactivate` releases the device slot.

Activation, account activation, claim, and deactivation operation IDs are
optional. The SDK generates secure IDs when omitted. Installed activation
persists a pending ID and reuses it after an uncertain response; explicit IDs
are useful when the caller coordinates retries across processes.
For account activation, sign in again as the same customer after restart and
retry the same licence. A failed login retains the pending operation; another
customer cannot reuse it. Explicit logout discards local recovery state.

`Cancellation` can be copied and signalled from another thread. `Error::kind()`
provides typed `not_activated` and `feature_unavailable` results, while `code()`
retains the stable server or SDK code. `customer_session_authorization()`
returns a sensitive bearer header: send it only to your trusted HTTPS backend
and never log or persist it.

## Tests

With dependencies already installed, run from the repository root:

```sh
cmake -S sdk/cpp -B build/cpp-tests -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=ON
cmake --build build/cpp-tests -j2
ctest --test-dir build/cpp-tests --output-on-failure
```

The native suite loads shared app-key, connected-grant, offline-file and download
ticket vectors and all 184 shared session-grant vectors. Installed lifecycle
checks cover floating acquisition, renewal, expiry, denials and generation fences.
The online-operation cases exercise generated retry IDs, bounded capacity errors,
released resource replay and target-specific updates. TLS tests use Python 3 and
the repository's synthetic certificates. Direct streams check certificate trust,
five redirects, bearer/cookie stripping, identity encoding, bounded streaming,
length/digest failures, cancellation and atomic destination preservation.

macOS build and native-runtime validation should be performed on macOS x64 and
arm64 with the installed CMake, Apple SDK, libcurl, OpenSSL and JsonCpp:

```sh
cmake -S sdk/cpp -B build/cpp-tests -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=ON
cmake --build build/cpp-tests -j2
ctest --test-dir build/cpp-tests --output-on-failure
cmake -S examples/cpp -B build/cpp-example -DBUILD_TESTING=OFF
cmake --build build/cpp-example -j2
build/cpp-tests/orbit_platform_tests --clock-suspend
```

The current implementation was developed and exercised on Linux; native macOS
hardware, IOKit identity acquisition, sleep behavior and Darwin filesystem
durability have not been tested here. Treat those commands as required checks
before claiming native macOS validation. The suspend check waits for Enter after
resuming from at least two seconds of sleep and compares `mach_continuous_time`
with the awake-only `mach_absolute_time` counter.

## Long-term offline-file verification

`orbit::OfflineKeys::parse(jwks_json, "test" or "live")` accepts a trusted
offline-purpose public JWKS. Put it in `Options::offline_keys` before opening an
installed client. The SDK validates every configured key before it opens
installed state and never trusts keys embedded in a file.

`Client::offline_request()` returns serializable public installation scope for
an authorized online issuance workflow. `Client::import_offline_file()` verifies
the signed file and stores its original JWS, sequence, issuance identity and
clock floors in the existing private installed store before returning a typed
`Snapshot`. Active offline files use format-3 storage records; after restart,
verification uses the currently configured trusted offline keys that still
verify the file, allowing trusted key rotation. `offline_file_mode` distinguishes
these files from cached connected grants.

While file mode is active, snapshots and access guards verify the storage lease,
clock, expiry and feature locally. They do not validate online or prompt for a
key. Expired files can be deliberately renewed using a higher signed sequence.
Logout, activation and account login clear local file authority while retaining
sequence/time floors. Disconnected files cannot be recalled immediately, and a
complete old machine snapshot cannot be detected reliably. The typed
`OwnedLicence::offline_file_duration` reports `offline_file_seconds`.

`orbit_offline_tests` runs all 104 shared signed-file cases, including strict key
boundaries and canonical-claims digest checks. Installed import, restart,
renewal, expiry, no-network behavior and logout-floor preservation run in
`orbit_sdk_tests`. See the [offline contract](../../contracts/sdk/offline.md).

## Seller-hosted downloads

`DownloadTicketVerifier` checks a short-lived download ticket on your seller
backend. Configure it once with the public app key, the exact protected HTTPS
endpoint, and the application's trusted connected-purpose JWKS JSON. Get the keys
through trusted configuration or verified HTTPS; the verifier never fetches them.
Copies share immutable configuration and support concurrent verification.

```cpp
#include <orbit_sdk.hpp>
#include <string_view>

bool authorize_artifact(const orbit::DownloadTicketVerifier& verifier,
                        std::string_view token, std::string_view release_id,
                        std::string_view artifact_id, std::string_view sha256,
                        std::int64_t byte_length) {
    try {
        const auto ticket = verifier.verify(token);
        return ticket.release_id == release_id && ticket.artifact_id == artifact_id &&
            ticket.sha256 == sha256 && ticket.byte_length == byte_length;
    } catch (const orbit::Error&) {
        return false;
    }
}
```

Construct the verifier with `orbit::DownloadTicketVerifier(app_key, endpoint,
jwks_json)` and pass your own artifact registry's metadata to the function above.
Send the exact compact ticket without a `Bearer ` prefix. Verification uses the
server clock; its optional `Timestamp` override is only for a trusted application
clock, never request data. Invalid or expired tickets return `ErrorKind::denied`
with `invalid_download_ticket`. Invalid endpoint/key configuration returns
`ErrorKind::configuration` with `invalid_download_endpoint`/`invalid_download_keys`.

The seller owns storage and credentials. After authorization, serve the matching
artifact or generate a storage URL that expires no later than the verified
ticket's `expires_at`. Recheck that deadline after any slow operation. Do not log
tickets or storage URLs; use no-store responses. A permanent public URL remains
shareable. The [Python seller example](../../examples/python/seller-downloads/README.md)
shows the full endpoint and expiring storage redirect.

`orbit_download_tests` checks all 110 shared cases, strict key/endpoint bounds,
owned configuration, expiry and concurrent verification. This verifier authorizes
an artifact request; the application serves the artifact or creates an expiring
storage URL. See the [download contract](../../contracts/sdk/downloads.md).

## Warm access benchmark

Configure and build the opt-in Release benchmark with installed dependencies,
then run it from the repository root:

```sh
cmake -S sdk/cpp -B build/cpp-bench-release -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build/cpp-bench-release --target orbit_sdk_tests -j2
build/cpp-bench-release/orbit_sdk_tests --benchmark-access
```

The benchmark activates a signed synthetic grant using private local installed
storage and the native clock, warms both paths, then measures five batches of
10,000 `require_access` calls and, separately, 10,000 `snapshot` calls. It
reports median time per call and verifies that the measured loops add no HTTP
requests or storage writes while retaining storage-invalidation checks.

On CachyOS Linux x86-64 with GCC 16.2.1 and libstdc++ 20260810, Release results
were:

| Path | Adjusted baseline (`4e735f8`) | Current |
| --- | ---: | ---: |
| `require_access` | 5.78126 µs/op | 3.02612 µs/op |
| `snapshot` | 5.4326 µs/op | 2.99526 µs/op |

The baseline uses the `4e735f8` source with the same installed-storage
verification check and benchmark harness applied; it retains the internal JSON
snapshot path. After timing, a separate 500-guard/500-snapshot verification
pass observed 1,000 successful lease checks. The timed loops had zero writes
and no increase from the two setup HTTP requests. These are local measurements,
not cross-platform performance guarantees; Windows and macOS were not measured.

See [online operations](online.md) for floating seats, verified update downloads,
usage reservation and persistent resource allocation.
