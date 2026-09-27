# Orbit C++ SDK

Add licence activation and feature checks to a C++17 desktop app or
customer-hosted service on Linux, Windows or macOS. The SDK requires libcurl 8+
with asynchronous DNS, OpenSSL 3+ and JsonCpp 1.9.5+.

## Quick start

Keep the SDK checkout beside your application directory. Add this
`CMakeLists.txt` to your application, then save the program below as `main.cpp`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(licensed_app LANGUAGES CXX)
add_subdirectory(../Orbit-SDK/sdk/cpp orbit-sdk)
add_executable(licensed_app main.cpp)
target_link_libraries(licensed_app PRIVATE Orbit::Sdk)
```

Copy the public app key from **Integration** in your Orbit dashboard, starting
with the Test environment, then build and run:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build
./build/licensed_app
```

```cpp
#include <orbit_sdk.hpp>

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

int main() {
    const char* app_key = std::getenv("ORBIT_APP_KEY");
    if (app_key == nullptr || *app_key == '\0') return 2;

    try {
        auto client = orbit::Client::open(app_key);
        client.ensure_access("export", []() -> std::optional<std::string> {
            std::cout << "Licence key: ";
            std::string key;
            std::getline(std::cin, key);
            if (key.empty()) return std::nullopt;
            return key;
        });
        // Perform the protected export here.
        client.close();
    } catch (const orbit::Error& error) {
        std::cerr << "Orbit error: " << error.code() << '\n';
        return 1;
    }
    return 0;
}
```

`ensure_access` asks for a key only when the installation has no activation.
Feature denials and service outages propagate without prompting. Call
`require_access("export")` immediately before each later protected operation;
`snapshot()` is for display. Errors are `orbit::Error` values whose `kind()`
distinguishes `not_activated` and `feature_unavailable`, and whose `code()` is
the stable protocol code.

The app key is public configuration, not a secret. Keep licence keys and
passwords out of source, command-line arguments and logs; the SDK stores an
installation credential, never the licence key.

The [console example](../../examples/cpp/README.md) shows the complete flow.

## Application version

Set `orbit::Options::app_version` so your licence policy can require a minimum
application version and offer updates. Use one to four
dot-separated numbers without leading zeros, optionally followed by a
`-pre-release` and `+build` part, in at most 32 bytes (for example
`3.0.0-beta.2+build.5`).
`Client::open` rejects an invalid value with `ErrorKind::configuration` and
sends a valid one with activation and validation.

```cpp
orbit::Options options;
options.app_version = "2.4.1";
auto client = orbit::Client::open(app_key, options);
```

When the policy blocks this version, access checks throw an `orbit::Error` with
`kind() == ErrorKind::app_version_unsupported`, and cached or offline access is
not used. Ask the user to update the application; the activation is kept, so
the updated version continues without a new licence key.
`Snapshot::update_available` contains a newer version when the policy offers
one. Every request also identifies the SDK with an `Orbit-Client` header
containing its language, version and platform.

## Installation state

`Client::open` creates one durable installation in the current user's private
state directory and binds it to a scoped `machine_v1` fingerprint when the
operating system identity is available. Set `Options::state_directory` to a
dedicated absolute directory for a service account or container volume.

Copies of a `Client` share one installation; use them across threads instead of
opening the same directory twice. A second process is rejected with
`installation_in_use`. `close()` stops refresh work and keeps the activation for
the next run, `logout()` clears local access, and `deactivate()` releases the
device slot on the server. See
[storage and clock guarantees](advanced.md#storage-and-clock-guarantees).

## Customer accounts

Customer accounts belong to people using your software, separately from your
Orbit dashboard account. When account authentication is enabled, sign the
customer in, choose one of their licences and activate it:

```cpp
client.login(username, password);
const auto page = client.owned_licences();
client.activate_account(page.items.at(0).id);
client.require_access("export");
```

Sign-in alone grants no licensed access. See
[customer accounts](advanced.md#customer-accounts) for registration, recovery
and backend proofs.

## Long-term offline files

For an installation that stays disconnected longer than a connected grant
allows, configure the trusted offline-purpose public JWKS when opening the
client. Ship it with your application or fetch it from the app-key origin over
verified HTTPS; never take keys from the imported file or from the person who
provides it.

```cpp
#include <orbit_sdk.hpp>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

std::string read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void run_offline(const std::string& app_key) {
    orbit::Options options;
    options.offline_keys = orbit::OfflineKeys::parse(read_file("trusted-offline-jwks.json"));
    auto client = orbit::Client::open(app_key, options);
    std::cout << client.offline_request().to_json() << '\n';
    // Transfer this public request to an authorized seller/customer issuance workflow.
    client.import_offline_file(read_file("licence.orbit"));
    client.require_access("export");
    client.close();
}
```

The request contains the public app key and the installation's binding identity,
but no licence key, customer session or credential. Import verifies the file and
saves it with its sequence and clock floors before returning access; reimporting
the same file never extends its expiry. While a file is active, `require_access`
makes no network request and never prompts; an expired file returns
`offline_file_expired`.

An issued file cannot be revoked while the machine is disconnected. Sequence and
clock floors prevent ordinary replay and clock rollback, but restoring a complete
old machine or VM snapshot cannot be detected reliably. Tell customers about this
limit before issuing long-term access.

## Floating seats

Floating policies acquire a seat automatically after activation and renew it in
the background. `require_access` checks the current signed interval locally, and
the snapshot's `session` shows its ID and sequence. A full seat pool, an expired
seat or an outage never asks for another licence key.

Call `end_session()` when your app becomes idle and `start_session()` when it
resumes. Ending clears local access before contacting Orbit and disables
automatic reacquisition. Both calls leave ordinary and offline-file access
unchanged.

`close()` makes a bounded attempt to release the seat and keeps the activation.
A restart obtains a new seat online. After a crash or failed release, the old
seat stays occupied until its interval ends. During an outage the app keeps only
the current verified interval, so a remote revocation takes effect locally at
that deadline.

## Licensed updates

```cpp
if (const auto update = client.check_for_update(installed_release_number)) {
    const auto authorization =
        client.authorize_download(update->release.id, update->artifact.id);
    authorization.download("update.bin", 128 * 1024 * 1024);
}
```

Compare the increasing release number built into your app, not display
versions. Discovery defaults to the `stable` channel and the running platform
and architecture; pass a channel and an `orbit::UpdateTarget{"windows", "arm64"}`
for an explicit target. There is no fallback to another target.

Authorization checks current licence eligibility separately from discovery. The
file streams directly from the seller over verified HTTPS, and the SDK checks
its exact length and SHA-256 before exposing it at your destination. An existing
destination is refused unless you pass `replace = true`; a failed or cancelled
download leaves it untouched. The SDK never runs or unpacks an installer. Keep
authorizations out of logs.

## Usage and resources

Configure an `exports` usage limit, then reserve a unit before doing the work:

```cpp
const auto debit = client.consume("exports", 1, export_job_id);
std::cout << "Remaining exports: " << debit.counter.remaining << '\n';
// Perform the export and record its result with export_job_id.
```

`usage(name)` and `resources(name)` read the current authoritative counters.
`acquire_resource(name, resource_id)` returns an allocation; remove the actual
resource before calling `release_resource(name, allocation_id)`. Closing,
logging out and outages do not release allocations.

Operation IDs are optional and generated securely. Failures throw
`orbit::OperationError`, whose `operation_id()` identifies the intent even after
a lost reply; retry an uncertain outcome with that ID and identical input.
Supply your own stable job ID of 16–128 characters when the operation must
survive a restart. Capacity denials (`usage_limit_reached`,
`resource_limit_reached`) carry a validated `usage_counter()` or
`resource_counter()`.

These calls always go online with the current activation. They do not acquire
floating seats, offline files cannot authorize them, and `require_access` never
consumes quota. Installed programs can be modified to skip reporting, so run the
metering call and the actual work on your trusted backend when enforcement must
be authoritative.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on
your seller backend before looking up the artifact in your own registry.
Configure the exact HTTPS endpoint and a trusted connected-purpose JWKS; never
take keys or a destination URL from the ticket. The verifier makes no network
requests, and copies can verify concurrently.

```cpp
#include <orbit_sdk.hpp>

#include <cstdint>
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

Construct the verifier once with
`orbit::DownloadTicketVerifier(app_key, "https://downloads.example.com/artifacts", jwks_json)`
and pass the metadata from your own registry. Send the compact ticket without
its `Bearer ` prefix. Invalid or expired tickets throw `invalid_download_ticket`.

A ticket expires within 120 seconds and can be replayed until then. Treat it as
a secret, never log it, and never use an artifact ID as an unchecked filesystem
path. Serve the file or issue a storage URL that expires no later than the
ticket's `expires_at`. The
[seller example](../../examples/python/seller-downloads/README.md) shows a
complete endpoint.
