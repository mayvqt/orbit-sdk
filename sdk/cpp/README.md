# Orbit C++ SDK

License a desktop app or customer-hosted service with C++17. The SDK requires
libcurl 8+ with asynchronous DNS, OpenSSL 3+ and JsonCpp 1.9.5+.

## Quickstart

Keep the SDK checkout beside your application directory. Add this
`CMakeLists.txt` to your application, then save the program below as `main.cpp`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(licensed_app LANGUAGES CXX)
add_subdirectory(../Orbit-SDK/sdk/cpp orbit-sdk)
add_executable(licensed_app main.cpp)
target_link_libraries(licensed_app PRIVATE Orbit::Sdk)
```

Build from your application directory:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build
```

Copy the public app key from Orbit's **Integration** page (start in **Test**) to
`ORBIT_APP_KEY`. The SDK selects a scoped `machine_v1` fingerprint by default;
ordinary setup does not need hardware-ID code.

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

`ensure_access` asks for a key only when the installation has no usable access.
Feature denials and service outages propagate without prompting. Access results
are typed `Snapshot` values; use `snapshot()` for display and
`require_access("export")` immediately before protected work.

The SDK stores an installation credential, never the licence key. Copies of a
`Client` share state. `close()` stops refresh work while keeping the installation
for the next run. `logout()` clears local access; `deactivate()` releases the
server-side device slot.

Customer accounts are separate from Orbit dashboard accounts. When account
authentication is enabled, call `login`, inspect `owned_licences`, then use
`activate_account` and `require_access`. Login alone grants no licensed access.

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

## Floating seats, updates and metering

Floating policies acquire and renew sessions automatically. Use `end_session()`
to stop seat use and `start_session()` to resume it. `check_for_update()` discovers
the newest eligible runtime release; `authorize_download()` and the result's
`download()` authorize and verify a direct transfer. `usage()`, `consume()`,
`resources()`, `acquire_resource()` and `release_resource()` return typed counters
and allocations. See [online operations](online.md) for examples and retry rules.

## Long-term offline files

When a licence policy enables `offline_file_seconds`, configure the trusted
offline-purpose public keys, export the current installation request, and import
the signed `.orbit` file returned through your authorized issuance workflow:

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
    auto keys = orbit::OfflineKeys::parse(read_file("trusted-offline-jwks.json"), "test");
    orbit::Options options;
    options.offline_keys = keys;
    auto client = orbit::Client::open(app_key, options);
    std::cout << client.offline_request().to_json() << '\n';
    // Transfer this public request to an authorized seller/customer issuance flow.
    const auto snapshot = client.import_offline_file(read_file("licence.orbit"));
    if (snapshot.has_feature("export")) client.require_access("export");
    client.close();
}
```

The importer stores the original signed file, renewal sequence and clock floors
before exposing its features. Offline guards make no HTTP request, refresh or
key prompt. When the client reopens, the configured trusted offline-purpose keys
must still verify an active file, which allows trusted key rotation.
Logout clears local authority while retaining renewal and time floors; the signed
file cannot be revoked while disconnected. `OwnedLicence::offline_file_duration`
reports the server's `offline_file_seconds` policy.

See the [runnable example](../../examples/cpp/README.md) and
[advanced usage](advanced.md) for storage options, cancellation and account APIs.
The library target for consumers building alongside this checkout is
`Orbit::Sdk`.

The native implementation targets Linux, Windows and macOS. macOS uses the
system IOKit and CoreFoundation frameworks and private POSIX installed files.
