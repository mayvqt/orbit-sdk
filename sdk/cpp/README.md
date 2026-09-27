# Orbit C++ SDK

License a desktop app or customer-hosted service with C++17. The v0.4 API
requires libcurl 8+ with asynchronous DNS, OpenSSL 3+, and JsonCpp 1.9.5+.

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

See the [runnable example](../../examples/cpp/README.md) and
[advanced usage](advanced.md) for storage options, cancellation and account APIs.
The library target for consumers building alongside this checkout is
`Orbit::Sdk`.

The native implementation supports Linux, Windows and macOS. macOS uses the
system IOKit and CoreFoundation frameworks and private POSIX installed files;
its native runtime still needs validation on Apple hardware.
