# Orbit C++ SDK

License a desktop app or customer-hosted service with C++17. Requires libcurl 8+
with asynchronous DNS, OpenSSL 3+, and JsonCpp 1.9.5+.

## Setup

Copy the API origin, application ID, environment ID and issuer from Orbit's
**Integration** page. Start in **Test**.

```cpp
#include <orbit_sdk.hpp>

// Configure once with public values from Integration.
auto orbit = orbit::Client::open({
    "https://orbit.mayvie.dev", "application_id", "environment_id", "issuer"
});

// Reuse access after a restart; ask for a key only when none is available.
try {
    orbit.require_access("export");
} catch (const orbit::Error& failure) {
    if (failure.code() != "access_unavailable") throw;
    orbit.activate(read_licence_key()); // Your UI or terminal prompt.
    orbit.require_access("export");
}
```

`open()` remembers the installation and credential, refreshes access automatically
and handles uncertain activation retries. It never stores the licence key.
Call `require_access()` before protected work; `snapshot()` is informational.
Temporary connection failures do not require another activation.

Copies of `Client` share one installation. `close()` stops refreshes and saves
state without deactivating it; destruction also closes the last copy.

## Build

Clone the release; CMake discovers installed dependencies without downloading them:

```sh
git clone --depth 1 --branch v0.3.0 https://github.com/mayvqt/orbit-sdk.git && cd orbit-sdk
cmake -S sdk/cpp -B build/orbit-cpp -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build/orbit-cpp
cmake --install build/orbit-cpp --prefix /path/to/prefix
```

Link the in-tree `Orbit::Sdk` target, or use the installed package:

```cmake
find_package(OrbitSdk CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Orbit::Sdk)
```

See the [runnable example](../../examples/cpp/README.md) and
[advanced usage](advanced.md) for account sign-in, custom storage and cancellation.
