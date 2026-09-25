# Orbit C++ SDK

The SDK is native C++17. It requires libcurl 8 or newer with asynchronous DNS
support, OpenSSL 3 or newer, and JsonCpp 1.9.5 or newer. Asynchronous DNS keeps
request deadlines and cancellation effective during name resolution. CMake
discovers installed dependencies; configuration does not download, build or
install them. Response and result metadata are UTF-8 JSON strings. Parse them
with your application's JSON library.

## Build

Build and install the static library with a normal CMake toolchain:

```sh
cmake -S sdk/cpp -B build/orbit-cpp -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build/orbit-cpp
cmake --install build/orbit-cpp --prefix /path/to/prefix
```

Consumers can link the in-tree `Orbit::Sdk` target or use the installed CMake
package:

```cmake
find_package(OrbitSdk CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Orbit::Sdk)
```

The example builds directly against the SDK source:

```sh
cmake -S examples/cpp -B build/cpp
cmake --build build/cpp
./build/cpp/orbit-cpp-licensed-export --smoke
```

To run the SDK tests from a complete repository checkout, enable testing in a
separate build. The optional TLS tests use Python 3's standard library and
synthetic certificates included in the repository:

```sh
cmake -S sdk/cpp -B build/cpp-tests -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=ON
cmake --build build/cpp-tests
ctest --test-dir build/cpp-tests --output-on-failure
```

## Connect and activate

Get the API origin, application ID, environment ID and issuer from Orbit
Integration. The example prints a generated installation ID; save it and reuse
it for the same device identity. Do not pass licence keys or passwords on the
command line. Credentials stay in memory by default. Optional Windows DPAPI
storage needs an existing dedicated absolute directory. Linux Secret Service
storage needs an existing dedicated absolute directory owned by the current
user with mode 0700, and a configured system keyring. The SDK does not create or
secure these directories.

`Client::connect` accepts optional installation and fingerprint fields plus a
storage mode and path. Request fingerprints only for hardware-locked apps;
`native_fingerprint` returns the scoped digest without exposing the raw OS
identifier. `machine_fingerprint` accepts an explicit Linux or Windows identity
adapter.

`Error` provides the safe error kind, code and request ID. Account, licence and
access results are JSON metadata; they do not alone prove customer identity or
licensed access. `customer_session_authorization()` returns a sensitive Bearer
header for your own trusted HTTPS backend. Never log or persist it, send it to
another host, or forward it through redirects.

You can copy and signal `Cancellation` from another thread. Copies of a
`Client` share one live client safely. `PendingRegistration` is move-only,
opaque and bound to its creating client; keep it only while resend is needed.
