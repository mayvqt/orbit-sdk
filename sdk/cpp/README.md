# Orbit C++ SDK

Check out the pinned source release and keep the repository intact. The
wrapper needs C++17 and the Rust FFI static library from the same checkout,
built for the same target and toolchain. It has no third-party dependencies or
network fetches. JSON responses are UTF-8 `std::string` values; parse them with
your application's JSON library.

## Build

Build the Rust library from the checkout root with Rust/Cargo 1.98.1 or newer:

```sh
cargo build --manifest-path sdk/ffi/Cargo.toml --lib
```

On Linux, build the example against `target/debug/liborbit_sdk_ffi.a`:

```sh
cmake -S examples/cpp -B build/cpp \
  -DORBIT_FFI_STATIC_LIB="$PWD/target/debug/liborbit_sdk_ffi.a"
cmake --build build/cpp
./build/cpp/orbit-cpp-licensed-export --smoke
```

On Windows, build for the C++ architecture and configuration, then set the
path to `orbit_sdk_ffi.lib`:

```powershell
cmake -S examples/cpp -B build/cpp -A x64 `
  -DORBIT_FFI_STATIC_LIB="C:/path/to/target/debug/orbit_sdk_ffi.lib"
cmake --build build/cpp --config Debug
```

CMake links the Rust static library's platform dependencies. Linux needs
pthread, `dl`, `m` and `rt`; Windows needs `ws2_32`, `bcrypt`, `ntdll`,
`userenv`, `advapi32`, `crypt32` and `secur32`. Build the Rust FFI for the
same architecture, runtime and configuration as the C++ app.

In your application's `CMakeLists.txt`, set the FFI path, add the SDK folder,
and link its target (use `orbit_sdk_ffi.lib` on Windows):

```cmake
set(ORBIT_SDK_DIR "/path/to/orbit-sdk")
set(ORBIT_FFI_STATIC_LIB "${ORBIT_SDK_DIR}/target/debug/liborbit_sdk_ffi.a"
    CACHE FILEPATH "")
add_subdirectory("${ORBIT_SDK_DIR}/sdk/cpp" orbit_sdk)
target_link_libraries(my_app PRIVATE Orbit::Sdk)
```

## Connect and activate

Get the public API origin, application ID, environment ID and issuer from
Orbit Integration. The example prints a generated installation ID; save it
and reuse it on later runs for the same device identity. Do not pass licence
keys or passwords on the command line. Credentials stay in memory by default.
Optional Windows DPAPI storage needs an existing dedicated absolute directory
under the current user's private profile. Linux Secret Service storage needs
an existing dedicated absolute directory owned by the current user with mode
0700, and a configured system keyring. The SDK does not create or secure these
directories.

`Client::connect` accepts optional installation and fingerprint fields plus a
storage mode and path. Request fingerprints only for hardware-locked apps;
`native_fingerprint` returns the scoped digest without exposing the raw OS
identifier. `machine_fingerprint` accepts an explicit Linux or Windows
identity adapter.

`Error` provides the error kind, safe code, request ID and FFI status. Keep it
with the operation that failed. Account, licence and access results are JSON
metadata; they do not alone prove customer identity or licensed access.
`customer_session_authorization()` returns a sensitive Bearer header for your
own trusted HTTPS backend. Never log or persist it, send it to another host,
or forward it through redirects.

You can copy and signal `Cancellation` from another thread. Copies of a
`Client` share one live client safely. `PendingRegistration` is move-only,
opaque and bound to its creating client; keep it only while resend is needed.
