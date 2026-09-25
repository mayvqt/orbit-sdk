# Orbit SDKs

Start with the **Test** environment in Orbit. Open your application's
**Integration** page and copy the API origin, application ID, environment ID,
and grant issuer. Then choose a language:

| Language | Setup | Example |
| --- | --- | --- |
| Rust | [SDK](sdk/rust/README.md) | [Licensed export](examples/rust/licensed-export/README.md) |
| Go | [SDK](sdk/go/README.md) | [Licensed export](examples/go/licensed-export/README.md) |
| C# | [SDK](sdk/csharp/README.md) | [Licensed export](examples/csharp/licensed-export/README.md) |
| C++ | [SDK](sdk/cpp/README.md) | [Licensed export](examples/cpp/README.md) |
| Python | [SDK](sdk/python/README.md) | [Quickstart](examples/python/README.md) |
| JavaScript/TypeScript | [Backend SDK](sdk/typescript/README.md) | [Backend example](examples/typescript/backend.mjs) |

## Install v0.2.0

Pin integrations to `v0.2.0`. Rust and Go can use their language-native Git
dependency support, and Python can install the release wheel below. For C#, C++
and JavaScript/TypeScript, check out the source tag and reference the language
folder:

```sh
git clone --depth 1 --branch v0.2.0 https://github.com/mayvqt/orbit-sdk.git orbit-sdk
```

| Language | Install |
| --- | --- |
| Rust | Add `orbit-sdk = { git = "https://github.com/mayvqt/orbit-sdk", tag = "v0.2.0" }` to `[dependencies]`. |
| Go | Run `go get github.com/mayvqt/orbit-sdk/sdk/go@v0.2.0`. Its repository tag is `sdk/go/v0.2.0`. |
| C# | Run `dotnet add MyApp/MyApp.csproj reference orbit-sdk/sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj`. |
| C++ | Build and link `sdk/cpp` with CMake and its C++ dependencies; see the [C++ setup](sdk/cpp/README.md). |
| Python | Install the release wheel with `python -m pip install https://github.com/mayvqt/orbit-sdk/releases/download/v0.2.0/orbit_sdk-0.2.0-py3-none-any.whl`; see the [Python setup](sdk/python/README.md). |
| JavaScript/TypeScript | Run `npm install ./orbit-sdk/sdk/typescript` from your backend project. |

Each SDK implements its client logic in its own language. C++ and Python need
no Orbit Rust library or Rust toolchain. Python's release wheel needs no source
checkout; a local checkout can also be installed with
`python -m pip install ./orbit-sdk/sdk/python`. No SDK packages are published to
language registries. The JavaScript/TypeScript SDK runs on a trusted backend
and checks access online; use the other SDKs for signed offline grants and
device activation.

Upgrading from v0.1.0: C++ no longer uses `ORBIT_FFI_STATIC_LIB` or
`orbit_ffi.h`. Python no longer accepts `library_path` or uses
`ORBIT_FFI_LIBRARY`; install the package instead of copying `orbit_sdk.py`.
Client operations, wire behavior and existing protected activation stores are
preserved. See the language setup guides for dependencies and migration details.

If you're calling the API without an SDK, see the [HTTP guide](examples/http/README.md).
The [Rust backend example](examples/rust/licensed-backend/README.md) shows how
to verify a customer session and check a feature on your own server. Shared
signed-grant fixtures are in [contracts/sdk](contracts/sdk/README.md).

Test and Live have separate IDs and data. Keep licence keys, passwords, sessions,
activation credentials, and management tokens out of source and logs. A
management token belongs only on your backend. Check access before protected
work.

This source is [MIT licensed](LICENSE). Keep each SDK folder intact; the
language setup guides list any additional files needed by that SDK.
