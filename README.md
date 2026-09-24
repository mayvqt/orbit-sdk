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

## Install the v0.1.0 source release

Pin integrations to the `v0.1.0` source tag. Rust and Go can use their
language-native Git dependency support. For the other SDKs, check out that tag
once and reference the language folder:

```sh
git clone --depth 1 --branch v0.1.0 https://github.com/mayvqt/orbit-sdk.git orbit-sdk
```

| Language | Install |
| --- | --- |
| Rust | Add `orbit-sdk = { git = "https://github.com/mayvqt/orbit-sdk", tag = "v0.1.0" }` to `[dependencies]`. |
| Go | Run `go get github.com/mayvqt/orbit-sdk/sdk/go@v0.1.0`. Its repository tag is `sdk/go/v0.1.0`. |
| C# | Run `dotnet add MyApp/MyApp.csproj reference orbit-sdk/sdk/csharp/Orbit.Sdk/Orbit.Sdk.csproj`. |
| C++ | Build the Rust FFI library from this checkout, then link `sdk/cpp` with CMake; see the [C++ setup](sdk/cpp/README.md). |
| Python | Build the Rust FFI library from this checkout, then add `sdk/python` to the import path; see the [Python setup](sdk/python/README.md). |
| JavaScript/TypeScript | Run `npm install ./orbit-sdk/sdk/typescript` from your backend project. |

The C++ and Python bindings need `sdk/ffi` and `sdk/rust` from the same
checkout to build their native library. No SDK packages are published to
language registries. The JavaScript/TypeScript SDK runs on a trusted backend
and checks access online; use the other SDKs for signed offline grants and
device activation.

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
