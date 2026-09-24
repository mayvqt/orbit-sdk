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

Add the SDK's whole directory to your project. C++ and Python also use the
included [Rust FFI library](sdk/ffi/README.md). The JavaScript/TypeScript SDK
runs on a trusted backend and checks access online; use the other SDKs for
signed offline grants and device activation.

If you're calling the API without an SDK, see the [HTTP guide](examples/http/README.md).
The [Rust backend example](examples/rust/licensed-backend/README.md) shows how
to verify a customer session and check a feature on your own server. Shared
signed-grant fixtures are in [contracts/sdk](contracts/sdk/README.md).

Test and Live have separate IDs and data. Keep licence keys, passwords, sessions,
activation credentials, and management tokens out of source and logs. A
management token belongs only on your backend. Check access before protected
work.

This source is [MIT licensed](LICENSE). No registry packages are published yet;
use the source folders and their included dependency locks.
