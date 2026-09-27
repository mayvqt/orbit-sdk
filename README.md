# Orbit SDKs

Add licence activation and feature checks to your application with one public
app key.

1. Select your application's **Test** environment in Orbit and copy the
   **App key** from **Integration**.
2. Create a policy with your feature enabled (for example, `export`), then
   issue a Test licence using that policy.
3. Install an SDK from this checkout using its language guide. Open the client
   with the app key and check access before running the protected feature.

The desktop SDKs remember activation and refresh access automatically. Their
`ensure_access` helper asks for a licence key when activation is needed. Each
guide includes installation, supported platforms and a working example:

| Language | Setup | Example |
| --- | --- | --- |
| Rust | [SDK](sdk/rust/README.md) | [Licensed export](examples/rust/licensed-export/README.md) |
| Go | [SDK](sdk/go/README.md) | [Licensed export](examples/go/licensed-export/README.md) |
| C# | [SDK](sdk/csharp/README.md) | [Licensed export](examples/csharp/licensed-export/README.md) |
| C++ | [SDK](sdk/cpp/README.md) | [Licensed export](examples/cpp/README.md) |
| Python | [SDK](sdk/python/README.md) | [Quickstart](examples/python/README.md) |
| Embedded C / Rust | [SDK](sdk/embedded/README.md) | [Boards](examples/embedded/README.md) |
| JavaScript/TypeScript | [Backend SDK](sdk/typescript/README.md) | [Backend example](examples/typescript/backend.mjs) |
| Node.js / Electron | [Installed SDK](sdk/typescript-installed/README.md) | [Installed client](examples/typescript-installed/client.mts), [Electron main process](examples/typescript-installed/main.mjs) |

Use the TypeScript backend SDK for online checks on your server, and the
installed SDK for Node.js desktop applications and Electron's main process. Use the
embedded SDK for caller-owned buffers and platform adapters on small devices.
If you're calling the API without an SDK, see the [HTTP guide](examples/http/README.md).
The [Rust backend example](examples/rust/licensed-backend/README.md) shows how
to verify a customer session and check a feature on your own server. Shared
signed-grant fixtures are in [contracts/sdk](contracts/sdk/README.md).

The app key is public and can be included in your application. Test and Live
have separate keys, IDs and data. Keep licence keys, passwords, sessions,
activation credentials, and management tokens out of source and logs. A
management token belongs only on your backend. Check access before protected
work.

The SDKs and examples are [MIT licensed](LICENSE).
