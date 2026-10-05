# Orbit SDKs

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-SDK-orange?logo=rust)
![Go](https://img.shields.io/badge/Go-SDK-00ADD8?logo=go&logoColor=white)
![C#](https://img.shields.io/badge/C%23-SDK-512BD4?logo=dotnet&logoColor=white)
![C++](https://img.shields.io/badge/C%2B%2B-SDK-00599C?logo=cplusplus&logoColor=white)
![Python](https://img.shields.io/badge/Python-SDK-3776AB?logo=python&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-SDK-3178C6?logo=typescript&logoColor=white)
![Embedded](https://img.shields.io/badge/Embedded-C%20%2F%20Rust-555?logo=espressif&logoColor=white)

Add licence activation and feature checks to your application with one public
app key. The installed SDKs remember activation, refresh access automatically
and ask for a licence key only when the installation has no activation.

1. Select your application's **Test** environment in Orbit and copy the
   **App key** from **Integration**.
2. Create a policy with your feature enabled (for example, `export`), then
   issue a Test licence using that policy.
3. Install an SDK by following its guide. Open the client with the app key and
   check access before running the protected feature.

| Language | Setup | Example |
| --- | --- | --- |
| Rust | [SDK](sdk/rust/README.md) | [Licensed export](examples/rust/licensed-export/README.md) |
| Go | [SDK](sdk/go/README.md) | [Licensed export](examples/go/licensed-export/README.md) |
| C# | [SDK](sdk/csharp/README.md) | [Licensed export](examples/csharp/licensed-export/README.md) |
| C++ | [SDK](sdk/cpp/README.md) | [Licensed export](examples/cpp/README.md) |
| Python | [SDK](sdk/python/README.md) | [Quickstart](examples/python/README.md) |
| Embedded C / Rust | [SDK](sdk/embedded/README.md) | [Boards](examples/embedded/README.md) |
| Node.js / Electron | [Installed SDK](sdk/typescript-installed/README.md) | [Installed client](examples/typescript-installed/client.mts), [Electron main process](examples/typescript-installed/main.mjs) |
| JavaScript/TypeScript backend | [Backend SDK](sdk/typescript/README.md) | [Backend example](examples/typescript/backend.mjs) |

Use an installed SDK inside the application you ship, the embedded SDK on
small devices with caller-owned buffers, and the backend SDK for online checks
on your own server. The [Rust backend example](examples/rust/licensed-backend/README.md)
verifies a customer session and checks a feature server-side. Without an SDK,
see Orbit's [HTTP API guide](https://orbit.mayvie.dev/guides/http) and the
[HTTP walkthrough](examples/http/README.md).

Each guide also covers the optional licensing features:

- **Floating sessions:** limit concurrent use and release a seat when work ends.
- **Offline files:** import a signed licence for installations that spend long
  periods without a connection.
- **Usage and resource limits:** count consumed work or reserve capacity for
  active resources.
- **Downloads and updates:** find compatible releases and verify downloaded
  files. You host the files; the [seller download example](examples/python/seller-downloads/README.md)
  protects them with expiring Orbit tickets.

To issue and manage licences or publish releases from a terminal or build
pipeline, use the [`orbit` command-line tool](cli/README.md) with a management
token.

The app key is public and can ship with your application; Test and Live have
separate keys and data. Keep licence keys, passwords, sessions and management
tokens out of source and logs.

The SDKs and examples are [MIT licensed](LICENSE).
