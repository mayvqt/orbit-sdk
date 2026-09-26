# Advanced C++ usage

## Installation storage

`Client::open(config, state_directory)` accepts an optional absolute directory.
Use a persistent volume for a service or container. The default is
`$XDG_STATE_HOME/orbit/<scope>` (or `~/.local/state/orbit/<scope>`) on Linux,
and `%LOCALAPPDATA%/Orbit/<scope>` on Windows.

Linux uses a private file with a `0700` directory and `0600` files. Windows uses
current-user DPAPI and a private ACL for the user, SYSTEM and Administrators.
Unsafe existing directories are rejected without changing their permissions.
Windows impersonating threads are unsupported. A lease allows one client to own
an installation; share its copies within a process instead of opening it twice.
Never delete the lock to bypass an active client.

A restart first attempts online validation. A temporary failure can use the
original verified offline grant until its signed deadline; strict-online policies
require the connection. Local storage and clock checks cannot prevent an attacker
who controls the user's account or restores the entire machine to an old snapshot.

## Optional username/password accounts

These are accounts for your application's customers, separate from Orbit dashboard
accounts. Enable Account or Both authentication for the application to use them.
Call `login`, choose a licence from `owned_licences`, then `activate_account`.
Login alone does not grant access. Account mutations use an explicit operation ID;
keep the same ID and session for retries. The SDK does not save passwords or
customer sessions. The installed activation continues across normal restarts.

`activate_previous` accepts the original activation credential for deliberate
same-fingerprint replacement. Remote `deactivate` frees the device slot;
`local_logout` clears local credentials without releasing it remotely.

## Host-managed configuration

`Client::connect(Config)` accepts a host-managed installation ID and memory,
Windows DPAPI or Linux Secret Service storage. Reuse the ID across restarts.
Protected adapters require a dedicated existing private absolute directory;
Secret Service also requires the user's configured system keyring.

Request fingerprints only for hardware-locked applications. `native_fingerprint`
returns the scoped digest; `machine_fingerprint` accepts a host-provided identity.

`Cancellation` can be copied and signalled from another thread. Result strings
contain UTF-8 JSON metadata. `Error` exposes a safe kind, code and request ID.
`customer_session_authorization()` returns a sensitive bearer header: send it
only to your trusted HTTPS backend, never to logs or storage.

## Tests

From a complete checkout with dependencies already installed:

```sh
cmake -S sdk/cpp -B build/cpp-tests -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=ON
cmake --build build/cpp-tests
ctest --test-dir build/cpp-tests --output-on-failure
```

TLS tests use Python 3 and the repository's synthetic certificates.
