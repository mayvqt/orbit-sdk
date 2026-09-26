# Advanced C++ usage

## Installation storage and device identity

`Client::open(app_key, options)` accepts an optional absolute
`state_directory`. The default is `$XDG_STATE_HOME/orbit/<scope>` (or
`~/.local/state/orbit/<scope>`) on Linux and `%LOCALAPPDATA%/Orbit/<scope>` on
Windows. Keep the directory on persistent storage when an installation must
survive restarts.

By default, the SDK uses its native `machine_v1` fingerprint. Set
`disable_machine_binding = true` to omit it, or supply one `Fingerprint{value,
provider}` for an application with its own stable identity source. The value
must be a lowercase SHA-256 digest; never provide a raw hardware identifier. A
changed or unavailable identity starts a new installation ID and clears the old
credential, pending activation, and cached grant before it can be used offline.

Linux stores a private file in a `0700` directory with `0600` files. Windows
uses current-user DPAPI and a private ACL for the user, SYSTEM and
Administrators. Unsafe existing directories are rejected without changing
their permissions. Windows impersonating threads are unsupported. A lease
allows one client to own an installation; share copies of that client within a
process instead of opening the same directory twice.

On restart, the client validates online first. A temporary failure may use the
original verified offline grant until its signed deadline; strict-online
policies require a connection. Local storage and clock checks cannot protect
against an attacker who controls the user's account or restores the entire
machine to an old snapshot.

## Optional username/password accounts

These are accounts for your application's customers, separate from Orbit
dashboard accounts. Enable Account or Both authentication for the application.
Call `login`, choose a licence from `owned_licences`, then call
`activate_account`. Login alone does not grant access. The SDK does not save
passwords or customer sessions. `logout_account` revokes the server session;
`logout` clears local licensed access; `deactivate` releases the device slot.

Activation, account activation, claim, and deactivation operation IDs are
optional. The SDK generates secure IDs when omitted. Installed activation
persists a pending ID and reuses it after an uncertain response; explicit IDs
are useful when the caller coordinates retries across processes.
For account activation, sign in again as the same customer after restart and
retry the same licence. A failed login retains the pending operation; another
customer cannot reuse it. Explicit logout discards local recovery state.

`Cancellation` can be copied and signalled from another thread. `Error::kind()`
provides typed `not_activated` and `feature_unavailable` results, while `code()`
retains the stable server or SDK code. `customer_session_authorization()`
returns a sensitive bearer header: send it only to your trusted HTTPS backend
and never log or persist it.

## Tests

With dependencies already installed, run from the repository root:

```sh
cmake -S sdk/cpp -B build/cpp-tests -DBUILD_TESTING=ON -DORBIT_ENABLE_TLS_TESTS=ON
cmake --build build/cpp-tests -j2
ctest --test-dir build/cpp-tests --output-on-failure
```

The native suite loads shared app-key and grant vectors. TLS tests use Python 3
and the repository's synthetic certificates.
