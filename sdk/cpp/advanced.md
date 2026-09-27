# Advanced C++ usage

Start with the [C++ SDK guide](README.md). This page covers storage guarantees,
explicit identities and IDs, cancellation, errors and the details behind the
online operations.

## Storage and clock guarantees

`Options::state_directory` accepts a dedicated absolute directory. The default
is `$XDG_STATE_HOME/orbit/<scope>` (or `~/.local/state/orbit/<scope>`) on Linux,
`%LOCALAPPDATA%/Orbit/<scope>` on Windows and
`~/Library/Application Support/Orbit/<scope>` on macOS. Keep it on persistent
storage when an installation must survive restarts.

Linux and macOS store private files in an owner-only directory. macOS uses
`F_FULLFSYNC` for file data and synchronizes the parent directory after
replacement; this is private POSIX storage, not Keychain encryption. Windows
uses current-user DPAPI and a private ACL for the user, SYSTEM and
Administrators; impersonating threads are unsupported. Unsafe existing
directories are rejected without changing their permissions, and corrupt state
is never silently replaced with a new installation.

An exclusive lease lets one client own an installation. The state contains the
installation ID, credential, any pending activation digest, the signed grant
and clock evidence; it never contains a licence key, password or customer
session.

On restart the client validates online first. A temporary outage may use the
original verified grant until its signed deadline; strict-online policies need a
connection. Sleep counts toward expiry: macOS uses `mach_continuous_time`. A
clock rollback or inconsistent saved clock evidence requires online validation.
Local storage cannot protect against someone who controls the user's account
or restores the whole machine from an old snapshot.

## Machine binding

By default the SDK sends a scoped `machine_v1` fingerprint derived from the
operating system identity (IOKit's `IOPlatformUUID` on macOS). Only the digest
leaves the process. If the identity is unavailable, the SDK sends none and the
licence's machine-lock policy decides whether activation is allowed.

Set `Options::disable_machine_binding = true` for shared VM or container images,
or set `Options::fingerprint` to a `Fingerprint{value, provider}` with a
64-character lowercase SHA-256 value and a `custom:` provider. Never send a raw
hardware identifier. When the identity differs from saved state, the SDK starts
a new installation ID and clears the old credential, pending activation and
cached grant before it can be used.

## Activation and operation IDs

`activate`, `activate_account`, `claim_licence` and `deactivate` generate secure
operation IDs when you omit one. Installed activation saves its pending ID and
reuses it after an uncertain response, so retry the same key or licence. Pass an
explicit ID when you coordinate retries across processes. For account
activation, sign in again as the same customer after a restart and retry the
same licence; another customer cannot reuse the pending operation. `logout()`
discards local recovery state.

`activate_previous` and `activate_account_previous` rebind a freshly
authenticated installation using proof of its previous credential.

## Cancellation and errors

Most calls accept a trailing `const orbit::Cancellation*`. A `Cancellation` can
be copied and signalled from another thread; the call then throws
`ErrorKind::cancelled`. `close()` cancels in-flight work owned by the client.

`orbit::Error` exposes `kind()`, the stable `code()` and a validated
`request_id()` for support. `what()` includes the code but never server messages
or caller input. Metering failures are `orbit::OperationError`, which adds
`operation_id()`, `requested_units()` and validated capacity counters.
`OfflineKeys::parse` and `SessionKeys::parse` take the `"test"` or `"live"`
environment from the key IDs when you omit it, and report invalid key sets as
`ErrorKind::configuration`.

## Customer accounts

Enable Account or Both authentication for the application. `register_customer`
returns a `RegistrationResult` whose `pending` handle is used with
`resend_registration`; the customer confirms the email link before `login`.
`owned_licences(cursor)` returns one bounded page; pass its `next_cursor` to
fetch the next. `claim_licence` adds a key to the signed-in account without
activating it. Recovery and email-change requests return generic acceptance.

Customer sessions stay in memory. `logout_account` revokes the server session;
`logout` clears local licensed access. `customer_session_authorization()`
returns a sensitive Bearer header for your own trusted HTTPS backend, which must
verify it online and enforce licensed access separately. Never log or persist
it. See the [backend example](../../examples/rust/licensed-backend/README.md).

## Offline file details

`OfflineKeys::parse` validates every configured key before installed state
opens. Import stores the original signed file with its sequence, issuance
identity and clock floors in the private installation store. After a restart
the file is verified again with the currently configured trusted keys, which
allows trusted key rotation. `Snapshot::offline_file_mode` distinguishes file
access from a cached connected grant.

Expired files can be renewed by importing one with a higher sequence; lower
sequences and conflicting equal sequences are rejected. Online activation,
account login and `logout()` clear local file authority but keep the sequence
and clock floors. `OwnedLicence::offline_file_duration` is zero when files are
disabled.

## Floating session details

The worker keeps at most one renewal in flight. A lost reply retries the same
session ID or renewal sequence; a transient renewal failure keeps only the
original signed interval and never extends it. An authoritative denial clears
local access. Session grants are never saved to disk, and an operator's remote
end is observed at the next renewal or signed expiry.

## Download details

Downloads use verified HTTPS without cookies or ambient credentials, request
identity encoding and follow at most five HTTPS redirects. The Orbit ticket is
sent only to the initial endpoint, never to a redirect. The byte limit applies
while streaming. A staging file beside the destination is exposed only after
verification, so the destination filesystem must support atomic rename and hard
links. The seller's filename never selects a path.

## Metering details

Resource IDs use 1–128 ASCII letters, digits, `_` or `-`; units are positive
integers up to `2^53-1`. A usage retry returns the original debit or denial,
even across a period boundary. A resource retry returns the original allocation
identity and units with its current state and counter, so an old acquire can
return `AllocationState::released` without reactivating it. Consumed usage is
not refunded if your work fails. `OwnedLicence::usage_limits`,
`resource_limits` and `concurrent_session_limit` describe policy, not current
capacity.

## Access-check performance

Reuse one client per installation. A warm `require_access` checks the trusted
clock, storage lease and feature in local verified state and contacts Orbit only
when a refresh is due. On Linux x86-64 it takes about 3 µs, with no network
request or storage write.
