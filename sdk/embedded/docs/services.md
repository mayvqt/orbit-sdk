# Licensed services and offline files

The default build keeps the small connected client. Enable `ORBIT_ENABLE_SERVICES`
(CMake `-DORBIT_ENABLE_SERVICES=ON`, Rust feature `services`) for floating sessions,
usage, resources and licensed downloads. Initialize once with the parsed app-key
config, your existing `orbit_client_services_t` callbacks and one
zero-initialized `orbit_client_extension_t`:

```c
orbit_client_init_extended(&client, &config, &services, &extension,
    arena, sizeof(arena), scratch, sizeof(scratch), NULL);
```

All objects must remain alive and exclusively owned until close. Compile the
library, adapters and application with matching feature and profile definitions.
The CMake imported targets propagate these definitions. Rust `Client::open`
accepts the same app key and caller-owned `ServiceBuffers`.

## Floating sessions

Activation saves the revocable credential before acquiring a seat. Call
`orbit_client_tick` from the event loop to acquire or renew; the signed session
supplies its refresh time. Warm access checks use the current seat locally and
never acquire another seat. A transient renewal failure permits access only
until the existing signed expiry. An authoritative denial clears access
immediately. At expiry, access fails even if the loop has not polled.

Call `orbit_client_end_session` when the application becomes idle and
`orbit_client_start_session` when it resumes. End suppresses automatic acquisition
until explicit start. Ending while initial activation is in flight preserves a
valid returned activation credential and suppresses access and seat acquisition;
explicit start resumes without another licence-key prompt. Both calls are
harmless for an ordinary licence.
`orbit_client_close` makes a bounded release attempt and clears local state;
a failed release does not prolong local authority. After a restart the client
validates online and requests a fresh seat. Session IDs, grants and authority are
never restored from storage.

Calls use one owner and no SDK thread. Platform I/O needs finite timeouts. The
only supported transport-callback reentry is `orbit_client_end_session`: while
another operation is busy it fences local authority, performs no nested I/O,
and the outer operation cleans up after its callback returns. Other reentry and
concurrent access are unsupported. Safe Rust borrows prevent callback reentry;
its cancellation closure provides cooperative cancellation instead.

## Usage and resources

`orbit_client_usage` and `orbit_client_resources` read a named counter.
`orbit_client_consume`, `orbit_client_acquire_resource` and
`orbit_client_release_resource` perform explicit mutations. They use current
activation proof directly, including with an ended floating seat. Access guards
do not consume units or allocate resources. The backend remains authoritative
for counter enforcement.

```c
orbit_limit_result_t result;
orbit_operation_t operation = {0}; /* secure ID generated if empty */
int32_t status = orbit_client_consume(&client, S("exports"), 1,
                                     &operation, &result);
/* Copy result.operation_id[0..operation_id_length] with the application's job.
 * If result.uncertain is set, retry that same operation with that exact ID. */
```

Here `S("text")` denotes a byte slice containing the literal without its NUL.
A caller-supplied ID is optional and must be reused with the same operation and
units. Cancellation or a lost response can leave a mutation uncertain. The
returned ID remains available in that case; a retry with a new ID may charge or
allocate twice. The SDK performs no hidden retry. Validated capacity denials
expose the matching counter, requested units and operation ID. Malformed denial
details are never treated as a trusted counter. Missing or malformed error
envelopes and unknown error codes retain uncertainty and the operation ID.
Released-allocation replays retain their original units within the immutable
resource limit. Integers are bounded by
9,007,199,254,740,991; units are positive.

Rust exposes `usage`, `consume`, `resources`, `acquire_resource` and
`release_resource`, with an optional `Operation` containing an ID and cancellation
closure. `MutationError` retains the operation ID, uncertainty and validated
capacity details without heap allocation.

## Updates and verified downloads

`orbit_client_check_for_updates` takes the installed release number and the
board's explicit platform/architecture. An empty channel selects `stable`.
There is no fallback to another target. A result without a newer matching
release has `available == 0`. Copy metadata needed after the next client call;
C metadata slices borrow the transaction arena. Rust borrows enforce that rule
and `Artifact::selection` makes an owned release/artifact selection.

Call `orbit_client_authorize_download` explicitly with that selection before
streaming. `orbit_download_stream` validates and copies raw bytes through
caller-owned TLS, incremental SHA-256 and destination callbacks. Supply at least
`ORBIT_DOWNLOAD_SCRATCH_MIN_BYTES` (2304 bytes), an explicit maximum byte count,
and `replace_existing = 0` unless the application opts into replacement.

The callback contract is part of the port: `open` verifies HTTPS chain, hostname
and trusted dates; requests identity encoding; uses no ambient credentials or
cookies; and disables automatic redirects. It sends only the supplied ticket as
`Authorization: Bearer`. The helper accepts at most five absolute HTTPS redirect
locations and strips the ticket at every redirect, including the same origin.
It checks the exact advertised byte length, optional HTTP Content-Length and
SHA-256 before `stage_commit`. Every error aborts the staged destination. An
existing destination remains unchanged on failure; commit publishes atomically.
No installer or firmware flasher runs. Relative redirect locations are rejected.
Rust's `DownloadIo` and `DownloadAuthorization::stream` expose the same contract.
The board adapters supply licensing HTTPS; the application supplies these
streaming and atomic-destination callbacks for its own file or firmware medium.

## Long-term offline files

Enable `ORBIT_ENABLE_OFFLINE` explicitly (Rust `offline` or `offline-full`). This
also enables services. The two file profiles accept at most **4096** and **16384**
bytes of signed JWS respectively. The transaction arena must fit that bound.
Allocate `ORBIT_OFFLINE_BUFFER_BYTES(file_limit)` bytes and initialize with an
`orbit_offline_config_t` containing that buffer, its checked capacity, the bound,
the original public app key, and a trusted offline-purpose public keyset.

```c
static uint8_t transaction[ORBIT_OFFLINE_BUFFER_BYTES(4096)];
orbit_offline_config_t offline = {
    &trusted_offline_keys, transaction, sizeof(transaction), 4096, app_key
};
orbit_client_init_extended(&client, &config, &services, &extension,
    arena, sizeof(arena), scratch, sizeof(scratch), &offline);
```

`orbit_client_offline_request` exports a bounded request with this stable
installation ID and optional machine binding. Import the issued file with
`orbit_client_import_offline_file`, or use `orbit_client_import_offline_reader`
to fill the existing transaction buffer in bounded chunks without a second
file-sized buffer. The reader returns zero bytes at EOF and must return promptly.
It supports cancellation, including a final check after signature verification
and hashing, before committing. Failed input reloads the prior committed file
before later checkpoints. The slice API trims surrounding ASCII whitespace; the reader
bounds the entire input, including whitespace.

Import verifies purpose, Test/Live key family, signature, app scope, installation,
optional binding, policy, expiry and monotonic sequence before persisting access.
Test/Live comes from the parsed app key. Tokens cannot choose their own trust.
Equal-sequence replay requires the identical signed file. The original JWS,
sequence, persisted UTC floor, selected mode and installation record form one
atomic record. Boot revalidates that original file against trusted keys and UTC.
A torn transaction, time rollback, expired file or unavailable trusted UTC fails
closed. Keep trusted offline-purpose keys through their required retention
period; they are supplied through the product's trusted configuration path.

Selected file mode does not make network requests or fall back to connected
access. Online service calls and deactivation return denial in that mode.
Explicit key activation selects connected mode; `invalidate` durably denies
local access while retaining rollback metadata. Offline time is checkpointed
periodically and at close. Access checks read trusted time again after a
checkpoint finishes, so a slow write cannot grant access past expiry. Call
`clock_lost` when elapsed time across sleep is unreliable, and restore trusted
UTC before access.

The [profile geometry](memory.md#optional-profile-buffers-and-storage) must be
reserved explicitly. Existing connected journal files are a different format:
select a separate offline-profile storage region when adopting this feature.
The SDK never erases or migrates an existing record silently.
