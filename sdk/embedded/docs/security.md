# Client and adapter contracts

The client uses one owner, synchronous callbacks, explicit ticks and no hidden
threads. Check every initialization result. Zero-initialize client storage and
destroy it before reinitializing; all entry points reject callback reentry.
Never copy a live client or let two contexts own the same installation store.
Destroy clears RAM but does not revoke a credential; use deactivate or invalidate
for that purpose.

## Authority and retries

Storage contains a stable installation ID, scope digest, revocable credential,
and any pending operation ID/input digest. It never contains a raw licence key,
password or restored access grant. The pending identity is committed before the
activation/deactivation request. Verified returned authority is committed before
access is granted. A malformed or lost mutation response preserves its retry
identity; definitive denial durably clears authority. A failed durable write
leaves access unavailable until the storage problem is resolved.

Normal boot validates an existing credential online. The client never restores a
grant using process-local ticks after power loss. After a valid online result,
trusted elapsed time advances the original server-time anchor. Offline access
requires a signed `offline_allowed` grant and a qualifying network/server
transient; it cannot extend the original expiry. An unknown-key fetch failure
invalidates cached access rather than falling back across an unverified candidate.
Clock rollback or uncertainty clears access and requires online recovery.

Finite credentials and strictly online grants use a signed refresh interval of
45–75 seconds. A persistent credential (explicit null expiry) with signed offline
permission uses 675–1,125 seconds, capped by the original expiry. Future issuance
is bounded by 30 seconds; receipt/current time, context, licence and credential
expiry checks all remain enforced.

## TLS, entropy and time

TLS ports must verify hostname, CA chain and certificate dates using trusted UTC.
Do not use insecure TLS modes, unauthenticated time as a security bootstrap, or
unseeded/weak random output. Pico firmware supplies a trusted clock and CSPRNG;
the same entropy callback seeds its maintained Mbed TLS library. ESP ports
require Wi-Fi entropy to be active and trusted system time established first.

A stream must finish sending and stop reading the request before delivering any
response body: that body reuses the request arena. Responses are bounded and
redirects are disabled. The portable HTTP reader accepts content length, chunked
or close-delimited responses, bounds headers, and rejects conflicting framing,
compression, trailers and chunk extensions. The provider classifies genuine
network timeouts/unavailability separately from TLS or malformed-data failures.
Ports that cannot distinguish a TLS failure conservatively return untrusted.

The physical host bridge is a trusted transport boundary, not a secure protocol
for an exposed network. Use a dedicated USB/UART byte stream without logs or
terminal echo. Its configured Linux host authenticates HTTPS and supplies trusted
time and CSPRNG output; the MCU still verifies every ES256 signature locally. A
changed host boot ID invalidates the elapsed-time anchor. Do not expose the helper
as an unauthenticated TCP listener.

## Durable storage

Only changes to installation, pending operation, credential or invalidation state
write flash. Successful refreshes and access checks do not write flash each
minute. The generic journal uses two independently erasable reserved slots,
durable intent, payload CRC and a final commit marker. A torn nonempty slot fails
closed; it never restores an older credential. Recovery is a deliberate product
flow, not automatic formatting or new-identity creation.

CRC detects corruption and torn writes, not hostile modification. The board must
protect persistent credentials using appropriate flash encryption/readout
protection and trusted firmware/update/debug boundaries. ESP32 encrypted raw
flash uses 16-byte writes; STM32 uses doublewords; Pico uses safe flash execution
and full page programming. Reserve the slots in the linker/partition layout and
keep other software out of them. Linux uses a private owned directory, no-follow
regular file, exclusive lifetime lock, generation checks and file/directory fsync.

The flash journal writes and syncs an intent in the current slot before erasing
its replacement. An incomplete newer generation then denies access on reboot;
a completed adjacent generation acknowledges the old intent. The intent occupies
an initially unprogrammed flash block, including on encrypted/ECC flash. A device
that cannot persist even that first intent cannot promise durable invalidation:
report the storage error and deny access in the running client; never report a
successful logout or erase storage to recover automatically.
