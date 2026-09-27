# Memory and ABI

The protocol bounds are fixed: 16 KiB compact JWS, 32 KiB HTTP JSON/JWKS,
8 signing keys, 64 entitlements, and 64 bytes per entitlement name. The client
uses one caller-owned 8–32 KiB arena for a request, response and decoded payload in turn.
Streaming JWKS import preserves that payload while refreshing an unknown key.
The explicit small-arena profile rejects responses larger than its chosen
buffer.

| Caller-owned object | Bytes |
| --- | ---: |
| Full client state, including keys and active entitlement cache | 7,008 |
| Shared transaction arena, default | 32,768 |
| Parser scratch | 2,048 |
| **Default client buffers** | **41,824** |
| Shared transaction arena, compact | 8,192 |
| **Compact client buffers** | **17,248** |
| App-key decoded origin buffer (additional) | 384 |
| Verifier-only claims view | 368 |
| Verifier-only trusted keyset | 1,545 |
| Prepared token integrity metadata | 260 |
| Incremental JWKS importer | 340 |

Verifier-only callers can use a 16 KiB token arena and feed JWKS chunks directly;
they do not need a separate 32 KiB JWKS buffer. Claims contain offsets borrowing
the decoded arena. Entitlement strings are unescaped only after full strict JSON
validation and signature verification. The full client copies only verified
feature names and bits to its compact active cache before reusing the arena.

`orbit_grant_prepare` hashes the exact original JOSE signing bytes, decodes in
place and binds the decoded payload with a second digest. `orbit_grant_verify`
rechecks that binding before parsing. The provider verifies the supplied SHA-256
digest directly, without hashing again. Pending metadata is trusted internal
state created by prepare, never a serialized input or an access decision.

All objects and buffers must be disjoint; invalid overlaps are rejected without
writes. Ordinary verifier failures clear claims. Retained text offsets expire
when the arena is overwritten. The Rust wrapper exposes no raw FFI, pending
constructor or mutable access to a live arena. C's private union layout supplies
the actual state type and alignment; its members are not application API.

## Portable footprint

Portable module sizes for Cortex-M0+ (`-Os`, Thumb):

| Linked portable module | Read-only code/data | Writable globals |
| --- | ---: | ---: |
| Grant verifier, strict JSON, in-place prepare, JWKS importer | 12,536 bytes | 0 |
| Full client, verifier, wire format, journal and app-key parser | 29,576 bytes | 0 |

These are linked library modules, **not firmware images**. Compiler runtime
helpers, crypto, networking, TLS, adapters, application strings, vector tables
and startup code are additional. Static archive file sizes are not flash-use
estimates.

Conservative portable stack is 1,412 bytes for standalone grant verification,
524 for standalone JWKS import, 240 for app-key parsing, and up to 3,716 for the
full portable client (including the 16-level JSON recursion limit). Provider
stack, TLS callbacks, board code, runtime helpers, interrupts and Rust callbacks
are additional. Mutation preparation uses a separate stack frame so its record
copy is released before network work. Check actual stack and free heap on each
firmware build, especially ESP8266, where TLS memory is a separate constraint.

The full client has no heap calls; platform TLS and crypto implementations may
allocate internally.

`ORBIT_CLIENT_ARENA_BYTES` controls the default application allocation, and can
be set from 8192 through 32768 bytes. C callers may pass any actual runtime arena
capacity in that same range, independently of the compile-time default. Rust
uses `Buffers::<8192>` or `Buffers::<32768>` to select a static size. The compact
choice saves 24 KiB of transaction RAM; protocol and verification rules stay the
same. Requests or responses that do not fit fail with a resource limit rather
than being truncated. Choose the size for your policy's grant and check TLS
handshake, stack and application heap on the actual board.

The heapless app-key parser needs a caller-owned 384-byte origin buffer in C;
its parsed application and environment IDs borrow the original key text. Rust
stores the decoded origin inline in `AppKey` and borrows the IDs from the input.
This setup memory is separate from the client buffer totals above.

## Linked example footprints

Static linker figures for the example firmware in bytes. RAM headroom subtracts
the linked static sections and the linker's minimum heap/stack reservations
(2 KiB each on Pico, 512-byte heap and 1 KiB stack on STM32); budget TLS heap
and runtime stack within it.

| Target/profile | `.text` | `.rodata` | `.data` | `.bss` | Flash remaining | Static RAM remaining |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ESP32 default | 296,402 | 77,464 | 9,500 | 49,392 | 608,000 / 1 MiB app slot | 121,844 / 180,736 DRAM; 74,269 / 131,072 IRAM |
| ESP32 8 KiB | 296,402 | 77,464 | 9,500 | 24,816 | 608,000 / 1 MiB app slot | 146,420 / 180,736 DRAM; 74,269 / 131,072 IRAM |
| ESP8266 NodeMCU 8 KiB | 426,723 code sections | 3,304 | 1,496 | 43,448 | 612,941 / 1,044,464-byte app slot | 33,672 / 81,920 |
| Pico W default | 191,880 | 20,228 | 3,008 | 56,856 | 1,873,548 / 2 MiB after 8 KiB journal reserve | 206,152 / 270,336 after 4 KiB heap/stack reserve |
| Pico W 8 KiB | 191,880 | 20,228 | 3,008 | 32,280 | 1,873,548 / 2 MiB after 8 KiB journal reserve | 230,728 / 270,336 after 4 KiB heap/stack reserve |
| Pico 2 W default | 171,988 | 18,468 | 4,104 | 56,416 | 3,991,480 / 4 MiB after 8 KiB journal reserve | 467,576 / 532,480 after 4 KiB heap/stack reserve |
| Pico 2 W 8 KiB | 171,988 | 18,468 | 4,104 | 31,840 | 3,991,480 / 4 MiB after 8 KiB journal reserve | 492,152 / 532,480 after 4 KiB heap/stack reserve |
| STM32G0B1RE default | 26,872 | 2,052 | 136 | 42,712 | 490,924 / 508 KiB linker region | 103,072 / 144 KiB after minimum heap/stack |
| STM32G0B1RE 8 KiB | 26,872 | 2,052 | 136 | 18,136 | 490,924 / 508 KiB linker region | 127,648 / 144 KiB after minimum heap/stack |

Pico flash totals include boot metadata and the `.data` load image; Pico static
RAM includes the vector table and uninitialized data. STM32 flash use is 29,268
bytes in each profile, ending below the reserved journal region at
`0x0807f000`. ESP32's padded app binary is 440,576 bytes. The ESP8266 code total
is `.text` + `.text1` + `.irom0.text`.

The dynamically linked AArch64 Linux `orbit_pi` example has text/data/BSS of
69,893/1,104/42,272 bytes with the default arena and 69,893/1,104/17,696 bytes
with 8 KiB, excluding shared libraries, process stack and TLS allocations.

Build commands for each target are in the [board guide](boards.md).

### Offline profile footprints

Raw GNU `size` text/data/BSS bytes, excluding TLS runtime needs:

| Target | Compact (4 KiB file) | Full (16 KiB file) |
| --- | --- | --- |
| Pico W | 238,752 / 0 / 37,980 | 238,792 / 0 / 58,460 |
| Pico 2 W | 216,784 / 0 / 37,604 | 216,808 / 0 / 58,084 |
| STM32G0B1RE | 42,672 / 0 / 25,144 | 42,704 / 0 / 45,624 |
| ESP32 | 364,853 / 87,444 / 30,313 | 364,869 / 87,444 / 50,793 |

On ESP8266, the compact profile uses 442,871 bytes of flash and 54,124 bytes of
RAM; the full profile uses 442,887 and 74,604, leaving only **7,316 bytes** of
the 81,920-byte static RAM budget for TLS, stack and application work.

## Optional profile buffers and storage

Services and offline files are explicit compile features. On Cortex-M0+, the
extended client is 7,024 bytes; its external extension is 248 bytes for services
or 336 bytes with offline support. The same structs can be larger on a 64-bit
host. Allocate by `sizeof`, using the same feature definitions as the library.

| C profile | Arena | External extension | Combined file/metadata buffer | Total caller buffers |
| --- | ---: | ---: | ---: | ---: |
| Connected compact | 8,192 | 0 | 0 | 17,248 |
| Services compact | 8,192 | 248 | 0 | 17,512 |
| Offline compact, 4 KiB file | 8,192 | 336 | 5,120 | 22,720 |
| Offline full, 16 KiB file | 16,384 | 336 | 17,408 | 43,200 |

Totals include client state and 2,048-byte scratch. Offline trust needs an
additional 1,545-byte keyset, which C may retain in immutable storage; app-key
storage, result objects, TLS, crypto, application state and stack are separate.
The Rust wrapper reserves 288/392 bytes for its extension so the same safe type
fits supported 32- and 64-bit ABIs. `OfflineBuffers` also owns its imported
1,545-byte keyset. Its buffers are explicit caller allocations. Reader import
uses the combined transaction buffer without another file-sized copy or heap
allocation. Download streaming separately needs at least 2,304 caller bytes.

| Profile | Portable code/read-only data | Writable globals | Conservative guard stack |
| --- | ---: | ---: | ---: |
| Connected | 29,576 | 0 | 3,716 |
| Services | 48,547 | 0 | 3,884 |
| Offline compact | 54,140 | 0 | 3,884 |
| Offline full | 54,136 | 0 | 3,884 |

These whole-module figures include optional APIs even when a firmware linker
can discard unused functions. Offline slice import uses a 2,636-byte
conservative portable stack, reader import 2,692, extended initialization 2,708,
consume 2,140, update discovery 1,716 and stream 344. Provider/TLS/reader callbacks,
interrupts and target runtime helpers remain additional.

The connected record remains 1,024 bytes. Offline records reserve 1,024 bytes of
metadata plus the exact selected file bound. The journal adds a 64-byte header;
each of two independent slots is rounded up to the port's erase unit:

| Port geometry | Connected: each slot / total | 4 KiB file: each slot / total | 16 KiB file: each slot / total |
| --- | ---: | ---: | ---: |
| STM32, 2 KiB erase pages | 2 / 4 KiB | 6 / 12 KiB | 18 / 36 KiB |
| ESP32/Pico, 4 KiB erase sectors | 4 / 8 KiB | 8 / 16 KiB | 20 / 40 KiB |
| ESP8266/Linux logical slot files | 4 / 8 KiB | 8 / 16 KiB | 20 / 40 KiB |

ESP8266 LittleFS needs additional filesystem capacity and runtime overhead beyond
its two logical slots. Linux uses one journal file containing two independent
slots. Firmware linker/partition reservations must match
`ORBIT_OFFLINE_PROFILE_FILE_BYTES`; the supported board examples provide
explicit reservations. STM32 slots span independently erased pages. Pico slots
erase each included sector.
