# Memory and ABI

The protocol bounds are fixed: 16 KiB compact JWS, 32 KiB HTTP JSON/JWKS,
8 signing keys, 64 entitlements, and 64 bytes per entitlement name. The client
uses one caller-owned 8–32 KiB arena for a request, response and decoded payload in turn.
Streaming JWKS import preserves that payload while refreshing an unknown key.
The default profile preserves these protocol bounds. The explicit small-arena
profile below rejects responses larger than its chosen buffer.

| Caller-owned object | Bytes |
| --- | ---: |
| Full client state, including keys and active entitlement cache | 6,960 |
| Shared transaction arena, default | 32,768 |
| Parser scratch | 2,048 |
| **Default client buffers** | **41,776** |
| Shared transaction arena, compact | 8,192 |
| **Compact client buffers** | **17,200** |
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

## Measured portable footprint

Clang 22.1.8, `--target=arm-none-eabi -mcpu=cortex-m0plus -mthumb -Os
-ffreestanding -fno-builtin`, followed by a relocatable `ld.lld -r` link:

| Linked portable module | Read-only code/data | Writable globals |
| --- | ---: | ---: |
| Grant verifier, strict JSON, in-place prepare, JWKS importer | 12,536 bytes | 0 |
| Full client, verifier, wire format, journal and app-key parser | 29,576 bytes | 0 |

These are linked library modules, **not firmware images**. Compiler runtime
helpers remain unresolved until a real target toolchain links them. Crypto,
networking, TLS, adapters, application strings, vector tables and startup code
are excluded. Static archive file sizes are not flash-use estimates.

The bounded call-graph estimate from `-fstack-usage` is 1,412 bytes for standalone
grant verification, 524 for standalone JWKS import, 240 for app-key parsing, and
up to 3,716 for the full portable client (including the 16-level JSON recursion
limit). Provider stack,
TLS callbacks, board code, runtime helpers, interrupts and Rust callbacks are
additional. Mutation preparation uses a separate stack frame so its record copy
is released before network work. Measure actual stack and free heap on each
firmware build, especially ESP8266; its TLS memory is a separate constraint.

Run `tests/measure_arm.py --output /tmp/orbit-arm-size` with the installed LLVM
tools to reproduce the portable figures. The full client has no heap calls;
platform TLS and crypto implementations may allocate internally.

The linked x86-64 Linux example with GCC 16.2.1 `-Os` has 47,569 bytes of code
and read-only data, 1,056 bytes of initialized data, and 42,320 bytes of BSS.
Its dynamically linked OpenSSL/libcurl, process stack and runtime allocations
are additional; this host measurement is not an MCU flash estimate.

`ORBIT_CLIENT_ARENA_BYTES` controls the default application allocation, and can
be set from 8192 through 32768 bytes. C callers may pass any actual runtime arena
capacity in that same range, independently of the compile-time default. Rust
uses `Buffers::<8192>` or `Buffers::<32768>` to select a static size. The compact
choice saves 24 KiB of transaction RAM; protocol and verification rules stay the
same. Requests or responses that do not fit fail with a resource limit rather
than being truncated. Choose the size for your policy's grant and measure TLS
handshake, stack and application heap on the actual board.

The heapless app-key parser needs a caller-owned 384-byte origin buffer in C;
its parsed application and environment IDs borrow the original key text. Rust
stores the decoded origin inline in `AppKey` and borrows the IDs from the input.
This setup memory is separate from the client buffer totals above.
The verifier-only API keeps its independent published limits.
