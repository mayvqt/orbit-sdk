# Memory and ABI

The protocol bounds are fixed: 16 KiB compact JWS, 32 KiB HTTP JSON/JWKS,
8 signing keys, 64 entitlements, and 64 bytes per entitlement name. The client
uses one 32 KiB arena for a request, response and decoded payload in turn.
Streaming JWKS import preserves that payload while refreshing an unknown key.
The default profile preserves these protocol bounds. The explicit small-arena
profile below rejects responses larger than its chosen buffer.

| Caller-owned object | Bytes |
| --- | ---: |
| Full client state, including keys and active entitlement cache | 6,960 |
| Shared transaction arena | 32,768 |
| Parser scratch | 2,048 |
| **Full client buffers** | **41,776** |
| Verifier-only claims view | 360 |
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
| Grant verifier, strict JSON, in-place prepare, JWKS importer | 12,488 bytes | 0 |
| Full client plus verifier, wire format and journal | 26,666 bytes | 0 |

These are linked library modules, **not firmware images**. Compiler runtime
helpers remain unresolved until a real target toolchain links them. Crypto,
networking, TLS, adapters, application strings, vector tables and startup code
are excluded. Static archive file sizes are not flash-use estimates.

The bounded call-graph estimate from `-fstack-usage` is 1,412 bytes for standalone
grant verification, 524 for standalone JWKS import, and up to 3,700 for the full
portable client (including the 16-level JSON recursion limit). Provider stack,
TLS callbacks, board code, runtime helpers, interrupts and Rust callbacks are
additional. Mutation preparation uses a separate stack frame so its record copy
is released before network work. Measure actual stack and free heap on each
firmware build, especially ESP8266; its TLS memory is a separate constraint.

Run `tests/measure_arm.py --output /tmp/orbit-arm-size` with the installed LLVM
tools to reproduce the portable figures. The full client has no heap calls;
platform TLS and crypto implementations may allocate internally.

The linked x86-64 Linux example with GCC 16.2.1 `-Os` has 44,550 bytes of code
and read-only data, 1,120 bytes of initialized data, and 41,840 bytes of BSS.
Its dynamically linked OpenSSL/libcurl, process stack and runtime allocations
are additional; this host measurement is not an MCU flash estimate.

For constrained boards, compile the SDK and application with
`ORBIT_CLIENT_ARENA_BYTES=8192` (supported range: 8192–32768 bytes). This saves
24 KiB versus the default transaction arena; the client and verification rules
are unchanged. Responses larger than the chosen arena fail with a resource
limit instead of being truncated. Choose the profile for your policy's grant
size, and measure TLS handshake, stack and application heap on the actual board.
The verifier-only API keeps its independent published limits.
