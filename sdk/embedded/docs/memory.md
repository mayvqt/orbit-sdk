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

## Linked example footprints

These measurements come from cross-linked examples; they do not measure hardware
at runtime.
RAM headroom subtracts the linked static sections and the explicit minimum
heap/stack reservations noted in the table from the board or linker region. It
does not measure TLS heap use, runtime stack high-water or free heap after
initialization. The Pico values include vectors and uninitialized data in the
static RAM total. STM32 RAM headroom includes the linker's 512-byte minimum
heap and 1 KiB minimum stack reservation.

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

Pico flash totals use the generated BIN size, including boot metadata, the load
image for `.data` and 32 bytes of Pico 2 W output padding;
Pico static RAM totals also include the runtime vector table and
uninitialized data. Their linkers reserve 2 KiB each for heap and stack, which
is subtracted from the displayed SRAM headroom. STM32 flash use is 29,268 bytes
in each profile, including the 188-byte interrupt vector, alignment padding,
exception index, init/fini arrays and the 136-byte `.data` load image. That
image contains 56 bytes of RAM-function code copied to RAM at startup; its end
is `0x08007254`, below the reserved journal region at `0x0807f000`. The ESP32
IDF report gives 440,457 bytes
of image sections (440,576-byte padded binary) for both profiles. The
NodeMCU's code total is `.text` + `.text1` + `.irom0.text`.

The AArch64 Linux `orbit_pi` ELF is dynamically linked and has no fixed flash
slot or per-process static RAM ceiling. `size` reports text/data/BSS of
69,893/1,104/42,272 bytes with the default arena, and 69,893/1,104/17,696 bytes
with 8 KiB. Linux shared libraries, process stack, TLS allocations, OS use and
free RAM were not measured.

Toolchains, linker budgets, and reproduction commands are listed in the
[board guide](boards.md). None of these figures establishes a physical-board
run.
