# Validation

Run from the SDK root with CMake, Python, a C11 compiler, OpenSSL 3 and libcurl.
The connected, services, compact-file and full-file configurations are separate
builds so their feature definitions and storage geometries stay consistent:

```sh
cmake -S sdk/embedded -B build/embedded -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS_RELEASE=-Os -DORBIT_BUILD_POSIX=ON
cmake --build build/embedded
ctest --test-dir build/embedded --output-on-failure

cmake -S sdk/embedded -B build/embedded-services -DORBIT_BUILD_POSIX=ON \
  -DORBIT_ENABLE_SERVICES=ON
cmake --build build/embedded-services
ctest --test-dir build/embedded-services --output-on-failure

cmake -S sdk/embedded -B build/embedded-offline -DORBIT_BUILD_POSIX=ON \
  -DORBIT_ENABLE_OFFLINE=ON -DORBIT_OFFLINE_PROFILE_FILE_BYTES=4096 \
  -DORBIT_CLIENT_ARENA_BYTES=8192
cmake --build build/embedded-offline
ctest --test-dir build/embedded-offline --output-on-failure

cmake -S sdk/embedded -B build/embedded-offline-full -DORBIT_BUILD_POSIX=ON \
  -DORBIT_ENABLE_OFFLINE=ON -DORBIT_OFFLINE_PROFILE_FILE_BYTES=16384 \
  -DORBIT_CLIENT_ARENA_BYTES=16384
cmake --build build/embedded-offline-full
ctest --test-dir build/embedded-offline-full --output-on-failure
```

The connected build passes seven suites: 27 app-key vectors, 104 grant vectors,
strict parser/bounds, lifecycle/retry/clock/storage, transport framing, Linux
storage and bridge-host framing. Services adds 288 shared session/file signature
cases, typed response/lifecycle tests and verified streaming tests. Offline adds
all journal interruption points and profile bounds, for eleven suites in total.

The extended cases cover credential-before-seat persistence, transient versus
terminal renewal failure, exact session expiry, retry ID reuse, bounded retry
scheduling, end during initial activation/renewal and credential recovery, ordinary no-ops, authoritative
counter arithmetic and HTTP status, safe capacity denials, missing update fields,
target mismatch, expired download tickets, output/input alias rejection, length/hash/encoding/redirect failures,
cancellation and preservation of an existing download destination. File cases
cover exact 4096/16384-byte signed input, one-byte overflow, sequence and clock
rollback, restart revalidation, mode isolation, failed atomic storage and bounded
reader cancellation/malformed-input recovery, cancellation during verification,
and access expiry crossed by a blocking checkpoint. Journal tests simulate every
full/partial erase, program and sync interruption at all four slot geometries.

Run the same full-file configuration with sanitizers:

```sh
cmake -S sdk/embedded -B build/embedded-sanitize -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DORBIT_BUILD_POSIX=ON -DORBIT_ENABLE_OFFLINE=ON \
  -DORBIT_OFFLINE_PROFILE_FILE_BYTES=16384 \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build/embedded-sanitize
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build/embedded-sanitize --output-on-failure
```

All eleven suites pass under ASan/UBSan. Leak detection is disabled because the
traced execution environment does not support LeakSanitizer. Portable SDK code
has no allocator calls. The streaming tests exercise callback contracts and
staging with a real incremental SHA-256 provider; board-specific TLS handshakes
and physical flash power loss need target validation.

## Rust and standalone consumption

The wrapper uses installed C and Rust tools and has no Cargo dependencies. Check
each feature set with `cargo test` and strict Clippy:

```sh
cargo test --manifest-path sdk/embedded/Cargo.toml --offline --locked
cargo test --manifest-path sdk/embedded/Cargo.toml --offline --locked --features services
cargo test --manifest-path sdk/embedded/Cargo.toml --offline --locked --features offline
cargo test --manifest-path sdk/embedded/Cargo.toml --offline --locked --features offline-full
cargo clippy --manifest-path sdk/embedded/Cargo.toml --offline --locked \
  --all-targets --features offline-full -- -D warnings
cargo fmt --manifest-path sdk/embedded/Cargo.toml -- --check
cargo check --manifest-path sdk/embedded/Cargo.toml --offline --locked --features external-c
```

Default Rust checks include four unit tests and two compile-fail borrow tests.
Services builds add ABI checks for typed results and callbacks plus owned
selection/cancellation tests (six unit tests). Offline builds also check that
the complete transaction pointer spans both metadata and file fields (seven
unit tests). The pointer derives from the whole `repr(C)` object. Miri dynamic
validation is unavailable in the installed stable toolchain. Default, services, offline and offline-full
also pass checks for Cortex-M0+ and Cortex-M33 with matching C compilation:

```sh
export ORBIT_CC=arm-none-eabi-gcc ORBIT_AR=arm-none-eabi-ar
ORBIT_CFLAGS='-mcpu=cortex-m0plus -mthumb' \
  cargo check --manifest-path sdk/embedded/Cargo.toml --offline --locked \
  --target thumbv6m-none-eabi --features offline-full
ORBIT_CFLAGS='-mcpu=cortex-m33 -mthumb' \
  cargo check --manifest-path sdk/embedded/Cargo.toml --offline --locked \
  --target thumbv8m.main-none-eabi --features offline-full
```

The crate archive contains its C sources, headers, wrapper and licence. Local
archive verification and tests from an extracted archive cover both default and
full-file features without sibling repository directories. CMake install/export
checks also build an isolated consumer against `Orbit::EmbeddedClient`,
`Orbit::EmbeddedTransport` and `Orbit::EmbeddedPosix`. Source-only CMake builds use
`-DBUILD_TESTING=OFF`; repository tests consume the shared contract corpora.

## Footprint and boards

```sh
python3 sdk/embedded/tests/measure_arm.py --profile connected --output /tmp/orbit-arm-connected
python3 sdk/embedded/tests/measure_arm.py --profile services --output /tmp/orbit-arm-services
python3 sdk/embedded/tests/measure_arm.py --profile offline-compact --output /tmp/orbit-arm-compact
python3 sdk/embedded/tests/measure_arm.py --profile offline-full --output /tmp/orbit-arm-full
```

The [memory guide](memory.md) distinguishes whole portable modules, explicit
caller buffers and conservative stack from board TLS/crypto/runtime overhead.
Connected measurements remain unchanged. Every profile has zero writable
portable globals.

ESP32, ESP8266, Pico W, Pico 2 W, STM32G0B1RE and Pi AArch64 compile/link both
file profiles with their explicit storage reservations. AArch64 QEMU runs all
eleven portable suites in each profile. The [board guide](boards.md) records
commands, toolchains, actual linker sizes and limits. Physical boards are not
flashed or executed; STM32's validation entry point does not initialize UART.
The full ESP8266 profile leaves very little static RAM for dynamic TLS and needs
an actual firmware memory budget before connected use.
