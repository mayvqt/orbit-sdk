# Validation

Run from the SDK root with installed CMake, Python, OpenSSL 3, libcurl and a C11
compiler. Configure and test both the default and compact SDK defaults:

```sh
cmake -S sdk/embedded -B build/embedded -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS_RELEASE=-Os -DORBIT_BUILD_POSIX=ON
cmake --build build/embedded
ctest --test-dir build/embedded --output-on-failure
cmake -S sdk/embedded -B build/embedded-compact -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS_RELEASE=-Os -DORBIT_BUILD_POSIX=ON \
  -DORBIT_CLIENT_ARENA_BYTES=8192
cmake --build build/embedded-compact
ctest --test-dir build/embedded-compact --output-on-failure
cargo test --manifest-path sdk/embedded/Cargo.toml --offline
cargo check --manifest-path sdk/embedded/Cargo.toml --offline --features external-c
cargo package --manifest-path sdk/embedded/Cargo.toml --offline --locked
python3 sdk/embedded/tests/measure_arm.py --output /tmp/orbit-arm-size
```

The seven CTest suites cover all 27 shared app-key vectors (4 accepted / 23
rejected), all 104 signed grant vectors (12 accepted / 92 rejected), strict
parser/bounds and payload binding, lifecycle/retry/clock/storage faults including
optional machine binding, HTTP framing across chunks, Linux storage
ownership/corruption and host-bridge time/entropy framing. Rust checks match the
real C layout, parse an app key, exercise default and compact buffers and
callback drop/restart, and compile-fail attempts to reuse buffers or drop an
AppKey while its client is active.

The crate archive includes the C core, required headers, Rust wrapper and MIT
licence. Package verification and the four Rust unit tests plus two compile-fail
documentation tests pass from an extracted standalone archive on Linux. This
checks local packaging. Use `--allow-dirty`
only when deliberately packaging uncommitted source for validation.

For v0.4.0, the same seven CTest executables were cross-built and
all passed under QEMU AArch64 11.1.1 with a Debian trixie arm64 sysroot, both
with the default and 8 KiB C arena. The Linux example and bridge host also
linked for AArch64. The Rust wrapper and its C build script passed `cargo check`
for `thumbv6m-none-eabi` (Cortex-M0+) and `thumbv8m.main-none-eabi`
(Cortex-M33), with both arena sizes. These checks establish compile/link and
portable emulation only; no board was flashed or run.

With both Rust targets installed and Arm GNU Embedded tools on `PATH`, reproduce
the wrapper checks from the SDK root with:

```sh
export ORBIT_CC=arm-none-eabi-gcc ORBIT_AR=arm-none-eabi-ar
ORBIT_CFLAGS='-mcpu=cortex-m0plus -mthumb -DORBIT_CLIENT_ARENA_BYTES=32768' \
  cargo check --locked --offline --manifest-path sdk/embedded/Cargo.toml \
  --target thumbv6m-none-eabi
ORBIT_CFLAGS='-mcpu=cortex-m0plus -mthumb -DORBIT_CLIENT_ARENA_BYTES=8192' \
  cargo check --locked --offline --manifest-path sdk/embedded/Cargo.toml \
  --target thumbv6m-none-eabi
ORBIT_CFLAGS='-mcpu=cortex-m33 -mthumb -DORBIT_CLIENT_ARENA_BYTES=32768' \
  cargo check --locked --offline --manifest-path sdk/embedded/Cargo.toml \
  --target thumbv8m.main-none-eabi
ORBIT_CFLAGS='-mcpu=cortex-m33 -mthumb -DORBIT_CLIENT_ARENA_BYTES=8192' \
  cargo check --locked --offline --manifest-path sdk/embedded/Cargo.toml \
  --target thumbv8m.main-none-eabi
```

The maintained STM32 link-only harness is under
[`examples/embedded/stm32g0b1re/validation`](../../../examples/embedded/stm32g0b1re/validation).
It links the current common example, parser, HAL adapter, startup, and Mbed TLS
crypto provider for both arena sizes. Its entry point does not initialize or
exercise the UART.

ASan/UBSan validation uses:

```sh
cmake -S sdk/embedded -B build/embedded-sanitize -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DORBIT_BUILD_POSIX=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build/embedded-sanitize
UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build/embedded-sanitize --output-on-failure
```

For v0.4.0, the app-key parser and client lifecycle suites were rerun
under ASan/UBSan with
`ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build/embedded-sanitize -R 'app_key|client_lifecycle' --output-on-failure`.
Full-suite sanitizer evidence predates v0.4.0. Leak detection was
disabled because LeakSanitizer cannot run under the traced sandbox.
The portable core itself has no heap. Board-specific builds/runs are separately listed in
[board requirements](boards.md), and are not implied by host or M0+ object tests.
