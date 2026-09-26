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
cargo test --manifest-path sdk/embedded/rust/Cargo.toml --offline
cargo check --manifest-path sdk/embedded/rust/Cargo.toml --offline --features external-c
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

ASan/UBSan validation uses:

```sh
cmake -S sdk/embedded -B build/embedded-sanitize -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DORBIT_BUILD_POSIX=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build/embedded-sanitize
UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build/embedded-sanitize --output-on-failure
```

For this candidate, the app-key parser and client lifecycle suites were rerun
under ASan/UBSan with
`ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build/embedded-sanitize -R 'app_key|client_lifecycle' --output-on-failure`.
Earlier full-suite sanitizer evidence predates this candidate. Leak detection was
disabled because LeakSanitizer cannot run under the traced sandbox.
The portable core itself has no heap. Board-specific builds/runs are separately listed in
[board requirements](boards.md), and are not implied by host or M0+ object tests.
