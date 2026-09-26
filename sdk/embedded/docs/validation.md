# Validation

Run from the SDK root with already-installed CMake, Python, OpenSSL 3, libcurl
and a C11 compiler:

```sh
cmake -S sdk/embedded -B build/embedded -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS_RELEASE=-Os -DORBIT_BUILD_POSIX=ON
cmake --build build/embedded
ctest --test-dir build/embedded --output-on-failure
cargo test --manifest-path sdk/embedded/rust/Cargo.toml --offline
cargo check --manifest-path sdk/embedded/rust/Cargo.toml --offline --features external-c
python3 sdk/embedded/tests/measure_arm.py --output /tmp/orbit-arm-size
```

The six CTest suites cover all 101 shared vectors (12 accepted / 89 rejected),
strict parser/bounds and payload binding, full lifecycle/retry/clock/storage
faults, HTTP framing across chunk boundaries, Linux storage ownership/corruption,
and local host-bridge time/entropy framing. Rust checks match the real C layout,
exercise callbacks and drop/restart, and reject buffer reuse at compile time.

ASan/UBSan validation uses:

```sh
cmake -S sdk/embedded -B build/embedded-sanitize -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Debug -DORBIT_BUILD_POSIX=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build/embedded-sanitize
UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build/embedded-sanitize --output-on-failure
```

All six suites pass under ASan/UBSan. In the current traced sandbox,
LeakSanitizer cannot run; that environment used `ASAN_OPTIONS=detect_leaks=0`.
The portable core itself has no heap. Board-specific builds/runs are separately listed in
[board requirements](boards.md), and are not implied by host or M0+ object tests.
