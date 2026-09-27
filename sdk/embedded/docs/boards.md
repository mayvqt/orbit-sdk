# Board setup and build checks

Set the public app-key build definition `ORBIT_APP_KEY` from the Orbit
Integration page. The [common example](../../../examples/embedded/common/client.c)
parses it into caller-owned origin storage before client initialization. Each
firmware provisions networking and trusted time, supplies a separate licence key
through its own UI, and gates actions with the access helper. The examples do
not embed or persist licence keys. Board hooks default to unavailable access
until configured.

The v0.4.0 SDK has been cross-compiled and linked for all supported
examples below. Seven portable CTest suites passed under AArch64 QEMU in both
the default and 8 KiB arena profiles; the Rust wrapper passed Cortex-M0+ and
Cortex-M33 target checks. No firmware has been flashed or run on physical
boards. The target figures below come from linked harnesses and linker reports,
not runtime heap, stack or board measurements. The app key used for these local
builds was synthetic and public.

| Target/profile | Linked code and data (`text / rodata / data / bss`, bytes) | Flash headroom | Static RAM headroom |
| --- | --- | --- | --- |
| ESP32 default | 296,402 / 77,464 / 9,500 / 49,392 | 608,000 bytes in the 1 MiB app partition | 121,844 bytes DRAM; 74,269 bytes IRAM |
| ESP32 8 KiB | 296,402 / 77,464 / 9,500 / 24,816 | 608,000 bytes in the 1 MiB app partition | 146,420 bytes DRAM; 74,269 bytes IRAM |
| ESP8266 NodeMCU 8 KiB | 426,723 code / 3,304 / 1,496 / 43,448 | 612,941 bytes in the 1,044,464-byte app slot | 33,672 of 81,920 bytes |
| Pico W default | 191,880 / 20,228 / 3,008 / 56,856 | 1,873,548 bytes after the 8 KiB journal reserve | 206,152 of 270,336 bytes after the 4 KiB linker heap/stack reserve |
| Pico W 8 KiB | 191,880 / 20,228 / 3,008 / 32,280 | 1,873,548 bytes after the 8 KiB journal reserve | 230,728 of 270,336 bytes after the 4 KiB linker heap/stack reserve |
| Pico 2 W default | 171,988 / 18,468 / 4,104 / 56,416 | 3,991,480 bytes after the 8 KiB journal reserve | 467,576 of 532,480 bytes after the 4 KiB linker heap/stack reserve |
| Pico 2 W 8 KiB | 171,988 / 18,468 / 4,104 / 31,840 | 3,991,480 bytes after the 8 KiB journal reserve | 492,152 of 532,480 bytes after the 4 KiB linker heap/stack reserve |
| STM32G0B1RE default | 26,872 / 2,052 / 136 / 42,712 | 490,924 bytes in the 508 KiB firmware region | 103,072 bytes after minimum heap/stack |
| STM32G0B1RE 8 KiB | 26,872 / 2,052 / 136 / 18,136 | 490,924 bytes in the 508 KiB firmware region | 127,648 bytes after minimum heap/stack |

Pico values also include the load image for `.data`, boot metadata, vectors and
uninitialized data where applicable; the Pico 2 W BIN includes 32 bytes of
output padding. Their displayed RAM headroom subtracts the linker's 2 KiB heap
and 2 KiB stack sections. The STM32 total includes its vector table,
alignment padding, exception index, init/fini arrays and the `.data` load image
(including 56 bytes of RAM-function code), as well as the linker's 512-byte
heap and 1 KiB stack reservation. ESP32's padded app binary is
440,576 bytes in both arena sizes; the IDF section report totals 440,457 bytes.
The ESP8266 code value combines `.text`, `.text1` and `.irom0.text`.

The AArch64 Linux `orbit_pi` example and bridge host linked with Debian trixie
arm64 libraries. The PIE example's `size` totals are text/data/BSS
69,893/1,104/42,272 bytes for the default arena and 69,893/1,104/17,696 bytes
for 8 KiB. Its `.rodata` section is 1,780 bytes. Linux uses a shared filesystem
and system memory, so this build has no fixed firmware flash slot or meaningful
per-process static RAM headroom; the OS, shared libraries, stack and dynamic
allocations are not included.

Build toolchains were ESP-IDF 5.5.2 with Xtensa GCC 14.2.0; PlatformIO Core
6.1.19, Espressif8266 4.2.1, Arduino core 3.1.2 and Xtensa GCC 10.3.0; Pico SDK
2.3.1 with Arm GNU 14.3.1; STM32CubeG0 1.6.3 and Mbed TLS 3.6.6 with Arm GNU
14.3.1; and Debian trixie arm64 (glibc 2.41, libcurl 8.14.1, OpenSSL 3.5.7)
with AArch64 GCC 14.2.0. Rust target checks used Rust 1.98.1. The AArch64 test
executables ran under QEMU 11.1.1.

## Linux and Pi Zero 2 W

Requires CMake, a C11 compiler, libcurl with HTTPS support, OpenSSL 3 development
headers/libraries, and trusted system UTC/CA roots. The adapter uses Linux
`getrandom`, `CLOCK_BOOTTIME`, file locking and fsync. Run from the SDK root:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
cmake -S examples/embedded/linux -B build/orbit-pi -DCMAKE_BUILD_TYPE=Release \
  -DORBIT_APP_KEY="$ORBIT_APP_KEY"
cmake --build build/orbit-pi
mkdir -m 700 "$HOME/.orbit-device"
build/orbit-pi/orbit_pi "$HOME/.orbit-device"
```

The example reads a key from its private terminal when needed; it never writes
the key to disk. Provisioning UIs should hide input. The same build creates
`orbit/orbit_bridge_host`, which can serve a trusted raw USB/UART stream for an
MCU. Pass the one allowed HTTPS origin as its argument. Do not mix log output or
terminal echo into that binary stream. Both the current Linux example and bridge
host linked for AArch64 with Debian trixie glibc 2.41, libcurl 8.14.1 and
OpenSSL 3.5.7. All seven current portable suites passed in QEMU AArch64 for both
arena sizes. Physical Pi testing remains outstanding.

For a cross-link, install an AArch64 Linux C compiler, QEMU AArch64 and a Debian
arm64 sysroot containing the target OpenSSL/libcurl development files. Point
pkg-config at the target files:

```sh
export AARCH64_SYSROOT=/path/to/debian-trixie-arm64-sysroot
export PKG_CONFIG_SYSROOT_DIR="$AARCH64_SYSROOT"
export PKG_CONFIG_LIBDIR="$AARCH64_SYSROOT/usr/lib/aarch64-linux-gnu/pkgconfig:$AARCH64_SYSROOT/usr/share/pkgconfig"
cmake -S examples/embedded/linux -B build/orbit-pi-aarch64 \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/examples/embedded/linux/cmake/aarch64-linux-gnu.cmake" \
  -DAARCH64_SYSROOT="$AARCH64_SYSROOT" -DAARCH64_CC=aarch64-linux-gnu-gcc \
  -DCMAKE_BUILD_TYPE=Release -DORBIT_BUILD_POSIX=ON \
  -DORBIT_CLIENT_ARENA_BYTES=32768 -DORBIT_APP_KEY="$ORBIT_APP_KEY"
cmake --build build/orbit-pi-aarch64
```

Configure `sdk/embedded` separately with the same toolchain, `-DBUILD_TESTING=ON`
and `-DORBIT_BUILD_POSIX=ON` to run the seven portable suites under QEMU.

## ESP32

Requires the maintained ESP-IDF SDK, its matching target GCC toolchain, Python
environment and CMake/Ninja. Use `examples/embedded/esp32` as the IDF project:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
idf.py -C examples/embedded/esp32 set-target esp32
idf.py -C examples/embedded/esp32 build
idf.py -D ORBIT_CLIENT_ARENA_BYTES=8192 -C examples/embedded/esp32 build
```

Implement `orbit_board_ready` after Wi-Fi and trusted UTC setup, and
`orbit_board_root_ca` with the real CA PEM. The dedicated `orbit` data partition
reserves two 4 KiB sectors; its encrypted flag supports ESP flash encryption when
enabled in the product's security configuration. Configure secure boot, readout
and update/debug controls for deployment. The port uses esp-tls and Mbed TLS,
requires Wi-Fi entropy to be active, and performs no automatic storage erasure.
Deep sleep resumes through client initialization and online validation.

The ESP32 example linked with ESP-IDF 5.5.2 and Xtensa GCC 14.2.0 for both
arena profiles. Its padded app binary is 440,576 bytes in the 1 MiB app
partition, leaving 608,000 bytes. The IDF report shows 58,892 bytes DRAM used
with the default arena and 34,316 with 8 KiB; the corresponding DRAM headroom is
121,844 and 146,420 bytes. Both builds use 56,803 of 131,072 bytes IRAM.
Physical-board testing remains outstanding.

## ESP8266 / NodeMCU

Requires PlatformIO Core with the `espressif8266` platform, ESP8266 Arduino core
and its matching Xtensa toolchain. The example includes the portable C sources,
BearSSL adapter, LittleFS journal and native Wi-Fi stream:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
pio run --project-dir examples/embedded/esp8266 --environment nodemcuv2
```

Implement the example's Wi-Fi/trusted-time readiness and CA-root hooks. Mount
LittleFS without automatic formatting. Keep default BearSSL receive capacity
unless the server actually negotiates smaller TLS fragments; reducing a buffer
locally is not negotiation. The port uses trusted wall time for conservative
elapsed tracking and denies access after rollback. Measure free heap during TLS
handshake as well as Orbit's static buffers; ESP8266 is the tightest RAM target.

The NodeMCU example linked with PlatformIO Core 6.1.19,
Espressif8266 4.2.1, ESP8266 Arduino 3.1.2 and GCC 10.3.0. The 8 KiB Orbit
profile uses 48,248 of PlatformIO's 81,920-byte RAM budget and 431,523 of the
1,044,464-byte application slot. That leaves 33,672 bytes of link-time RAM and
612,941 bytes in the app slot. TLS handshake heap use and physical-board
operation remain unmeasured.

## Pico W and Pico 2 W: native Wi-Fi

Requires Arm GNU Embedded tools (`arm-none-eabi-gcc`, `ar`, `objcopy`), CMake,
Ninja or Make, Python, and a Pico SDK checkout containing cyw43, lwIP and Mbed TLS
submodules. Both targets use the Cortex-M build:

```sh
export ORBIT_APP_KEY='orbit_app_test_...'
cmake -S examples/embedded/pico_wifi -B build/pico-w -DPICO_BOARD=pico_w \
  -DORBIT_CLIENT_ARENA_BYTES=32768
cmake --build build/pico-w
cmake -S examples/embedded/pico_wifi -B build/pico-w-compact -DPICO_BOARD=pico_w \
  -DORBIT_CLIENT_ARENA_BYTES=8192
cmake --build build/pico-w-compact
cmake -S examples/embedded/pico_wifi -B build/pico2-w -DPICO_BOARD=pico2_w \
  -DORBIT_CLIENT_ARENA_BYTES=32768
cmake --build build/pico2-w
cmake -S examples/embedded/pico_wifi -B build/pico2-w-compact -DPICO_BOARD=pico2_w \
  -DORBIT_CLIENT_ARENA_BYTES=8192
cmake --build build/pico2-w-compact
```

Set `PICO_SDK_PATH` to that installed SDK first. Implement the Wi-Fi, CA, trusted
clock and CSPRNG hooks in `main.c`. The native port uses the polling cyw43/lwIP
architecture with required certificate verification and certificate date checks.
It links the SDK's Mbed TLS component libraries and supplies the entropy callback
from your trusted source; it does not use an insecure TLS mode or treat weak
oscillator output as a sufficient CSPRNG seed. The same source is used for both
board targets. [Pico SDK networking documentation](https://www.raspberrypi.com/documentation/pico-sdk/networking.html)
describes the underlying libraries.

Reserve the final two 4 KiB flash sectors for the journal in the product's linker
layout. The adapter also rejects overlap with `__flash_binary_end`. The context
has static lifetime, including outstanding DNS callbacks. Use `pico_flash` safe
execution for other-core/interrupt coordination. Reinitialize after uncertain
sleep elapsed time. A trusted host bridge is an optional alternative transport;
the native example does not require one.

The current Pico W and Pico 2 W examples linked with Pico SDK 2.3.1 and Arm GNU
14.3.1 in both arena profiles, producing ELF, BIN and UF2 files. Their exact
flash and static RAM use is in the measurement table above. The SRAM figures
are gross static headroom; they do not measure TLS heap or stack at runtime.
Physical-board testing remains outstanding.

## STM32G0B1RE

Requires Arm GNU Embedded tools, STM32CubeG0 HAL/CMSIS, your Cube-generated
STM32G0B1RE firmware project with startup/linker configuration, and maintained
Mbed TLS SHA-256/P-256/ECDSA support. Add the files listed in the
[STM32 integration example](../../../examples/embedded/stm32g0b1re/README.md), then
build the application with its Cube-generated CMake project:

```sh
cmake -S path/to/your-cube-project -B build/stm32g0b1re -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/absolute/path/to/your-cube-project/cmake/gcc-arm-none-eabi.cmake
cmake --build build/stm32g0b1re
arm-none-eabi-size build/stm32g0b1re/your-application.elf
```

The maintained link-only harness used for these measurements can also
be built directly. Set the paths to your installed toolchain and vendor SDKs:

```sh
export PATH="/path/to/arm-gnu-toolchain/bin:$PATH"
export STM32CUBE_G0_PATH=/path/to/STM32CubeG0
export MBEDTLS_PATH=/path/to/mbedtls
export ORBIT_APP_KEY='orbit_app_test_...'
cmake -S examples/embedded/stm32g0b1re/validation \
  -B build/stm32g0b1re/default \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/examples/embedded/stm32g0b1re/validation/arm-none-eabi-gcc.cmake" \
  -DSTM32CUBE_G0_PATH="$STM32CUBE_G0_PATH" -DMBEDTLS_PATH="$MBEDTLS_PATH" \
  -DORBIT_APP_KEY="$ORBIT_APP_KEY" -DORBIT_CLIENT_ARENA_BYTES=32768 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build/stm32g0b1re/default
cmake -S examples/embedded/stm32g0b1re/validation \
  -B build/stm32g0b1re/compact \
  -DCMAKE_TOOLCHAIN_FILE="$PWD/examples/embedded/stm32g0b1re/validation/arm-none-eabi-gcc.cmake" \
  -DSTM32CUBE_G0_PATH="$STM32CUBE_G0_PATH" -DMBEDTLS_PATH="$MBEDTLS_PATH" \
  -DORBIT_APP_KEY="$ORBIT_APP_KEY" -DORBIT_CLIENT_ARENA_BYTES=8192 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build/stm32g0b1re/compact
```

The validation `main` only forces the current adapter and crypto sources into
the link. It does not initialize the HAL or UART and is not a runnable firmware
test.

Use a dedicated trusted UART host bridge. The host provides HTTPS, time and
entropy, while the MCU verifies ES256 locally and persists authority in two
reserved flash pages. The port is for 512 KiB dual-bank flash with unchanged
bank mapping. It validates slot/firmware bounds; the board must reserve the pages
and configure readout/update/debug protection. The MCU has no built-in Wi-Fi;
standalone networking needs an external network module and a separately
integrated authenticated TLS transport.

The [STM32G0B1RE](https://www.st.com/en/microcontrollers-microprocessors/stm32g0b1re.html)
has a 64 MHz Cortex-M0+, 512 KiB flash and 144 KiB RAM. The
maintained link-only harness under
[`validation`](../../../examples/embedded/stm32g0b1re/validation) links CubeG0
1.6.3, Arm GNU 14.3.1 and Mbed TLS 3.6.6 with the parser and current Orbit
sources. Its flash load image ends at `0x08007254`, 29,268 bytes from the start
of the 508 KiB firmware region and 490,924 bytes before the reserved journal
region. The default profile uses 44,384 bytes of RAM including the harness's
512-byte heap and 1 KiB stack reservation, leaving 103,072 bytes. The 8 KiB
profile uses 19,808 bytes, leaving 127,648. The 136-byte `.data` includes the
56-byte RAM function code copied from its flash load image at startup. This
link-only entry point does not
initialize UART or establish runtime stack, heap or power-loss behaviour; those
checks still require board firmware and hardware.
