# Board setup

Set the public app-key build definition `ORBIT_APP_KEY` from the Orbit
Integration page. The [common example](../../../examples/embedded/common/client.c)
parses it into caller-owned origin storage before client initialization. Each
firmware provisions networking and trusted time, supplies a separate licence key
through its own UI, and gates actions with the access helper. The examples do
not embed or persist licence keys. Board hooks default to unavailable access
until configured.

## Footprint

The connected SDK builds for every target below in both the default and 8 KiB
arena profiles; the Rust wrapper builds for Cortex-M0+ and Cortex-M33. Linked
flash and static RAM figures for each example are in the
[memory reference](memory.md#linked-example-footprints).

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
terminal echo into that binary stream.

To cross-compile for a Pi, install an AArch64 Linux C compiler and a Debian
arm64 sysroot containing the target OpenSSL/libcurl development files, then
point pkg-config at the target files:

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

## ESP32

Requires ESP-IDF 5.5 or newer, its matching target GCC toolchain, Python
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
elapsed tracking and denies access after rollback. ESP8266 is the tightest RAM
target; budget the TLS handshake heap within the remaining static RAM.

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
the native example does not require one. The SRAM headroom in the footprint
table is gross static headroom; budget TLS heap and stack within it.

## STM32G0B1RE

Requires Arm GNU Embedded tools, STM32CubeG0 HAL/CMSIS, your Cube-generated
STM32G0B1RE firmware project with startup/linker configuration, and Mbed TLS
SHA-256/P-256/ECDSA support. Add the files listed in the
[STM32 integration example](../../../examples/embedded/stm32g0b1re/README.md), then
build the application with its Cube-generated CMake project:

```sh
cmake -S path/to/your-cube-project -B build/stm32g0b1re -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/absolute/path/to/your-cube-project/cmake/gcc-arm-none-eabi.cmake
cmake --build build/stm32g0b1re
arm-none-eabi-size build/stm32g0b1re/your-application.elf
```

Use a dedicated trusted UART host bridge. The host provides HTTPS, time and
entropy, while the MCU verifies ES256 locally and persists authority in two
reserved flash pages. The port is for 512 KiB dual-bank flash with unchanged
bank mapping. It validates slot/firmware bounds; the board must reserve the pages
and configure readout/update/debug protection. The MCU has no built-in Wi-Fi;
standalone networking needs an external network module and a separately
integrated authenticated TLS transport.

The [STM32G0B1RE](https://www.st.com/en/microcontrollers-microprocessors/stm32g0b1re.html)
has a 64 MHz Cortex-M0+, 512 KiB flash and 144 KiB RAM. Size your firmware's
runtime stack and heap on top of the
[linked footprint](memory.md#linked-example-footprints).

## Offline profile builds

Every supported target also builds with the explicit compact (4096-byte file,
8192-byte arena) and full (16384-byte file, 16384-byte arena) profiles. Their
sizes are in the [memory reference](memory.md#offline-profile-footprints); on
ESP8266, use the compact profile unless your complete firmware's runtime needs
fit the full profile.

Select a profile consistently in the library, adapter and application. CMake
builds use `-DORBIT_ENABLE_OFFLINE=ON`,
`-DORBIT_OFFLINE_PROFILE_FILE_BYTES=4096` (or `16384`) and
`-DORBIT_CLIENT_ARENA_BYTES=8192` (or `16384`). Trusted offline-purpose keys come
from `orbit_board_offline_keys`; its default denies initialization until supplied.
A valid file is checked locally against the app key, installation and UTC.

- **ESP32:** use `SDKCONFIG_DEFAULTS=.../sdkconfig.offline-compact` or
  `sdkconfig.offline-full`. These select explicit encrypted journal partitions of
  16 or 40 KiB through `partitions-offline-compact.csv` and
  `partitions-offline-full.csv`. Keep the matching file-profile build definition.
- **ESP8266:** `pio run -d examples/embedded/esp8266 -e offline_compact` or
  `-e offline_full` selects both the file bound and arena. LittleFS contains two
  8 or 20 KiB logical slot files and needs filesystem overhead in addition. An
  existing incompatible journal is rejected; it is never autoformatted.
- **Pico W/Pico 2 W:** pass the CMake flags above and choose `PICO_BOARD=pico_w`
  or `pico2_w`. The linker reserves 16 or 40 KiB at the end of the physical
  2 MiB/4 MiB flash and asserts that the firmware ends before it.
- **STM32G0B1RE:** pass the slot size into your linker script. Compact reserves
  the final 12 KiB (two 6 KiB slots); full reserves 36 KiB (two 18 KiB slots).
  Each slot stays within one bank and erases its own 2 KiB pages.
- **Linux/Pi AArch64:** pass the same CMake flags. One journal file contains two
  slots using 16 or 40 KiB in total. File locking and atomic journal semantics
  remain required.

Trusted UTC is required again after reboot. The host bridge is a trusted physical
transport for STM32 clock/entropy and HTTPS; it is not a replacement for an
untrusted network's end-to-end licensing verification. Download destination
streaming is application-owned, using the verified TLS/staging callback contract
in the [services guide](services.md).
