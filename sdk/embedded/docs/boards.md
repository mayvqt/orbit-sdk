# Board setup and build checks

Set your API origin, issuer, application and environment in the
[common example](../../../examples/embedded/common/client.c). Each firmware
provisions networking and trusted time before starting Orbit, supplies a licence
key through its own provisioning UI, and gates actions with the access helper.
The example board hooks default to unavailable access until configured.

## Linux and Pi Zero 2 W

Requires CMake, a C11 compiler, libcurl with HTTPS support, OpenSSL 3 development
headers/libraries, and trusted system UTC/CA roots. The adapter uses Linux
`getrandom`, `CLOCK_BOOTTIME`, file locking and fsync. Run from the SDK root:

```sh
cmake -S examples/embedded/linux -B build/orbit-pi -DCMAKE_BUILD_TYPE=Release
cmake --build build/orbit-pi
mkdir -m 700 "$HOME/.orbit-device"
build/orbit-pi/orbit_pi "$HOME/.orbit-device"
```

The example reads a key from its private terminal when needed; it never writes
the key to disk. Provisioning UIs should hide input. The same build creates
`orbit/orbit_bridge_host`, which can serve a trusted raw USB/UART stream for an
MCU. Pass the one allowed HTTPS origin as its argument. Do not mix log output or
terminal echo into that binary stream. Linux x86-64 builds/tests pass; no Pi
hardware or ARM Linux runtime check has been performed yet.

## ESP32

Requires the maintained ESP-IDF SDK, its matching target GCC toolchain, Python
environment and CMake/Ninja. Use `examples/embedded/esp32` as the IDF project:

```sh
idf.py -C examples/embedded/esp32 set-target esp32
idf.py -C examples/embedded/esp32 build
```

Implement `orbit_board_ready` after Wi-Fi and trusted UTC setup, and
`orbit_board_root_ca` with the real CA PEM. The dedicated `orbit` data partition
reserves two 4 KiB sectors; its encrypted flag supports ESP flash encryption when
enabled in the product's security configuration. Configure secure boot, readout
and update/debug controls for deployment. The port uses esp-tls and Mbed TLS,
requires Wi-Fi entropy to be active, and performs no automatic storage erasure.
Deep sleep resumes through client initialization and online validation.

The IDF SDK/toolchain is not installed in the current validation environment;
this board build and hardware run remain outstanding.

## ESP8266 / NodeMCU

Requires PlatformIO Core with the `espressif8266` platform, ESP8266 Arduino core
and its matching Xtensa toolchain. The example includes the portable C sources,
BearSSL adapter, LittleFS journal and native Wi-Fi stream:

```sh
pio run --project-dir examples/embedded/esp8266 --environment nodemcuv2
```

Implement the example's Wi-Fi/trusted-time readiness and CA-root hooks. Mount
LittleFS without automatic formatting. Keep default BearSSL receive capacity
unless the server actually negotiates smaller TLS fragments; reducing a buffer
locally is not negotiation. The port uses trusted wall time for conservative
elapsed tracking and denies access after rollback. Measure free heap during TLS
handshake as well as Orbit's static buffers; ESP8266 is the tightest RAM target.

PlatformIO, the ESP8266 core/toolchain and hardware are unavailable in the current
validation environment. This target has not been built or run yet.

## Pico W and Pico 2 W: native Wi-Fi

Requires Arm GNU Embedded tools (`arm-none-eabi-gcc`, `ar`, `objcopy`), CMake,
Ninja or Make, Python, and a Pico SDK checkout containing cyw43, lwIP and Mbed TLS
submodules. Both targets use the Cortex-M build:

```sh
cmake -S examples/embedded/pico_wifi -B build/pico-w -DPICO_BOARD=pico_w
cmake --build build/pico-w
cmake -S examples/embedded/pico_wifi -B build/pico2-w -DPICO_BOARD=pico2_w
cmake --build build/pico2-w
```

Set `PICO_SDK_PATH` to that installed SDK first. Implement the Wi-Fi, CA, trusted
clock and CSPRNG hooks in `main.c`. The native port uses the polling cyw43/lwIP
architecture with required certificate verification and certificate date checks.
It links the SDK's Mbed TLS component libraries and supplies the entropy callback
from your trusted source; it does not use an insecure TLS mode or treat weak
oscillator output as a sufficient CSPRNG seed. The same source builds for both
boards. [Pico SDK networking documentation](https://www.raspberrypi.com/documentation/pico-sdk/networking.html)
describes the underlying libraries.

Reserve the final two 4 KiB flash sectors for the journal in the product's linker
layout. The adapter also rejects overlap with `__flash_binary_end`. The context
has static lifetime, including outstanding DNS callbacks. Use `pico_flash` safe
execution for other-core/interrupt coordination. Reinitialize after uncertain
sleep elapsed time. A trusted host bridge is an optional alternative transport;
the native example does not require one.

The Pico SDK, Arm GCC tools and hardware are unavailable in the current validation
environment. Native Wi-Fi builds and hardware tests remain outstanding.

## STM32G0B1RE

Requires Arm GNU Embedded tools, STM32CubeG0 HAL/CMSIS, your Cube-generated
STM32G0B1RE firmware project with startup/linker configuration, and maintained
Mbed TLS SHA-256/P-256/ECDSA support. Add the files listed in the
[STM32 integration example](../../../examples/embedded/stm32g0b1re/README.md), then
build the application with its Cube-generated CMake project:

```sh
cmake -S path/to/your-cube-project -B build/stm32g0b1re -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=path/to/your-cube-project/cmake/gcc-arm-none-eabi.cmake
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
has a 64 MHz Cortex-M0+, 512 KiB flash and 144 KiB RAM. Portable M0+ compilation
passes; CubeG0 integration, a final firmware link and hardware tests remain
outstanding because that SDK/toolchain and board are unavailable here.
