# STM32G0B1RE

Add `orbit_board.c`, `../common/client.c`, the eight C files in
`sdk/embedded/src`, and `adapters/{bridge,stm32g0,mbedtls}.c` to your STM32Cube
application. Include `sdk/embedded/include` and `../common`. Enable the HAL UART
and flash drivers and a maintained Mbed TLS build with SHA-256, P-256 and ECDSA.

Reserve `0x0807f000..0x0807ffff` in the linker script, reduce firmware flash to
508 KiB, and keep flash bank mapping unchanged. The adapter validates the supplied
firmware end and uses two independent 2 KiB pages. Enable your product's flash
readout protection; persistent credentials must not be exposed through debug or
firmware update interfaces.

Connect a dedicated UART to a trusted Linux host. Configure the same baud rate,
raw mode and no terminal echo on both sides. Run `orbit_bridge_host` with your
HTTPS origin on that stream. The host performs TLS validation, supplies trusted
UTC/elapsed time and CSPRNG bytes; the STM32 verifies ES256 grants locally. A
host reboot invalidates the link's elapsed-time anchor and requires MCU client
reinitialization and online validation.

Build with `ORBIT_APP_KEY` set to the public key from the Orbit Integration page.
The common example parses that one value into its static decoded-origin buffer
before `orbit_client_init`. Call `orbit_board_start(&huart, firmware_flash_end)`
after HAL initialization.
Provision a key once with `orbit_example_activate`; call `orbit_example_tick`
from your loop and `orbit_example_check` before each protected action.

This port targets the STM32G0B1RE's 512 KiB flash and 144 KiB RAM; the MCU has
no built-in Wi-Fi, so the host bridge supplies networking. Add your Cube
application's board and UART initialization, and size its runtime stack and heap
on top of the [linked footprint](../../../sdk/embedded/docs/memory.md#linked-example-footprints).
