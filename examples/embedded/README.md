# Embedded examples

Choose [Linux/Pi](linux), [ESP32](esp32), [ESP8266/NodeMCU](esp8266),
[Pico W/Pico 2 W Wi-Fi](pico_wifi), or [STM32G0B1RE host bridge](stm32g0b1re).
Set the four scope values in [common/client.c](common/client.c), configure the
board's network/CA/trusted-time/storage prerequisites, then initialize the
adapter and common client. Provision a key through `orbit_example_activate` once,
call `orbit_example_tick` from the loop and require `orbit_example_check()==0`
before the protected action.

The [SDK guide](../../sdk/embedded/README.md) explains the lifecycle. Exact build
prerequisites, commands and current validation limits are in the
[board guide](../../sdk/embedded/docs/boards.md). Firmware hook defaults deny
access until the application supplies real provisioning and trust inputs.
