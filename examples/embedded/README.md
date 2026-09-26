# Embedded examples

These examples use the unreleased local `0.4.0` candidate checkout; no tag or
firmware package is implied. This candidate has not been run on physical boards.

Choose [Linux/Pi](linux), [ESP32](esp32), [ESP8266/NodeMCU](esp8266),
[Pico W/Pico 2 W Wi-Fi](pico_wifi), or [STM32G0B1RE host bridge](stm32g0b1re).
Set one public `ORBIT_APP_KEY` build definition from the Orbit Integration page.
The common client parses it into caller-owned origin storage before initializing
the adapter-backed client. Configure the board's network, CA, trusted time and
storage, then provision the user's licence key through `orbit_example_activate`.
Call `orbit_example_tick` from the loop and require `orbit_example_check()==0`
before a protected action. The app key is public configuration; the licence key
is provided at runtime and is not saved by the example.

The [SDK guide](../../sdk/embedded/README.md) explains the lifecycle. Exact build
prerequisites, commands and current validation limits are in the
[board guide](../../sdk/embedded/docs/boards.md). Firmware hook defaults deny
access until the application supplies real provisioning and trust inputs.
