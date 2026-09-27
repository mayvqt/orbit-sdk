# Embedded examples

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

Each supported target has a cross-link check. Physical-board operation is not
covered by those checks; validate your firmware on its target hardware.

Enable services in the firmware build to use `orbit_example_idle` and
`orbit_example_resume` around idle periods. Continue polling `orbit_example_tick`
while active. Ordinary licences treat these session calls as no-ops.

Offline profiles add a combined file/metadata buffer and an explicitly reserved
journal. Provide `orbit_board_offline_keys()` through your trusted firmware
configuration; its default returns no keys and initialization fails closed.
Import a signed file through `orbit_example_import_file`. See the
[services guide](../../sdk/embedded/docs/services.md) for the bounded reader,
usage/resources and application-owned verified download callbacks, and the
[board profile table](../../sdk/embedded/docs/boards.md#offline-profile-builds)
for exact flash reservations. Full-profile ESP8266 static RAM leaves little room
for runtime TLS and must be measured on the actual firmware.
