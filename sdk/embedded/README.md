# Orbit for embedded devices

Activate a licence key once, then check access before each protected operation.
The C11 client owns no heap or threads. A `no_std` Rust wrapper provides the same
client with exclusive buffer and platform borrows.

## Choose your adapter

| Target | Network and crypto | Starting point |
| --- | --- | --- |
| ESP32 | ESP-IDF Wi-Fi / esp-tls / Mbed TLS | [ESP32 example](../../examples/embedded/esp32) |
| ESP8266 / NodeMCU | Arduino Wi-Fi / BearSSL | [NodeMCU example](../../examples/embedded/esp8266) |
| Pico W / Pico 2 W | Pico SDK Wi-Fi / lwIP / Mbed TLS | [Pico Wi-Fi example](../../examples/embedded/pico_wifi) |
| Linux / Pi Zero 2 W | libcurl HTTPS / OpenSSL 3 | [Linux example](../../examples/embedded/linux) |
| STM32G0B1RE | Trusted UART host bridge / local Mbed TLS verification | [STM32 example](../../examples/embedded/stm32g0b1re) |

The Wi-Fi examples and STM32 integration harness have passed cross-builds;
physical-board testing is still required. The Linux adapter and portable client
have host test coverage. See the [board requirements and build commands](docs/boards.md)
before integrating a port.

## Configure and activate

Choose your API origin, issuer, application ID and environment ID. Use the
matching board adapter to fill `orbit_client_services_t`, then initialize one
client with caller-owned storage:

```c
#include "orbit_client.h"

static orbit_client_t client;
static uint8_t arena[ORBIT_CLIENT_ARENA_BYTES];
static uint8_t scratch[ORBIT_GRANT_WORKSPACE_BYTES];

/* config and services come from your application's setup. */
int32_t start(const orbit_client_config_t *config,
              const orbit_client_services_t *services) {
    return orbit_client_init(&client, config, services,
                              arena, sizeof(arena), scratch, sizeof(scratch));
}
```

For a hardware-bound licence policy, also supply your stable fingerprint and
matching fingerprint provider in the client configuration.

Call `orbit_client_tick` from your loop. On first use it returns
`ORBIT_CLIENT_ACTIVATION_REQUIRED`; supply the user's key with
`orbit_client_activate`. The client persists the resulting revocable credential,
never the raw key. After a reboot, the first tick validates that credential
online before allowing access.

Call `orbit_client_require_access(&client, entitlement)` immediately before a
protected action. Only `ORBIT_CLIENT_OK` allows it. The helper refreshes when due;
signed offline access is available only after a qualifying transient failure
and only until the original grant expires. A snapshot is informational.

An uncertain activation returns a retryable error while preserving the pending
operation. Retry with the same supplied key. `ORBIT_CLIENT_PENDING` means the
pending mutation must be resolved first. Use `orbit_client_deactivate` to revoke
the installation, or `orbit_client_invalidate` for immediate durable local denial.
Treat storage errors as unavailable access; never erase storage automatically.

The [common example](../../examples/embedded/common/client.c) shows these calls.
The tiny client focuses on key activation. Customer registration and sign-in use
the [native HTTP API](../../examples/http/README.md).

## Rust

Add a path dependency on `sdk/embedded/rust` and implement its `Platform` trait
with your maintained platform libraries. Create `Buffers`, `Config` and
`Client`, then use `activate`, `tick` and `require_access`. The wrapper adds no
dependencies or allocator and prevents reuse of its platform or arena while the
client is alive. See [Rust setup](rust/README.md).

## Requirements and memory

Use authenticated HTTPS, a trusted UTC source, elapsed time including sleep, a
CSPRNG and exclusive durable storage. Configuration and callback contexts must
outlive the client. Calls are synchronous and serialized; callbacks cannot
reenter. Call `orbit_client_clock_lost` if sleep/resume makes elapsed time
uncertain. Keep credentials out of logs and protect their storage on the device.

The full client reserves **41,776 bytes** for state, transaction arena and parser
scratch. Measured portable Cortex-M0+ stack is conservatively **3,700 bytes**;
crypto, TLS, board libraries, runtime helpers and interrupts are additional.
The STM32G0B1RE's 144 KiB RAM can accommodate these portable buffers with room for
its bridge and crypto. The integration harness links successfully; measure actual
stack and heap after adding your board initialization and application.

The [memory and ABI reference](docs/memory.md) explains limits and verifier-only
use. The [security and storage reference](docs/security.md) covers lifecycle and
adapter contracts. [Validation commands](docs/validation.md) reproduce host and
freestanding checks.
