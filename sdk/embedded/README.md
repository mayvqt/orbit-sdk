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

Toolchains, build commands and storage reservations for each target are in the
[board guide](docs/boards.md).

## Configure and activate

Copy the public app key from the Orbit Integration page into your build as
`ORBIT_APP_KEY`. The heapless parser validates its HTTPS origin and scope, then
returns config slices borrowing the caller-owned origin buffer and app-key text.
The common examples parse this value before initializing the client:

```c
#include "orbit_client.h"
#include "orbit_app_key.h"
#include <string.h>

static orbit_client_t client;
static uint8_t decoded_origin[ORBIT_APP_KEY_ORIGIN_MAX_BYTES];
static orbit_client_config_t config;
static uint8_t arena[ORBIT_CLIENT_ARENA_BYTES];
static uint8_t scratch[ORBIT_GRANT_WORKSPACE_BYTES];

int32_t start(const char *app_key,
              const orbit_client_services_t *services) {
    orbit_embedded_slice_t key = {
        (const uint8_t *)app_key, (uint32_t)strlen(app_key)
    };
    int32_t result = orbit_app_key_parse(key, decoded_origin,
                                         sizeof(decoded_origin), &config);
    if (result != ORBIT_CLIENT_OK) return result;
    return orbit_client_init(&client, &config, services,
                              arena, sizeof(arena), scratch, sizeof(scratch));
}
```

Keep the origin buffer and app-key text alive as long as the client. For a
hardware-bound policy, add its stable fingerprint and provider to parsed config
before initialization. An unbound policy can still send an optional pair; the
signed grant remains strictly unbound and the reply provider must match it.

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

## Optional licensed services

Enable `ORBIT_ENABLE_SERVICES` and initialize with one caller-owned extension for
floating sessions, typed usage/resource APIs, update discovery and verified
streaming downloads. Enable `ORBIT_ENABLE_OFFLINE` separately for trusted
long-term licence files with a 4096- or 16384-byte profile. The
[services guide](docs/services.md) shows setup, retries, cancellation, file
import and port callback requirements.

## Rust

Add a path dependency on `sdk/embedded` and implement its `Platform` trait
with your maintained platform libraries. Parse one key into `AppKey`, then
create `Buffers::<32768>` (or `Buffers::<8192>`), `Config` and `Client`, then
use `activate`, `tick` and `require_access`. The wrapper adds no
dependencies or allocator and prevents reuse of its platform or arena while the
client is alive. See [Rust setup](rust/README.md).

## Requirements and memory

Use authenticated HTTPS, a trusted UTC source, elapsed time including sleep, a
CSPRNG and exclusive durable storage. Configuration and callback contexts must
outlive the client. Calls are synchronous and serialized; the services guide
documents the one local end-session call allowed during a transport callback.
Call `orbit_client_clock_lost` if sleep/resume makes elapsed time uncertain.
Keep credentials out of logs and protect their storage on the device.

The default client reserves **41,776 bytes** for state, a 32 KiB transaction
arena and parser scratch. Set `ORBIT_CLIENT_ARENA_BYTES=8192` for a
**17,200-byte** compact caller buffer, or choose a runtime C arena from 8 to
32 KiB. A compact arena rejects any request or response that does not fit.
Crypto, TLS, board libraries and stack are additional. The
[memory and ABI reference](docs/memory.md) covers stack, optional-profile
buffers, storage geometry and per-board footprints. The
[security and storage reference](docs/security.md) covers lifecycle and adapter
contracts.
