#ifndef ORBIT_APP_KEY_H
#define ORBIT_APP_KEY_H

#include "orbit_client.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_APP_KEY_MAX_LENGTH 512u
#define ORBIT_APP_KEY_ORIGIN_MAX_BYTES 384u

/* Parse the single public value copied from Orbit's Integration page.
 * origin_buffer is caller-owned and must remain alive with config; config's
 * origin/issuer slices borrow it and its application/environment IDs borrow
 * app_key. Surrounding Unicode whitespace is trimmed. On a non-aliasing
 * failure, config is zeroed and the origin buffer is cleared. Aliased ranges
 * are rejected without writing to either range. */
int32_t orbit_app_key_parse(orbit_embedded_slice_t app_key,
                            uint8_t *origin_buffer,
                            uint32_t origin_capacity,
                            orbit_client_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
