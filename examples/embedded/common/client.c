#include "orbit_app_key.h"
#include "orbit_client.h"
#include <stddef.h>
#include <stdint.h>

/* Supply the public app key from the Orbit Integration page at build time, for
 * example with -DORBIT_APP_KEY=\"orbit_app_test_...\". It is configuration,
 * not a licence key or secret. */
#ifndef ORBIT_APP_KEY
#define ORBIT_APP_KEY ""
#endif

#define S(value) ((orbit_embedded_slice_t){(const uint8_t *)(value),          \
                                           (uint32_t)(sizeof(value) - 1u)})

static orbit_client_t client;
static uint8_t origin[ORBIT_APP_KEY_ORIGIN_MAX_BYTES];
static uint8_t arena[ORBIT_CLIENT_ARENA_BYTES];
static uint8_t scratch[ORBIT_GRANT_WORKSPACE_BYTES];
static orbit_client_config_t config;

int32_t orbit_example_start(const orbit_client_services_t *services) {
  const orbit_embedded_slice_t app_key = S(ORBIT_APP_KEY);
  int32_t result;
  if (services == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  result = orbit_app_key_parse(app_key, origin, sizeof(origin), &config);
  if (result != ORBIT_CLIENT_OK)
    return result;
  return orbit_client_init(&client, &config, services, arena, sizeof(arena),
                           scratch, sizeof(scratch));
}

/* Supply a key through the provisioning UI; do not persist it. Reuse the same
 * supplied key after an uncertain activation reply. */
int32_t orbit_example_activate(const uint8_t *key, uint32_t length) {
  return orbit_client_activate(&client, (orbit_embedded_slice_t){key, length});
}

int32_t orbit_example_check(void) {
  return orbit_client_require_access(&client, S("export"));
}

int32_t orbit_example_tick(void) { return orbit_client_tick(&client); }

int32_t orbit_example_deactivate(void) {
  return orbit_client_deactivate(&client);
}
