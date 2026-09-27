#include "orbit_app_key.h"
#include "orbit_client.h"
#include <stddef.h>
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_downloads.h"
#include "orbit_extensions.h"
static orbit_client_extension_t extension;
#endif
#ifdef ORBIT_ENABLE_OFFLINE
static uint8_t offline_transaction[ORBIT_OFFLINE_BUFFER_BYTES(
    ORBIT_OFFLINE_PROFILE_FILE_BYTES)];
/* Supply trusted offline-purpose public keys through the firmware trust path.
 */
__attribute__((weak)) const orbit_grant_keyset_t *
orbit_board_offline_keys(void) {
  return NULL;
}
#endif
#include <stdint.h>

/* Supply the public app key from the Orbit Integration page at build time, for
 * example with -DORBIT_APP_KEY=\"orbit_app_test_...\". It is configuration,
 * not a licence key or secret. */
#ifndef ORBIT_APP_KEY
#define ORBIT_APP_KEY ""
#endif

#define S(value)                                                               \
  ((orbit_embedded_slice_t){(const uint8_t *)(value),                          \
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
#ifdef ORBIT_ENABLE_SERVICES
#ifdef ORBIT_ENABLE_OFFLINE
  orbit_offline_config_t offline = {
      orbit_board_offline_keys(), offline_transaction,
      sizeof(offline_transaction), ORBIT_OFFLINE_PROFILE_FILE_BYTES, app_key};
  return orbit_client_init_extended(&client, &config, services, &extension,
                                    arena, sizeof(arena), scratch,
                                    sizeof(scratch), &offline);
#else
  return orbit_client_init_extended(&client, &config, services, &extension,
                                    arena, sizeof(arena), scratch,
                                    sizeof(scratch), NULL);
#endif
#else
  return orbit_client_init(&client, &config, services, arena, sizeof(arena),
                           scratch, sizeof(scratch));
#endif
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

#ifdef ORBIT_ENABLE_OFFLINE
int32_t orbit_example_import_file(const uint8_t *file, uint32_t length) {
  return orbit_client_import_offline_file(
      &client, (orbit_embedded_slice_t){file, length});
}
#endif
#ifdef ORBIT_ENABLE_SERVICES
int32_t orbit_example_idle(void) {
  return orbit_client_end_session(&client, NULL);
}
int32_t orbit_example_resume(void) {
  orbit_session_snapshot_t seat;
  return orbit_client_start_session(&client, NULL, &seat);
}
#endif
