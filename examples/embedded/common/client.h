#ifndef ORBIT_EXAMPLE_CLIENT_H
#define ORBIT_EXAMPLE_CLIENT_H
#include "orbit_client.h"
#ifdef __cplusplus
extern "C" {
#endif
int32_t orbit_example_start(const orbit_client_services_t *);
int32_t orbit_example_activate(const uint8_t *, uint32_t);
int32_t orbit_example_check(void);
int32_t orbit_example_tick(void);
int32_t orbit_example_deactivate(void);
#ifdef ORBIT_ENABLE_SERVICES
int32_t orbit_example_idle(void);
int32_t orbit_example_resume(void);
#endif
#ifdef ORBIT_ENABLE_OFFLINE
const orbit_grant_keyset_t *orbit_board_offline_keys(void);
int32_t orbit_example_import_file(const uint8_t *, uint32_t);
#endif
#ifdef __cplusplus
}
#endif
#endif
