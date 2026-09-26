#ifndef ORBIT_EXAMPLE_CLIENT_H
#define ORBIT_EXAMPLE_CLIENT_H
#include "orbit_client.h"
#ifdef __cplusplus
extern "C" {
#endif
int32_t orbit_example_start(const orbit_client_services_t*);
int32_t orbit_example_activate(const uint8_t*,uint32_t);
int32_t orbit_example_check(void);
int32_t orbit_example_tick(void);
int32_t orbit_example_deactivate(void);
#ifdef __cplusplus
}
#endif
#endif
