#include "orbit_client.h"
#include <stdint.h>
/* Set these build definitions to the values from your Orbit application. */
#ifndef ORBIT_API_ORIGIN
#define ORBIT_API_ORIGIN "https://licensing.example.com"
#endif
#ifndef ORBIT_ISSUER
#define ORBIT_ISSUER ORBIT_API_ORIGIN
#endif
#ifndef ORBIT_APPLICATION_ID
#define ORBIT_APPLICATION_ID "your-application-id"
#endif
#ifndef ORBIT_ENVIRONMENT_ID
#define ORBIT_ENVIRONMENT_ID "your-environment-id"
#endif
#define S(s) {(const uint8_t*)(s),sizeof(s)-1}
static orbit_client_t client;
static uint8_t arena[ORBIT_CLIENT_ARENA_BYTES],scratch[ORBIT_GRANT_WORKSPACE_BYTES];
static const orbit_client_config_t config={S(ORBIT_API_ORIGIN),S(ORBIT_ISSUER),S(ORBIT_APPLICATION_ID),S(ORBIT_ENVIRONMENT_ID),{0,0},{0,0}};
int32_t orbit_example_start(const orbit_client_services_t*services){return orbit_client_init(&client,&config,services,arena,sizeof(arena),scratch,sizeof(scratch));}
/* Supply a key once through your provisioning UI; do not put it in firmware or
 * persist it. Reuse the same supplied key after an uncertain activation reply. */
int32_t orbit_example_activate(const uint8_t*key,uint32_t length){return orbit_client_activate(&client,(orbit_embedded_slice_t){key,length});}
int32_t orbit_example_check(void){return orbit_client_require_access(&client,(orbit_embedded_slice_t)S("export"));}
int32_t orbit_example_tick(void){return orbit_client_tick(&client);}
int32_t orbit_example_deactivate(void){return orbit_client_deactivate(&client);}
