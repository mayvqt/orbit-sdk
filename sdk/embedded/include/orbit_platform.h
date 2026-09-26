#ifndef ORBIT_PLATFORM_H
#define ORBIT_PLATFORM_H
#include "orbit_adapters.h"
#include "orbit_http.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Platform objects and callback contexts remain at stable addresses for the
 * client's lifetime. Platform libraries may allocate; the Orbit core does not.
 */
typedef struct orbit_platform {
  orbit_tls_stream_t tls;
  orbit_journal_t journal;
  void *context;
  int32_t (*clock)(void *, int64_t *, uint64_t *);
  int32_t (*entropy)(void *, uint8_t *, uint32_t);
  orbit_grant_crypto_t crypto;
} orbit_platform_t;
int32_t orbit_platform_services(orbit_platform_t *, orbit_client_services_t *);
#ifdef __cplusplus
}
#endif
#endif
