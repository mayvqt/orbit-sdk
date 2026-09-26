#ifndef ORBIT_POSIX_H
#define ORBIT_POSIX_H
#include "orbit_adapters.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct orbit_posix {
  orbit_journal_t journal;
  int descriptor;
} orbit_posix_t;
/* directory_fd is an owned, private 0700 directory opened by the host. A 0600
 * regular no-follow journal is locked for the context's entire lifetime.
 * Uses system CA roots and trusted system UTC; requires CLOCK_BOOTTIME. */
int32_t orbit_posix_open(orbit_posix_t *context, int directory_fd,
                         orbit_client_services_t *services);
void orbit_posix_close(orbit_posix_t *context);
/* Network/time/entropy functions also serve the trusted physical host bridge.
 */
int32_t orbit_posix_exchange(void *, const orbit_http_request_t *, uint16_t *,
                             orbit_receive_fn, void *);
int32_t orbit_posix_clock(void *, int64_t *, uint64_t *);
int32_t orbit_posix_entropy(void *, uint8_t *, uint32_t);
#ifdef __cplusplus
}
#endif
#endif
