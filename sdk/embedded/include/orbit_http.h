#ifndef ORBIT_HTTP_H
#define ORBIT_HTTP_H
#include "orbit_client.h"
#ifdef __cplusplus
extern "C" {
#endif
/* A synchronous authenticated TLS connection. connect must verify the CA chain,
 * hostname and certificate dates using trusted UTC. All operations have finite
 * deadlines; read returns 1..capacity bytes or zero at orderly EOF. Only
 * genuine network unavailability/timeouts return TRANSIENT. One owner, no
 * reentry. */
typedef struct orbit_tls_stream {
  void *context;
  int32_t (*connect)(void *, const char *hostname, uint16_t port);
  int32_t (*write)(void *, const uint8_t *, uint32_t);
  int32_t (*read)(void *, uint8_t *, uint32_t, uint32_t *);
  void (*close)(void *);
} orbit_tls_stream_t;
int32_t orbit_http_exchange(void *stream, const orbit_http_request_t *request,
                            uint16_t *status, orbit_receive_fn receive,
                            void *receive_context);
#ifdef __cplusplus
}
#endif
#endif
