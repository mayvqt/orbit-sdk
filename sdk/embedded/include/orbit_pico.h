#ifndef ORBIT_PICO_H
#define ORBIT_PICO_H
#include "lwip/altcp_tls.h"
#include "lwip/ip_addr.h"
#include "orbit_platform.h"
#include <time.h>
typedef struct orbit_pico {
  orbit_platform_t platform;
  struct altcp_tls_config *tls_config;
  struct altcp_pcb *pcb;
  struct pbuf *received;
  ip_addr_t address;
  uint64_t deadline;
  uint32_t flash_offset;
  uint16_t received_offset;
  uint8_t connected, closed, failed, dns_pending, dns_ready;
} orbit_pico_t;
/* One static-lifetime context with pico_cyw43_arch_lwip_poll, Wi-Fi connected.
 * journal_offset reserves two 4096-byte sectors beyond __flash_binary_end.
 * The board supplies trusted UTC and CSPRNG callbacks; the latter also seeds
 * Mbed TLS. Link pico_mbedtls_{crypto,x509,tls} component libraries rather than
 * pico_mbedtls (whose default entropy hook is replaced by this port).
 * Reset/reinitialize after sleep that makes elapsed time uncertain. */
int32_t orbit_pico_open(orbit_pico_t *, const uint8_t *ca_pem,
                        uint32_t ca_length, uint32_t journal_offset,
                        void *board_context,
                        int32_t (*clock)(void *, int64_t *, uint64_t *),
                        int32_t (*entropy)(void *, uint8_t *, uint32_t),
                        orbit_client_services_t *);
time_t orbit_pico_tls_time(time_t *);
#endif
