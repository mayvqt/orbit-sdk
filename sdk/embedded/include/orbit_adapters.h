#ifndef ORBIT_ADAPTERS_H
#define ORBIT_ADAPTERS_H
#include "orbit_client.h"
#include "orbit_storage.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Link exactly the crypto adapter provided by your platform. Mbed TLS/BearSSL
 * implementations use the platform library; the portable core implements no
 * cryptographic primitives. Library allocator/stack costs are additional. */
const orbit_grant_crypto_t *orbit_mbedtls_crypto(void);
const orbit_grant_crypto_t *orbit_bearssl_crypto(void);
const orbit_grant_crypto_t *orbit_openssl_crypto(void);

/* Trusted physical host link. The host performs authenticated HTTPS and
 * supplies trusted time/CSPRNG output; the MCU still checks every signed grant
 * locally. read/write must transfer exactly length bytes or fail, with a finite
 * timeout. No logs or other traffic may share this byte stream. Ports own
 * serialization. */
typedef struct orbit_bridge {
  void *io_context;
  int32_t (*read)(void *context, uint8_t *bytes, uint32_t length);
  int32_t (*write)(void *context, const uint8_t *bytes, uint32_t length);
  orbit_journal_t *journal;
  orbit_grant_crypto_t crypto;
  uint8_t host_boot_id[16], has_boot_id, broken;
} orbit_bridge_t;
int32_t orbit_bridge_services(orbit_bridge_t *bridge,
                              orbit_client_services_t *services);

#ifdef __cplusplus
}
#endif
#endif
