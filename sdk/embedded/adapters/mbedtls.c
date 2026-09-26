#include "orbit_adapters.h"
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER >= 0x04000000
#error                                                                         \
    "Use the platform's maintained PSA/P-256 adapter for Mbed TLS 4; this adapter targets 2.28/3.x."
#endif
static int point(mbedtls_ecp_group *group, mbedtls_ecp_point *q,
                 const uint8_t x[32], const uint8_t y[32]) {
  uint8_t encoded[65];
  unsigned i;
  encoded[0] = 4u;
  for (i = 0; i < 32u; ++i) {
    encoded[i + 1u] = x[i];
    encoded[i + 33u] = y[i];
  }
  return mbedtls_ecp_group_load(group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
         mbedtls_ecp_point_read_binary(group, q, encoded, sizeof(encoded)) ==
             0 &&
         mbedtls_ecp_check_pubkey(group, q) == 0;
}
static int32_t validate(void *context, const uint8_t x[32],
                        const uint8_t y[32]) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point q;
  int result;
  (void)context;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&q);
  result = point(&group, &q, x, y) ? 0 : -1;
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&group);
  return result;
}
static int32_t sha256(void *context, const uint8_t *bytes, uint32_t length,
                      uint8_t digest[32]) {
  (void)context;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  return mbedtls_sha256(bytes, length, digest, 0);
#else
  return mbedtls_sha256_ret(bytes, length, digest, 0);
#endif
}
static int32_t verify(void *context, const uint8_t x[32], const uint8_t y[32],
                      const uint8_t digest[32], const uint8_t signature[64]) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point q;
  mbedtls_mpi r, s;
  int result = -1;
  (void)context;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  if (point(&group, &q, x, y) &&
      mbedtls_mpi_read_binary(&r, signature, 32u) == 0 &&
      mbedtls_mpi_read_binary(&s, signature + 32u, 32u) == 0)
    result = mbedtls_ecdsa_verify(&group, digest, 32u, &q, &r, &s);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&group);
  return result;
}
const orbit_grant_crypto_t *orbit_mbedtls_crypto(void) {
  static const orbit_grant_crypto_t crypto = {0, validate, sha256, verify};
  return &crypto;
}
