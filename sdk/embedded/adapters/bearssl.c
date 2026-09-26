#include "orbit_adapters.h"
#include <bearssl/bearssl.h>

static void encoded_point(uint8_t q[65], const uint8_t x[32],
                          const uint8_t y[32]) {
  unsigned i;
  q[0] = 4u;
  for (i = 0; i < 32u; ++i) {
    q[i + 1u] = x[i];
    q[i + 33u] = y[i];
  }
}
static int32_t validate(void *context, const uint8_t x[32],
                        const uint8_t y[32]) {
  const br_ec_impl *ec = br_ec_get_default();
  uint8_t q[65], one = 1u;
  (void)context;
  if (!ec || !(ec->supported_curves & ((uint32_t)1u << BR_EC_secp256r1)))
    return -1;
  encoded_point(q, x, y);
  return ec->mul(q, sizeof(q), &one, 1u, BR_EC_secp256r1) == 1u ? 0 : -1;
}
static int32_t sha256(void *context, const uint8_t *bytes, uint32_t length,
                      uint8_t digest[32]) {
  br_sha256_context hash;
  (void)context;
  br_sha256_init(&hash);
  br_sha256_update(&hash, bytes, length);
  br_sha256_out(&hash, digest);
  return 0;
}
static int32_t verify(void *context, const uint8_t x[32], const uint8_t y[32],
                      const uint8_t digest[32], const uint8_t signature[64]) {
  uint8_t q[65];
  br_ec_public_key key;
  const br_ec_impl *ec = br_ec_get_default();
  (void)context;
  encoded_point(q, x, y);
  key.curve = BR_EC_secp256r1;
  key.q = q;
  key.qlen = sizeof(q);
  return br_ecdsa_vrfy_raw_get_default()(ec, digest, 32u, &key, signature,
                                         64u) == 1u
             ? 0
             : -1;
}
const orbit_grant_crypto_t *orbit_bearssl_crypto(void) {
  static const orbit_grant_crypto_t crypto = {0, validate, sha256, verify};
  return &crypto;
}
