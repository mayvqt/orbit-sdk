#include "openssl_adapter.h"
#include "orbit_adapters.h"
static int fail_validate, fail_verify;
static uint32_t validate_calls;
static int32_t validate(void *ctx, const uint8_t x[32], const uint8_t y[32]) {
  const orbit_grant_crypto_t *c = orbit_openssl_crypto();
  (void)ctx;
  ++validate_calls;
  return fail_validate ? -1 : c->validate_p256(c->context, x, y);
}
static int32_t hash(void *ctx, const uint8_t *p, uint32_t n,
                    uint8_t digest[32]) {
  const orbit_grant_crypto_t *c = orbit_openssl_crypto();
  (void)ctx;
  return c->sha256(c->context, p, n, digest);
}
static int32_t verify(void *ctx, const uint8_t x[32], const uint8_t y[32],
                      const uint8_t digest[32], const uint8_t signature[64]) {
  const orbit_grant_crypto_t *c = orbit_openssl_crypto();
  (void)ctx;
  return fail_verify ? -1
                     : c->verify_es256(c->context, x, y, digest, signature);
}
const orbit_grant_crypto_t *orbit_test_openssl_crypto(void) {
  static const orbit_grant_crypto_t c = {0, validate, hash, verify};
  return &c;
}
void orbit_test_openssl_fail_validate(int enabled) { fail_validate = enabled; }
void orbit_test_openssl_fail_verify(int enabled) { fail_verify = enabled; }
uint32_t orbit_test_openssl_validate_calls(void) { return validate_calls; }
