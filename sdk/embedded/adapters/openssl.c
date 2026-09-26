#include "orbit_adapters.h"

#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdint.h>
#include <stdlib.h>

static EVP_PKEY *make_key(const uint8_t x[32], const uint8_t y[32]) {
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY_CTX *check = NULL;
  EVP_PKEY *key = NULL;
  uint8_t point[65];
  char group[] = "prime256v1";
  OSSL_PARAM parameters[3];
  point[0] = 0x04;
  for (uint32_t i = 0; i < 32u; ++i) {
    point[1u + i] = x[i];
    point[33u + i] = y[i];
  }
  context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (context == NULL || EVP_PKEY_fromdata_init(context) <= 0)
    goto done;
  parameters[0] =
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
  parameters[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                    point, sizeof(point));
  parameters[2] = OSSL_PARAM_construct_end();
  if (EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, parameters) <= 0 ||
      key == NULL)
    goto done;
  check = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if (check == NULL || EVP_PKEY_public_check(check) <= 0) {
    EVP_PKEY_free(key);
    key = NULL;
  }
done:
  EVP_PKEY_CTX_free(check);
  EVP_PKEY_CTX_free(context);
  return key;
}

static int32_t validate_point(void *context, const uint8_t x[32],
                              const uint8_t y[32]) {
  EVP_PKEY *key;
  (void)context;
  key = make_key(x, y);
  if (key == NULL)
    return -1;
  EVP_PKEY_free(key);
  return 0;
}

static int32_t verify_signature(void *context, const uint8_t x[32],
                                const uint8_t y[32], const uint8_t message[32],
                                const uint8_t signature[64]) {
  EVP_PKEY *key = NULL;
  EVP_PKEY_CTX *digest = NULL;
  ECDSA_SIG *ecdsa = NULL;
  BIGNUM *r = NULL, *s = NULL;
  uint8_t der[80];
  unsigned char *der_output = der;
  int der_length, result = -1;
  (void)context;
  key = make_key(x, y);
  if (key == NULL)
    goto done;
  ecdsa = ECDSA_SIG_new();
  r = BN_bin2bn(signature, 32, NULL);
  s = BN_bin2bn(signature + 32, 32, NULL);
  if (ecdsa == NULL || r == NULL || s == NULL)
    goto done;
  if (ECDSA_SIG_set0(ecdsa, r, s) != 1)
    goto done;
  r = NULL;
  s = NULL;
  der_length = i2d_ECDSA_SIG(ecdsa, NULL);
  if (der_length <= 0 || der_length > (int)sizeof(der))
    goto done;
  if (i2d_ECDSA_SIG(ecdsa, &der_output) != der_length)
    goto done;
  digest = EVP_PKEY_CTX_new(key, NULL);
  if (digest == NULL || EVP_PKEY_verify_init(digest) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(digest, EVP_sha256()) <= 0)
    goto done;
  result = EVP_PKEY_verify(digest, der, (size_t)der_length, message, 32u) == 1
               ? 0
               : -1;
done:
  BN_free(r);
  BN_free(s);
  ECDSA_SIG_free(ecdsa);
  EVP_PKEY_CTX_free(digest);
  EVP_PKEY_free(key);
  return result;
}

static int32_t hash_sha256(void *context, const uint8_t *bytes, uint32_t length,
                           uint8_t digest[32]) {
  unsigned int output_length = 0u;
  (void)context;
  return EVP_Digest(bytes, length, digest, &output_length, EVP_sha256(),
                    NULL) == 1 &&
                 output_length == 32u
             ? 0
             : -1;
}

const orbit_grant_crypto_t *orbit_openssl_crypto(void) {
  static const orbit_grant_crypto_t crypto = {NULL, validate_point, hash_sha256,
                                              verify_signature};
  return &crypto;
}
