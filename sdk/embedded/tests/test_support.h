#ifndef ORBIT_TEST_SUPPORT_H
#define ORBIT_TEST_SUPPORT_H
#include "orbit_embedded.h"
#include <string.h>

static inline int32_t orbit_test_verify(const uint8_t *token, uint32_t token_length,
    const uint8_t *jwks, uint32_t jwks_length, const orbit_grant_expected_t *expected,
    const orbit_grant_crypto_t *crypto, uint8_t *arena, void *scratch,
    orbit_grant_claims_t *claims) {
    orbit_grant_pending_t pending;
    orbit_grant_keyset_t keys;
    int32_t status;
    memset(claims, 0, sizeof(*claims));
    if (token_length > ORBIT_GRANT_MAX_TOKEN_BYTES) return ORBIT_GRANT_STATUS_RESOURCE_LIMIT;
    memcpy(arena, token, token_length);
    status = orbit_jwks_import(jwks, jwks_length, crypto, &keys);
    if (status != 0) return status;
    status = orbit_grant_prepare(arena, token_length, crypto, &pending);
    if (status != 0) return status;
    return orbit_grant_verify(arena, token_length, &pending, &keys, expected, crypto,
        scratch, ORBIT_GRANT_WORKSPACE_BYTES, claims);
}
#endif
