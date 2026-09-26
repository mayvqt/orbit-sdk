#include "orbit_embedded.h"
#include "openssl_adapter.h"
#include "orbit_generated_vectors.h"
#include "test_support.h"
#include <stdio.h>
#include <string.h>

static uint8_t workspace[ORBIT_GRANT_WORKSPACE_BYTES], arena[ORBIT_GRANT_MAX_TOKEN_BYTES];
static orbit_grant_claims_t claims;
static orbit_grant_keyset_t keys;
static orbit_grant_pending_t pending;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "core:%d: %s\n", __LINE__, #x); return 1; } } while (0)
static int zero(const void *p, size_t n) {
    const uint8_t *b = p;
    while (n--) if (*b++) return 0;
    return 1;
}
static const generated_grant_vector_t *valid(void) {
    uint32_t i;
    for (i = 0; i < GENERATED_GRANT_VECTOR_COUNT; ++i)
        if (generated_grant_vectors[i].expected_valid) return &generated_grant_vectors[i];
    return NULL;
}
static int32_t prepare(const generated_grant_vector_t *v, const orbit_grant_crypto_t *crypto) {
    memcpy(arena, v->token, v->token_length);
    return orbit_grant_prepare(arena, v->token_length, crypto, &pending);
}
static int32_t verify(const generated_grant_vector_t *v, const orbit_grant_expected_t *e,
    const orbit_grant_crypto_t *crypto) {
    return orbit_grant_verify(arena, v->token_length, &pending, &keys, e, crypto,
        workspace, sizeof(workspace), &claims);
}
static int32_t fail_hash(void *c, const uint8_t *p, uint32_t n, uint8_t out[32]) {
    (void)c; (void)p; (void)n; (void)out; return -1;
}
int main(void) {
    const generated_grant_vector_t *v = valid();
    const orbit_grant_crypto_t *crypto = orbit_test_openssl_crypto();
    orbit_grant_crypto_t broken = *crypto;
    orbit_grant_expected_t expected;
    uint32_t i;
    orbit_jwks_importer_t importer;
    CHECK(v != NULL);
    CHECK(orbit_jwks_import(v->jwks, v->jwks_length, crypto, &keys) == 0);
    CHECK(prepare(v, crypto) == 0 && verify(v, &v->expected, crypto) == 0);
    CHECK(claims.arena_length == pending.payload_length);
    for (i = 0; i <= v->jwks_length; ++i) {
        CHECK(orbit_jwks_begin(&importer, &keys) == 0);
        CHECK(orbit_jwks_feed(&importer, &keys, crypto, v->jwks, i) == 0);
        CHECK(keys.count == 0);
        CHECK(orbit_jwks_feed(&importer, &keys, crypto, v->jwks + i, v->jwks_length - i) == 0);
        CHECK(orbit_jwks_finish(&importer, &keys) == 0);
    }
    CHECK(orbit_jwks_begin(&importer, &keys) == 0);
    for (i = 0; i < v->jwks_length; ++i)
        CHECK(orbit_jwks_feed(&importer, &keys, crypto, v->jwks + i, 1u) == 0);
    CHECK(orbit_jwks_finish(&importer, &keys) == 0);
    CHECK(prepare(v, crypto) == 0);
    expected = v->expected;
    expected.current_unix_seconds += 86401;
    CHECK(verify(v, &expected, crypto) != 0 && zero(&claims, sizeof(claims)));
    CHECK(prepare(v, crypto) == 0);
    orbit_test_openssl_fail_verify(1);
    CHECK(verify(v, &v->expected, crypto) == ORBIT_GRANT_STATUS_CRYPTO_FAILURE);
    CHECK(zero(&claims, sizeof(claims)));
    orbit_test_openssl_fail_verify(0);
    broken.sha256 = fail_hash;
    CHECK(prepare(v, &broken) == ORBIT_GRANT_STATUS_CRYPTO_FAILURE && zero(&pending, sizeof(pending)));
    CHECK(orbit_grant_prepare(arena, sizeof(arena) + 1u, crypto, &pending) == ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    CHECK(orbit_grant_prepare(arena, 16u, crypto, (orbit_grant_pending_t *)arena) == ORBIT_GRANT_STATUS_INVALID_ARGUMENT);
    CHECK(prepare(v, crypto) == 0);
    CHECK(orbit_grant_verify(arena, v->token_length, &pending, &keys, &v->expected, crypto,
        workspace, sizeof(workspace) - 1u, &claims) == ORBIT_GRANT_STATUS_INVALID_ARGUMENT);
    CHECK(orbit_grant_verify(arena, v->token_length, &pending, &keys, &v->expected, crypto,
        arena, sizeof(workspace), &claims) == ORBIT_GRANT_STATUS_INVALID_ARGUMENT);
    pending.signature[0] ^= 1u;
    CHECK(verify(v, &v->expected, crypto) == ORBIT_GRANT_STATUS_CRYPTO_FAILURE);
    CHECK(prepare(v, crypto) == 0);
    arena[0] ^= 1u;
    CHECK(verify(v, &v->expected, crypto) == ORBIT_GRANT_STATUS_INVALID_GRANT && zero(&claims, sizeof(claims)));
    CHECK(orbit_jwks_begin(&importer, &keys) == 0);
    CHECK(orbit_jwks_feed(&importer, &keys, crypto, v->jwks, v->jwks_length - 1u) == 0);
    CHECK(orbit_jwks_finish(&importer, &keys) != 0 && zero(&keys, sizeof(keys)));
    orbit_test_openssl_fail_validate(1);
    CHECK(orbit_jwks_import(v->jwks, v->jwks_length, crypto, &keys) == ORBIT_GRANT_STATUS_CRYPTO_FAILURE);
    CHECK(zero(&keys, sizeof(keys)));
    orbit_test_openssl_fail_validate(0);
    printf("bounds, ownership, digest, import chunk boundaries, and expiry passed; claims=%zu keys=%zu pending=%zu importer=%zu\n",
        sizeof(claims), sizeof(keys), sizeof(pending), sizeof(importer));
    return 0;
}
