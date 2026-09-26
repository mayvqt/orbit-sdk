#include "orbit_embedded.h"
#include "openssl_adapter.h"
#include "orbit_generated_vectors.h"
#include "test_support.h"

#include <stdio.h>
#include <string.h>

static uint8_t workspace[ORBIT_GRANT_WORKSPACE_BYTES];
static orbit_grant_claims_t claims;
static uint8_t arena[ORBIT_GRANT_MAX_TOKEN_BYTES];

int main(void) {
    uint32_t i, accepted = 0u, rejected = 0u;
    const orbit_grant_crypto_t *crypto = orbit_test_openssl_crypto();
    for (i = 0; i < GENERATED_GRANT_VECTOR_COUNT; ++i) {
        const generated_grant_vector_t *vector = &generated_grant_vectors[i];
        const int32_t status = orbit_test_verify(
            vector->token, vector->token_length, vector->jwks, vector->jwks_length,
            &vector->expected, crypto, arena, workspace, &claims);
        const int ok = status == ORBIT_GRANT_STATUS_OK;
        if (ok != vector->expected_valid) {
            fprintf(stderr, "vector %u (%s): status=%d expected=%d\n",
                    i, vector->name, (int)status, vector->expected_valid);
            return 1;
        }
        if (ok) {
            ++accepted;
            if (claims.expires_at <= vector->expected.received_unix_seconds || claims.entitlement_count > ORBIT_GRANT_MAX_ENTITLEMENTS) {
                fprintf(stderr, "vector %u (%s): malformed successful output\n", i, vector->name);
                return 1;
            }
        } else {
            const uint8_t *raw = (const uint8_t *)&claims;
            uint32_t j;
            ++rejected;
            for (j = 0; j < sizeof(claims); ++j) {
                if (raw[j] != 0u) {
                    fprintf(stderr, "vector %u (%s): output was not reset\n", i, vector->name);
                    return 1;
                }
            }
        }
    }
    printf("shared grant vectors: %u passed (%u accepted, %u rejected)\n",
           GENERATED_GRANT_VECTOR_COUNT, accepted, rejected);
    return 0;
}
