#ifndef ORBIT_SIGNED_H
#define ORBIT_SIGNED_H
#include "orbit_embedded.h"
#ifdef __cplusplus
extern "C" {
#endif
#define ORBIT_SIGNED_SESSION 1u
#define ORBIT_SIGNED_OFFLINE 2u
#define ORBIT_ENVIRONMENT_TEST 1u
#define ORBIT_ENVIRONMENT_LIVE 2u
typedef struct orbit_signed_expected {
  orbit_grant_expected_t scope;
  orbit_embedded_slice_t session_id;
  uint64_t sequence;
  uint8_t purpose, environment_kind, allow_unbound_fingerprint;
} orbit_signed_expected_t;
typedef struct orbit_signed_claims {
  orbit_grant_claims_t access;
  orbit_grant_text_t session_id;
  uint64_t sequence;
} orbit_signed_claims_t;
/* Session and offline are separate purposes. The environment kind is trusted
 * app-key configuration, never inferred from a token or its key ID. */
int32_t orbit_signed_prepare(uint8_t *, uint32_t, const orbit_grant_crypto_t *,
                             uint8_t purpose, orbit_grant_pending_t *);
int32_t orbit_signed_verify(uint8_t *, uint32_t, const orbit_grant_pending_t *,
                            const orbit_grant_keyset_t *,
                            const orbit_signed_expected_t *,
                            const orbit_grant_crypto_t *, void *, uint32_t,
                            orbit_signed_claims_t *);
int32_t orbit_signed_keys_valid(const orbit_grant_keyset_t *, uint8_t purpose,
                                uint8_t environment_kind,
                                const orbit_grant_crypto_t *);
#ifdef __cplusplus
}
#endif
#endif
