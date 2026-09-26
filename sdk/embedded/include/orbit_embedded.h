#ifndef ORBIT_EMBEDDED_H
#define ORBIT_EMBEDDED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORBIT_GRANT_MAX_TOKEN_BYTES 16384u
#define ORBIT_GRANT_MAX_JSON_BYTES 32768u
#define ORBIT_GRANT_MAX_ENTITLEMENTS 64u
#define ORBIT_GRANT_MAX_ENTITLEMENT_NAME 64u
#define ORBIT_GRANT_WORKSPACE_BYTES 2048u
#define ORBIT_GRANT_MAX_KEYS 8u

#define ORBIT_GRANT_STATUS_OK ((int32_t)0)
#define ORBIT_GRANT_STATUS_INVALID_ARGUMENT ((int32_t)1)
#define ORBIT_GRANT_STATUS_INVALID_GRANT ((int32_t)2)
#define ORBIT_GRANT_STATUS_RESOURCE_LIMIT ((int32_t)3)
#define ORBIT_GRANT_STATUS_CRYPTO_FAILURE ((int32_t)4)
#define ORBIT_GRANT_STATUS_UNKNOWN_KEY ((int32_t)5)

typedef struct orbit_embedded_slice {
  const uint8_t *data;
  uint32_t length;
} orbit_embedded_slice_t;

typedef struct orbit_grant_expected {
  orbit_embedded_slice_t issuer;
  orbit_embedded_slice_t application_id;
  orbit_embedded_slice_t environment_id;
  orbit_embedded_slice_t licence_id;
  orbit_embedded_slice_t activation_id;
  orbit_embedded_slice_t installation_id;
  orbit_embedded_slice_t fingerprint;
  orbit_embedded_slice_t fingerprint_provider;
  int64_t received_unix_seconds;
  int64_t current_unix_seconds;
  int64_t credential_expires_at;
  int64_t licence_expires_at;
  uint8_t has_licence_id;
  uint8_t has_fingerprint;
  uint8_t has_fingerprint_provider;
  uint8_t has_credential_expiry;
  uint8_t has_licence_expiry;
} orbit_grant_expected_t;

typedef struct orbit_grant_text {
  uint16_t offset;
  uint16_t length;
} orbit_grant_text_t;

typedef struct orbit_grant_entitlement {
  orbit_grant_text_t name;
} orbit_grant_entitlement_t;

typedef struct orbit_grant_claims {
  int64_t issued_at;
  int64_t not_before;
  int64_t expires_at;
  int64_t refresh_after;
  int64_t licence_expires_at;
  uint32_t policy_version;
  /* Offsets reference the caller's decoded arena, never this object. */
  orbit_grant_text_t issuer;
  orbit_grant_text_t audience;
  orbit_grant_text_t subject;
  orbit_grant_text_t token_id;
  orbit_grant_text_t application_id;
  orbit_grant_text_t environment_id;
  orbit_grant_text_t activation_id;
  orbit_grant_text_t installation_id;
  orbit_grant_text_t binding_mode;
  orbit_grant_text_t fingerprint;
  orbit_grant_text_t fingerprint_provider;
  orbit_grant_entitlement_t entitlements[ORBIT_GRANT_MAX_ENTITLEMENTS];
  uint8_t entitlement_enabled[8];
  uint16_t arena_length;
  uint8_t has_fingerprint;
  uint8_t has_fingerprint_provider;
  uint8_t has_licence_expiry;
  uint8_t offline_allowed;
  uint8_t entitlement_count;
} orbit_grant_claims_t;

typedef struct orbit_grant_key {
  uint8_t kid[128], x[32], y[32], kid_length;
} orbit_grant_key_t;

typedef struct orbit_grant_keyset {
  orbit_grant_key_t keys[ORBIT_GRANT_MAX_KEYS];
  uint8_t count;
} orbit_grant_keyset_t;

typedef struct orbit_grant_pending {
  uint8_t digest[32], payload_digest[32], signature[64], kid[128];
  uint16_t payload_length;
  uint8_t kid_length, prepared;
} orbit_grant_pending_t;

typedef int32_t (*orbit_grant_validate_p256_fn)(void *context,
                                                const uint8_t x[32],
                                                const uint8_t y[32]);

typedef int32_t (*orbit_grant_verify_es256_fn)(void *context,
                                               const uint8_t x[32],
                                               const uint8_t y[32],
                                               const uint8_t sha256_digest[32],
                                               const uint8_t signature[64]);

typedef int32_t (*orbit_grant_sha256_fn)(void *context, const uint8_t *input,
                                         uint32_t length, uint8_t digest[32]);

typedef struct orbit_grant_crypto {
  void *context;
  orbit_grant_validate_p256_fn validate_p256;
  orbit_grant_sha256_fn sha256;
  orbit_grant_verify_es256_fn verify_es256;
} orbit_grant_crypto_t;

/* Incremental importer owns no pointers. Its output is unusable until finish.
 * Supply the same output and crypto provider to every call, without reentry.
 * All buffers/objects must be disjoint; callbacks must not retain pointers. */
typedef struct orbit_jwks_importer {
  uint32_t total;
  int32_t status;
  uint16_t token_length, unicode_value;
  uint8_t token[129];
  uint8_t state, lexical, unicode_left, field, seen, count;
  orbit_grant_key_t candidate;
} orbit_jwks_importer_t;

int32_t orbit_jwks_begin(orbit_jwks_importer_t *importer,
                         orbit_grant_keyset_t *keys);
int32_t orbit_jwks_feed(orbit_jwks_importer_t *importer,
                        orbit_grant_keyset_t *keys,
                        const orbit_grant_crypto_t *crypto,
                        const uint8_t *bytes, uint32_t length);
int32_t orbit_jwks_finish(orbit_jwks_importer_t *importer,
                          orbit_grant_keyset_t *keys);
int32_t orbit_jwks_import(const uint8_t *bytes, uint32_t length,
                          const orbit_grant_crypto_t *crypto,
                          orbit_grant_keyset_t *keys);

/* Hashes the exact JOSE signing bytes BEFORE overwriting token with decoded
 * payload. Pending is trusted integrity metadata constructed ONLY by prepare;
 * never deserialize, construct or edit it yourself. It does not authorize
 * access. The arena and pending stay unchanged until verify (including a key fetch).
 * Bounds are checked before reads; all buffers/objects must be disjoint.
 * Crypto callbacks return zero only on success; verify_es256 receives a SHA-256
 * digest and MUST NOT hash it again. No callback may retain pointers or
 * reenter. */
int32_t orbit_grant_prepare(uint8_t *token, uint32_t token_length,
                            const orbit_grant_crypto_t *crypto,
                            orbit_grant_pending_t *pending);

/* Verifies a prepared payload and then unescapes retained spans in place.
 * Successful text/name offsets borrow arena until it is overwritten. Scratch
 * may be reused immediately; it needs no special alignment. Claims is zeroed
 * on failure, except invalid overlapping arguments are rejected without writes.
 * received_unix_seconds is the original trusted receipt time,
 * current_unix_seconds the trusted current time; neither retry nor
 * re-verification extends expiry. A prepared payload may be verified once:
 * success mutates its strings. */
int32_t orbit_grant_verify(uint8_t *arena, uint32_t arena_length,
                           const orbit_grant_pending_t *pending,
                           const orbit_grant_keyset_t *keys,
                           const orbit_grant_expected_t *expected,
                           const orbit_grant_crypto_t *crypto, void *scratch,
                           uint32_t scratch_length,
                           orbit_grant_claims_t *claims);

#ifdef __cplusplus
}
#endif

#endif
