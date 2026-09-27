#include "openssl_adapter.h"
#include "orbit_signed.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "orbit_generated_signed_vectors.h"

static uint8_t arena[32768], scratch[2048];
static int aliases(void) {
  const signed_case_t *v=&signed_cases[0];
  orbit_grant_crypto_t crypto=*orbit_test_openssl_crypto();
  orbit_grant_keyset_t keys, previous;
  orbit_grant_pending_t pending;
  orbit_signed_claims_t claims;
  orbit_signed_expected_t expected=v->expected;
  uint32_t n=(uint32_t)strlen(v->token);
  memcpy(arena,v->token,n);
  if(orbit_jwks_import((const uint8_t *)v->jwks,(uint32_t)strlen(v->jwks),&crypto,&keys))return 1;
  if(orbit_signed_prepare(arena,n,&crypto,expected.purpose,&pending))return 1;
  previous=keys;
  if(orbit_signed_verify(arena,n,&pending,&keys,&expected,&crypto,scratch,sizeof(scratch),(orbit_signed_claims_t *)&keys)!=ORBIT_GRANT_STATUS_INVALID_ARGUMENT || memcmp(&keys,&previous,sizeof(keys)))return 1;
  memset(&claims,0xa5,sizeof(claims));
  expected.session_id=(orbit_embedded_slice_t){(const uint8_t *)&claims,32};
  if(orbit_signed_verify(arena,n,&pending,&keys,&expected,&crypto,scratch,sizeof(scratch),&claims)!=ORBIT_GRANT_STATUS_INVALID_ARGUMENT || ((uint8_t *)&claims)[0]!=0xa5)return 1;
  return 0;
}
int main(void) {
  unsigned i, failures = 0;
  if(aliases()) { fputs("signed verifier overlap failure\n",stderr);return 1; }
  orbit_grant_crypto_t crypto = *orbit_test_openssl_crypto();
  for (i = 0; i < sizeof(signed_cases) / sizeof(signed_cases[0]); ++i) {
    const signed_case_t *v = &signed_cases[i];
    orbit_grant_keyset_t keys;
    orbit_grant_pending_t pending;
    orbit_signed_claims_t claims;
    size_t n = strlen(v->token);
    int r;
    memcpy(arena, v->token, n);
    r = orbit_jwks_import((const uint8_t *)v->jwks, (uint32_t)strlen(v->jwks),
                          &crypto, &keys);
    if (!r)
      r = orbit_signed_prepare(arena, (uint32_t)n, &crypto, v->expected.purpose,
                               &pending);
    if (!r)
      r = orbit_signed_verify(arena, (uint32_t)n, &pending, &keys, &v->expected,
                              &crypto, scratch, sizeof(scratch), &claims);
    if (v->invalid_type)
      r = 1; /* A typed integer API cannot express JSON booleans. */
    if ((r == 0) != v->valid) {
      fprintf(stderr, "%s: got %d expected valid=%d\n", v->name, r, v->valid);
      ++failures;
    }
  }
  printf("%u signed corpus cases, %u failures\n", i, failures);
  return failures != 0;
}
