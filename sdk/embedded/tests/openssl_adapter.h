#ifndef ORBIT_TEST_OPENSSL_ADAPTER_H
#define ORBIT_TEST_OPENSSL_ADAPTER_H

#include "orbit_embedded.h"

const orbit_grant_crypto_t *orbit_test_openssl_crypto(void);
void orbit_test_openssl_fail_validate(int enabled);
void orbit_test_openssl_fail_verify(int enabled);
uint32_t orbit_test_openssl_validate_calls(void);

#endif
