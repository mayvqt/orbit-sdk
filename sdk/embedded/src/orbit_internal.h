#ifndef ORBIT_INTERNAL_H
#define ORBIT_INTERNAL_H
#include "orbit_embedded.h"
#include <stddef.h>
static inline void orbit_zero(void *p, uint32_t n) {
    uint8_t *b = (uint8_t *)p;
    while (n-- != 0u)
        *b++ = 0u;
}
static inline void orbit_copy(void *to, const void *from, uint32_t n) {
    uint8_t *d = (uint8_t *)to;
    const uint8_t *s = (const uint8_t *)from;
    while (n-- != 0u)
        *d++ = *s++;
}
static inline int orbit_equal(const void *a, const void *b, uint32_t n) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    while (n-- != 0u)
        if (*x++ != *y++)
            return 0;
    return 1;
}
static inline int orbit_overlap(const void *a, uint32_t an, const void *b, uint32_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (an == 0u || bn == 0u || a == NULL || b == NULL)
        return 0;
    return x <= y ? y - x < an : x - y < bn;
}
static inline int orbit_crypto_valid(const orbit_grant_crypto_t *c) {
    return c != NULL && c->validate_p256 != NULL && c->sha256 != NULL && c->verify_es256 != NULL;
}
int32_t orbit_base64url_decode(const uint8_t *input, uint32_t input_length, uint8_t *output,
                               uint32_t capacity, uint32_t *output_length);
#endif
