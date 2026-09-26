#include "orbit_platform.h"
#include <string.h>
static int32_t exchange(void *p, const orbit_http_request_t *q, uint16_t *s,
                        orbit_receive_fn r, void *c) {
  return orbit_http_exchange(&((orbit_platform_t *)p)->tls, q, s, r, c);
}
static int32_t clock_now(void *p, int64_t *u, uint64_t *t) {
  orbit_platform_t *b = p;
  return b->clock(b->context, u, t);
}
static int32_t random_bytes(void *p, uint8_t *b, uint32_t n) {
  orbit_platform_t *s = p;
  return s->entropy(s->context, b, n);
}
static int32_t load(void *p, uint8_t *b, uint32_t c, uint32_t *n) {
  return orbit_journal_load(&((orbit_platform_t *)p)->journal, b, c, n);
}
static int32_t commit(void *p, uint64_t g, const uint8_t *b, uint32_t n) {
  return orbit_journal_commit(&((orbit_platform_t *)p)->journal, g, b, n);
}
int32_t orbit_platform_services(orbit_platform_t *p,
                                orbit_client_services_t *s) {
  if (!p || !s || !p->clock || !p->entropy || !p->crypto.sha256 ||
      !p->crypto.verify_es256 || !p->crypto.validate_p256 || !p->tls.connect ||
      !p->tls.read || !p->tls.write || !p->tls.close)
    return ORBIT_CLIENT_ARGUMENT;
  memset(s, 0, sizeof(*s));
  s->context = p;
  s->exchange = exchange;
  s->clock = clock_now;
  s->entropy = random_bytes;
  s->load = load;
  s->commit = commit;
  s->crypto = p->crypto;
  return 0;
}
