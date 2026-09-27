#include "orbit_adapters.h"
#include <string.h>
static void put16(uint8_t *p, uint32_t n) {
  p[0] = (uint8_t)n;
  p[1] = (uint8_t)(n >> 8);
}
static void put32(uint8_t *p, uint32_t n) {
  for (unsigned i = 0; i < 4; ++i)
    p[i] = (uint8_t)(n >> (8 * i));
}
static uint32_t get32(const uint8_t *p) {
  uint32_t n = 0;
  for (unsigned i = 0; i < 4; ++i)
    n |= (uint32_t)p[i] << (8 * i);
  return n;
}
static uint64_t get64(const uint8_t *p) {
  uint64_t n = 0;
  for (unsigned i = 0; i < 8; ++i)
    n |= (uint64_t)p[i] << (8 * i);
  return n;
}
/* A byte-stream timeout is an outage; the framing is lost either way, so the
 * bridge stays broken until it is initialized again. */
static int32_t io_failure(orbit_bridge_t *b, int32_t r) {
  b->broken = 1;
  return r == ORBIT_CLIENT_TRANSIENT ? r : ORBIT_CLIENT_UNTRUSTED;
}
static int32_t rd(orbit_bridge_t *b, uint8_t *p, uint32_t n) {
  if (b->broken)
    return ORBIT_CLIENT_UNTRUSTED;
  int32_t r = b->read(b->io_context, p, n);
  return r ? io_failure(b, r) : 0;
}
static int32_t wr(orbit_bridge_t *b, const uint8_t *p, uint32_t n) {
  if (b->broken)
    return ORBIT_CLIENT_UNTRUSTED;
  int32_t r = b->write(b->io_context, p, n);
  return r ? io_failure(b, r) : 0;
}
static int32_t begin(orbit_bridge_t *b, uint8_t op, uint32_t origin,
                     uint32_t path, uint32_t body) {
  uint8_t h[16] = {0};
  memcpy(h, "ORB1", 4);
  h[4] = op;
  put16(h + 6, origin);
  put16(h + 8, path);
  put32(h + 12, body);
  return wr(b, h, sizeof(h));
}
static int32_t result(orbit_bridge_t *b) {
  uint8_t h[8];
  int32_t r = rd(b, h, 8);
  if (r)
    return r;
  if (memcmp(h, "ORS1", 4)) {
    b->broken = 1;
    return ORBIT_CLIENT_UNTRUSTED;
  }
  r = (int32_t)get32(h + 4);
  if (r && r != ORBIT_CLIENT_TRANSIENT && r != ORBIT_CLIENT_CLOCK &&
      r != ORBIT_CLIENT_UNTRUSTED && r != ORBIT_CLIENT_RESOURCE_LIMIT) {
    b->broken = 1;
    return ORBIT_CLIENT_UNTRUSTED;
  }
  return r;
}
static int32_t exchange(void *ctx, const orbit_http_request_t *q,
                        uint16_t *status, orbit_receive_fn receive, void *rc) {
  orbit_bridge_t *b = ctx;
  uint8_t bytes[512], h[2];
  uint32_t total = 0;
  int32_t r;
  if (q->origin.length > 512 || q->path.length > 512 ||
      q->body.length > ORBIT_CLIENT_ARENA_MAX_BYTES)
    return ORBIT_CLIENT_ARGUMENT;
  if ((r = begin(b, q->post ? 2 : 1, q->origin.length, q->path.length,
                 q->body.length)) != 0 ||
      (r = wr(b, q->origin.data, q->origin.length)) != 0 ||
      (r = wr(b, q->path.data, q->path.length)) != 0 ||
      (r = wr(b, q->body.data, q->body.length)) != 0 ||
      (r = rd(b, h, 2)) != 0)
    return r;
  *status = (uint16_t)(h[0] | ((uint16_t)h[1] << 8));
  for (;;) {
    if ((r = rd(b, h, 2)) != 0)
      return r;
    uint32_t n = h[0] | ((uint32_t)h[1] << 8);
    if (!n)
      return result(b);
    if (n > sizeof(bytes) || n > ORBIT_CLIENT_ARENA_MAX_BYTES - total) {
      b->broken = 1;
      return ORBIT_CLIENT_RESOURCE_LIMIT;
    }
    if ((r = rd(b, bytes, n)) != 0)
      return r;
    total += n;
    r = receive(rc, bytes, n);
    if (r) {
      b->broken = 1;
      return r;
    }
  }
}
static int32_t now(void *ctx, int64_t *utc, uint64_t *ticks) {
  orbit_bridge_t *b = ctx;
  uint8_t p[32];
  int32_t r;
  if (begin(b, 3, 0, 0, 0))
    return ORBIT_CLIENT_UNTRUSTED;
  r = result(b);
  if (r)
    return r;
  if (rd(b, p, sizeof(p)))
    return ORBIT_CLIENT_UNTRUSTED;
  uint64_t u = get64(p);
  if (u > INT64_MAX)
    return ORBIT_CLIENT_CLOCK;
  if (b->has_boot_id && memcmp(b->host_boot_id, p + 16, 16)) {
    b->broken = 1;
    return ORBIT_CLIENT_CLOCK;
  }
  memcpy(b->host_boot_id, p + 16, 16);
  b->has_boot_id = 1;
  *utc = (int64_t)u;
  *ticks = get64(p + 8);
  return 0;
}
static int32_t entropy(void *ctx, uint8_t *p, uint32_t n) {
  orbit_bridge_t *b = ctx;
  int32_t r;
  if (n > 256)
    return ORBIT_CLIENT_ARGUMENT;
  if (begin(b, 4, 0, 0, n))
    return ORBIT_CLIENT_UNTRUSTED;
  r = result(b);
  return r ? r : rd(b, p, n);
}
static int32_t load(void *ctx, uint8_t *p, uint32_t c, uint32_t *n) {
  return orbit_journal_load(((orbit_bridge_t *)ctx)->journal, p, c, n);
}
static int32_t commit(void *ctx, uint64_t generation, const uint8_t *p,
                      uint32_t n) {
  return orbit_journal_commit(((orbit_bridge_t *)ctx)->journal, generation, p,
                              n);
}
int32_t orbit_bridge_services(orbit_bridge_t *b, orbit_client_services_t *s) {
  if (!b || !s || !b->read || !b->write || !b->journal ||
      !b->crypto.validate_p256 || !b->crypto.sha256 || !b->crypto.verify_es256)
    return ORBIT_CLIENT_ARGUMENT;
  memset(s, 0, sizeof(*s));
  s->context = b;
  s->exchange = exchange;
  s->clock = now;
  s->entropy = entropy;
  s->load = load;
  s->commit = commit;
  s->crypto = b->crypto;
  return 0;
}
