#include "openssl_adapter.h"
#include "orbit_downloads.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#define S(s) ((orbit_embedded_slice_t){(const uint8_t *)(s), sizeof(s) - 1})
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "downloads:%d: %s\n", __LINE__, #x);                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)
typedef struct sink {
  EVP_MD_CTX *hash;
  uint8_t staged[32], destination[32];
  uint32_t staged_length, destination_length, at, opens, closes, aborts,
      commits, redirects;
  int bad_digest, truncated, oversized, encoded, false_length, cancel,
      replace_refused;
} sink_t;
static int32_t open_stream(void *p, orbit_embedded_slice_t url,
                           orbit_embedded_slice_t ticket,
                           orbit_download_response_t *r) {
  sink_t *s = p;
  ++s->opens;
  if (url.length < 8 || memcmp(url.data, "https://", 8))
    return ORBIT_CLIENT_UNTRUSTED;
  if ((s->opens == 1 &&
       (ticket.length != 6 || memcmp(ticket.data, "ticket", 6))) ||
      (s->opens > 1 && ticket.length))
    return ORBIT_CLIENT_UNTRUSTED;
  if (s->opens <= s->redirects) {
    r->status = 302;
    r->location = S("https://files.example/file");
    return 0;
  }
  r->status = 200;
  r->has_content_length = (uint8_t)s->false_length;
  r->content_length = 99;
  if (s->encoded)
    r->content_encoding = S("gzip");
  return 0;
}
static int32_t read_stream(void *p, uint8_t *b, uint32_t capacity,
                           uint32_t *n) {
  sink_t *s = p;
  const char *payload = s->oversized   ? "hello!"
                        : s->truncated ? "hell"
                                       : "hello";
  uint32_t remaining = (uint32_t)strlen(payload) - s->at;
  *n = remaining > 3 ? 3 : remaining;
  if (*n > capacity)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  memcpy(b, payload + s->at, *n);
  s->at += *n;
  return 0;
}
static void close_stream(void *p) { ++((sink_t *)p)->closes; }
static int32_t stage_begin(void *p, uint8_t replace) {
  sink_t *s = p;
  s->staged_length = 0;
  if (s->destination_length && !replace) {
    s->replace_refused = 1;
    return ORBIT_CLIENT_STORAGE;
  }
  return 0;
}
static int32_t stage_write(void *p, const uint8_t *b, uint32_t n) {
  sink_t *s = p;
  memcpy(s->staged + s->staged_length, b, n);
  s->staged_length += n;
  return 0;
}
static int32_t stage_commit(void *p) {
  sink_t *s = p;
  memcpy(s->destination, s->staged, s->staged_length);
  s->destination_length = s->staged_length;
  ++s->commits;
  return 0;
}
static void stage_abort(void *p) {
  sink_t *s = p;
  ++s->aborts;
  s->staged_length = 0;
}
static int32_t hash_begin(void *p) {
  sink_t *s = p;
  return EVP_DigestInit_ex(s->hash, EVP_sha256(), NULL) == 1 ? 0 : 12;
}
static int32_t hash_update(void *p, const uint8_t *b, uint32_t n) {
  return EVP_DigestUpdate(((sink_t *)p)->hash, b, n) == 1 ? 0 : 12;
}
static int32_t hash_finish(void *p, uint8_t digest[32]) {
  sink_t *s = p;
  unsigned n = 0;
  if (EVP_DigestFinal_ex(s->hash, digest, &n) != 1 || n != 32)
    return 12;
  if (s->bad_digest)
    digest[0] ^= 1;
  return 0;
}
static int32_t cancelled(void *p) {
  sink_t *s = p;
  return s->cancel && s->staged_length > 0;
}
int main(void) {
  sink_t s;
  orbit_download_authorization_t auth = {0};
  uint8_t scratch[2304];
  int scenario;
  int32_t r;
  orbit_download_io_t io = {&s,           open_stream, read_stream,
                            close_stream, stage_begin, stage_write,
                            stage_commit, stage_abort, hash_begin,
                            hash_update,  hash_finish, cancelled};
  auth.artifact.url = S("https://seller.example/download");
  auth.artifact.byte_length = 5;
  auth.artifact.protected_delivery = 1;
  auth.ticket = S("ticket");
  CHECK(orbit_test_openssl_crypto()->sha256(NULL, (const uint8_t *)"hello", 5,
                                            auth.artifact.sha256) == 0);
  for (scenario = 0; scenario < 9; ++scenario) {
    memset(&s, 0, sizeof(s));
    s.hash = EVP_MD_CTX_new();
    memcpy(s.destination, "old", 3);
    s.destination_length = 3;
    s.redirects = 2;
    if (scenario == 1)
      s.bad_digest = 1;
    if (scenario == 2)
      s.truncated = 1;
    if (scenario == 3)
      s.oversized = 1;
    if (scenario == 4)
      s.encoded = 1;
    if (scenario == 5)
      s.false_length = 1;
    if (scenario == 6)
      s.cancel = 1;
    if (scenario == 7)
      s.redirects = 6;
    r = orbit_download_stream(&auth, 10, (uint8_t)(scenario != 8), &io, scratch,
                              sizeof(scratch));
    if (scenario == 0) {
      CHECK(r == 0 && s.commits == 1 && s.aborts == 0 &&
            s.destination_length == 5 && !memcmp(s.destination, "hello", 5) &&
            s.opens == 3);
    } else {
      CHECK(r != 0 && s.commits == 0 && s.destination_length == 3 &&
            !memcmp(s.destination, "old", 3));
      if (scenario != 8)
        CHECK(s.aborts == 1);
    }
    CHECK(s.opens == s.closes);
    EVP_MD_CTX_free(s.hash);
  }
  auth.artifact.url = S("https://seller.example:0/file");
  CHECK(orbit_download_stream(&auth, 10, 1, &io, scratch, sizeof(scratch)) ==
        ORBIT_CLIENT_ARGUMENT);
  auth.artifact.url = S("https://@seller.example/file");
  CHECK(orbit_download_stream(&auth, 10, 1, &io, scratch, sizeof(scratch)) ==
        ORBIT_CLIENT_ARGUMENT);
  auth.artifact.url = S("https://[::::]/file");
  CHECK(orbit_download_stream(&auth, 10, 1, &io, scratch, sizeof(scratch)) ==
        ORBIT_CLIENT_ARGUMENT);
  puts("verified staging, redirect stripping and stream failures passed");
  return 0;
}
