#include "orbit_adapters.h"
#include "orbit_http.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      return 1;                                                                \
    }                                                                          \
  } while (0)
typedef struct mock {
  const char *response;
  uint32_t at, chunk, sent, got;
  char output[32];
  int closed;
  uint16_t *status;
} mock_t;
static int32_t connect_tls(void *p, const char *host, uint16_t port) {
  (void)p;
  return strcmp(host, "example.com") || port != 443 ? 12 : 0;
}
static int32_t write_tls(void *p, const uint8_t *b, uint32_t n) {
  mock_t *m = p;
  (void)b;
  m->sent += n;
  return 0;
}
static int32_t read_tls(void *p, uint8_t *b, uint32_t cap, uint32_t *n) {
  mock_t *m = p;
  uint32_t left = (uint32_t)strlen(m->response) - m->at;
  if (cap > m->chunk)
    cap = m->chunk;
  if (cap > left)
    cap = left;
  memcpy(b, m->response + m->at, cap);
  m->at += cap;
  *n = cap;
  return 0;
}
static void close_tls(void *p) { ((mock_t *)p)->closed++; }
static int32_t receive(void *p, const uint8_t *b, uint32_t n) {
  mock_t *m = p;
  if (*m->status != 200 || m->sent < 100 || n > sizeof(m->output) - m->got)
    return 12;
  memcpy(m->output + m->got, b, n);
  m->got += n;
  return 0;
}
static int check_response(const char *response, int valid,
                          const char *expected) {
  for (uint32_t chunk = 1; chunk < 80; ++chunk) {
    uint16_t status = 0;
    mock_t m = {response, 0, chunk, 0, 0, {0}, 0, &status};
    orbit_tls_stream_t stream = {&m, connect_tls, write_tls, read_tls,
                                 close_tls};
    orbit_http_request_t q = {{(const uint8_t *)"https://example.com", 19},
                              {(const uint8_t *)"/test", 5},
                              {(const uint8_t *)"{}", 2},
                              1};
    int32_t result = orbit_http_exchange(&stream, &q, &status, receive, &m);
    CHECK((result == 0) == valid);
    CHECK(m.closed == 1);
    if (valid)
      CHECK(m.got == strlen(expected) && !memcmp(m.output, expected, m.got));
  }
  return 0;
}
int main(void) {
  CHECK(!check_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 1,
                        "hello"));
  CHECK(!check_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: "
                        "chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n",
                        1, "hello"));
  CHECK(!check_response("HTTP/1.0 200 OK\r\n\r\nhello", 1, "hello"));
  CHECK(!check_response("HTTP/1.1 204 No Content\r\n\r\n", 1, ""));
  const char *bad[] = {
      "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: "
      "chunked\r\n\r\n0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 32769\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
      "HTTP/1.1 200 OK\r\n folded: value\r\n\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: "
      "unsupported\r\n\r\n",
      "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello",
      "HTTP/1.1 100 Continue\r\n\r\n"};
  for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
    CHECK(!check_response(bad[i], 0, ""));
  puts("HTTP framing: complete, chunked, close-delimited, all chunk boundaries "
       "and malformed deliveries passed");
  return 0;
}
