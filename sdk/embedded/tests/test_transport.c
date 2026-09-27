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
  char request[256];
} mock_t;
static int32_t connect_tls(void *p, const char *host, uint16_t port) {
  (void)p;
  return strcmp(host, "example.com") || port != 443 ? 12 : 0;
}
static int32_t write_tls(void *p, const uint8_t *b, uint32_t n) {
  mock_t *m = p;
  if (m->sent < sizeof(m->request) - 1u)
    memcpy(m->request + m->sent, b,
           n < sizeof(m->request) - 1u - m->sent
               ? n
               : sizeof(m->request) - 1u - m->sent);
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
                              {(const uint8_t *)"embedded/0.4.0 (none-arm)", 25},
                              1};
    int32_t result = orbit_http_exchange(&stream, &q, &status, receive, &m);
    CHECK((result == 0) == valid);
    CHECK(strstr(m.request, "\r\nOrbit-Client: embedded/0.4.0 (none-arm)\r\n"));
    CHECK(m.closed == 1);
    if (valid)
      CHECK(m.got == strlen(expected) && !memcmp(m.output, expected, m.got));
  }
  return 0;
}
static int32_t count_receive(void *p, const uint8_t *b, uint32_t n) {
  mock_t *m = p;
  (void)b;
  m->got += n;
  return m->got <= ORBIT_CLIENT_ARENA_MAX_BYTES ? 0 : ORBIT_CLIENT_RESOURCE_LIMIT;
}
static int check_content_length_limit(void) {
  static char response[ORBIT_CLIENT_ARENA_MAX_BYTES + 128];
  const uint32_t chunks[] = {1, 31, 512};
  for (uint32_t extra = 0; extra <= 1; ++extra) {
    uint32_t length = ORBIT_CLIENT_ARENA_MAX_BYTES + extra;
    int header = snprintf(response, sizeof(response),
                          "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n\r\n", length);
    CHECK(header > 0 && (uint32_t)header + length < sizeof(response));
    memset(response + header, 'x', length);
    response[header + length] = 0;
    for (uint32_t i = 0; i < sizeof(chunks) / sizeof(chunks[0]); ++i) {
      uint16_t status = 0;
      mock_t m = {response, 0, chunks[i], 0, 0, {0}, 0, &status};
      orbit_tls_stream_t stream = {&m, connect_tls, write_tls, read_tls, close_tls};
      orbit_http_request_t q = {{(const uint8_t *)"https://example.com", 19},
                                {(const uint8_t *)"/test", 5},
                                {(const uint8_t *)"{}", 2},
                                {(const uint8_t *)"embedded/0.4.0 (none-arm)", 25}, 1};
      int32_t result = orbit_http_exchange(&stream, &q, &status, count_receive, &m);
      CHECK(result == (extra ? ORBIT_CLIENT_RESOURCE_LIMIT : 0));
      CHECK(m.got == (extra ? 0 : length));
      CHECK(m.closed == 1);
    }
  }
  return 0;
}
static int check_malformed_chunk_size(void) {
  const char *responses[] = {
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"};
  for (unsigned i = 0; i < sizeof(responses) / sizeof(responses[0]); ++i) {
    uint16_t status = 0;
    mock_t m = {responses[i], 0, 512, 0, 0, {0}, 0, &status};
    orbit_tls_stream_t stream = {&m, connect_tls, write_tls, read_tls,
                                 close_tls};
    orbit_http_request_t q = {{(const uint8_t *)"https://example.com", 19},
                              {(const uint8_t *)"/test", 5},
                              {(const uint8_t *)"{}", 2},
                              {NULL, 0},
                              1};
    CHECK(orbit_http_exchange(&stream, &q, &status, receive, &m) ==
          ORBIT_CLIENT_UNTRUSTED);
  }
  return 0;
}
static int check_short_read(void) {
  const char *responses[] = {
      "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
      "HTTP/1.1 200 OK\r\nContent-Len",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r"};
  for (unsigned i = 0; i < sizeof(responses) / sizeof(responses[0]); ++i) {
    uint16_t status = 0;
    mock_t m = {responses[i], 0, 7, 0, 0, {0}, 0, &status};
    orbit_tls_stream_t stream = {&m, connect_tls, write_tls, read_tls,
                                 close_tls};
    orbit_http_request_t q = {{(const uint8_t *)"https://example.com", 19},
                              {(const uint8_t *)"/test", 5},
                              {(const uint8_t *)"{}", 2},
                              {NULL, 0},
                              1};
    CHECK(orbit_http_exchange(&stream, &q, &status, receive, &m) ==
          ORBIT_CLIENT_TRANSIENT);
  }
  return 0;
}
static int check_client_header(void) {
  uint16_t status = 0;
  mock_t m = {"HTTP/1.1 204 No Content\r\n\r\n", 0, 64, 0, 0, {0}, 0, &status, {0}};
  orbit_tls_stream_t stream = {&m, connect_tls, write_tls, read_tls, close_tls};
  orbit_http_request_t q = {{(const uint8_t *)"https://example.com", 19},
                            {(const uint8_t *)"/test", 5},
                            {(const uint8_t *)"{}", 2},
                            {(const uint8_t *)"x/1 (a)\r\nX: y", 14},
                            1};
  CHECK(orbit_http_exchange(&stream, &q, &status, receive, &m) ==
        ORBIT_CLIENT_ARGUMENT);
  CHECK(m.sent == 0);
  q.client.length = 0;
  CHECK(orbit_http_exchange(&stream, &q, &status, receive, &m) == 0);
  CHECK(!strstr(m.request, "Orbit-Client"));
  return 0;
}
int main(void) {
  CHECK(!check_client_header());
  CHECK(!check_content_length_limit());
  CHECK(!check_short_read());
  CHECK(!check_malformed_chunk_size());
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
