#include "orbit_http.h"
#include <stddef.h>
#include <string.h>

typedef struct reader {
  orbit_tls_stream_t *stream;
  uint8_t bytes[512];
  uint32_t at, length, headers;
  int32_t error;
} reader_t;
static int next(reader_t *r) {
  if (r->at == r->length) {
    r->at = r->length = 0;
    r->error = r->stream->read(r->stream->context, r->bytes, sizeof(r->bytes),
                               &r->length);
    if (r->error || r->length > sizeof(r->bytes)) {
      if (!r->error)
        r->error = ORBIT_CLIENT_UNTRUSTED;
      return -1;
    }
    if (!r->length)
      return -1;
  }
  return r->bytes[r->at++];
}
static int32_t line(reader_t *r, char *out, uint32_t capacity) {
  uint32_t n = 0;
  for (;;) {
    int c = next(r);
    if (c < 0)
      return r->error ? r->error : ORBIT_CLIENT_UNTRUSTED;
    if (++r->headers > 8192)
      return ORBIT_CLIENT_RESOURCE_LIMIT;
    if (c == '\r') {
      c = next(r);
      if (c != '\n')
        return r->error ? r->error : ORBIT_CLIENT_UNTRUSTED;
      ++r->headers;
      out[n] = 0;
      return 0;
    }
    if (c < 32 || c > 126 || n + 1 >= capacity)
      return ORBIT_CLIENT_UNTRUSTED;
    out[n++] = (char)c;
  }
}
static int same(const char *a, const char *b) {
  for (; *a && *b; ++a, ++b) {
    char c = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a;
    if (c != *b)
      return 0;
  }
  return *a == *b;
}
static int number(const char *s, uint32_t base, uint32_t *out) {
  uint32_t v = 0;
  if (!*s)
    return 0;
  for (; *s; ++s) {
    uint32_t d = *s >= '0' && *s <= '9'   ? (uint32_t)(*s - '0')
                 : *s >= 'a' && *s <= 'f' ? (uint32_t)(*s - 'a' + 10)
                 : *s >= 'A' && *s <= 'F' ? (uint32_t)(*s - 'A' + 10)
                                          : 99;
    if (d >= base || v > (UINT32_MAX - d) / base)
      return 0;
    v = v * base + d;
  }
  *out = v;
  return 1;
}
static int32_t write_bytes(orbit_tls_stream_t *s, const void *p, uint32_t n) {
  return n ? s->write(s->context, (const uint8_t *)p, n) : 0;
}
static int32_t body(reader_t *r, uint32_t count, orbit_receive_fn receive,
                    void *context) {
  while (count) {
    if (r->at == r->length) {
      int c = next(r);
      if (c < 0)
        return r->error ? r->error : ORBIT_CLIENT_UNTRUSTED;
      --r->at;
    }
    uint32_t n = r->length - r->at;
    if (n > count)
      n = count;
    int32_t rc = receive(context, r->bytes + r->at, n);
    if (rc)
      return rc;
    r->at += n;
    count -= n;
  }
  return 0;
}
int32_t orbit_http_exchange(void *opaque, const orbit_http_request_t *request,
                            uint16_t *status, orbit_receive_fn receive,
                            void *context) {
  orbit_tls_stream_t *s = opaque;
  char host[254], text[512], digits[11];
  uint32_t host_len, authority_len, content_length = 0, total = 0;
  uint16_t port = 443;
  int32_t rc;
  int has_length = 0, chunked = 0;
  reader_t r = {0};
  if (!s || !s->connect || !s->read || !s->write || !s->close || !request ||
      !status || !receive || !request->origin.data ||
      request->origin.length < 9 || request->origin.length > 270 ||
      memcmp(request->origin.data, "https://", 8) || !request->path.data ||
      !request->path.length || request->path.length > 512 ||
      request->path.data[0] != '/' ||
      request->body.length > ORBIT_CLIENT_ARENA_BYTES ||
      (!request->body.data && request->body.length) || request->post > 1)
    return ORBIT_CLIENT_ARGUMENT;
  *status = 0;
  authority_len = request->origin.length - 8;
  host_len = 0;
  while (host_len < authority_len &&
         request->origin.data[8 + host_len] != ':') {
    uint8_t c = request->origin.data[8 + host_len];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '.') ||
        host_len >= sizeof(host) - 1)
      return ORBIT_CLIENT_ARGUMENT;
    host[host_len++] = (char)c;
  }
  if (!host_len)
    return ORBIT_CLIENT_ARGUMENT;
  host[host_len] = 0;
  if (host_len < authority_len) {
    uint32_t p = 0, i = host_len + 1;
    if (i == authority_len)
      return ORBIT_CLIENT_ARGUMENT;
    for (; i < authority_len; ++i) {
      uint8_t c = request->origin.data[8 + i];
      if (c < '0' || c > '9' || p > 6553)
        return ORBIT_CLIENT_ARGUMENT;
      p = p * 10 + c - '0';
      if (p > 65535)
        return ORBIT_CLIENT_ARGUMENT;
    }
    if (!p)
      return ORBIT_CLIENT_ARGUMENT;
    port = (uint16_t)p;
  }
  for (uint32_t i = 0; i < request->path.length; ++i)
    if (request->path.data[i] <= 32 || request->path.data[i] >= 127 ||
        request->path.data[i] == '#')
      return ORBIT_CLIENT_ARGUMENT;
  rc = s->connect(s->context, host, port);
  if (rc) {
    s->close(s->context);
    return rc;
  }
#define SEND(p, n)                                                             \
  do {                                                                         \
    rc = write_bytes(s, (p), (n));                                             \
    if (rc)                                                                    \
      goto done;                                                               \
  } while (0)
  SEND(request->post ? "POST " : "GET ", request->post ? 5 : 4);
  SEND(request->path.data, request->path.length);
  SEND(" HTTP/1.1\r\nHost: ", 17);
  SEND(request->origin.data + 8, authority_len);
  {
    static const char h[] =
        "\r\nConnection: close\r\nAccept: application/json\r\nAccept-Encoding: "
        "identity\r\nContent-Type: application/json\r\nContent-Length: ";
    SEND(h, sizeof(h) - 1);
  }
  {
    uint32_t n = request->body.length, i = sizeof(digits);
    do {
      digits[--i] = (char)('0' + n % 10);
      n /= 10;
    } while (n);
    SEND(digits + i, sizeof(digits) - i);
  }
  SEND("\r\n\r\n", 4);
  SEND(request->body.data, request->body.length);
#undef SEND
  r.stream = s;
  rc = line(&r, text, sizeof(text));
  if (rc)
    goto done;
  if (strlen(text) < 12 ||
      (memcmp(text, "HTTP/1.1 ", 9) && memcmp(text, "HTTP/1.0 ", 9)) ||
      text[9] < '2' || text[9] > '5' || text[10] < '0' || text[10] > '9' ||
      text[11] < '0' || text[11] > '9' || (text[12] && text[12] != ' ')) {
    rc = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  *status = (uint16_t)((text[9] - '0') * 100 + (text[10] - '0') * 10 +
                       text[11] - '0');
  for (;;) {
    rc = line(&r, text, sizeof(text));
    if (rc)
      goto done;
    if (!text[0])
      break;
    char *colon = strchr(text, ':');
    if (!colon || colon == text) {
      rc = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
    for (char *p = text; p < colon; ++p)
      if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '-')) {
        rc = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
    *colon++ = 0;
    while (*colon == ' ')
      ++colon;
    char *end = colon + strlen(colon);
    while (end > colon && end[-1] == ' ')
      *--end = 0;
    if (same(text, "content-length")) {
      if (has_length++ || !number(colon, 10, &content_length)) {
        rc = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
    } else if (same(text, "transfer-encoding")) {
      if (chunked++ || !same(colon, "chunked")) {
        rc = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
    } else if (same(text, "content-encoding") && !same(colon, "identity")) {
      rc = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
  }
  if ((has_length && chunked) ||
      (*status == 204 && (chunked || content_length))) {
    rc = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (*status == 204) {
    rc = 0;
    goto done;
  }
  if (has_length && content_length > ORBIT_CLIENT_ARENA_BYTES) {
    rc = ORBIT_CLIENT_RESOURCE_LIMIT;
    goto done;
  }
  if (chunked) {
    for (;;) {
      uint32_t n;
      rc = line(&r, text, sizeof(text));
      if (rc)
        goto done;
      if (!number(text, 16, &n) || n > ORBIT_CLIENT_ARENA_BYTES - total) {
        rc = ORBIT_CLIENT_RESOURCE_LIMIT;
        goto done;
      }
      if (!n) {
        rc = line(&r, text, sizeof(text));
        if (!rc && text[0])
          rc = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
      rc = body(&r, n, receive, context);
      if (rc)
        goto done;
      total += n;
      if (next(&r) != '\r' || next(&r) != '\n') {
        rc = r.error ? r.error : ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
    }
  }
  if (has_length) {
    rc = body(&r, content_length, receive, context);
    goto done;
  }
  for (;;) {
    int c = next(&r);
    if (c < 0) {
      rc = r.error;
      goto done;
    }
    --r.at;
    uint32_t n = r.length - r.at;
    if (n > ORBIT_CLIENT_ARENA_BYTES - total) {
      rc = ORBIT_CLIENT_RESOURCE_LIMIT;
      goto done;
    }
    rc = body(&r, n, receive, context);
    if (rc)
      goto done;
    total += n;
  }
done:
  s->close(s->context);
  return rc;
}
