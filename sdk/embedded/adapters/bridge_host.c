#define _POSIX_C_SOURCE 200809L
#include "orbit_posix.h"
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Run on a dedicated, trusted physical byte stream. stderr is diagnostic only;
 * never attach this helper to an unauthenticated TCP listener. */
static int transfer(int fd, void *p, size_t n, int writing) {
  uint8_t *b = p;
  while (n) {
    ssize_t v = writing ? write(fd, b, n) : read(fd, b, n);
    if (v < 0 && errno == EINTR)
      continue;
    if (v <= 0)
      return 0;
    b += v;
    n -= (size_t)v;
  }
  return 1;
}
static int output(const void *p, size_t n) {
  return transfer(STDOUT_FILENO, (void *)p, n, 1);
}
static uint32_t u16(const uint8_t *p) { return p[0] | ((uint32_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return u16(p) | (u16(p + 2) << 16); }
static void put64(uint8_t *p, uint64_t n) {
  for (unsigned i = 0; i < 8; ++i)
    p[i] = (uint8_t)(n >> (i * 8));
}
static int result(int32_t r) {
  uint8_t p[8] = {'O', 'R', 'S', '1'};
  for (unsigned i = 0; i < 4; ++i)
    p[4 + i] = (uint8_t)((uint32_t)r >> (8 * i));
  return output(p, 8);
}
typedef struct sink {
  uint16_t *status;
  int sent;
} sink_t;
static int send_status(sink_t *s) {
  if (s->sent)
    return 1;
  uint8_t p[2] = {(uint8_t)*s->status, (uint8_t)(*s->status >> 8)};
  s->sent = 1;
  return output(p, 2);
}
static int32_t receive(void *ctx, const uint8_t *p, uint32_t n) {
  sink_t *s = ctx;
  if (!send_status(s))
    return ORBIT_CLIENT_UNTRUSTED;
  while (n) {
    uint32_t m = n > 512 ? 512 : n;
    uint8_t h[2] = {(uint8_t)m, (uint8_t)(m >> 8)};
    if (!output(h, 2) || !output(p, m))
      return ORBIT_CLIENT_UNTRUSTED;
    p += m;
    n -= m;
  }
  return 0;
}
int main(int argc, char **argv) {
  static uint8_t body[ORBIT_CLIENT_ARENA_BYTES];
  uint8_t h[16], boot[16];
  char origin[513], path[513], id[37];
  if (argc != 2 || strncmp(argv[1], "https://", 8)) {
    fputs("usage: orbit_bridge_host https://your-orbit-origin\n", stderr);
    return 2;
  }
  FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!f || fread(id, 1, 36, f) != 36)
    return 2;
  fclose(f);
  unsigned j = 0;
  for (unsigned i = 0; i < 36;) {
    if (id[i] == '-') {
      ++i;
      continue;
    }
    char p[3] = {id[i], id[i + 1], 0}, *end;
    unsigned long n = strtoul(p, &end, 16);
    if (*end || j >= 16)
      return 2;
    boot[j++] = (uint8_t)n;
    i += 2;
  }
  if (j != 16 || curl_global_init(CURL_GLOBAL_DEFAULT))
    return 2;
  while (transfer(STDIN_FILENO, h, 16, 0)) {
    uint32_t a = u16(h + 6), b = u16(h + 8), n = u32(h + 12);
    if (memcmp(h, "ORB1", 4) || h[5] || h[10] || h[11] || a > 512 || b > 512 ||
        n > sizeof(body))
      return 2;
    if (h[4] == 1 || h[4] == 2) {
      if (!a || !b || !transfer(STDIN_FILENO, origin, a, 0) ||
          !transfer(STDIN_FILENO, path, b, 0) ||
          !transfer(STDIN_FILENO, body, n, 0))
        return 2;
      origin[a] = 0;
      path[b] = 0;
      if (a != strlen(argv[1]) || memcmp(origin, argv[1], a) ||
          memchr(path, 0, b) || path[0] != '/')
        return 2;
      orbit_http_request_t q = {{(uint8_t *)origin, a},
                                {(uint8_t *)path, b},
                                {body, n},
                                (uint8_t)(h[4] == 2)};
      uint16_t status = 0;
      sink_t s = {&status, 0};
      int32_t r = orbit_posix_exchange(NULL, &q, &status, receive, &s);
      memset(body, 0, n);
      uint8_t end[2] = {0};
      if (!send_status(&s) || !output(end, 2) || !result(r))
        return 2;
    } else if (h[4] == 3) {
      if (a || b || n)
        return 2;
      int64_t utc;
      uint64_t ticks;
      int32_t r = orbit_posix_clock(NULL, &utc, &ticks);
      if (!result(r))
        return 2;
      if (!r) {
        uint8_t p[32];
        put64(p, (uint64_t)utc);
        put64(p + 8, ticks);
        memcpy(p + 16, boot, 16);
        if (!output(p, 32))
          return 2;
      }
    } else if (h[4] == 4) {
      if (a || b || n > 256)
        return 2;
      int32_t r = orbit_posix_entropy(NULL, body, n);
      if (!result(r) || (!r && !output(body, n)))
        return 2;
      memset(body, 0, n);
    } else
      return 2;
  }
  curl_global_cleanup();
  return 0;
}
