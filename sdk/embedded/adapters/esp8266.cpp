#include "orbit_esp8266.hpp"
#include <time.h>
extern "C" {
#include <user_interface.h>
}
static int32_t now(void *p, int64_t *u, uint64_t *t) {
  auto *b = static_cast<orbit_esp8266 *>(p);
  time_t v = time(nullptr);
  if (!b->trusted_time || v < 0)
    return ORBIT_CLIENT_CLOCK;
  *u = static_cast<int64_t>(v);
  *t = static_cast<uint64_t>(v) * 1000;
  return 0;
}
static int32_t entropy(void *, uint8_t *b, uint32_t n) {
  if (WiFi.status() != WL_CONNECTED)
    return ORBIT_CLIENT_UNTRUSTED;
  while (n) {
    uint32_t m = n > 65535 ? 65535 : n;
    if (os_get_random(b, static_cast<uint16_t>(m)) != 0)
      return ORBIT_CLIENT_UNTRUSTED;
    b += m;
    n -= m;
  }
  return 0;
}
static int32_t connect_tls(void *p, const char *host, uint16_t port) {
  auto *b = static_cast<orbit_esp8266 *>(p);
  int64_t u;
  uint64_t t;
  if (now(p, &u, &t))
    return ORBIT_CLIENT_CLOCK;
  if (WiFi.status() != WL_CONNECTED)
    return ORBIT_CLIENT_TRANSIENT;
  b->connection.stop();
  b->connection.setTrustAnchors(b->roots);
  b->connection.setX509Time(static_cast<time_t>(u));
  b->connection.setTimeout(15000); /* BearSSL connect combines certificate and
                                      network errors; fail closed. */
  return b->connection.connect(host, port) ? 0 : ORBIT_CLIENT_UNTRUSTED;
}
static int32_t write_tls(void *p, const uint8_t *b, uint32_t n) {
  auto *c = static_cast<orbit_esp8266 *>(p);
  while (n) {
    size_t m = c->connection.write(b, n);
    if (!m)
      return ORBIT_CLIENT_UNTRUSTED;
    b += m;
    n -= static_cast<uint32_t>(m);
  }
  return 0;
}
static int32_t read_tls(void *p, uint8_t *b, uint32_t capacity, uint32_t *n) {
  auto *c = static_cast<orbit_esp8266 *>(p);
  uint32_t start = millis();
  *n = 0;
  while (!c->connection.available()) {
    if (!c->connection.connected())
      return 0;
    if (static_cast<uint32_t>(millis() - start) >= 15000)
      return ORBIT_CLIENT_TRANSIENT;
    delay(1);
  }
  int m = c->connection.read(b, capacity);
  if (m < 0)
    return ORBIT_CLIENT_UNTRUSTED;
  *n = static_cast<uint32_t>(m);
  return 0;
}
static void close_tls(void *p) {
  static_cast<orbit_esp8266 *>(p)->connection.stop();
}
static const char *path(uint8_t s) {
  return s ? "/orbit-b.bin" : "/orbit-a.bin";
}
static int32_t read_slot(void *, uint8_t s, uint32_t o, uint8_t *b,
                         uint32_t n) {
  if (!LittleFS.exists(path(s))) {
    memset(b, 255, n);
    return 0;
  }
  File f = LittleFS.open(path(s), "r");
  if (!f || f.size() != 4096 || !f.seek(o, SeekSet))
    return ORBIT_CLIENT_STORAGE;
  int read_count = f.read(b, n);
  if (read_count < 0 || static_cast<uint32_t>(read_count) != n)
    return ORBIT_CLIENT_STORAGE;
  return 0;
}
static int32_t erase_slot(void *, uint8_t s) {
  File f = LittleFS.open(path(s), "w");
  uint8_t b[64];
  memset(b, 255, sizeof(b));
  if (!f)
    return ORBIT_CLIENT_STORAGE;
  for (unsigned i = 0; i < 4096 / sizeof(b); ++i)
    if (f.write(b, sizeof(b)) != sizeof(b))
      return ORBIT_CLIENT_STORAGE;
  f.flush();
  int error = f.getWriteError();
  f.close();
  return error ? ORBIT_CLIENT_STORAGE : 0;
}
static int32_t program_slot(void *, uint8_t s, uint32_t o, const uint8_t *b,
                            uint32_t n) {
  File f = LittleFS.open(path(s), "r+");
  if (!f || f.size() != 4096 || !f.seek(o, SeekSet) || f.write(b, n) != n)
    return ORBIT_CLIENT_STORAGE;
  f.flush();
  int error = f.getWriteError();
  f.close();
  return error ? ORBIT_CLIENT_STORAGE : 0;
}
static int32_t sync_slot(void *) { return 0; }
int32_t orbit_esp8266_open(orbit_esp8266 *b, BearSSL::X509List *roots,
                           orbit_client_services_t *s) {
  if (!b || !roots || !s)
    return ORBIT_CLIENT_ARGUMENT;
  b->roots = roots;
  b->trusted_time = true;
  b->platform.context = b;
  b->platform.clock = now;
  b->platform.entropy = entropy;
  b->platform.crypto = *orbit_bearssl_crypto();
  b->platform.tls = {b, connect_tls, write_tls, read_tls, close_tls};
  b->platform.journal = {b,          4096,         read_slot,
                         erase_slot, program_slot, sync_slot};
  return orbit_platform_services(&b->platform, s);
}
