#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "orbit_esp32.h"
#include <string.h>
#include <time.h>
static int32_t now(void *p, int64_t *u, uint64_t *t) {
  orbit_esp32_t *b = p;
  time_t v = time(NULL);
  int64_t ticks = esp_timer_get_time();
  if (!b->trusted_time || v < 0 || ticks < 0)
    return ORBIT_CLIENT_CLOCK;
  *u = (int64_t)v;
  *t = (uint64_t)ticks / 1000;
  return 0;
}
static int32_t entropy(void *p, uint8_t *b, uint32_t n) {
  wifi_mode_t mode;
  (void)p;
  if (esp_wifi_get_mode(&mode) != ESP_OK || mode == WIFI_MODE_NULL)
    return ORBIT_CLIENT_UNTRUSTED;
  esp_fill_random(b, n);
  return 0;
}
static void close_tls(void *p) {
  orbit_esp32_t *b = p;
  if (b->connection)
    esp_tls_conn_destroy(b->connection);
  b->connection = NULL;
}
static int32_t connect_tls(void *p, const char *host, uint16_t port) {
  orbit_esp32_t *b = p;
  int64_t u;
  uint64_t t;
  if (now(p, &u, &t))
    return ORBIT_CLIENT_CLOCK;
  close_tls(p);
  esp_tls_cfg_t cfg = {0};
  cfg.cacert_buf = (const unsigned char *)b->root_ca_pem;
  cfg.cacert_bytes = strlen(b->root_ca_pem) + 1;
  cfg.timeout_ms = 15000;
  cfg.skip_common_name = false;
  b->connection = esp_tls_init();
  if (!b->connection)
    return ORBIT_CLIENT_RESOURCE_LIMIT; /* esp-tls combines network and
                                           certificate failures; conservatively
                                           deny offline fallback. */
  return esp_tls_conn_new_sync(host, strlen(host), port, &cfg, b->connection) ==
                 1
             ? 0
             : ORBIT_CLIENT_UNTRUSTED;
}
static int32_t write_tls(void *p, const uint8_t *b, uint32_t n) {
  orbit_esp32_t *s = p;
  while (n) {
    ssize_t m = esp_tls_conn_write(s->connection, b, n);
    if (m <= 0)
      return ORBIT_CLIENT_UNTRUSTED;
    b += m;
    n -= (uint32_t)m;
  }
  return 0;
}
static int32_t read_tls(void *p, uint8_t *b, uint32_t c, uint32_t *n) {
  orbit_esp32_t *s = p;
  ssize_t m = esp_tls_conn_read(s->connection, b, c);
  if (m < 0)
    return ORBIT_CLIENT_UNTRUSTED;
  *n = (uint32_t)m;
  return 0;
}
static int32_t read_slot(void *p, uint8_t s, uint32_t o, uint8_t *b,
                         uint32_t n) {
  orbit_esp32_t *c = p;
  if (c->partition->encrypted) {
    if (esp_partition_read_raw(c->partition, (size_t)s * 4096 + o, b, n) !=
        ESP_OK)
      return ORBIT_CLIENT_STORAGE;
    uint32_t i;
    for (i = 0; i < n && b[i] == 255; ++i) {
    }
    if (i == n)
      return 0; /* An erased encrypted sector has no plaintext yet. */
  }
  return esp_partition_read(c->partition, (size_t)s * 4096 + o, b, n) == ESP_OK
             ? 0
             : ORBIT_CLIENT_STORAGE;
}
static int32_t erase_slot(void *p, uint8_t s) {
  orbit_esp32_t *c = p;
  return esp_partition_erase_range(c->partition, (size_t)s * 4096, 4096) ==
                 ESP_OK
             ? 0
             : ORBIT_CLIENT_STORAGE;
}
static int32_t program_slot(void *p, uint8_t s, uint32_t o, const uint8_t *b,
                            uint32_t n) {
  orbit_esp32_t *c = p;
  return esp_partition_write(c->partition, (size_t)s * 4096 + o, b, n) == ESP_OK
             ? 0
             : ORBIT_CLIENT_STORAGE;
}
static int32_t sync_slot(void *p) {
  (void)p;
  return 0;
}
int32_t orbit_esp32_open(orbit_esp32_t *b, const char *label, const char *ca,
                         orbit_client_services_t *s) {
  if (!b || !label || !ca || !*ca || !s)
    return ORBIT_CLIENT_ARGUMENT;
  memset(b, 0, sizeof(*b));
  b->partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                          ESP_PARTITION_SUBTYPE_ANY, label);
  if (!b->partition || b->partition->size < 8192)
    return ORBIT_CLIENT_STORAGE;
  b->root_ca_pem = ca;
  b->trusted_time = 1;
  b->platform.context = b;
  b->platform.clock = now;
  b->platform.entropy = entropy;
  b->platform.crypto = *orbit_mbedtls_crypto();
  b->platform.tls =
      (orbit_tls_stream_t){b, connect_tls, write_tls, read_tls, close_tls};
  b->platform.journal = (orbit_journal_t){b,          4096,         read_slot,
                                          erase_slot, program_slot, sync_slot};
  return orbit_platform_services(&b->platform, s);
}
