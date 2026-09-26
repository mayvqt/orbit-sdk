#include "hardware/flash.h"
#include "hardware/regs/addressmap.h"
#include "lwip/dns.h"
#include "lwip/pbuf.h"
#include "mbedtls/ssl.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/version.h"
#include "orbit_pico.h"
#include "pico/cyw43_arch.h"
#include "pico/flash.h"
#include "pico/stdlib.h"
#include <string.h>
#if !PICO_CYW43_ARCH_POLL
#error "Orbit Pico port uses the single-owner polling architecture"
#endif
#if ALTCP_MBEDTLS_AUTHMODE != MBEDTLS_SSL_VERIFY_REQUIRED
#error "ALTCP_MBEDTLS_AUTHMODE must require certificate verification"
#endif
#if !defined(MBEDTLS_HAVE_TIME_DATE) || !defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#error "Enable trusted certificate time and the board entropy callback"
#endif
static orbit_pico_t *owner;
extern uint8_t __flash_binary_end;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000 && defined(MBEDTLS_PLATFORM_MS_TIME_ALT)
mbedtls_ms_time_t mbedtls_ms_time(void) {
  return (mbedtls_ms_time_t)(time_us_64() / 1000u);
}
#endif
time_t orbit_pico_tls_time(time_t *out) {
  int64_t u;
  uint64_t t;
  time_t v = (time_t)-1;
  if (owner && owner->platform.clock(owner->platform.context, &u, &t) == 0 &&
      u >= 0 && (int64_t)(time_t)u == u)
    v = (time_t)u;
  if (out)
    *out = v;
  return v;
}
int mbedtls_hardware_poll(void *unused, unsigned char *out, size_t n,
                          size_t *olen) {
  (void)unused;
  *olen = 0;
  if (!owner || n > UINT32_MAX ||
      owner->platform.entropy(owner->platform.context, out, (uint32_t)n))
    return -1;
  *olen = n;
  return 0;
}
static int32_t poll_one(orbit_pico_t *b) {
  if (b->failed)
    return ORBIT_CLIENT_UNTRUSTED;
  if (time_us_64() >= b->deadline)
    return ORBIT_CLIENT_TRANSIENT;
  cyw43_arch_poll();
  sleep_ms(1);
  return 0;
}
static void error_cb(void *arg, err_t e) {
  orbit_pico_t *b = arg;
  (void)e;
  b->pcb = NULL;
  b->failed = 1;
}
static err_t receive_cb(void *arg, struct altcp_pcb *p, struct pbuf *buf,
                        err_t e) {
  orbit_pico_t *b = arg;
  (void)p;
  if (e != ERR_OK)
    return e;
  if (!buf) {
    b->closed = 1;
    return ERR_OK;
  }
  if (b->received)
    return ERR_MEM;
  b->received = buf;
  b->received_offset = 0;
  return ERR_OK;
}
static err_t connected_cb(void *arg, struct altcp_pcb *p, err_t e) {
  orbit_pico_t *b = arg;
  if (e != ERR_OK || mbedtls_ssl_get_verify_result(altcp_tls_context(p)) != 0)
    b->failed = 1;
  else
    b->connected = 1;
  return ERR_OK;
}
static void dns_cb(const char *name, const ip_addr_t *ip, void *arg) {
  orbit_pico_t *b = arg;
  (void)name;
  b->dns_pending = 0;
  if (ip) {
    b->address = *ip;
    b->dns_ready = 1;
  } else
    b->dns_ready = 2;
}
static void close_tls(void *arg) {
  orbit_pico_t *b = arg;
  if (b->pcb) {
    altcp_arg(b->pcb, NULL);
    altcp_recv(b->pcb, NULL);
    altcp_err(b->pcb, NULL);
    altcp_abort(b->pcb);
    b->pcb = NULL;
  }
  if (b->received) {
    pbuf_free(b->received);
    b->received = NULL;
  }
  b->connected = 0;
}
static int32_t connect_tls(void *arg, const char *host, uint16_t port) {
  orbit_pico_t *b = arg;
  int64_t utc;
  uint64_t ticks;
  int32_t r;
  err_t e;
  if (b->dns_pending)
    return ORBIT_CLIENT_TRANSIENT;
  if (b->platform.clock(b->platform.context, &utc, &ticks))
    return ORBIT_CLIENT_CLOCK;
  close_tls(b);
  b->failed = b->closed = b->dns_ready = 0;
  b->deadline = time_us_64() + 30000000;
  e = dns_gethostbyname(host, &b->address, dns_cb, b);
  if (e == ERR_INPROGRESS)
    b->dns_pending = 1;
  else if (e == ERR_OK)
    b->dns_ready = 1;
  else
    return ORBIT_CLIENT_TRANSIENT;
  while (!b->dns_ready) {
    r = poll_one(b);
    if (r)
      return r;
  }
  if (b->dns_ready == 2)
    return ORBIT_CLIENT_TRANSIENT;
  b->pcb = altcp_tls_new(b->tls_config, IPADDR_TYPE_ANY);
  if (!b->pcb)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  altcp_arg(b->pcb, b);
  altcp_recv(b->pcb, receive_cb);
  altcp_err(b->pcb, error_cb);
  if (mbedtls_ssl_set_hostname(altcp_tls_context(b->pcb), host))
    return ORBIT_CLIENT_UNTRUSTED;
  if (altcp_connect(b->pcb, &b->address, port, connected_cb) != ERR_OK)
    return ORBIT_CLIENT_TRANSIENT;
  while (!b->connected) {
    r = poll_one(b);
    if (r)
      return r;
  }
  return 0;
}
static int32_t write_tls(void *arg, const uint8_t *p, uint32_t n) {
  orbit_pico_t *b = arg;
  while (n) {
    int32_t r = poll_one(b);
    if (r)
      return r;
    if (!b->pcb || b->closed)
      return ORBIT_CLIENT_UNTRUSTED;
    uint32_t m = altcp_sndbuf(b->pcb);
    if (m > n)
      m = n;
    if (m > 1024)
      m = 1024;
    if (!m)
      continue;
    err_t e = altcp_write(b->pcb, p, (u16_t)m, TCP_WRITE_FLAG_COPY);
    if (e == ERR_MEM)
      continue;
    if (e != ERR_OK)
      return ORBIT_CLIENT_UNTRUSTED;
    altcp_output(b->pcb);
    p += m;
    n -= m;
  }
  return 0;
}
static int32_t read_tls(void *arg, uint8_t *out, uint32_t capacity,
                        uint32_t *n) {
  orbit_pico_t *b = arg;
  *n = 0;
  while (!b->received) {
    if (b->closed)
      return 0;
    int32_t r = poll_one(b);
    if (r)
      return r;
  }
  uint32_t available = b->received->tot_len - b->received_offset;
  if (available > capacity)
    available = capacity;
  *n =
      pbuf_copy_partial(b->received, out, (u16_t)available, b->received_offset);
  b->received_offset += (uint16_t)*n;
  if (b->pcb)
    altcp_recved(b->pcb, (u16_t)*n);
  if (b->received_offset == b->received->tot_len) {
    pbuf_free(b->received);
    b->received = NULL;
  }
  return 0;
}
typedef struct flash_op {
  uint32_t offset;
  const uint8_t *bytes;
} flash_op_t;
static void erase_flash(void *p) {
  flash_range_erase(((flash_op_t *)p)->offset, FLASH_SECTOR_SIZE);
}
static void program_flash(void *p) {
  flash_op_t *o = p;
  flash_range_program(o->offset, o->bytes, FLASH_PAGE_SIZE);
}
static int32_t read_slot(void *p, uint8_t s, uint32_t o, uint8_t *b,
                         uint32_t n) {
  orbit_pico_t *c = p;
  memcpy(b,
         (const void *)(uintptr_t)(XIP_BASE + c->flash_offset + s * 4096 + o),
         n);
  return 0;
}
static int32_t erase_slot(void *p, uint8_t s) {
  orbit_pico_t *c = p;
  flash_op_t o = {c->flash_offset + s * 4096, NULL};
  return flash_safe_execute(erase_flash, &o, 1000) == PICO_OK
             ? 0
             : ORBIT_CLIENT_STORAGE;
}
static int32_t program_slot(void *p, uint8_t s, uint32_t offset,
                            const uint8_t *b, uint32_t n) {
  orbit_pico_t *c = p;
  uint8_t page[FLASH_PAGE_SIZE];
  while (n) {
    uint32_t address = c->flash_offset + s * 4096 + offset,
             at = address % FLASH_PAGE_SIZE, m = FLASH_PAGE_SIZE - at;
    if (m > n)
      m = n;
    memcpy(page, (const void *)(uintptr_t)(XIP_BASE + address - at),
           sizeof(page));
    for (uint32_t i = 0; i < m; ++i) {
      if ((page[at + i] & b[i]) != b[i])
        return ORBIT_CLIENT_STORAGE;
      page[at + i] = b[i];
    }
    flash_op_t o = {address - at, page};
    if (flash_safe_execute(program_flash, &o, 1000) != PICO_OK)
      return ORBIT_CLIENT_STORAGE;
    b += m;
    n -= m;
    offset += m;
  }
  return 0;
}
static int32_t sync_slot(void *p) {
  (void)p;
  return 0;
}
int32_t orbit_pico_open(orbit_pico_t *b, const uint8_t *ca, uint32_t ca_length,
                        uint32_t offset, void *context,
                        int32_t (*clock_fn)(void *, int64_t *, uint64_t *),
                        int32_t (*entropy_fn)(void *, uint8_t *, uint32_t),
                        orbit_client_services_t *s) {
  if (!b || owner || !ca || !ca_length || !clock_fn || !entropy_fn || !s ||
      offset % FLASH_SECTOR_SIZE || offset > PICO_FLASH_SIZE_BYTES - 8192 ||
      XIP_BASE + offset < (uintptr_t)&__flash_binary_end)
    return ORBIT_CLIENT_ARGUMENT;
  memset(b, 0, sizeof(*b));
  b->flash_offset = offset;
  b->platform.context = context;
  b->platform.clock = clock_fn;
  b->platform.entropy = entropy_fn;
  b->platform.crypto = *orbit_mbedtls_crypto();
  owner = b;
  b->tls_config = altcp_tls_create_config_client(ca, ca_length);
  if (!b->tls_config) {
    owner = NULL;
    return ORBIT_CLIENT_UNTRUSTED;
  }
  b->platform.tls =
      (orbit_tls_stream_t){b, connect_tls, write_tls, read_tls, close_tls};
  b->platform.journal = (orbit_journal_t){b,          4096,         read_slot,
                                          erase_slot, program_slot, sync_slot};
  return orbit_platform_services(&b->platform, s);
}
