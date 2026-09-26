#include "orbit_storage.h"
#include "orbit_internal.h"

typedef struct slot_header {
  uint64_t generation;
  uint32_t length, crc;
  uint8_t present, pending;
} slot_header_t;
static uint32_t crc_step(uint32_t crc, const uint8_t *bytes, uint32_t length) {
  uint32_t i;
  while (length--) {
    crc ^= *bytes++;
    for (i = 0u; i < 8u; ++i)
      crc = (crc >> 1u) ^ (0xedb88320u & (0u - (crc & 1u)));
  }
  return crc;
}
static uint64_t get64(const uint8_t *p) {
  uint64_t value = 0u;
  uint32_t i;
  for (i = 0u; i < 8u; ++i)
    value |= (uint64_t)p[i] << (i * 8u);
  return value;
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) | ((uint32_t)p[2] << 16u) |
         ((uint32_t)p[3] << 24u);
}
static void put64(uint8_t *p, uint64_t value) {
  uint32_t i;
  for (i = 0u; i < 8u; ++i)
    p[i] = (uint8_t)(value >> (i * 8u));
}
static void put32(uint8_t *p, uint32_t value) {
  uint32_t i;
  for (i = 0u; i < 4u; ++i)
    p[i] = (uint8_t)(value >> (i * 8u));
}
static int valid(const orbit_journal_t *j) {
  return j != NULL && j->slot_bytes >= 1088u && j->read != NULL &&
         j->erase != NULL && j->program != NULL && j->sync != NULL;
}
static int32_t header(orbit_journal_t *j, uint8_t slot, slot_header_t *out) {
  uint8_t bytes[64];
  uint32_t i;
  int erased = 1;
  orbit_zero(out, sizeof(*out));
  /* Encrypted flash must identify each still-erased programming block before
   * attempting decryption. Intent has its own initially untouched block. */
  for (i = 0u; i < sizeof(bytes); i += 16u)
    if (j->read(j->context, slot, i, bytes + i, 16u) != 0)
      return ORBIT_CLIENT_STORAGE;
  for (i = 0u; i < sizeof(bytes); ++i)
    if (bytes[i] != 255u)
      erased = 0;
  if (erased)
    return 0;
  /* A partially written newer slot is a durable denial, never permission to
   * fall back to the previous credential. Recovery must be deliberate. */
  if (!orbit_equal(bytes, "ORBJNL2", 8u) ||
      get32(bytes + 24u) != ~crc_step(UINT32_MAX, bytes, 24u) ||
      get64(bytes + 48u) != 0u || get64(bytes + 56u) != 0u)
    return ORBIT_CLIENT_STORAGE;
  out->generation = get64(bytes + 8u);
  out->length = get32(bytes + 16u);
  out->crc = get32(bytes + 20u);
  out->present = 1u;
  for (i = 32u; i < 48u; ++i)
    if (bytes[i] != 255u)
      out->pending = 1u;
  if (out->generation == 0u || out->generation == UINT64_MAX ||
      out->length < 16u || out->length > ORBIT_CLIENT_RECORD_BYTES)
    return ORBIT_CLIENT_STORAGE;
  return 0;
}
static int32_t newest(orbit_journal_t *j, slot_header_t h[2], uint8_t *slot) {
  if (header(j, 0u, &h[0]) != 0 || header(j, 1u, &h[1]) != 0)
    return ORBIT_CLIENT_STORAGE;
  if (!h[0].present && !h[1].present)
    return ORBIT_CLIENT_NOT_FOUND;
  if (h[0].present && h[1].present && h[0].generation == h[1].generation)
    return ORBIT_CLIENT_STORAGE;
  *slot = (uint8_t)(!h[0].present ||
                    (h[1].present && h[1].generation > h[0].generation));
  if (h[*slot].pending)
    return ORBIT_CLIENT_STORAGE;
  if (h[*slot ^ 1u].present &&
      (!h[*slot ^ 1u].pending ||
       h[*slot].generation != h[*slot ^ 1u].generation + 1u))
    return ORBIT_CLIENT_STORAGE;
  return 0;
}
int32_t orbit_journal_load(void *context, uint8_t *record, uint32_t capacity,
                           uint32_t *length) {
  orbit_journal_t *j = (orbit_journal_t *)context;
  slot_header_t h[2];
  uint8_t slot = 0u;
  int32_t status;
  if (length != NULL)
    *length = 0u;
  if (!valid(j) || record == NULL || length == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  status = newest(j, h, &slot);
  if (status != 0)
    return status;
  if (h[slot].length > capacity)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  if (j->read(j->context, slot, 64u, record, h[slot].length) != 0 ||
      ~crc_step(UINT32_MAX, record, h[slot].length) != h[slot].crc ||
      !orbit_equal(record, "ORBITMC1", 8u) ||
      get64(record + 8u) != h[slot].generation) {
    orbit_zero(record, h[slot].length);
    return ORBIT_CLIENT_STORAGE;
  }
  *length = h[slot].length;
  return 0;
}
int32_t orbit_journal_commit(void *context, uint64_t expected,
                             const uint8_t *record, uint32_t length) {
  orbit_journal_t *j = (orbit_journal_t *)context;
  slot_header_t h[2];
  uint8_t slot = 0u, bytes[64];
  uint32_t i, at, n;
  int32_t status;
  if (!valid(j) || record == NULL || length < 16u ||
      length > ORBIT_CLIENT_RECORD_BYTES || expected >= UINT64_MAX - 1u ||
      !orbit_equal(record, "ORBITMC1", 8u) ||
      get64(record + 8u) != expected + 1u)
    return ORBIT_CLIENT_ARGUMENT;
  status = newest(j, h, &slot);
  if (status == ORBIT_CLIENT_NOT_FOUND) {
    if (expected != 0u)
      return ORBIT_CLIENT_STALE;
    slot = 0u;
  } else if (status != 0)
    return status;
  else {
    if (h[slot].generation != expected)
      return ORBIT_CLIENT_STALE;
    /* Fence the current generation before touching the alternate slot. This
     * block has never been programmed, including as all-ones plaintext. */
    orbit_zero(bytes, 16u);
    if (j->program(j->context, slot, 32u, bytes, 16u) != 0 ||
        j->sync(j->context) != 0)
      return ORBIT_CLIENT_STORAGE;
    slot ^= 1u;
  }
  if (j->erase(j->context, slot) != 0 || j->sync(j->context) != 0)
    return ORBIT_CLIENT_STORAGE;
  for (i = 0u; i < sizeof(bytes); ++i)
    bytes[i] = 255u;
  orbit_copy(bytes, "ORBJNL2", 8u);
  put64(bytes + 8u, expected + 1u);
  put32(bytes + 16u, length);
  put32(bytes + 20u, ~crc_step(UINT32_MAX, record, length));
  put32(bytes + 24u, ~crc_step(UINT32_MAX, bytes, 24u));
  if (j->program(j->context, slot, 0u, bytes, 32u) != 0 ||
      j->sync(j->context) != 0)
    return ORBIT_CLIENT_STORAGE;
  for (at = 0u; at < length; at += n) {
    uint32_t padded;
    n = length - at;
    if (n > sizeof(bytes))
      n = sizeof(bytes);
    padded = (n + 15u) & ~15u;
    for (i = 0u; i < padded; ++i)
      bytes[i] = 255u;
    orbit_copy(bytes, record + at, n);
    if (j->program(j->context, slot, 64u + at, bytes, padded) != 0)
      return ORBIT_CLIENT_STORAGE;
  }
  if (j->sync(j->context) != 0)
    return ORBIT_CLIENT_STORAGE;
  orbit_zero(bytes, 16u);
  if (j->program(j->context, slot, 48u, bytes, 16u) != 0 ||
      j->sync(j->context) != 0)
    return ORBIT_CLIENT_STORAGE;
  return 0;
}
