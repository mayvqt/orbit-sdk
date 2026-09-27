#include "orbit_storage.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "journal:%d: %s\n", __LINE__, #x);                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)
typedef struct flash {
  uint8_t slots[2][20480];
  uint32_t slot_bytes, calls, cut;
  int partial;
} flash_t;
static flash_t baseline, current;
static uint8_t record[17408], loaded[17408];
static int32_t read_slot(void *p, uint8_t slot, uint32_t at, uint8_t *b,
                         uint32_t n) {
  flash_t *f = p;
  if (slot > 1 || at > f->slot_bytes || n > f->slot_bytes - at)
    return 11;
  memcpy(b, f->slots[slot] + at, n);
  return 0;
}
static int32_t erase_slot(void *p, uint8_t slot) {
  flash_t *f = p;
  if (slot > 1)
    return 11;
  if (++f->calls == f->cut) {
    if (f->partial)
      memset(f->slots[slot], 255, f->slot_bytes / 2);
    return 11;
  }
  memset(f->slots[slot], 255, f->slot_bytes);
  return 0;
}
static int32_t program_slot(void *p, uint8_t slot, uint32_t at,
                            const uint8_t *b, uint32_t n) {
  flash_t *f = p;
  uint32_t i;
  if (slot > 1 || at > f->slot_bytes || n > f->slot_bytes - at || at % 16 ||
      n % 16)
    return 11;
  if (++f->calls == f->cut) {
    if (f->partial)
      for (i = 0; i < n / 2; ++i)
        f->slots[slot][at + i] &= b[i];
    return 11;
  }
  for (i = 0; i < n; ++i) {
    if ((f->slots[slot][at + i] & b[i]) != b[i])
      return 11;
    f->slots[slot][at + i] = b[i];
  }
  return 0;
}
static int32_t sync_slot(void *p) {
  flash_t *f = p;
  return ++f->calls == f->cut ? 11 : 0;
}
static void generation(uint8_t *b, uint64_t n) {
  unsigned i;
  for (i = 0; i < 8; ++i)
    b[8 + i] = (uint8_t)(n >> (i * 8));
}
int main(void) {
  uint32_t slots[] = {6144, 8192, 18432, 20480}, index, n, calls, cut, length;
  int partial, r;
  orbit_journal_t j = {&current,     0,        read_slot, erase_slot,
                       program_slot, sync_slot};
  for (index = 0; index < 4; ++index) {
    n = index < 2 ? 5120 : 17408;
    if (n > ORBIT_PROFILE_RECORD_BYTES)
      continue;
    memset(&current, 0, sizeof(current));
    memset(current.slots, 255, sizeof(current.slots));
    current.slot_bytes = slots[index];
    j.slot_bytes = slots[index];
    memset(record, 0x5a, n);
    memcpy(record, "ORBITMC1", 8);
    generation(record, 1);
    CHECK(orbit_journal_commit(&j, 0, record, n) == 0);
    baseline = current;
    generation(record, 2);
    record[n - 1] = 0xa5;
    current.calls = 0;
    CHECK(orbit_journal_commit(&j, 1, record, n) == 0);
    calls = current.calls;
    CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &length) == 0 &&
          length == n && !memcmp(record, loaded, n));
    for (partial = 0; partial < 2; ++partial)
      for (cut = 1; cut <= calls; ++cut) {
        current = baseline;
        current.calls = 0;
        current.cut = cut;
        current.partial = partial;
        CHECK(orbit_journal_commit(&j, 1, record, n) == ORBIT_CLIENT_STORAGE);
        current.cut = 0;
        r = orbit_journal_load(&j, loaded, sizeof(loaded), &length);
        /* Only failure before a persistent intent write may retain the old
         * record. Failure at the final sync may leave the complete new
         * generation. */
        if (r == 0)
          CHECK((cut == 1 && !partial && loaded[n - 1] == 0x5a) ||
                (cut == calls && loaded[n - 1] == 0xa5));
        else
          CHECK(r == ORBIT_CLIENT_STORAGE);
      }
    current = baseline;
    current.calls = 0;
    generation(record, 2);
    j.slot_bytes = n + 63;
    CHECK(orbit_journal_commit(&j, 1, record, n) == ORBIT_CLIENT_ARGUMENT);
    j.slot_bytes = slots[index];
  }
  puts("all journal cut points and slot ranges passed");
  return 0;
}
