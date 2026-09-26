#ifndef ORBIT_STORAGE_H
#define ORBIT_STORAGE_H
#include "orbit_client.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Two independently erasable reserved slots, each at least 1088 bytes. Only
 * this adapter may own them. read/program are exact; erased bytes are 0xff.
 * program offsets and lengths are multiples of sixteen, permitting encrypted
 * ESP32 flash and STM32G0 doubleword writes. sync establishes durability. A synced intent fences the old generation before
 * erase; a write failure before any persistent change cannot guarantee denial
 * after power loss. The port owns
 * locking and any platform encryption/read protection; CRC detects torn data,
 * not malicious tampering. Never overwrite firmware or an unreserved sector. */
typedef struct orbit_journal {
  void *context;
  uint32_t slot_bytes;
  int32_t (*read)(void *context, uint8_t slot, uint32_t offset, uint8_t *bytes,
                  uint32_t length);
  int32_t (*erase)(void *context, uint8_t slot);
  int32_t (*program)(void *context, uint8_t slot, uint32_t offset,
                     const uint8_t *bytes, uint32_t length);
  int32_t (*sync)(void *context);
} orbit_journal_t;
int32_t orbit_journal_load(void *journal, uint8_t *record, uint32_t capacity,
                           uint32_t *length);
int32_t orbit_journal_commit(void *journal, uint64_t expected_generation,
                             const uint8_t *record, uint32_t length);
#ifdef __cplusplus
}
#endif
#endif
