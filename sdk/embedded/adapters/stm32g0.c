#include "orbit_stm32g0.h"
#include <string.h>
#if !defined(STM32G0B1xx)
#error "This flash geometry is for STM32G0B1RE (512 KiB dual-bank flash)"
#endif
static int32_t receive_bytes(void *p, uint8_t *b, uint32_t n) {
  orbit_stm32g0_t *c = p;
  while (n) {
    uint16_t m = n > 65535 ? 65535 : (uint16_t)n;
    if (HAL_UART_Receive(c->uart, b, m, 30000) != HAL_OK)
      return ORBIT_CLIENT_UNTRUSTED;
    b += m;
    n -= m;
  }
  return 0;
}
static int32_t send_bytes(void *p, const uint8_t *b, uint32_t n) {
  orbit_stm32g0_t *c = p;
  while (n) {
    uint16_t m = n > 65535 ? 65535 : (uint16_t)n;
    if (HAL_UART_Transmit(c->uart, (uint8_t *)b, m, 30000) != HAL_OK)
      return ORBIT_CLIENT_UNTRUSTED;
    b += m;
    n -= m;
  }
  return 0;
}
static int32_t read_slot(void *p, uint8_t s, uint32_t o, uint8_t *b,
                         uint32_t n) {
  orbit_stm32g0_t *c = p;
  memcpy(b, (const void *)(uintptr_t)(c->addresses[s] + o), n);
  return 0;
}
static int32_t erase_slot(void *p, uint8_t s) {
  orbit_stm32g0_t *c = p;
  FLASH_EraseInitTypeDef e = {0};
  uint32_t error;
  e.TypeErase = FLASH_TYPEERASE_PAGES;
  e.Banks = c->banks[s];
  e.Page = c->pages[s];
  e.NbPages = 1;
  if (HAL_FLASH_Unlock() != HAL_OK)
    return ORBIT_CLIENT_STORAGE;
  HAL_StatusTypeDef result = HAL_FLASHEx_Erase(&e, &error);
  HAL_FLASH_Lock();
  return result == HAL_OK ? 0 : ORBIT_CLIENT_STORAGE;
}
static int32_t program_slot(void *p, uint8_t s, uint32_t o, const uint8_t *b,
                            uint32_t n) {
  orbit_stm32g0_t *c = p;
  int32_t result = 0;
  if (HAL_FLASH_Unlock() != HAL_OK)
    return ORBIT_CLIENT_STORAGE;
  for (uint32_t i = 0; i < n; i += 8) {
    uint64_t word;
    memcpy(&word, b + i, 8);
    if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, c->addresses[s] + o + i,
                          word) != HAL_OK) {
      result = ORBIT_CLIENT_STORAGE;
      break;
    }
  }
  HAL_FLASH_Lock();
  return result;
}
static int32_t sync_slot(void *p) {
  (void)p;
  __DSB();
  __ISB();
  return 0;
}
int32_t orbit_stm32g0_open(orbit_stm32g0_t *c, UART_HandleTypeDef *uart,
                           uint32_t a, uint32_t b, uint32_t firmware_end,
                           orbit_grant_crypto_t crypto,
                           orbit_client_services_t *s) {
  if (!c || !uart || !s || a == b || a % 2048 || b % 2048 || a < FLASH_BASE ||
      b < FLASH_BASE || a > FLASH_BASE + 512u * 1024u - 2048 ||
      b > FLASH_BASE + 512u * 1024u - 2048 || a < firmware_end ||
      b < firmware_end)
    return ORBIT_CLIENT_ARGUMENT;
  memset(c, 0, sizeof(*c));
  c->uart = uart;
  c->addresses[0] = a;
  c->addresses[1] = b;
  for (unsigned i = 0; i < 2; ++i) {
    uint32_t relative = c->addresses[i] - FLASH_BASE;
    c->banks[i] = relative >= 256u * 1024u ? FLASH_BANK_2 : FLASH_BANK_1;
    c->pages[i] = (relative % (256u * 1024u)) / 2048;
  }
  c->journal = (orbit_journal_t){c,          2048,         read_slot,
                                 erase_slot, program_slot, sync_slot};
  c->bridge.io_context = c;
  c->bridge.read = receive_bytes;
  c->bridge.write = send_bytes;
  c->bridge.journal = &c->journal;
  c->bridge.crypto = crypto;
  return orbit_bridge_services(&c->bridge, s);
}
