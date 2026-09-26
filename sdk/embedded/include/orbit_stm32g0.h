#ifndef ORBIT_STM32G0_H
#define ORBIT_STM32G0_H
#include "orbit_adapters.h"
#include "stm32g0xx_hal.h"
/* STM32G0B1RE: reserve two 2048-byte pages in the board linker script. These
 * addresses must map to the physical banks/pages supplied here (no bank swap).
 * UART is a dedicated trusted host bridge, never an unauthenticated network.
 * Use the maintained Mbed TLS adapter or another verified P-256 provider. */
typedef struct orbit_stm32g0 {
  orbit_bridge_t bridge;
  orbit_journal_t journal;
  UART_HandleTypeDef *uart;
  uint32_t addresses[2], banks[2], pages[2];
} orbit_stm32g0_t;
int32_t orbit_stm32g0_open(orbit_stm32g0_t *, UART_HandleTypeDef *,
                           uint32_t first_address, uint32_t second_address,
                           uint32_t firmware_flash_end, orbit_grant_crypto_t,
                           orbit_client_services_t *);
#endif
