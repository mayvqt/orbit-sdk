#include "client.h"
#include "orbit_stm32g0.h"
#include "stm32g0xx_hal.h"

int32_t orbit_board_start(UART_HandleTypeDef *uart, uint32_t firmware_end);
extern uint32_t __flash_image_end;

/* Link-only entry point. Hardware UART initialization and board execution are
 * deliberately outside this harness. */
int main(void) {
  UART_HandleTypeDef uart = {0};
  return orbit_board_start(&uart, (uint32_t)(uintptr_t)&__flash_image_end);
}
