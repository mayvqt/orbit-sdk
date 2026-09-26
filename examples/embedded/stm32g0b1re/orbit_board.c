#include "orbit_stm32g0.h"
#include "client.h"
static orbit_stm32g0_t board;
/* Call after HAL and the dedicated host UART are initialized. Pass the actual
 * end of flash-resident firmware from the linker map. Reserve the last two
 * pages (0x0807f000..0x0807ffff) in your STM32Cube linker script. */
int32_t orbit_board_start(UART_HandleTypeDef*uart,uint32_t firmware_end){orbit_client_services_t services;int32_t r=orbit_stm32g0_open(&board,uart,0x0807f000u,0x0807f800u,firmware_end,*orbit_mbedtls_crypto(),&services);return r?r:orbit_example_start(&services);}
/* Main loop: orbit_example_tick(); check orbit_example_check()==0 immediately
 * before the protected action. The companion host runs orbit_bridge_host with
 * the same configured API origin on this trusted UART, with terminal echo off. */
