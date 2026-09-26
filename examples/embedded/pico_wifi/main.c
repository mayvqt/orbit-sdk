#include "orbit_pico.h"
#include "client.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
/* Your firmware provisions Wi-Fi, a real CA root, trusted UTC (for example an
 * authenticated RTC), and a maintained CSPRNG seeded from trusted hardware or
 * a provisioned secure element. Defaults deliberately grant no access. */
__attribute__((weak)) int orbit_board_wifi_connect(void){return -1;}
__attribute__((weak)) const uint8_t*orbit_board_root_ca(uint32_t*n){*n=0;return NULL;}
__attribute__((weak)) int32_t orbit_board_clock(void*p,int64_t*u,uint64_t*t){(void)p;(void)u;(void)t;return ORBIT_CLIENT_CLOCK;}
__attribute__((weak)) int32_t orbit_board_entropy(void*p,uint8_t*b,uint32_t n){(void)p;(void)b;(void)n;return ORBIT_CLIENT_UNTRUSTED;}
int main(void){static orbit_pico_t board;orbit_client_services_t services;uint32_t ca_length;stdio_init_all();if(cyw43_arch_init()||orbit_board_wifi_connect())return 1;const uint8_t*ca=orbit_board_root_ca(&ca_length);if(orbit_pico_open(&board,ca,ca_length,PICO_FLASH_SIZE_BYTES-8192,NULL,orbit_board_clock,orbit_board_entropy,&services)||orbit_example_start(&services))return 1;for(;;){(void)orbit_example_tick();/* Gate each protected operation with orbit_example_check(). */cyw43_arch_poll();sleep_ms(500);}}
