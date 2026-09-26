#include "orbit_esp32.h"
#include "client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
/* Implement these board provisioning hooks in your application. This default
 * refuses to run until Wi-Fi, trusted UTC and the real CA root are configured. */
__attribute__((weak)) int orbit_board_ready(void){return 0;}
__attribute__((weak)) const char*orbit_board_root_ca(void){return NULL;}
void app_main(void){static orbit_esp32_t board;orbit_client_services_t services;if(!orbit_board_ready())return;if(orbit_esp32_open(&board,"orbit",orbit_board_root_ca(),&services)||orbit_example_start(&services))return;for(;;){(void)orbit_example_tick();/* Call orbit_example_check immediately before your protected action. */vTaskDelay(pdMS_TO_TICKS(500));}}
