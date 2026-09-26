#include <ESP8266WiFi.h>
#include <LittleFS.h>
#include <WiFiClientSecureBearSSL.h>
#include "orbit_esp8266.hpp"
#include "client.h"
static orbit_esp8266 board;
static bool ready=false;
/* Supply trusted UTC, Wi-Fi provisioning and a long-lived BearSSL::X509List
 * holding your API's CA roots. Never use setInsecure or auto-format LittleFS. */
__attribute__((weak)) bool orbit_board_ready(){return false;}
__attribute__((weak)) BearSSL::X509List*orbit_board_roots(){return nullptr;}
void setup(){if(!orbit_board_ready()||!LittleFS.begin())return;orbit_client_services_t services;ready=orbit_esp8266_open(&board,orbit_board_roots(),&services)==0&&orbit_example_start(&services)==0;}
void loop(){if(ready)(void)orbit_example_tick();/* Protect each operation with orbit_example_check(). */delay(500);}
