#ifndef ORBIT_ESP8266_HPP
#define ORBIT_ESP8266_HPP
#include "orbit_platform.h"
#include <ESP8266WiFi.h>
#include <LittleFS.h>
#include <WiFiClientSecureBearSSL.h>
/* Static-lifetime, single owner. Mount LittleFS without automatic formatting;
 * establish trusted UTC before open. A CA object must outlive this context.
 * Keep the default TLS receive buffer unless the server negotiates MFLN. */
struct orbit_esp8266 {
  orbit_platform_t platform{};
  BearSSL::WiFiClientSecure connection;
  BearSSL::X509List *roots = nullptr;
  bool trusted_time = false;
};
int32_t orbit_esp8266_open(orbit_esp8266 *, BearSSL::X509List *,
                           orbit_client_services_t *);
#endif
