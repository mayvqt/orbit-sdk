#ifndef ORBIT_ESP32_H
#define ORBIT_ESP32_H
#include "esp_partition.h"
#include "esp_tls.h"
#include "orbit_platform.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct orbit_esp32 {
  orbit_platform_t platform;
  const esp_partition_t *partition;
  const char *root_ca_pem;
  esp_tls_t *connection;
  uint8_t trusted_time;
} orbit_esp32_t;
/* Call after Wi-Fi is started (hardware CSPRNG entropy source enabled), trusted
 * UTC has been established, and a dedicated >=8192-byte data partition exists.
 * Secure boot, flash encryption and encrypted storage are deployment settings.
 * Deep sleep resumes through init, never a retained grant. root_ca includes
 * NUL. */
int32_t orbit_esp32_open(orbit_esp32_t *, const char *partition_label,
                         const char *root_ca_pem, orbit_client_services_t *);
#ifdef __cplusplus
}
#endif
#endif
