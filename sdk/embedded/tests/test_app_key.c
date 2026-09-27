#include "orbit_app_key.h"
#include "orbit_generated_app_key_vectors.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "app-key:%d: %s\n", __LINE__, #x);                     \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int matches(orbit_embedded_slice_t slice, const char *expected) {
  uint32_t length = (uint32_t)strlen(expected);
  return slice.length == length &&
         (length == 0u || (slice.data != NULL && memcmp(slice.data, expected, length) == 0));
}

static int zeroed(const orbit_client_config_t *config) {
  const uint8_t *bytes = (const uint8_t *)config;
  uint32_t i;
  for (i = 0u; i < sizeof(*config); ++i)
    if (bytes[i] != 0u)
      return 0;
  return 1;
}
static int zero_bytes(const uint8_t *bytes, uint32_t length) {
  uint32_t i;
  for (i = 0u; i < length; ++i)
    if (bytes[i] != 0u)
      return 0;
  return 1;
}

static uint32_t encode_origin(const char *origin, char *key, uint32_t capacity) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  static const char prefix[] = "orbit_app_test_";
  uint32_t at = (uint32_t)(sizeof(prefix) - 1u), bits = 0u, value = 0u;
  uint32_t i, length = (uint32_t)strlen(origin);
  if (capacity < at + 8u)
    return 0u;
  memcpy(key, prefix, at);
  for (i = 0u; i < length; ++i) {
    value = (value << 8u) | (uint8_t)origin[i];
    bits += 8u;
    while (bits >= 6u) {
      bits -= 6u;
      if (at + 8u >= capacity)
        return 0u;
      key[at++] = alphabet[(value >> bits) & 63u];
    }
  }
  if (bits != 0u) {
    if (at + 8u >= capacity)
      return 0u;
    key[at++] = alphabet[(value << (6u - bits)) & 63u];
  }
  if (at + 8u >= capacity)
    return 0u;
  memcpy(key + at, ".app.env", 8u);
  at += 8u;
  key[at] = '\0';
  return at;
}

static int origin_case(const char *origin_text, int expected_valid) {
  char key[1024];
  uint8_t decoded[ORBIT_APP_KEY_ORIGIN_MAX_BYTES];
  orbit_client_config_t parsed;
  uint32_t key_length = encode_origin(origin_text, key, sizeof(key));
  int32_t status;
  CHECK(key_length != 0u);
  memset(decoded, 0xa5, sizeof(decoded));
  memset(&parsed, 0xa5, sizeof(parsed));
  status = orbit_app_key_parse(
      (orbit_embedded_slice_t){(const uint8_t *)key, key_length}, decoded,
      sizeof(decoded), &parsed);
  if (expected_valid) {
    uint32_t origin_length = (uint32_t)strlen(origin_text);
    CHECK(status == ORBIT_CLIENT_OK);
    CHECK(parsed.api_origin.data == decoded && parsed.issuer.data == decoded);
    CHECK(parsed.api_origin.length == origin_length &&
          parsed.issuer.length == origin_length);
    CHECK(memcmp(decoded, origin_text, origin_length) == 0);
    CHECK(matches(parsed.application_id, "app"));
    CHECK(matches(parsed.environment_id, "env"));
  } else {
    CHECK(status != ORBIT_CLIENT_OK);
    CHECK(zeroed(&parsed) && zero_bytes(decoded, sizeof(decoded)));
  }
  return 0;
}

int main(void) {
  uint32_t i, valid_count = 0u, invalid_count = 0u;
  uint8_t origin[ORBIT_APP_KEY_ORIGIN_MAX_BYTES];
  orbit_client_config_t config;
  for (i = 0u; i < GENERATED_APP_KEY_VECTOR_COUNT; ++i) {
    const generated_app_key_vector_t *vector = &generated_app_key_vectors[i];
    const orbit_embedded_slice_t key = {
        (const uint8_t *)vector->key, (uint32_t)strlen(vector->key)};
    memset(origin, 0xa5, sizeof(origin));
    memset(&config, 0xa5, sizeof(config));
    const int32_t status = orbit_app_key_parse(key, origin, sizeof(origin), &config);
    if (vector->valid) {
      if (status != ORBIT_CLIENT_OK ||
          !matches(config.api_origin, vector->api_origin) ||
          !matches(config.issuer, vector->issuer) ||
          !matches(config.application_id, vector->application_id) ||
          !matches(config.environment_id, vector->environment_id) ||
          config.api_origin.data != origin || config.issuer.data != origin ||
          config.fingerprint.data != NULL || config.fingerprint.length != 0u ||
          config.fingerprint_provider.data != NULL ||
          config.fingerprint_provider.length != 0u) {
        fprintf(stderr, "vector %u (%s): parse mismatch status=%d\n", i,
                vector->name, (int)status);
        return 1;
      }
      ++valid_count;
    } else {
      if (status == ORBIT_CLIENT_OK || !zeroed(&config) ||
          !zero_bytes(origin, sizeof(origin))) {
        fprintf(stderr, "vector %u (%s): invalid key was accepted or output retained\n",
                i, vector->name);
        return 1;
      }
      ++invalid_count;
    }
  }
  CHECK(origin_case("https://ORBIT.example.com", 1) == 0);
  CHECK(origin_case("https://orbit.example.com:443", 1) == 0);
  CHECK(origin_case("https://orbit.example.com:0443", 1) == 0);
  CHECK(origin_case("https://orbit.example.com:65535", 1) == 0);
  CHECK(origin_case("https://orbit.example.com.", 1) == 0);
  CHECK(origin_case("https://127.0.0.1", 1) == 0);
  CHECK(origin_case("https://[2001:db8::1]", 1) == 0);
  CHECK(origin_case("https://[2001:db8::1]:0443", 1) == 0);
  CHECK(origin_case("https://orbit.example.com:0", 0) == 0);
  CHECK(origin_case("https://orbit.example.com:0000", 0) == 0);
  CHECK(origin_case("https://orbit.example.com:65536", 0) == 0);
  CHECK(origin_case("https://orbit.example.com:12x", 0) == 0);
  CHECK(origin_case("https://orbit.example.com:", 0) == 0);
  CHECK(origin_case("https://example.com..", 0) == 0);
  CHECK(origin_case("https://.example.com", 0) == 0);
  CHECK(origin_case("https://256.0.0.1", 0) == 0);
  CHECK(origin_case("https://[2001::db8::1]", 0) == 0);
  CHECK(origin_case("https://[2001:db8::1]:65536", 0) == 0);
  {
    static const char key_text[] =
        "orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.env";
    uint8_t tiny[1], overlap[128];
    uint8_t before[sizeof(config)];
    union {
      orbit_client_config_t config;
      uint8_t bytes[512];
    } alias;
    memset(&config, 0xa5, sizeof(config));
    memcpy(before, &config, sizeof(config));
    CHECK(orbit_app_key_parse(
              (orbit_embedded_slice_t){(const uint8_t *)key_text,
                                       sizeof(key_text) - 1u},
              tiny, sizeof(tiny), &config) == ORBIT_CLIENT_ARGUMENT);
    CHECK(zeroed(&config) && tiny[0] == 0u);
    memset(&config, 0xa5, sizeof(config));
    CHECK(orbit_app_key_parse(
              (orbit_embedded_slice_t){(const uint8_t *)key_text,
                                       sizeof(key_text) - 1u},
              (uint8_t *)&config, sizeof(config), &config) == ORBIT_CLIENT_ARGUMENT);
    CHECK(memcmp(before, &config, sizeof(config)) == 0);
    memcpy(overlap, key_text, sizeof(key_text) - 1u);
    memset(&config, 0xa5, sizeof(config));
    CHECK(orbit_app_key_parse(
              (orbit_embedded_slice_t){overlap, sizeof(key_text) - 1u},
              overlap + 8u, sizeof(overlap) - 8u, &config) == ORBIT_CLIENT_ARGUMENT);
    CHECK(zeroed(&config) &&
          memcmp(overlap, key_text, sizeof(key_text) - 1u) == 0);
    memcpy(alias.bytes, key_text, sizeof(key_text) - 1u);
    CHECK(orbit_app_key_parse(
              (orbit_embedded_slice_t){alias.bytes, sizeof(key_text) - 1u},
              origin, sizeof(origin), &alias.config) == ORBIT_CLIENT_ARGUMENT);
    CHECK(memcmp(alias.bytes, key_text, sizeof(key_text) - 1u) == 0);
  }
  printf("shared app-key vectors: %zu passed (%u accepted, %u rejected)\n",
         GENERATED_APP_KEY_VECTOR_COUNT, valid_count, invalid_count);
  return 0;
}
