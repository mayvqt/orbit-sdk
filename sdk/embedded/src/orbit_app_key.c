#include "orbit_app_key.h"
#include "orbit_client_internal.h"

static int ascii_space(uint8_t value) {
  return (value >= 9u && value <= 13u) || value == 32u;
}

static uint32_t leading_space(const uint8_t *bytes, uint32_t length) {
  uint8_t a, b, c;
  if (length == 0u)
    return 0u;
  a = bytes[0];
  if (ascii_space(a))
    return 1u;
  if (length >= 2u && a == 0xc2u && (bytes[1] == 0x85u || bytes[1] == 0xa0u))
    return 2u;
  if (length >= 3u) {
    b = bytes[1];
    c = bytes[2];
    if ((a == 0xe1u && b == 0x9au && c == 0x80u) ||
        (a == 0xe3u && b == 0x80u && c == 0x80u) ||
        (a == 0xe2u && b == 0x80u && c >= 0x80u && c <= 0x8au) ||
        (a == 0xe2u && b == 0x80u && (c == 0xa8u || c == 0xa9u || c == 0xafu)) ||
        (a == 0xe2u && b == 0x81u && c == 0x9fu))
      return 3u;
  }
  return 0u;
}

static uint32_t trailing_space(const uint8_t *bytes, uint32_t length) {
  uint8_t a, b, c;
  if (length == 0u)
    return 0u;
  c = bytes[length - 1u];
  if (ascii_space(c))
    return 1u;
  if (length >= 2u) {
    a = bytes[length - 2u];
    if (a == 0xc2u && (c == 0x85u || c == 0xa0u))
      return 2u;
  }
  if (length >= 3u) {
    a = bytes[length - 3u];
    b = bytes[length - 2u];
    if ((a == 0xe1u && b == 0x9au && c == 0x80u) ||
        (a == 0xe3u && b == 0x80u && c == 0x80u) ||
        (a == 0xe2u && b == 0x80u && c >= 0x80u && c <= 0x8au) ||
        (a == 0xe2u && b == 0x80u && (c == 0xa8u || c == 0xa9u || c == 0xafu)) ||
        (a == 0xe2u && b == 0x81u && c == 0x9fu))
      return 3u;
  }
  return 0u;
}

static int port_valid(const uint8_t *bytes, uint32_t length) {
  uint32_t i, value = 0u;
  if (length == 0u)
    return 0;
  for (i = 0u; i < length; ++i) {
    uint32_t digit;
    if (bytes[i] < '0' || bytes[i] > '9')
      return 0;
    digit = (uint32_t)(bytes[i] - '0');
    if (value > (65535u - digit) / 10u)
      return 0;
    value = value * 10u + digit;
  }
  return value != 0u;
}

static int ipv4_valid(const uint8_t *bytes, uint32_t length) {
  uint32_t i = 0u, value = 0u, digits = 0u, parts = 0u;
  if (length == 0u)
    return 0;
  for (;;) {
    if (i == length || bytes[i] == '.') {
      if (digits == 0u || (digits > 1u && bytes[i - digits] == '0') || value > 255u)
        return 0;
      ++parts;
      if (parts == 4u)
        return i == length;
      if (i == length)
        return 0;
      value = 0u;
      digits = 0u;
      ++i;
      continue;
    }
    if (bytes[i] < '0' || bytes[i] > '9')
      return 0;
    if (++digits > 3u)
      return 0;
    value = value * 10u + (uint32_t)(bytes[i] - '0');
    ++i;
  }
}

static int hex_value(uint8_t value) {
  if (value >= '0' && value <= '9')
    return (int)(value - '0');
  if (value >= 'a' && value <= 'f')
    return (int)(value - 'a') + 10;
  return -1;
}

static uint32_t append_hex(char *output, uint32_t at, uint16_t value) {
  static const char digits[] = "0123456789abcdef";
  char reverse[4];
  uint32_t count = 0u;
  do {
    reverse[count++] = digits[value & 15u];
    value >>= 4u;
  } while (value != 0u);
  while (count != 0u)
    output[at++] = reverse[--count];
  return at;
}

static int ipv6_valid(const uint8_t *bytes, uint32_t length) {
  uint16_t words[8];
  char canonical[40];
  uint32_t i = 0u, count = 0u, compressed = UINT32_MAX;
  uint32_t best_start = UINT32_MAX, best_length = 0u, at = 0u, j;
  if (length == 0u)
    return 0;
  if (length >= 2u && bytes[0] == ':' && bytes[1] == ':') {
    compressed = 0u;
    i = 2u;
    if (i == length)
      count = 0u;
  } else if (bytes[0] == ':')
    return 0;
  while (i < length) {
    uint32_t start = i, group_length;
    uint32_t value = 0u;
    while (i < length && bytes[i] != ':') {
      if (hex_value(bytes[i]) < 0 || ++i - start > 4u)
        return 0;
      value = value * 16u + (uint32_t)hex_value(bytes[i - 1u]);
    }
    group_length = i - start;
    if (group_length == 0u || count >= 8u)
      return 0;
    words[count++] = (uint16_t)value;
    if (i == length)
      break;
    if (i + 1u < length && bytes[i + 1u] == ':') {
      if (compressed != UINT32_MAX)
        return 0;
      compressed = count;
      i += 2u;
      if (i == length)
        break;
    } else {
      ++i;
      if (i == length)
        return 0;
    }
  }
  if (compressed == UINT32_MAX) {
    if (count != 8u)
      return 0;
  } else {
    uint32_t missing;
    if (count > 6u || compressed > count)
      return 0;
    missing = 8u - count;
    for (j = count; j > compressed; --j)
      words[j - 1u + missing] = words[j - 1u];
    for (j = 0u; j < missing; ++j)
      words[compressed + j] = 0u;
    count = 8u;
  }
  for (i = 0u; i < 8u;) {
    if (words[i] != 0u) {
      ++i;
      continue;
    }
    j = i;
    while (j < 8u && words[j] == 0u)
      ++j;
    if (j - i > best_length && j - i >= 2u) {
      best_start = i;
      best_length = j - i;
    }
    i = j;
  }
  for (i = 0u; i < 8u;) {
    if (i == best_start) {
      canonical[at++] = ':';
      canonical[at++] = ':';
      i += best_length;
      if (i == 8u)
        break;
    } else {
      if (at != 0u && canonical[at - 1u] != ':')
        canonical[at++] = ':';
      at = append_hex(canonical, at, words[i++]);
    }
  }
  return at == length && orbit_equal(bytes, canonical, length);
}

static int dns_valid(const uint8_t *bytes, uint32_t length) {
  uint32_t i, label_start = 0u, label_length = 0u;
  uint32_t last_start = 0u, host_end = length;
  int all_numeric_dots = 1;
  if (length == 0u || length > 253u)
    return 0;
  for (i = 0u; i < length; ++i) {
    uint8_t c = bytes[i];
    if (c == '.') {
      if (label_length == 0u || label_length > 63u ||
          bytes[label_start] == '-' || bytes[i - 1u] == '-')
        return 0;
      last_start = label_start;
      label_start = i + 1u;
      label_length = 0u;
      if (i == length - 1u)
        host_end = i;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-'))
      return 0;
    if (!(c >= '0' && c <= '9'))
      all_numeric_dots = 0;
    ++label_length;
  }
  if (label_length != 0u) {
    if (label_length > 63u || bytes[label_start] == '-' || bytes[length - 1u] == '-')
      return 0;
    last_start = label_start;
  } else if (length == 1u || bytes[length - 1u] != '.')
    return 0;
  if (all_numeric_dots)
    return ipv4_valid(bytes, host_end);
  /* WHATWG URL parsers treat numeric final labels as IPv4 candidates. */
  if (last_start < host_end) {
    uint32_t n = host_end - last_start;
    int numeric = 1;
    for (i = last_start; i < host_end; ++i)
      if (bytes[i] < '0' || bytes[i] > '9')
        numeric = 0;
    if (numeric || (n > 2u && bytes[last_start] == '0' &&
                    (bytes[last_start + 1u] == 'x' ||
                     bytes[last_start + 1u] == 'X')))
      return 0;
  }
  return 1;
}

#ifndef ORBIT_ENABLE_SERVICES
static
#endif
int orbit_https_origin_valid(const uint8_t *origin, uint32_t length) {
  uint32_t authority, host_end, i;
  if (origin == NULL || length < 9u || length > ORBIT_APP_KEY_ORIGIN_MAX_BYTES ||
      !orbit_json_valid_utf8_no_nul(origin, length) ||
      !orbit_equal(origin, "https://", 8u) || origin[length - 1u] == '/')
    return 0;
  authority = 8u;
  for (i = authority; i < length; ++i)
    if (origin[i] <= 32u || origin[i] >= 127u || origin[i] == '/' ||
        origin[i] == '\\' || origin[i] == '@' || origin[i] == '?' ||
        origin[i] == '#' || origin[i] == '%')
      return 0;
  if (origin[authority] == '[') {
    uint32_t close = authority + 1u;
    while (close < length && origin[close] != ']')
      ++close;
    if (close == length || !ipv6_valid(origin + authority + 1u, close - authority - 1u))
      return 0;
    if (close + 1u == length)
      return 1;
    return origin[close + 1u] == ':' && port_valid(origin + close + 2u, length - close - 2u);
  }
  host_end = authority;
  while (host_end < length && origin[host_end] != ':')
    ++host_end;
  if (!dns_valid(origin + authority, host_end - authority))
    return 0;
  if (host_end == length)
    return 1;
  return port_valid(origin + host_end + 1u, length - host_end - 1u);
}

static void clear_origin(uint8_t *origin, uint32_t capacity) {
  if (origin != NULL) {
    uint32_t length = capacity < ORBIT_APP_KEY_ORIGIN_MAX_BYTES
                          ? capacity
                          : ORBIT_APP_KEY_ORIGIN_MAX_BYTES;
    orbit_zero(origin, length);
  }
}

static int32_t fail(uint8_t *origin, uint32_t capacity,
                    orbit_client_config_t *config) {
  clear_origin(origin, capacity);
  orbit_zero(config, sizeof(*config));
  return ORBIT_CLIENT_ARGUMENT;
}

int32_t orbit_app_key_parse(orbit_embedded_slice_t app_key,
                            uint8_t *origin_buffer,
                            uint32_t origin_capacity,
                            orbit_client_config_t *config) {
  static const uint8_t test_prefix[] = "orbit_app_test_";
  static const uint8_t live_prefix[] = "orbit_app_live_";
  uint32_t start = 0u, end = app_key.length, prefix_length, first, second;
  uint32_t origin_length = 0u, key_length, id1_length, id2_length;
  const uint8_t *key;
  int32_t decoded;
  if (config == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  if (app_key.data != NULL &&
      orbit_overlap(app_key.data, app_key.length, config, sizeof(*config)))
    return ORBIT_CLIENT_ARGUMENT;
  if (origin_buffer != NULL &&
      orbit_overlap(origin_buffer, origin_capacity, config, sizeof(*config)))
    return ORBIT_CLIENT_ARGUMENT;
  orbit_zero(config, sizeof(*config));
  if (app_key.data == NULL || app_key.length == 0u || origin_buffer == NULL ||
      origin_capacity == 0u)
    return fail(origin_buffer, origin_capacity, config);
  if (orbit_overlap(app_key.data, app_key.length, origin_buffer, origin_capacity))
    return ORBIT_CLIENT_ARGUMENT;
  key = app_key.data;
  while (start < end) {
    uint32_t width = leading_space(key + start, end - start);
    if (width == 0u)
      break;
    start += width;
  }
  while (end > start) {
    uint32_t width = trailing_space(key + start, end - start);
    if (width == 0u)
      break;
    end -= width;
  }
  key += start;
  key_length = end - start;
  if (key_length == 0u || key_length > ORBIT_APP_KEY_MAX_LENGTH)
    return fail(origin_buffer, origin_capacity, config);
  if (key_length >= sizeof(test_prefix) - 1u &&
      orbit_equal(key, test_prefix, sizeof(test_prefix) - 1u))
    prefix_length = (uint32_t)sizeof(test_prefix) - 1u;
  else if (key_length >= sizeof(live_prefix) - 1u &&
           orbit_equal(key, live_prefix, sizeof(live_prefix) - 1u))
    prefix_length = (uint32_t)sizeof(live_prefix) - 1u;
  else
    return fail(origin_buffer, origin_capacity, config);
  first = prefix_length;
  while (first < key_length && key[first] != '.')
    ++first;
  if (first == prefix_length || first == key_length)
    return fail(origin_buffer, origin_capacity, config);
  second = first + 1u;
  while (second < key_length && key[second] != '.')
    ++second;
  if (second == first + 1u || second == key_length ||
      second + 1u == key_length)
    return fail(origin_buffer, origin_capacity, config);
  {
    uint32_t extra = second + 1u;
    while (extra < key_length)
      if (key[extra++] == '.')
        return fail(origin_buffer, origin_capacity, config);
  }
  id1_length = second - first - 1u;
  id2_length = key_length - second - 1u;
  if (!orbit_client_opaque((orbit_embedded_slice_t){key + first + 1u, id1_length}, 1u, 128u) ||
      !orbit_client_opaque((orbit_embedded_slice_t){key + second + 1u, id2_length}, 1u, 128u))
    return fail(origin_buffer, origin_capacity, config);
  decoded = orbit_base64url_decode(key + prefix_length, first - prefix_length,
                                   origin_buffer,
                                   origin_capacity < ORBIT_APP_KEY_ORIGIN_MAX_BYTES
                                       ? origin_capacity
                                       : ORBIT_APP_KEY_ORIGIN_MAX_BYTES,
                                   &origin_length);
  if (decoded != ORBIT_GRANT_STATUS_OK || !orbit_https_origin_valid(origin_buffer, origin_length))
    return fail(origin_buffer, origin_capacity, config);
  config->api_origin = (orbit_embedded_slice_t){origin_buffer, origin_length};
  config->issuer = config->api_origin;
#ifdef ORBIT_ENABLE_SERVICES
  config->environment_kind = key[10] == 't' ? 1u : 2u;
#endif
  config->application_id = (orbit_embedded_slice_t){key + first + 1u, id1_length};
  config->environment_id = (orbit_embedded_slice_t){key + second + 1u, id2_length};
  return ORBIT_CLIENT_OK;
}
