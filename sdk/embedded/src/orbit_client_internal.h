#ifndef ORBIT_CLIENT_INTERNAL_H
#define ORBIT_CLIENT_INTERNAL_H
#include "orbit_client.h"
#include "orbit_internal.h"
#include "orbit_json.h"

typedef struct orbit_writer {
    uint8_t *bytes;
    uint32_t length, capacity;
    int32_t status;
} orbit_writer_t;
void orbit_write(orbit_writer_t *w, const void *bytes, uint32_t length);
void orbit_write_string(orbit_writer_t *w, orbit_embedded_slice_t value);
#define ORBIT_LITERAL(w, s) orbit_write((w), (s), (uint32_t)(sizeof(s) - 1u))

int orbit_client_opaque(orbit_embedded_slice_t value, uint32_t minimum, uint32_t maximum);
int32_t orbit_record_encode(const orbit_record_t *r, uint8_t *bytes, uint32_t *length);
int32_t orbit_record_decode(const uint8_t *bytes, uint32_t length, orbit_record_t *r);

typedef struct orbit_reply {
    orbit_json_span_t grant, activation, installation, credential, binding, provider;
    int64_t server_time, credential_expiry, licence_expiry;
    uint8_t has_credential, has_credential_expiry, has_licence_expiry, has_provider, replay_expired;
} orbit_reply_t;
int32_t orbit_reply_parse(const uint8_t *bytes, uint32_t length, uint8_t *scratch,
                          orbit_reply_t *reply);
#endif
