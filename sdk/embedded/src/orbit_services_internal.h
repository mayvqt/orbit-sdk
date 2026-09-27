#ifndef ORBIT_SERVICES_INTERNAL_H
#define ORBIT_SERVICES_INTERNAL_H
#include "orbit_client_internal.h"
#include "orbit_services.h"
typedef struct orbit_field {
  const char *name;
  orbit_json_span_t value;
} orbit_field_t;
int32_t orbit_fields(const uint8_t *, uint32_t, uint8_t *, orbit_field_t *,
                     uint32_t);
int32_t orbit_field_string(uint8_t *, orbit_json_span_t,
                           orbit_embedded_slice_t *);
int32_t orbit_field_uint(const uint8_t *, orbit_json_span_t, uint64_t *);
int32_t orbit_field_time(const uint8_t *, orbit_json_span_t, int64_t *);
int orbit_field_null(const uint8_t *, orbit_json_span_t);
int orbit_slice_equal(orbit_embedded_slice_t, orbit_embedded_slice_t);
int orbit_limit_name(orbit_embedded_slice_t);
void orbit_write_uint(orbit_writer_t *, uint64_t);
void orbit_service_proof(orbit_client_state_t *, orbit_writer_t *);
int32_t orbit_service_begin(orbit_client_t *, const orbit_operation_t *,
                            orbit_client_state_t **);
int32_t orbit_service_exchange(orbit_client_state_t *,
                               orbit_embedded_slice_t path,
                               uint32_t body_length, const orbit_operation_t *,
                               uint16_t *, uint32_t *);
void orbit_service_finish(orbit_client_state_t *);
int32_t orbit_operation_id(orbit_client_state_t *, const orbit_operation_t *,
                           uint8_t[128], uint8_t *);
int32_t orbit_service_status(int32_t, uint16_t);
#endif
