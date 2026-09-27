#ifndef ORBIT_SERVICES_H
#define ORBIT_SERVICES_H
#include "orbit_client.h"
#ifdef __cplusplus
extern "C" {
#endif
#define ORBIT_SAFE_INTEGER_MAX UINT64_C(9007199254740991)
#define ORBIT_CLIENT_CANCELLED ((int32_t)23)
#define ORBIT_CLIENT_CAPACITY ((int32_t)24)
#define ORBIT_CLIENT_SESSION_REQUIRED ((int32_t)25)
#define ORBIT_OPERATION_ID_BYTES 128u
/* Empty id generates 128 random bits. Copy result.operation_id before retrying
 * an uncertain outcome, and pass it back unchanged. Cancellation is
 * cooperative; platform I/O must have a finite timeout. Callbacks must not
 * reenter. */
typedef struct orbit_operation {
  orbit_embedded_slice_t id;
  void *context;
  int32_t (*cancelled)(void *context);
} orbit_operation_t;
typedef enum orbit_usage_period {
  ORBIT_PERIOD_LIFETIME = 0,
  ORBIT_PERIOD_DAY = 1,
  ORBIT_PERIOD_MONTH = 2
} orbit_usage_period_t;
typedef struct orbit_counter {
  uint64_t limit, used, remaining;
  int64_t period_started_at, resets_at;
  uint8_t name[64];
  uint8_t name_length, period, usage;
} orbit_counter_t;
typedef struct orbit_limit_result {
  orbit_counter_t counter;
  uint64_t units;
  uint8_t operation_id[128], allocation_id[128], resource_id[128];
  uint8_t operation_id_length, allocation_id_length, resource_id_length;
  uint8_t released, capacity_denied, uncertain;
} orbit_limit_result_t;
/* Online calls use the durable activation proof directly. They never acquire a
 * floating seat, consume implicitly, or leave an explicitly selected file mode.
 * Result is initialized even on error; uncertain mutations retain their ID. */
int32_t orbit_client_usage(orbit_client_t *, orbit_embedded_slice_t name,
                           const orbit_operation_t *, orbit_limit_result_t *);
int32_t orbit_client_consume(orbit_client_t *, orbit_embedded_slice_t name,
                             uint64_t units, const orbit_operation_t *,
                             orbit_limit_result_t *);
int32_t orbit_client_resources(orbit_client_t *, orbit_embedded_slice_t name,
                               const orbit_operation_t *,
                               orbit_limit_result_t *);
int32_t orbit_client_acquire_resource(orbit_client_t *,
                                      orbit_embedded_slice_t name,
                                      orbit_embedded_slice_t resource_id,
                                      uint64_t units, const orbit_operation_t *,
                                      orbit_limit_result_t *);
int32_t orbit_client_release_resource(orbit_client_t *,
                                      orbit_embedded_slice_t name,
                                      orbit_embedded_slice_t allocation_id,
                                      const orbit_operation_t *,
                                      orbit_limit_result_t *);
#ifdef __cplusplus
}
#endif
#endif
