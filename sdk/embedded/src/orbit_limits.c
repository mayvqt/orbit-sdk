#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_services_internal.h"
#define F(n) {n, {0, 0}}
static int32_t counter(uint8_t *b, uint32_t n, uint8_t *scratch,
                       orbit_embedded_slice_t name, int usage, uint8_t action,
                       orbit_limit_result_t *out) {
  orbit_field_t f[] = {
      F("name"),          F("limit"),           F("used"),
      F("remaining"),     F("period"),          F("period_started_at"),
      F("resets_at"),     F("idempotency_key"), F("consumed_units"),
      F("allocation_id"), F("resource_id"),     F("units"),
      F("state")};
  orbit_embedded_slice_t text;
  uint64_t units;
  uint32_t i;
  if (orbit_fields(b, n, scratch, f, 13) ||
      orbit_field_string(b, f[0].value, &text) ||
      !orbit_slice_equal(text, name) ||
      orbit_field_uint(b, f[1].value, &out->counter.limit) ||
      orbit_field_uint(b, f[2].value, &out->counter.used) ||
      orbit_field_uint(b, f[3].value, &out->counter.remaining) ||
      out->counter.used > out->counter.limit ||
      out->counter.remaining != out->counter.limit - out->counter.used)
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_copy(out->counter.name, name.data, name.length);
  out->counter.name_length = (uint8_t)name.length;
  out->counter.usage = (uint8_t)usage;
  if (usage) {
    if (orbit_field_string(b, f[4].value, &text))
      return ORBIT_CLIENT_UNTRUSTED;
    if (orbit_slice_equal(
            text, (orbit_embedded_slice_t){(const uint8_t *)"lifetime", 8})) {
      out->counter.period = ORBIT_PERIOD_LIFETIME;
      if (!orbit_field_null(b, f[5].value) || !orbit_field_null(b, f[6].value))
        return ORBIT_CLIENT_UNTRUSTED;
    } else {
      int day = orbit_slice_equal(
          text, (orbit_embedded_slice_t){(const uint8_t *)"day", 3});
      if (!day && !orbit_slice_equal(text, (orbit_embedded_slice_t){
                                               (const uint8_t *)"month", 5}))
        return ORBIT_CLIENT_UNTRUSTED;
      out->counter.period = day ? ORBIT_PERIOD_DAY : ORBIT_PERIOD_MONTH;
      if (orbit_field_time(b, f[5].value, &out->counter.period_started_at) ||
          orbit_field_time(b, f[6].value, &out->counter.resets_at) ||
          out->counter.period_started_at % 86400 ||
          out->counter.resets_at % 86400 ||
          out->counter.resets_at <= out->counter.period_started_at)
        return ORBIT_CLIENT_UNTRUSTED;
      if (!day &&
          (b[f[5].value.start + 9] != '0' || b[f[5].value.start + 10] != '1' ||
           b[f[6].value.start + 9] != '0' || b[f[6].value.start + 10] != '1'))
        return ORBIT_CLIENT_UNTRUSTED;
      if (day ? out->counter.resets_at - out->counter.period_started_at != 86400
              : (out->counter.resets_at - out->counter.period_started_at <
                     2419200 ||
                 out->counter.resets_at - out->counter.period_started_at >
                     2678400))
        return ORBIT_CLIENT_UNTRUSTED;
    }
    for (i = 9; i < 13; ++i)
      if (f[i].value.length)
        return ORBIT_CLIENT_UNTRUSTED;
  } else {
    for (i = 4; i < 7; ++i)
      if (f[i].value.length)
        return ORBIT_CLIENT_UNTRUSTED;
    if (f[8].value.length)
      return ORBIT_CLIENT_UNTRUSTED;
  }
  if (!action) {
    for (i = 7; i < 13; ++i)
      if (f[i].value.length)
        return ORBIT_CLIENT_UNTRUSTED;
    return 0;
  }
  if (orbit_field_string(b, f[7].value, &text) ||
      !orbit_slice_equal(text,
                         (orbit_embedded_slice_t){out->operation_id,
                                                  out->operation_id_length}))
    return ORBIT_CLIENT_UNTRUSTED;
  if (usage) {
    if (orbit_field_uint(b, f[8].value, &units) || units != out->units ||
        out->counter.used < units)
      return ORBIT_CLIENT_UNTRUSTED;
    return 0;
  }
  if (orbit_field_string(b, f[9].value, &text) ||
      !orbit_client_opaque(text, 1, 128))
    return ORBIT_CLIENT_UNTRUSTED;
  if (action == 3 && !orbit_slice_equal(text, (orbit_embedded_slice_t){
                                                  out->allocation_id,
                                                  out->allocation_id_length}))
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_copy(out->allocation_id, text.data, text.length);
  out->allocation_id_length = (uint8_t)text.length;
  if (orbit_field_string(b, f[10].value, &text) ||
      !orbit_client_opaque(text, 1, 128))
    return ORBIT_CLIENT_UNTRUSTED;
  if (action == 2 &&
      !orbit_slice_equal(text, (orbit_embedded_slice_t){
                                   out->resource_id, out->resource_id_length}))
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_copy(out->resource_id, text.data, text.length);
  out->resource_id_length = (uint8_t)text.length;
  if (orbit_field_uint(b, f[11].value, &units) || !units ||
      units > out->counter.limit || (action == 2 && units != out->units))
    return ORBIT_CLIENT_UNTRUSTED;
  out->units = units;
  if (orbit_field_string(b, f[12].value, &text))
    return ORBIT_CLIENT_UNTRUSTED;
  if (orbit_slice_equal(
          text, (orbit_embedded_slice_t){(const uint8_t *)"released", 8}))
    out->released = 1;
  else if (action == 3 ||
           !orbit_slice_equal(
               text, (orbit_embedded_slice_t){(const uint8_t *)"active", 6}))
    return ORBIT_CLIENT_UNTRUSTED;
  if (!out->released && out->counter.used < out->units)
    return ORBIT_CLIENT_UNTRUSTED;
  return 0;
}
static int32_t denial(uint8_t *b, uint32_t n, uint8_t *scratch,
                      orbit_embedded_slice_t name, int usage,
                      orbit_limit_result_t *out, uint16_t http,
                      uint8_t action) {
  orbit_field_t envelope[] = {F("error")};
  orbit_field_t f[] = {
      F("code"),    F("message"),         F("request_id"),
      F("counter"), F("idempotency_key"), F("requested_units")};
  orbit_embedded_slice_t text;
  uint64_t units;
  if (orbit_fields(b, n, scratch, envelope, 1))
    return ORBIT_CLIENT_UNTRUSTED;
  b += envelope[0].value.start;
  n = envelope[0].value.length;
  if (orbit_fields(b, n, scratch, f, 6) ||
      orbit_field_string(b, f[1].value, &text) || !text.length ||
      text.length > 1024 || orbit_field_string(b, f[2].value, &text) ||
      !orbit_client_opaque(text, 1, 64) ||
      orbit_field_string(b, f[0].value, &text))
    return ORBIT_CLIENT_UNTRUSTED;
  if (!orbit_slice_equal(
          text, (orbit_embedded_slice_t){
                    (const uint8_t *)(usage ? "usage_limit_reached"
                                            : "resource_limit_reached"),
                    usage ? 19u : 22u})) {
    static const struct {
      uint16_t status;
      const char *code;
    } definitive[] = {{401, "authentication_required"},
                      {401, "invalid_credentials"},
                      {401, "credential_expired"},
                      {401, "credential_revoked"},
                      {401, "reauthentication_required"},
                      {403, "access_denied"},
                      {403, "application_archived"},
                      {403, "device_mismatch"},
                      {403, "licence_expired"},
                      {403, "licence_suspended"},
                      {403, "licence_revoked"},
                      {403, "feature_unavailable"},
                      {404, "not_found"},
                      {404, "unknown_limit"},
                      {409, "idempotency_conflict"},
                      {409, "idempotency_expired"},
                      {409, "resource_units_conflict"},
                      {422, "invalid_limit_name"},
                      {422, "invalid_units"},
                      {422, "invalid_resource_id"},
                      {422, "invalid_idempotency_key"},
                      {422, "invalid_installation_id"}};
    uint32_t i, j;
    if (f[3].value.length || f[4].value.length || f[5].value.length)
      return ORBIT_CLIENT_UNTRUSTED;
    for (i = 0; i < sizeof(definitive) / sizeof(definitive[0]); ++i) {
      for (j = 0; definitive[i].code[j]; ++j) {
      }
      if (http == definitive[i].status &&
          orbit_slice_equal(text, (orbit_embedded_slice_t){
                                      (const uint8_t *)definitive[i].code, j}))
        return ORBIT_CLIENT_DENIED;
    }
    return ORBIT_CLIENT_UNTRUSTED;
  }
  if (http != 409 || (action != 1 && action != 2))
    return ORBIT_CLIENT_UNTRUSTED;
  if (orbit_field_string(b, f[4].value, &text) ||
      !orbit_slice_equal(text,
                         (orbit_embedded_slice_t){out->operation_id,
                                                  out->operation_id_length}) ||
      orbit_field_uint(b, f[5].value, &units) || units != out->units ||
      counter(b + f[3].value.start, f[3].value.length, scratch, name, usage, 0,
              out))
    return ORBIT_CLIENT_UNTRUSTED;
  if (out->units <= out->counter.remaining)
    return ORBIT_CLIENT_UNTRUSTED;
  out->capacity_denied = 1;
  out->uncertain = 0;
  return ORBIT_CLIENT_CAPACITY;
}
static int32_t limits(orbit_client_t *client, orbit_embedded_slice_t name,
                      orbit_embedded_slice_t identity, uint64_t units,
                      uint8_t action, int usage, const orbit_operation_t *op,
                      orbit_limit_result_t *out) {
  orbit_client_state_t *c;
  uint8_t path[512];
  uint32_t n;
  orbit_writer_t route = {path, 0, sizeof(path), 0}, body;
  uint16_t http;
  int32_t r;
  if (!out || !client || !orbit_limit_name(name) ||
      (action && action != 3 && (!units || units > ORBIT_SAFE_INTEGER_MAX)) ||
      ((action == 2 || action == 3) &&
       !orbit_client_opaque(identity, 1, 128)) ||
      orbit_overlap(out, sizeof(*out), client, sizeof(*client)))
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (orbit_overlap(out, sizeof(*out), c->arena, c->arena_capacity) ||
      orbit_overlap(out, sizeof(*out), c->scratch,
                    ORBIT_GRANT_WORKSPACE_BYTES) ||
      orbit_overlap(name.data, name.length, c->arena, c->arena_capacity) ||
      orbit_overlap(identity.data, identity.length, c->arena,
                    c->arena_capacity))
    return ORBIT_CLIENT_ARGUMENT;
  orbit_zero(out, sizeof(*out));
  out->units = units;
  r = orbit_service_begin(client, op, &c);
  if (r)
    return r;
  if (action) {
    r = orbit_operation_id(c, op, out->operation_id, &out->operation_id_length);
    if (r)
      goto done;
  }
  if (action == 2) {
    orbit_copy(out->resource_id, identity.data, identity.length);
    out->resource_id_length = (uint8_t)identity.length;
  }
  if (action == 3) {
    orbit_copy(out->allocation_id, identity.data, identity.length);
    out->allocation_id_length = (uint8_t)identity.length;
  }
  ORBIT_LITERAL(&route, "/api/client/v1/activations/");
  orbit_write(&route, c->record.activation, c->record.activation_length);
  if (usage)
    ORBIT_LITERAL(&route, "/usage/");
  else
    ORBIT_LITERAL(&route, "/resources/");
  orbit_write(&route, name.data, name.length);
  if (action == 1)
    ORBIT_LITERAL(&route, "/consume");
  else if (action == 2)
    ORBIT_LITERAL(&route, "/acquire");
  else if (action == 3) {
    ORBIT_LITERAL(&route, "/allocations/");
    orbit_write(&route, identity.data, identity.length);
    ORBIT_LITERAL(&route, "/release");
  }
  body = (orbit_writer_t){c->arena, 0, c->arena_capacity, 0};
  orbit_service_proof(c, &body);
  if (action) {
    ORBIT_LITERAL(&body, ",\"idempotency_key\":");
    orbit_write_string(&body, (orbit_embedded_slice_t){
                                  out->operation_id, out->operation_id_length});
    if (action != 3) {
      ORBIT_LITERAL(&body, ",\"units\":");
      orbit_write_uint(&body, units);
    }
    if (action == 2) {
      ORBIT_LITERAL(&body, ",\"resource_id\":");
      orbit_write_string(&body, identity);
    }
  }
  ORBIT_LITERAL(&body, "}");
  r = route.status ? route.status : body.status;
  if (r)
    goto done;
  out->uncertain = (uint8_t)(action != 0);
  r = orbit_service_exchange(c, (orbit_embedded_slice_t){path, route.length},
                             body.length, op, &http, &n);
  if (r)
    goto done;
  if (http == 401 || http == 403 || http == 404 || http == 409 || http == 410 ||
      http == 422) {
    r = denial(c->arena, n, c->scratch, name, usage, out, http, action);
    if (r == ORBIT_CLIENT_DENIED)
      out->uncertain = 0;
    goto done;
  }
  r = orbit_service_status(0, http);
  if (r)
    goto done;
  r = counter(c->arena, n, c->scratch, name, usage, action, out);
  if (!r)
    out->uncertain = 0;
done:
  if (r && r != ORBIT_CLIENT_CAPACITY) {
    orbit_zero(&out->counter, sizeof(out->counter));
    out->capacity_denied = 0;
    orbit_zero(out->allocation_id, sizeof(out->allocation_id));
    orbit_zero(out->resource_id, sizeof(out->resource_id));
    out->allocation_id_length = out->resource_id_length = out->released = 0;
    out->units = units;
  }
  orbit_service_finish(c);
  return r;
}
int32_t orbit_client_usage(orbit_client_t *c, orbit_embedded_slice_t n,
                           const orbit_operation_t *o,
                           orbit_limit_result_t *r) {
  return limits(c, n, (orbit_embedded_slice_t){0, 0}, 0, 0, 1, o, r);
}
int32_t orbit_client_consume(orbit_client_t *c, orbit_embedded_slice_t n,
                             uint64_t u, const orbit_operation_t *o,
                             orbit_limit_result_t *r) {
  return limits(c, n, (orbit_embedded_slice_t){0, 0}, u, 1, 1, o, r);
}
int32_t orbit_client_resources(orbit_client_t *c, orbit_embedded_slice_t n,
                               const orbit_operation_t *o,
                               orbit_limit_result_t *r) {
  return limits(c, n, (orbit_embedded_slice_t){0, 0}, 0, 0, 0, o, r);
}
int32_t orbit_client_acquire_resource(orbit_client_t *c,
                                      orbit_embedded_slice_t n,
                                      orbit_embedded_slice_t id, uint64_t u,
                                      const orbit_operation_t *o,
                                      orbit_limit_result_t *r) {
  return limits(c, n, id, u, 2, 0, o, r);
}
int32_t orbit_client_release_resource(orbit_client_t *c,
                                      orbit_embedded_slice_t n,
                                      orbit_embedded_slice_t id,
                                      const orbit_operation_t *o,
                                      orbit_limit_result_t *r) {
  return limits(c, n, id, 0, 3, 0, o, r);
}

#endif
