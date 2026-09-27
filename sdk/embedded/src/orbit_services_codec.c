#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_services_internal.h"

int orbit_slice_equal(orbit_embedded_slice_t a, orbit_embedded_slice_t b) {
  return a.length == b.length && orbit_equal(a.data, b.data, a.length);
}
int orbit_limit_name(orbit_embedded_slice_t n) {
  uint32_t i;
  if (!n.data || n.length == 0 || n.length > 64 || n.data[0] < 'a' ||
      n.data[0] > 'z')
    return 0;
  for (i = 1; i < n.length; ++i)
    if (!((n.data[i] >= 'a' && n.data[i] <= 'z') ||
          (n.data[i] >= '0' && n.data[i] <= '9') || n.data[i] == '_'))
      return 0;
  return 1;
}
void orbit_write_uint(orbit_writer_t *w, uint64_t n) {
  uint8_t b[20];
  uint32_t at = sizeof(b);
  do {
    b[--at] = (uint8_t)('0' + n % 10u);
    n /= 10u;
  } while (n);
  orbit_write(w, b + at, sizeof(b) - at);
}
int32_t orbit_fields(const uint8_t *b, uint32_t n, uint8_t *scratch,
                     orbit_field_t *fields, uint32_t count) {
  orbit_json_parser_t p;
  orbit_json_span_t key;
  uint32_t base, i, k, start;
  int first, present;
  for (i = 0; i < count; ++i)
    fields[i].value = (orbit_json_span_t){0, 0};
  orbit_json_init(&p, b, n, scratch);
  if (orbit_json_object_open(&p, 0, &base, &first))
    return ORBIT_CLIENT_UNTRUSTED;
  for (;;) {
    if (orbit_json_object_next(&p, base, &first, &key, &present))
      return ORBIT_CLIENT_UNTRUSTED;
    if (!present)
      break;
    for (i = 0; i < count; ++i) {
      for (k = 0; fields[i].name[k]; ++k) {
      }
      if (orbit_json_span_equals_ascii(b, key, fields[i].name, k))
        break;
    }
    if (i == count || fields[i].value.length)
      return ORBIT_CLIENT_UNTRUSTED;
    orbit_json_skip_space(&p);
    start = p.position;
    if (orbit_json_skip_value(&p, 1))
      return ORBIT_CLIENT_UNTRUSTED;
    fields[i].value = (orbit_json_span_t){start, p.position - start};
  }
  return orbit_json_finish(&p) ? ORBIT_CLIENT_UNTRUSTED : 0;
}
int orbit_field_null(const uint8_t *b, orbit_json_span_t s) {
  return s.length == 4 && orbit_equal(b + s.start, "null", 4);
}
int32_t orbit_field_string(uint8_t *b, orbit_json_span_t s,
                           orbit_embedded_slice_t *out) {
  uint32_t n;
  if (s.length < 2 || b[s.start] != '"' || b[s.start + s.length - 1] != '"')
    return ORBIT_CLIENT_UNTRUSTED;
  s.start++;
  s.length -= 2;
  if (orbit_json_decode_span(b, s, b + s.start, s.length, &n, 0))
    return ORBIT_CLIENT_UNTRUSTED;
  *out = (orbit_embedded_slice_t){b + s.start, n};
  return 0;
}
int32_t orbit_field_uint(const uint8_t *b, orbit_json_span_t s, uint64_t *out) {
  uint64_t n = 0;
  uint32_t i;
  if (!s.length || (s.length > 1 && b[s.start] == '0'))
    return ORBIT_CLIENT_UNTRUSTED;
  for (i = 0; i < s.length; ++i) {
    uint8_t c = b[s.start + i];
    if (c < '0' || c > '9' || n > (ORBIT_SAFE_INTEGER_MAX - (c - '0')) / 10)
      return ORBIT_CLIENT_UNTRUSTED;
    n = n * 10 + c - '0';
  }
  *out = n;
  return 0;
}
int32_t orbit_field_time(const uint8_t *b, orbit_json_span_t s, int64_t *out) {
  if (s.length < 2 || b[s.start] != '"' || b[s.start + s.length - 1] != '"')
    return ORBIT_CLIENT_UNTRUSTED;
  s.start++;
  s.length -= 2;
  return orbit_timestamp(b, s, out) ? 0 : ORBIT_CLIENT_UNTRUSTED;
}
void orbit_service_proof(orbit_client_state_t *c, orbit_writer_t *w) {
  ORBIT_LITERAL(w, "{\"application_id\":");
  orbit_write_string(w, c->config.application_id);
  ORBIT_LITERAL(w, ",\"environment_id\":");
  orbit_write_string(w, c->config.environment_id);
  ORBIT_LITERAL(w, ",\"credential\":");
  orbit_write_string(w, (orbit_embedded_slice_t){c->record.credential,
                                                 c->record.credential_length});
  ORBIT_LITERAL(w, ",\"installation_id\":");
  orbit_write_string(w,
                     (orbit_embedded_slice_t){c->record.installation,
                                              c->record.installation_length});
  ORBIT_LITERAL(w, ",\"fingerprint\":");
  if (c->config.fingerprint.length)
    orbit_write_string(w, c->config.fingerprint);
  else
    ORBIT_LITERAL(w, "null");
  ORBIT_LITERAL(w, ",\"fingerprint_provider\":");
  if (c->config.fingerprint_provider.length)
    orbit_write_string(w, c->config.fingerprint_provider);
  else
    ORBIT_LITERAL(w, "null");
}
int32_t orbit_service_begin(orbit_client_t *client, const orbit_operation_t *op,
                            orbit_client_state_t **out) {
  orbit_client_state_t *c;
  if (!client || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
#ifdef ORBIT_ENABLE_OFFLINE
  if (c->extension && c->extension->offline_mode)
    return ORBIT_CLIENT_DENIED;
#endif
  if (c->record.pending_kind)
    return ORBIT_CLIENT_PENDING;
  if (!c->record.credential_length)
    return ORBIT_CLIENT_ACTIVATION_REQUIRED;
  c->busy = 1;
  *out = c;
  return 0;
}
typedef struct service_sink {
  orbit_client_state_t *c;
  const orbit_operation_t *op;
  uint32_t length;
  int32_t error;
} service_sink_t;
static int32_t receive_service(void *context, const uint8_t *b, uint32_t n) {
  service_sink_t *s = context;
  if (s->op && s->op->cancelled && s->op->cancelled(s->op->context))
    return s->error = ORBIT_CLIENT_CANCELLED;
  if ((!b && n) || n > s->c->arena_capacity - s->length)
    return s->error = ORBIT_CLIENT_RESOURCE_LIMIT;
  orbit_copy(s->c->arena + s->length, b, n);
  s->length += n;
  return 0;
}
int32_t orbit_service_exchange(orbit_client_state_t *c,
                               orbit_embedded_slice_t path, uint32_t n,
                               const orbit_operation_t *op, uint16_t *http,
                               uint32_t *length) {
  orbit_http_request_t req = {c->config.api_origin, path, {c->arena, n}, 1};
  service_sink_t sink = {c, op, 0, 0};
  uint64_t generation = c->generation;
  int32_t r;
  *http = 0;
  *length = 0;
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
  r = c->services.exchange(c->services.context, &req, http, receive_service,
                           &sink);
  if (generation != c->generation)
    return ORBIT_CLIENT_STALE;
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
  *length = sink.length;
  return sink.error ? sink.error : r;
}
void orbit_service_finish(orbit_client_state_t *c) {
  orbit_zero(c->arena, c->arena_capacity);
  orbit_zero(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  c->busy = 0;
}
int32_t orbit_operation_id(orbit_client_state_t *c, const orbit_operation_t *op,
                           uint8_t out[128], uint8_t *length) {
  static const uint8_t hex[] = "0123456789abcdef";
  uint8_t entropy[16];
  uint32_t i;
  if (op && op->id.length) {
    if (!orbit_client_opaque(op->id, 1, 128))
      return ORBIT_CLIENT_ARGUMENT;
    orbit_copy(out, op->id.data, op->id.length);
    *length = (uint8_t)op->id.length;
    return 0;
  }
  if (c->services.entropy(c->services.context, entropy, 16))
    return ORBIT_CLIENT_UNTRUSTED;
  for (i = 0; i < 16; ++i) {
    out[i * 2] = hex[entropy[i] >> 4];
    out[i * 2 + 1] = hex[entropy[i] & 15];
  }
  orbit_zero(entropy, 16);
  *length = 32;
  return 0;
}
int32_t orbit_service_status(int32_t r, uint16_t http) {
  if (r)
    return r;
  if (http == 200)
    return 0;
  if (http == 429 || (http >= 500 && http <= 599))
    return ORBIT_CLIENT_TRANSIENT;
  if (http == 401 || http == 403 || http == 404 || http == 409 || http == 410)
    return ORBIT_CLIENT_DENIED;
  return ORBIT_CLIENT_UNTRUSTED;
}

#endif
