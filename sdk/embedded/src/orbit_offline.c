#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_OFFLINE
#include "orbit_app_key.h"
#include "orbit_extensions.h"
#include "orbit_services_internal.h"
static uint64_t get64(const uint8_t *p) {
  uint64_t n = 0;
  uint32_t i;
  for (i = 0; i < 8; ++i)
    n |= (uint64_t)p[i] << (i * 8);
  return n;
}
static void put64(uint8_t *p, uint64_t n) {
  uint32_t i;
  for (i = 0; i < 8; ++i)
    p[i] = (uint8_t)(n >> (i * 8));
}
static uint32_t get32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static void put32(uint8_t *p, uint32_t n) {
  uint32_t i;
  for (i = 0; i < 4; ++i)
    p[i] = (uint8_t)(n >> (i * 8));
}
int32_t orbit_extension_load(void *p, uint8_t *b, uint32_t capacity,
                             uint32_t *length) {
  orbit_client_extension_t *e = p;
  uint32_t n, inner;
  uint8_t *t = e->offline.transaction;
  int32_t r;
  if (!t)
    return e->platform.load(e->platform.context, b, capacity, length);
  r = e->platform.load(e->platform.context, t,
                       ORBIT_OFFLINE_BUFFER_BYTES(e->offline.max_file_bytes),
                       &n);
  if (r)
    return r;
  if (n < 1024 || !orbit_equal(t, "ORBITMC1", 8) ||
      !orbit_equal(t + 16, "ORBOFF1", 8))
    return ORBIT_CLIENT_STORAGE;
  inner = (uint32_t)t[24] | ((uint32_t)t[25] << 8);
  e->file_length = get32(t + 28);
  e->offline_sequence = get64(t + 32);
  e->offline_floor = (int64_t)get64(t + 40);
  if (inner < 103 || inner > 944 || inner > capacity ||
      e->file_length > e->offline.max_file_bytes ||
      n != 1024 + e->file_length || t[26] > 1 ||
      t[27] != (uint8_t)e->client->private_state.config.environment_kind ||
      e->offline_sequence > ORBIT_SAFE_INTEGER_MAX || e->offline_floor < 0 ||
      e->offline_floor > INT64_C(253402300799) ||
      get64(t + 88) != get64(t + 8) ||
      (!e->file_length && (e->offline_sequence || t[26])))
    return ORBIT_CLIENT_STORAGE;
  orbit_copy(e->file_digest, t + 48, 32);
  e->offline_mode = t[26];
  e->offline_checkpoint = e->offline_floor;
  orbit_copy(b, t + 80, inner);
  *length = inner;
  return 0;
}
int32_t orbit_extension_commit(void *p, uint64_t generation, const uint8_t *b,
                               uint32_t n) {
  orbit_client_extension_t *e = p;
  uint8_t *t = e->offline.transaction;
  if (!t)
    return e->platform.commit(e->platform.context, generation, b, n);
  if (n < 16 || n > 944 || e->file_length > e->offline.max_file_bytes)
    return ORBIT_CLIENT_STORAGE;
  orbit_zero(t, 1024);
  orbit_copy(t, "ORBITMC1", 8);
  put64(t + 8, generation + 1);
  orbit_copy(t + 16, "ORBOFF1", 8);
  t[24] = (uint8_t)n;
  t[25] = (uint8_t)(n >> 8);
  t[26] = e->offline_mode;
  t[27] = e->client->private_state.config.environment_kind;
  put32(t + 28, e->file_length);
  put64(t + 32, e->offline_sequence);
  put64(t + 40, (uint64_t)e->offline_floor);
  orbit_copy(t + 48, e->file_digest, 32);
  orbit_copy(t + 80, b, n);
  return e->platform.commit(e->platform.context, generation, t,
                            1024 + e->file_length);
}
int32_t orbit_offline_checkpoint(orbit_client_state_t *c, int64_t now,
                                 int force) {
  orbit_client_extension_t *e = c->extension;
  uint32_t n;
  uint64_t previous;
  int32_t r;
  if (!e || !e->offline.transaction)
    return 0;
  if (now < e->offline_floor || now > INT64_C(253402300799)) {
    orbit_client_clear_access(c);
    return ORBIT_CLIENT_CLOCK;
  }
  if (!force && now - e->offline_checkpoint < 60)
    return 0;
  if (c->record.generation >= UINT64_MAX - 1)
    return ORBIT_CLIENT_STORAGE;
  previous = c->record.generation;
  e->offline_floor = now;
  ++c->record.generation;
  r = orbit_record_encode(&c->record, c->scratch, &n);
  if (!r)
    r = orbit_extension_commit(e, previous, c->scratch, n);
  orbit_zero(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  if (r) {
    c->failed = 1;
    orbit_client_clear_access(c);
    return ORBIT_CLIENT_STORAGE;
  }
  e->offline_checkpoint = now;
  return 0;
}
static int32_t verify_file(orbit_client_state_t *c, orbit_embedded_slice_t file,
                           int64_t now, orbit_signed_claims_t *claims) {
  orbit_client_extension_t *e = c->extension;
  orbit_signed_expected_t expected;
  orbit_grant_pending_t pending;
  int32_t r;
  if (file.length > e->offline.max_file_bytes ||
      file.length > c->arena_capacity)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  orbit_copy(c->arena, file.data, file.length);
  orbit_zero(&expected, sizeof(expected));
  expected.purpose = ORBIT_SIGNED_OFFLINE;
  expected.environment_kind = c->config.environment_kind;
  expected.sequence = e->offline_sequence;
  expected.scope.issuer = c->config.issuer;
  expected.scope.application_id = c->config.application_id;
  expected.scope.environment_id = c->config.environment_id;
  expected.scope.activation_id =
      (orbit_embedded_slice_t){(const uint8_t *)"offline", 7};
  expected.scope.installation_id = (orbit_embedded_slice_t){
      c->record.installation, c->record.installation_length};
  expected.scope.received_unix_seconds = now;
  expected.scope.current_unix_seconds = now;
  if (c->config.fingerprint.length) {
    expected.scope.fingerprint = c->config.fingerprint;
    expected.scope.fingerprint_provider = c->config.fingerprint_provider;
    expected.scope.has_fingerprint = expected.scope.has_fingerprint_provider =
        1;
  }
  r = orbit_signed_prepare(c->arena, file.length, &c->services.crypto,
                           ORBIT_SIGNED_OFFLINE, &pending);
  if (!r)
    r = orbit_signed_verify(c->arena, file.length, &pending, e->offline.keys,
                            &expected, &c->services.crypto, c->scratch,
                            ORBIT_GRANT_WORKSPACE_BYTES, claims);
  return r ? ORBIT_CLIENT_UNTRUSTED : 0;
}
int32_t orbit_offline_restore(orbit_client_state_t *c) {
  orbit_client_extension_t *e = c->extension;
  orbit_signed_claims_t claims;
  int64_t now;
  uint64_t ticks;
  uint8_t digest[32];
  int32_t r;
  if (!e || !e->offline_mode || !e->offline.transaction)
    return ORBIT_CLIENT_ARGUMENT;
  c->busy = 1;
  r = orbit_client_clock(c, &now, &ticks);
  if (!r && now < e->offline_floor)
    r = ORBIT_CLIENT_CLOCK;
  if (!r && (c->services.crypto.sha256(c->services.crypto.context,
                                       e->offline.transaction + 1024,
                                       e->file_length, digest) ||
             !orbit_equal(digest, e->file_digest, 32)))
    r = ORBIT_CLIENT_STORAGE;
  if (!r)
    r = verify_file(
        c,
        (orbit_embedded_slice_t){e->offline.transaction + 1024, e->file_length},
        now, &claims);
  if (!r && claims.sequence != e->offline_sequence)
    r = ORBIT_CLIENT_STORAGE;
  if (!r)
    orbit_client_apply_claims(c, &claims.access, now, ticks);
  else
    orbit_client_clear_access(c);
  orbit_service_finish(c);
  return r;
}
static int32_t import_file(orbit_client_state_t *c, orbit_embedded_slice_t file,
                           const orbit_operation_t *op) {
  orbit_client_extension_t *e = c->extension;
  orbit_signed_claims_t claims;
  uint8_t digest[32];
  uint64_t ticks;
  int64_t now;
  int32_t r;
  uint64_t generation = c->generation;
  c->busy = 1;
  r = orbit_client_clock(c, &now, &ticks);
  if (!r && now < e->offline_floor)
    r = ORBIT_CLIENT_CLOCK;
  if (!r)
    r = verify_file(c, file, now, &claims);
  if (!r && c->services.crypto.sha256(c->services.crypto.context, file.data,
                                      file.length, digest))
    r = ORBIT_CLIENT_UNTRUSTED;
  if (!r && claims.sequence == e->offline_sequence &&
      !orbit_equal(digest, e->file_digest, 32))
    r = ORBIT_CLIENT_DENIED;
  /* Verification and hashing may block; cancellation is checked again at the
   * last point before changing metadata or committing the new atomic pair. */
  if (!r && op && op->cancelled && op->cancelled(op->context))
    r = ORBIT_CLIENT_CANCELLED;
  if (!r && generation != c->generation)
    r = ORBIT_CLIENT_STALE;
  if (!r) {
    orbit_client_clear_access(c);
    ++c->generation;
    orbit_zero(&e->session, sizeof(e->session));
    e->session.automatic = 1;
    e->policy_known = 0;
    c->record.pending_kind = 0;
    c->record.pending_created = 0;
    orbit_zero(c->record.pending_id, sizeof(c->record.pending_id));
    orbit_zero(c->record.pending_digest, sizeof(c->record.pending_digest));
    if (file.data != e->offline.transaction + 1024)
      orbit_copy(e->offline.transaction + 1024, file.data, file.length);
    e->file_length = file.length;
    orbit_copy(e->file_digest, digest, 32);
    e->offline_sequence = claims.sequence;
    e->offline_mode = 1;
    r = orbit_offline_checkpoint(c, now, 1);
    if (!r)
      orbit_client_apply_claims(c, &claims.access, now, ticks);
  }
  orbit_service_finish(c);
  return r;
}
int32_t orbit_client_import_offline_file(orbit_client_t *client,
                                         orbit_embedded_slice_t file) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  uint32_t start = 0, end = file.length;
  if (!client || client->private_state.magic != 0x4f524243u || !file.data)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  e = c->extension;
  if (!e || !e->offline.transaction)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  while (start < end && (file.data[start] == 32 ||
                         (file.data[start] >= 9 && file.data[start] <= 13)))
    ++start;
  while (end > start && (file.data[end - 1] == 32 ||
                         (file.data[end - 1] >= 9 && file.data[end - 1] <= 13)))
    --end;
  file.data += start;
  file.length = end - start;
  if (file.length > e->offline.max_file_bytes)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  if (!file.length ||
      orbit_overlap(file.data, file.length, client, sizeof(*client)) ||
      orbit_overlap(file.data, file.length, c->arena, c->arena_capacity) ||
      orbit_overlap(file.data, file.length, c->scratch,
                    ORBIT_GRANT_WORKSPACE_BYTES) ||
      orbit_overlap(file.data, file.length, e->offline.transaction,
                    e->offline.transaction_capacity))
    return ORBIT_CLIENT_ARGUMENT;
  return import_file(c, file, NULL);
}
/* A failed reader reloads the previously committed pair before allowing any
 * later checkpoint. No unverified bytes become the file belonging to old
 * sequence metadata. */
int32_t orbit_client_import_offline_reader(orbit_client_t *client,
                                           orbit_offline_read_fn read,
                                           void *context,
                                           const orbit_operation_t *op) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  uint64_t generation, record_generation;
  uint32_t n = 0, got, capacity, loaded;
  int32_t r = 0, restore;
  if (!client || !read || client->private_state.magic != 0x4f524243u)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  e = c->extension;
  if (!e || !e->offline.transaction)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
  generation = c->generation;
  record_generation = c->record.generation;
  c->busy = 1;
  /* Suppress authority during input while retaining the monotonic clock
   * anchor; a rejected file must not reset time to an older wall reading. */
  orbit_zero(&c->active, sizeof(c->active));
  do {
    capacity = e->offline.max_file_bytes - n;
    if (capacity > 256)
      capacity = 256;
    got = 0;
    r = read(context, capacity ? e->offline.transaction + 1024 + n : c->scratch,
             capacity ? capacity : 1, &got);
    if (!r && got > (capacity ? capacity : 1))
      r = ORBIT_CLIENT_ARGUMENT;
    if (!r && !capacity && got)
      r = ORBIT_CLIENT_RESOURCE_LIMIT;
    if (!r && op && op->cancelled && op->cancelled(op->context))
      r = ORBIT_CLIENT_CANCELLED;
    if (generation != c->generation)
      r = ORBIT_CLIENT_STALE;
    if (r || !got)
      break;
    n += got;
  } while (1);
  if (!r && !n)
    r = ORBIT_CLIENT_ARGUMENT;
  if (!r)
    r = import_file(
        c, (orbit_embedded_slice_t){e->offline.transaction + 1024, n}, op);
  if (r && !c->failed) {
    restore =
        orbit_extension_load(e, c->scratch, ORBIT_CLIENT_RECORD_BYTES, &loaded);
    if (restore || loaded < 16 || get64(c->scratch + 8) != record_generation) {
      c->failed = 1;
      r = ORBIT_CLIENT_STORAGE;
    } else if (e->offline_mode && generation == c->generation) {
      restore = orbit_offline_restore(c);
      if (restore)
        r = restore;
    }
  }
  orbit_service_finish(c);
  return r;
}
int32_t orbit_client_offline_request(orbit_client_t *client, uint8_t *out,
                                     uint32_t capacity, uint32_t *length) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  orbit_writer_t w;
  orbit_client_config_t parsed;
  uint8_t origin[ORBIT_APP_KEY_ORIGIN_MAX_BYTES];
  if (!client || !out || !length || client->private_state.magic != 0x4f524243u)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  e = c->extension;
  *length = 0;
  if (!e || !e->offline.transaction || c->busy || c->failed ||
      orbit_overlap(out, capacity, client, sizeof(*client)) ||
      orbit_overlap(out, capacity, e, sizeof(*e)) ||
      orbit_overlap(out, capacity, c->arena, c->arena_capacity) ||
      orbit_overlap(out, capacity, c->scratch, ORBIT_GRANT_WORKSPACE_BYTES) ||
      orbit_overlap(out, capacity, e->offline.transaction,
                    e->offline.transaction_capacity) ||
      orbit_overlap(out, capacity, e->offline.keys, sizeof(*e->offline.keys)) ||
      orbit_overlap(out, capacity, e->offline.app_key.data,
                    e->offline.app_key.length))
    return ORBIT_CLIENT_ARGUMENT;
  if (orbit_app_key_parse(e->offline.app_key, origin, sizeof(origin),
                          &parsed) ||
      !orbit_slice_equal(parsed.api_origin, c->config.api_origin) ||
      !orbit_slice_equal(parsed.application_id, c->config.application_id) ||
      !orbit_slice_equal(parsed.environment_id, c->config.environment_id) ||
      parsed.environment_kind != c->config.environment_kind)
    return ORBIT_CLIENT_ARGUMENT;
  w = (orbit_writer_t){out, 0, capacity < 4096 ? capacity : 4096, 0};
  ORBIT_LITERAL(
      &w, "{\"format\":\"orbit-offline-request\",\"version\":1,\"app_key\":");
  orbit_write_string(&w, e->offline.app_key);
  ORBIT_LITERAL(&w, ",\"installation_id\":");
  orbit_write_string(&w,
                     (orbit_embedded_slice_t){c->record.installation,
                                              c->record.installation_length});
  ORBIT_LITERAL(&w, ",\"fingerprint\":");
  if (c->config.fingerprint.length)
    orbit_write_string(&w, c->config.fingerprint);
  else
    ORBIT_LITERAL(&w, "null");
  ORBIT_LITERAL(&w, ",\"fingerprint_provider\":");
  if (c->config.fingerprint_provider.length)
    orbit_write_string(&w, c->config.fingerprint_provider);
  else
    ORBIT_LITERAL(&w, "null");
  ORBIT_LITERAL(&w, "}");
  if (!w.status)
    *length = w.length;
  return w.status;
}

#endif
