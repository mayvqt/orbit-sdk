#include "orbit_client_internal.h"

#if defined(__GNUC__) || defined(__clang__)
#define ORBIT_NOINLINE __attribute__((noinline))
#else
#define ORBIT_NOINLINE
#endif

#define CLIENT_MAGIC 0x4f524243u
#define KEY_FETCH_TRANSIENT ((int32_t)22)
_Static_assert(sizeof(orbit_client_state_t) <= ORBIT_CLIENT_STORAGE_BYTES,
               "client storage bound");
_Static_assert(_Alignof(orbit_client_t) >= _Alignof(orbit_client_state_t),
               "client storage alignment");

static orbit_client_state_t *state(orbit_client_t *client) {
  orbit_client_state_t *c = client != NULL ? &client->private_state : NULL;
  return c != NULL && c->magic == CLIENT_MAGIC ? c : NULL;
}
static orbit_embedded_slice_t slice(const uint8_t *p, uint32_t n) {
  orbit_embedded_slice_t s = {p, n};
  return s;
}
static void wipe(void *p, uint32_t n) {
  volatile uint8_t *b = (volatile uint8_t *)p;
  while (n--)
    *b++ = 0u;
}
static void clear_access(orbit_client_state_t *c) {
  orbit_zero(&c->active, sizeof(c->active));
  c->anchored = 0u;
  c->transient = 0u;
  c->retry_ticks = 0u;
}
static int32_t advance(orbit_client_state_t *c) {
  if (c->generation == UINT64_MAX) {
    c->failed = 1u;
    clear_access(c);
    return ORBIT_CLIENT_STORAGE;
  }
  ++c->generation;
  return 0;
}
static void clear_authority(orbit_record_t *r) {
  wipe(r->credential, sizeof(r->credential));
  r->credential_length = 0u;
  orbit_zero(r->activation, sizeof(r->activation));
  r->activation_length = 0u;
  orbit_zero(r->licence, sizeof(r->licence));
  r->licence_length = 0u;
  r->credential_expiry = 0;
  r->has_expiry = 0u;
  orbit_zero(r->pending_id, sizeof(r->pending_id));
  orbit_zero(r->pending_digest, sizeof(r->pending_digest));
  r->pending_kind = 0u;
  r->pending_created = 0;
}
static int32_t save(orbit_client_state_t *c, orbit_record_t *next) {
  uint32_t length;
  int32_t result;
  uint64_t previous = c->record.generation;
  if (previous >= UINT64_MAX - 1u) {
    c->failed = 1u;
    clear_access(c);
    return ORBIT_CLIENT_STORAGE;
  }
  next->generation = previous + 1u;
  result = orbit_record_encode(next, c->scratch, &length);
  if (result == 0)
    result =
        c->services.commit(c->services.context, previous, c->scratch, length);
  wipe(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  if (result != 0) {
    c->failed = 1u;
    clear_access(c);
    (void)advance(c);
    return ORBIT_CLIENT_STORAGE;
  }
  c->record = *next;
  return 0;
}
static int32_t terminal(orbit_client_state_t *c, int32_t error) {
  orbit_record_t next;
  clear_access(c);
  (void)advance(c);
  if (c->record.credential_length == 0u && c->record.pending_kind == 0u)
    return error;
  next = c->record;
  clear_authority(&next);
  if (save(c, &next) != 0)
    error = ORBIT_CLIENT_STORAGE;
  wipe(&next, sizeof(next));
  return error;
}
static int32_t clock_now(orbit_client_state_t *c, int64_t *now,
                         uint64_t *ticks) {
  int64_t wall;
  if (c->services.clock(c->services.context, &wall, ticks) != 0 || wall < 0 ||
      (c->last_wall >= 0 &&
       (wall < c->last_wall - 30 || *ticks < c->last_ticks))) {
    clear_access(c);
    (void)advance(c);
    c->last_wall = -1;
    return ORBIT_CLIENT_CLOCK;
  }
  c->last_wall = wall;
  c->last_ticks = *ticks;
  if (!c->anchored) {
    *now = wall;
    return 0;
  }
  if (*ticks < c->anchor_ticks ||
      (*ticks - c->anchor_ticks) / 1000u > (uint64_t)INT64_MAX ||
      c->anchor_server >
          INT64_MAX - (int64_t)((*ticks - c->anchor_ticks) / 1000u)) {
    clear_access(c);
    (void)advance(c);
    return ORBIT_CLIENT_CLOCK;
  }
  *now = c->anchor_server + (int64_t)((*ticks - c->anchor_ticks) / 1000u);
  return 0;
}
static int32_t random_id(orbit_client_state_t *c, uint8_t out[32]) {
  static const uint8_t hex[] = "0123456789abcdef";
  uint8_t bytes[16];
  uint32_t i;
  if (c->services.entropy(c->services.context, bytes, sizeof(bytes)) != 0)
    return ORBIT_CLIENT_UNTRUSTED;
  for (i = 0; i < 16u; ++i) {
    out[i * 2u] = hex[bytes[i] >> 4u];
    out[i * 2u + 1u] = hex[bytes[i] & 15u];
  }
  wipe(bytes, sizeof(bytes));
  return 0;
}
static int valid_config(const orbit_client_config_t *cfg) {
  uint32_t i;
  orbit_embedded_slice_t origin = cfg->api_origin;
  if (origin.data == NULL || origin.length < 9u || origin.length > 512u ||
      !orbit_equal(origin.data, "https://", 8u) ||
      !orbit_client_opaque(cfg->application_id, 1u, 128u) ||
      !orbit_client_opaque(cfg->environment_id, 1u, 128u) ||
      cfg->issuer.data == NULL || cfg->issuer.length == 0u ||
      cfg->issuer.length > ORBIT_GRANT_MAX_JSON_BYTES ||
      !orbit_json_valid_utf8_no_nul(cfg->issuer.data, cfg->issuer.length))
    return 0;
  for (i = 8u; i < origin.length; ++i)
    if (origin.data[i] <= 32u || origin.data[i] >= 127u ||
        origin.data[i] == '/' || origin.data[i] == '?' ||
        origin.data[i] == '#' || origin.data[i] == '@' ||
        origin.data[i] == '\\')
      return 0;
  if (cfg->fingerprint.length == 0u)
    return cfg->fingerprint_provider.length == 0u;
  if (cfg->fingerprint.data == NULL || cfg->fingerprint.length != 64u ||
      cfg->fingerprint_provider.data == NULL)
    return 0;
  for (i = 0; i < 64u; ++i)
    if (!((cfg->fingerprint.data[i] >= '0' &&
           cfg->fingerprint.data[i] <= '9') ||
          (cfg->fingerprint.data[i] >= 'a' && cfg->fingerprint.data[i] <= 'f')))
      return 0;
  if (cfg->fingerprint_provider.length == 10u &&
      orbit_equal(cfg->fingerprint_provider.data, "machine_v1", 10u))
    return 1;
  if (cfg->fingerprint_provider.length < 8u ||
      cfg->fingerprint_provider.length > 55u ||
      !orbit_equal(cfg->fingerprint_provider.data, "custom:", 7u))
    return 0;
  for (i = 7u; i < cfg->fingerprint_provider.length; ++i) {
    uint8_t v = cfg->fingerprint_provider.data[i];
    if (!((v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '_' ||
          v == '.' || v == '-'))
      return 0;
  }
  return 1;
}
static int32_t scope_digest(const orbit_client_config_t *cfg,
                            const orbit_grant_crypto_t *crypto,
                            uint8_t out[32]) {
  orbit_embedded_slice_t fields[6] = {
      cfg->api_origin,     cfg->issuer,      cfg->application_id,
      cfg->environment_id, cfg->fingerprint, cfg->fingerprint_provider};
  uint8_t input[208];
  uint32_t i;
  orbit_copy(input, "orbit.mcu.scope1", 16u);
  for (i = 0; i < 6u; ++i)
    if (crypto->sha256(crypto->context, fields[i].data, fields[i].length,
                       input + 16u + i * 32u) != 0)
      return ORBIT_CLIENT_UNTRUSTED;
  return crypto->sha256(crypto->context, input, sizeof(input), out) == 0
             ? 0
             : ORBIT_CLIENT_UNTRUSTED;
}

int32_t orbit_client_init(orbit_client_t *client,
                          const orbit_client_config_t *cfg,
                          const orbit_client_services_t *services,
                          uint8_t *arena, uint32_t arena_length, void *scratch,
                          uint32_t scratch_length) {
  const void *objects[5] = {client, cfg, services, arena, scratch};
  uint32_t sizes[5] = {sizeof(*client), sizeof(*cfg), sizeof(*services),
                       arena_length, scratch_length};
  uint32_t i, j, length = 0u;
  int32_t result;
  uint8_t scope[32];
  orbit_client_state_t *c;
  if (client == NULL || cfg == NULL || services == NULL || arena == NULL ||
      scratch == NULL || arena_length < ORBIT_CLIENT_ARENA_BYTES ||
      scratch_length < ORBIT_GRANT_WORKSPACE_BYTES)
    return ORBIT_CLIENT_ARGUMENT;
  /* A live or initializing owner cannot be replaced from inside a callback. */
  if (state(client) != NULL)
    return ORBIT_CLIENT_BUSY;
  for (i = 0; i < 5u; ++i)
    for (j = i + 1u; j < 5u; ++j)
      if (orbit_overlap(objects[i], sizes[i], objects[j], sizes[j]))
        return ORBIT_CLIENT_ARGUMENT;
  {
    orbit_embedded_slice_t fields[6] = {
        cfg->api_origin,     cfg->issuer,      cfg->application_id,
        cfg->environment_id, cfg->fingerprint, cfg->fingerprint_provider};
    for (i = 0; i < 6u; ++i)
      if (orbit_overlap(fields[i].data, fields[i].length, client,
                        sizeof(*client)) ||
          orbit_overlap(fields[i].data, fields[i].length, arena,
                        arena_length) ||
          orbit_overlap(fields[i].data, fields[i].length, scratch,
                        scratch_length))
        return ORBIT_CLIENT_ARGUMENT;
  }
  orbit_zero(client, sizeof(*client));
  if (!valid_config(cfg) || !orbit_crypto_valid(&services->crypto) ||
      services->exchange == NULL || services->clock == NULL ||
      services->entropy == NULL || services->load == NULL ||
      services->commit == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  c->config = *cfg;
  c->services = *services;
  c->arena = arena;
  c->scratch = (uint8_t *)scratch;
  c->last_wall = -1;
  c->magic = CLIENT_MAGIC;
  c->busy = 1u;
  result = scope_digest(cfg, &services->crypto, scope);
  if (result != 0)
    goto failed;
  result = services->load(services->context, c->scratch,
                          ORBIT_CLIENT_RECORD_BYTES, &length);
  if (result == ORBIT_CLIENT_NOT_FOUND) {
    orbit_copy(c->record.scope, scope, sizeof(scope));
    result = random_id(c, c->record.installation);
    c->record.installation_length = 32u;
    if (result != 0)
      goto failed;
    result = save(c, &c->record);
  } else if (result == 0) {
    result = length > ORBIT_CLIENT_RECORD_BYTES
                 ? ORBIT_CLIENT_STORAGE
                 : orbit_record_decode(c->scratch, length, &c->record);
    if (result == 0 && !orbit_equal(scope, c->record.scope, sizeof(scope)))
      result = ORBIT_CLIENT_STORAGE;
  } else
    result = ORBIT_CLIENT_STORAGE;
  wipe(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  if (result != 0)
    goto failed;
  c->generation = c->record.generation;
  c->magic = CLIENT_MAGIC;
  c->busy = 0u;
  return 0;
failed:
  wipe(scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  wipe(client, sizeof(*client));
  return result;
}

static void body(orbit_client_state_t *c, orbit_writer_t *w,
                 orbit_embedded_slice_t key, uint8_t operation,
                 const orbit_record_t *r) {
  ORBIT_LITERAL(w, "{\"application_id\":");
  orbit_write_string(w, c->config.application_id);
  ORBIT_LITERAL(w, ",\"environment_id\":");
  orbit_write_string(w, c->config.environment_id);
  ORBIT_LITERAL(w, ",\"installation_id\":");
  orbit_write_string(w, slice(r->installation, r->installation_length));
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
  if (operation == 1u) {
    ORBIT_LITERAL(w, ",\"licence_key\":");
    orbit_write_string(w, key);
    ORBIT_LITERAL(
        w, ",\"credential_mode\":\"persistent\",\"previous_credential\":");
    if (r->credential_length)
      orbit_write_string(w, slice(r->credential, r->credential_length));
    else
      ORBIT_LITERAL(w, "null");
  } else {
    ORBIT_LITERAL(w, ",\"credential\":");
    orbit_write_string(w, slice(r->credential, r->credential_length));
  }
  if (operation != 0u) {
    ORBIT_LITERAL(w, ",\"idempotency_key\":");
    orbit_write_string(w, slice(r->pending_id, 32u));
  }
  ORBIT_LITERAL(w, "}");
}
typedef struct response_sink {
  orbit_client_state_t *c;
  uint32_t length;
  int32_t error;
} response_sink_t;
static int32_t receive_response(void *context, const uint8_t *bytes,
                                uint32_t length) {
  response_sink_t *sink = (response_sink_t *)context;
  if (bytes == NULL && length)
    return sink->error = ORBIT_CLIENT_UNTRUSTED;
  if (length > ORBIT_CLIENT_ARENA_BYTES - sink->length)
    return sink->error = ORBIT_CLIENT_RESOURCE_LIMIT;
  orbit_copy(sink->c->arena + sink->length, bytes, length);
  sink->length += length;
  return 0;
}
static int32_t response_status(int32_t transport, uint16_t http) {
  if (transport == ORBIT_CLIENT_TRANSIENT)
    return ORBIT_CLIENT_TRANSIENT;
  if (transport != 0)
    return transport == ORBIT_CLIENT_RESOURCE_LIMIT ? transport
                                                    : ORBIT_CLIENT_UNTRUSTED;
  if (http == 429u || (http >= 500u && http <= 599u))
    return ORBIT_CLIENT_TRANSIENT;
  if (http == 401u || http == 403u || http == 404u || http == 409u ||
      http == 410u)
    return ORBIT_CLIENT_DENIED;
  return http == 200u ? 0 : ORBIT_CLIENT_UNTRUSTED;
}
typedef struct key_sink {
  orbit_client_state_t *c;
  orbit_jwks_importer_t importer;
  uint16_t *http;
  uint32_t bytes;
  int32_t error;
} key_sink_t;
static int32_t receive_keys(void *context, const uint8_t *bytes,
                            uint32_t length) {
  key_sink_t *sink = (key_sink_t *)context;
  if (length > ORBIT_GRANT_MAX_JSON_BYTES - sink->bytes)
    return sink->error = ORBIT_CLIENT_RESOURCE_LIMIT;
  sink->bytes += length;
  if (*sink->http != 200u)
    return 0;
  if (orbit_jwks_feed(&sink->importer, &sink->c->keys,
                      &sink->c->services.crypto, bytes, length) != 0)
    return sink->error = ORBIT_CLIENT_UNTRUSTED;
  return 0;
}
static int32_t fetch_keys(orbit_client_state_t *c, uint64_t generation) {
  uint8_t path[384];
  uint16_t http = 0u;
  int32_t status;
  orbit_writer_t w = {path, 0u, sizeof(path), 0};
  orbit_http_request_t request;
  key_sink_t sink;
  orbit_zero(&sink, sizeof(sink));
  sink.c = c;
  sink.http = &http;
  ORBIT_LITERAL(&w, "/.well-known/orbit-jwks.json?application_id=");
  orbit_write(&w, c->config.application_id.data,
              c->config.application_id.length);
  ORBIT_LITERAL(&w, "&environment_id=");
  orbit_write(&w, c->config.environment_id.data,
              c->config.environment_id.length);
  if (w.status)
    return w.status;
  request.origin = c->config.api_origin;
  request.path = slice(path, w.length);
  request.body = slice(NULL, 0u);
  request.post = 0u;
  (void)orbit_jwks_begin(&sink.importer, &c->keys);
  status = c->services.exchange(c->services.context, &request, &http,
                                receive_keys, &sink);
  if (c->generation != generation)
    return ORBIT_CLIENT_STALE;
  if (sink.error)
    return sink.error;
  status = response_status(status, http);
  if (status == 0 && orbit_jwks_finish(&sink.importer, &c->keys) != 0)
    status = ORBIT_CLIENT_UNTRUSTED;
  return status;
}
static int has_key(const orbit_grant_keyset_t *keys,
                   const orbit_grant_pending_t *pending) {
  uint32_t i;
  for (i = 0; i < keys->count; ++i)
    if (keys->keys[i].kid_length == pending->kid_length &&
        orbit_equal(keys->keys[i].kid, pending->kid, pending->kid_length))
      return 1;
  return 0;
}
static int decode_equal(const uint8_t *bytes, orbit_json_span_t span,
                        orbit_embedded_slice_t expected) {
  uint8_t text[128];
  uint32_t length;
  return orbit_json_decode_span(bytes, span, text, sizeof(text), &length, 0) ==
             0 &&
         length == expected.length && orbit_equal(text, expected.data, length);
}
static ORBIT_NOINLINE int32_t accept(orbit_client_state_t *c,
                                     uint32_t response_length,
                                     uint8_t operation, uint64_t generation,
                                     uint64_t started) {
  orbit_reply_t reply;
  orbit_record_t next = c->record;
  orbit_grant_expected_t expected;
  orbit_grant_pending_t pending;
  orbit_grant_claims_t claims;
  uint32_t length, i, used = 0u;
  uint64_t ticks;
  int64_t now;
  int32_t result;
  result = orbit_reply_parse(c->arena, response_length, c->scratch, &reply);
  if (result != 0)
    goto done;
  if (reply.replay_expired) {
    result = ORBIT_CLIENT_PENDING;
    goto done;
  }
  if (reply.grant.length == 0u ||
      !decode_equal(
          c->arena, reply.installation,
          slice(c->record.installation, c->record.installation_length)) ||
      !decode_equal(
          c->arena, reply.binding,
          slice(
              (const uint8_t *)(c->config.fingerprint.length ? "hwid" : "none"),
              4u)) ||
      reply.has_provider != (c->config.fingerprint_provider.length != 0u) ||
      (reply.has_provider && !decode_equal(c->arena, reply.provider,
                                           c->config.fingerprint_provider))) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (orbit_json_decode_span(c->arena, reply.activation, next.activation,
                             sizeof(next.activation), &length, 1) != 0 ||
      !orbit_client_opaque(slice(next.activation, length), 1u, 128u)) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  next.activation_length = (uint8_t)length;
  if (operation == 0u) {
    if (reply.has_credential ||
        reply.has_credential_expiry != c->record.has_expiry ||
        reply.credential_expiry != c->record.credential_expiry ||
        next.activation_length != c->record.activation_length ||
        !orbit_equal(next.activation, c->record.activation,
                     next.activation_length)) {
      result = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
  } else {
    if (reply.has_credential_expiry || !reply.has_credential ||
        orbit_json_decode_span(c->arena, reply.credential, next.credential,
                               sizeof(next.credential), &length, 1) != 0 ||
        !orbit_client_opaque(slice(next.credential, length), 1u, 256u)) {
      result = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
    next.credential_length = (uint16_t)length;
    next.has_expiry = 0u;
    next.credential_expiry = 0;
  }
  orbit_zero(&expected, sizeof(expected));
  expected.issuer = c->config.issuer;
  expected.application_id = c->config.application_id;
  expected.environment_id = c->config.environment_id;
  expected.activation_id = slice(next.activation, next.activation_length);
  expected.installation_id = slice(next.installation, next.installation_length);
  expected.fingerprint = c->config.fingerprint;
  if (!c->config.fingerprint.length)
    expected.fingerprint = slice(NULL, 0u);
  expected.fingerprint_provider = c->config.fingerprint_provider;
  if (!c->config.fingerprint_provider.length)
    expected.fingerprint_provider = slice(NULL, 0u);
  expected.has_fingerprint = (uint8_t)(c->config.fingerprint.length != 0u);
  expected.has_fingerprint_provider = expected.has_fingerprint;
  expected.has_credential_expiry = next.has_expiry;
  expected.credential_expires_at = next.credential_expiry;
  expected.has_licence_expiry = reply.has_licence_expiry;
  expected.licence_expires_at = reply.licence_expiry;
  expected.received_unix_seconds = reply.server_time;
  if (operation == 0u) {
    expected.licence_id = slice(c->record.licence, c->record.licence_length);
    expected.has_licence_id = 1u;
  }
  if (orbit_json_decode_span(c->arena, reply.grant, c->arena,
                             ORBIT_GRANT_MAX_TOKEN_BYTES, &length, 1) != 0) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (orbit_grant_prepare(c->arena, length, &c->services.crypto, &pending) !=
      0) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (!has_key(&c->keys, &pending)) {
    result = fetch_keys(c, generation);
    if (result != 0) {
      clear_access(c);
      if (result == ORBIT_CLIENT_TRANSIENT)
        result = KEY_FETCH_TRANSIENT;
      goto done;
    }
  }
  result = clock_now(c, &now, &ticks);
  if (result != 0)
    goto done;
  if (ticks < started || (ticks - started) / 1000u > (uint64_t)INT64_MAX ||
      reply.server_time > INT64_MAX - (int64_t)((ticks - started) / 1000u)) {
    result = ORBIT_CLIENT_CLOCK;
    goto done;
  }
  expected.current_unix_seconds =
      reply.server_time + (int64_t)((ticks - started) / 1000u);
  if ((next.has_expiry &&
       (next.credential_expiry <= expected.current_unix_seconds ||
        next.credential_expiry - expected.current_unix_seconds > 2592000)) ||
      orbit_grant_verify(c->arena, length, &pending, &c->keys, &expected,
                         &c->services.crypto, c->scratch,
                         ORBIT_GRANT_WORKSPACE_BYTES, &claims) != 0) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (c->generation != generation) {
    result = ORBIT_CLIENT_STALE;
    goto done;
  }
  for (i = 0; i < claims.entitlement_count; ++i)
    used += claims.entitlements[i].name.length;
  if (used > sizeof(c->active.pool)) {
    result = ORBIT_CLIENT_RESOURCE_LIMIT;
    goto done;
  }
  if (operation == 1u) {
    next.licence_length = (uint8_t)claims.subject.length;
    orbit_copy(next.licence, c->arena + claims.subject.offset,
               claims.subject.length);
    next.pending_kind = 0u;
    next.pending_created = 0;
    orbit_zero(next.pending_id, sizeof(next.pending_id));
    orbit_zero(next.pending_digest, sizeof(next.pending_digest));
    result = save(c, &next);
    if (result != 0)
      goto done;
  }
  if (c->generation != generation) {
    result = ORBIT_CLIENT_STALE;
    goto done;
  }
  orbit_zero(&c->active, sizeof(c->active));
  used = 0u;
  for (i = 0; i < claims.entitlement_count; ++i) {
    c->active.names[i].offset = (uint16_t)used;
    c->active.names[i].length = claims.entitlements[i].name.length;
    orbit_copy(c->active.pool + used,
               c->arena + claims.entitlements[i].name.offset,
               claims.entitlements[i].name.length);
    used += claims.entitlements[i].name.length;
  }
  orbit_copy(c->active.enabled, claims.entitlement_enabled,
             sizeof(c->active.enabled));
  c->active.count = claims.entitlement_count;
  c->active.expires = claims.expires_at;
  c->active.refresh = claims.refresh_after;
  c->active.policy = claims.policy_version;
  c->active.offline_allowed = claims.offline_allowed;
  c->anchor_server = reply.server_time;
  c->anchor_ticks = started;
  c->anchored = 1u;
  c->transient = 0u;
  c->retry_ticks = 0u;
  c->active.valid = 1u;
  result = 0;
done:
  wipe(&next, sizeof(next));
  return result;
}

static int32_t perform(orbit_client_state_t *c, uint8_t operation,
                       orbit_embedded_slice_t key) {
  uint8_t path[256];
  orbit_writer_t route = {path, 0u, sizeof(path), 0};
  orbit_writer_t request_body = {c->arena, 0u, ORBIT_CLIENT_ARENA_BYTES, 0};
  orbit_http_request_t request;
  response_sink_t sink = {c, 0u, 0};
  uint16_t http = 0u;
  int32_t result;
  int64_t now;
  uint64_t started, generation = c->generation;
  result = clock_now(c, &now, &started);
  if (result != 0)
    return result;
  ORBIT_LITERAL(&route, "/api/client/v1/activations");
  if (operation != 1u) {
    ORBIT_LITERAL(&route, "/");
    orbit_write(&route, c->record.activation, c->record.activation_length);
    if (operation == 2u)
      ORBIT_LITERAL(&route, "/deactivate");
    else
      ORBIT_LITERAL(&route, "/validate");
  }
  body(c, &request_body, key, operation, &c->record);
  if (route.status || request_body.status)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  request.origin = c->config.api_origin;
  request.path = slice(path, route.length);
  request.body = slice(c->arena, request_body.length);
  request.post = 1u;
  result = c->services.exchange(c->services.context, &request, &http,
                                receive_response, &sink);
  if (c->generation != generation)
    return result == ORBIT_CLIENT_STORAGE || result == ORBIT_CLIENT_CLOCK
               ? result
               : ORBIT_CLIENT_STALE;
  if (sink.error)
    result = sink.error;
  if (operation == 2u && result == 0 && http == 204u) {
    if (sink.length != 0u)
      result = ORBIT_CLIENT_UNTRUSTED;
    else
      return terminal(c, 0);
  } else
    result = response_status(result, http);
  if (result == 0) {
    if (operation == 2u)
      result = ORBIT_CLIENT_UNTRUSTED;
    else
      result = accept(c, sink.length, operation, generation, started);
  }
  if (c->generation != generation)
    return result == ORBIT_CLIENT_STORAGE || result == ORBIT_CLIENT_CLOCK
               ? result
               : ORBIT_CLIENT_STALE;
  if (result == KEY_FETCH_TRANSIENT) {
    if (advance(c) != 0)
      return ORBIT_CLIENT_STORAGE;
    result = ORBIT_CLIENT_TRANSIENT;
  }
  if (result == ORBIT_CLIENT_TRANSIENT) {
    if (clock_now(c, &now, &started) != 0)
      return ORBIT_CLIENT_CLOCK;
    c->transient = 1u;
    c->retry_ticks =
        started > UINT64_MAX - 30000u ? UINT64_MAX : started + 30000u;
    if (!c->active.offline_allowed || !c->active.valid ||
        now >= c->active.expires)
      c->active.valid = 0u;
    return result;
  }
  if (result != 0 && result != ORBIT_CLIENT_PENDING &&
      result != ORBIT_CLIENT_CLOCK && result != ORBIT_CLIENT_STALE &&
      result != ORBIT_CLIENT_STORAGE) {
    /* An uncertain mutation keeps its durable retry identity. The pending
     * flag fences validation/access until a deliberate identical retry. */
    if (operation != 0u && result != ORBIT_CLIENT_DENIED) {
      clear_access(c);
      (void)advance(c);
      return result;
    }
    return terminal(c, result);
  }
  return result;
}
static int32_t finish_operation(orbit_client_state_t *c, int32_t result) {
  c->busy = 0u;
  wipe(c->arena, ORBIT_CLIENT_ARENA_BYTES);
  wipe(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  return result;
}
static ORBIT_NOINLINE int32_t prepare_activation(orbit_client_state_t *c,
                                                 orbit_embedded_slice_t key) {
  orbit_record_t next;
  uint8_t digest[32];
  uint32_t length;
  int64_t now;
  uint64_t ticks;
  int32_t result;
  orbit_writer_t w;
  result = clock_now(c, &now, &ticks);
  if (result != 0)
    return result;
  next = c->record;
  if (!next.pending_kind) {
    result = random_id(c, next.pending_id);
    if (result != 0)
      goto done;
    next.pending_kind = 1u;
    next.pending_created = now;
  }
  if (next.pending_created > now || now - next.pending_created >= 86400) {
    result = ORBIT_CLIENT_PENDING;
    goto done;
  }
  w = (orbit_writer_t){c->arena, 0u, ORBIT_CLIENT_ARENA_BYTES, 0};
  body(c, &w, key, 1u, &next);
  length = w.length;
  if (w.status || c->services.crypto.sha256(c->services.crypto.context,
                                            c->arena, length, digest) != 0) {
    result = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  if (c->record.pending_kind) {
    if (!orbit_equal(digest, c->record.pending_digest, 32u)) {
      result = ORBIT_CLIENT_PENDING;
      goto done;
    }
  } else {
    orbit_copy(next.pending_digest, digest, 32u);
    clear_access(c);
    result = advance(c);
    if (result != 0)
      goto done;
    result = save(c, &next);
    if (result != 0)
      goto done;
  }
  result = 0;
done:
  wipe(&next, sizeof(next));
  wipe(digest, sizeof(digest));
  return result;
}
int32_t orbit_client_activate(orbit_client_t *client,
                              orbit_embedded_slice_t key) {
  orbit_client_state_t *c = state(client);
  int32_t result;
  if (c == NULL || key.data == NULL || key.length == 0u || key.length > 256u ||
      !orbit_json_valid_utf8_no_nul(key.data, key.length))
    return ORBIT_CLIENT_ARGUMENT;
  if (orbit_overlap(key.data, key.length, client, sizeof(*client)) ||
      orbit_overlap(key.data, key.length, c->arena, ORBIT_CLIENT_ARENA_BYTES) ||
      orbit_overlap(key.data, key.length, c->scratch,
                    ORBIT_GRANT_WORKSPACE_BYTES))
    return ORBIT_CLIENT_ARGUMENT;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->record.pending_kind == 2u)
    return ORBIT_CLIENT_PENDING;
  c->busy = 1u;
  result = prepare_activation(c, key);
  if (result == 0)
    result = perform(c, 1u, key);
  return finish_operation(c, result);
}
int32_t orbit_client_tick(orbit_client_t *client) {
  orbit_client_state_t *c = state(client);
  int64_t now;
  uint64_t ticks;
  int32_t result;
  if (c == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->record.pending_kind)
    return ORBIT_CLIENT_PENDING;
  if (c->record.credential_length == 0u)
    return ORBIT_CLIENT_ACTIVATION_REQUIRED;
  c->busy = 1u;
  result = clock_now(c, &now, &ticks);
  if (result != 0)
    goto done;
  if (c->record.has_expiry && now >= c->record.credential_expiry) {
    result = terminal(c, ORBIT_CLIENT_ACTIVATION_REQUIRED);
    goto done;
  }
  if (c->active.valid && now < c->active.refresh && now < c->active.expires)
    goto done;
  if (c->retry_ticks && ticks < c->retry_ticks) {
    result = ORBIT_CLIENT_TRANSIENT;
    goto done;
  }
  result = perform(c, 0u, slice(NULL, 0u));
  return finish_operation(c, result);
done:
  c->busy = 0u;
  return result;
}
int32_t orbit_client_snapshot(orbit_client_t *client,
                              orbit_access_snapshot_t *out) {
  orbit_client_state_t *c = state(client);
  int64_t now;
  uint64_t ticks;
  int32_t result;
  if (out == NULL || c == NULL ||
      orbit_overlap(out, sizeof(*out), client, sizeof(*client)) ||
      orbit_overlap(out, sizeof(*out), c->arena, ORBIT_CLIENT_ARENA_BYTES) ||
      orbit_overlap(out, sizeof(*out), c->scratch, ORBIT_GRANT_WORKSPACE_BYTES))
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  orbit_zero(out, sizeof(*out));
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  out->activation_required = (uint8_t)(c->record.credential_length == 0u);
  out->pending = c->record.pending_kind;
  out->has_credential_expiry = c->record.has_expiry;
  out->credential_expires_at = c->record.credential_expiry;
  c->busy = 1u;
  result = clock_now(c, &now, &ticks);
  c->busy = 0u;
  if (result != 0)
    return result;
  out->expires_at = c->active.expires;
  out->refresh_after = c->active.refresh;
  out->policy_version = c->active.policy;
  out->offline = (uint8_t)(c->transient && c->active.offline_allowed);
  out->allowed = (uint8_t)(!c->record.pending_kind && c->active.valid &&
                           now < c->active.expires &&
                           (now < c->active.refresh || out->offline));
  return 0;
}
int32_t orbit_client_require_access(orbit_client_t *client,
                                    orbit_embedded_slice_t name) {
  orbit_client_state_t *c = state(client);
  orbit_access_snapshot_t snapshot;
  uint32_t i;
  int32_t result;
  if (c == NULL || name.data == NULL || name.length == 0u ||
      name.length > 64u ||
      orbit_overlap(name.data, name.length, client, sizeof(*client)) ||
      orbit_overlap(name.data, name.length, c->arena,
                    ORBIT_CLIENT_ARENA_BYTES) ||
      orbit_overlap(name.data, name.length, c->scratch,
                    ORBIT_GRANT_WORKSPACE_BYTES))
    return ORBIT_CLIENT_ARGUMENT;
  result = orbit_client_tick(client);
  if (result != 0 && result != ORBIT_CLIENT_TRANSIENT)
    return result;
  result = orbit_client_snapshot(client, &snapshot);
  if (result != 0)
    return result;
  if (!snapshot.allowed)
    return ORBIT_CLIENT_DENIED;
  for (i = 0; i < c->active.count; ++i)
    if (c->active.names[i].length == name.length &&
        orbit_equal(c->active.pool + c->active.names[i].offset, name.data,
                    name.length))
      return (c->active.enabled[i / 8u] & (1u << (i % 8u)))
                 ? 0
                 : ORBIT_CLIENT_DENIED;
  return ORBIT_CLIENT_DENIED;
}
static ORBIT_NOINLINE int32_t prepare_deactivation(orbit_client_state_t *c) {
  orbit_record_t next;
  int32_t result;
  int64_t now;
  uint64_t ticks;
  result = clock_now(c, &now, &ticks);
  if (result != 0)
    return result;
  next = c->record;
  result = random_id(c, next.pending_id);
  if (result != 0)
    goto done;
  next.pending_kind = 2u;
  next.pending_created = now;
  result = save(c, &next);
  if (result != 0)
    goto done;
done:
  wipe(&next, sizeof(next));
  return result;
}
int32_t orbit_client_deactivate(orbit_client_t *client) {
  orbit_client_state_t *c = state(client);
  int32_t result;
  if (c == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->failed)
    return ORBIT_CLIENT_STORAGE;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  clear_access(c);
  result = advance(c);
  if (result != 0)
    return result;
  if (!c->record.credential_length)
    return orbit_client_invalidate(client);
  if (c->record.pending_kind == 1u)
    return ORBIT_CLIENT_PENDING;
  c->busy = 1u;
  result = c->record.pending_kind ? 0 : prepare_deactivation(c);
  if (result == 0)
    result = perform(c, 2u, slice(NULL, 0u));
  return finish_operation(c, result);
}
int32_t orbit_client_invalidate(orbit_client_t *client) {
  orbit_client_state_t *c = state(client);
  int32_t result;
  if (c == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  if (c->failed) {
    clear_access(c);
    return ORBIT_CLIENT_STORAGE;
  }
  c->busy = 1u;
  result = terminal(c, 0);
  c->busy = 0u;
  return result;
}
int32_t orbit_client_clock_lost(orbit_client_t *client) {
  orbit_client_state_t *c = state(client);
  if (c == NULL)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  clear_access(c);
  c->last_wall = -1;
  return advance(c);
}
void orbit_client_destroy(orbit_client_t *client) {
  orbit_client_state_t *c = state(client);
  if (c == NULL)
    return;
  if (c->busy)
    return;
  wipe(c->arena, ORBIT_CLIENT_ARENA_BYTES);
  wipe(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  wipe(client, sizeof(*client));
}
