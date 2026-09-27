#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_services_internal.h"
#define F(n) {n, {0, 0}}
static void clear_session(orbit_client_state_t *c, int discard) {
  orbit_client_extension_t *e = c->extension;
  orbit_client_clear_access(c);
  e->session.active = 0;
  e->session.expires_at = e->session.refresh_after = 0;
  if (discard) {
    orbit_zero(e->session.id, 128);
    e->session.id_length = 0;
    e->session.sequence = 0;
    e->pending_start = 0;
    e->pending_sequence = 0;
    e->pending_started = 0;
    e->next_poll = 0;
  }
}
static int32_t accept_session(orbit_client_state_t *c, uint32_t n,
                              uint64_t sequence, uint64_t started) {
  orbit_client_extension_t *e = c->extension;
  uint64_t generation = c->generation;
  orbit_field_t f[] = {F("session_id"), F("sequence"), F("expires_at"),
                       F("server_time"), F("grant")};
  orbit_embedded_slice_t id, token;
  orbit_signed_expected_t expected;
  orbit_grant_pending_t pending;
  orbit_signed_claims_t claims;
  int64_t expiry, server, now;
  uint64_t seq, ticks;
  int32_t r;
  if (orbit_fields(c->arena, n, c->scratch, f, 5) ||
      orbit_field_string(c->arena, f[0].value, &id) ||
      !orbit_slice_equal(
          id, (orbit_embedded_slice_t){e->session.id, e->session.id_length}) ||
      orbit_field_uint(c->arena, f[1].value, &seq) || seq != sequence ||
      orbit_field_time(c->arena, f[2].value, &expiry) ||
      orbit_field_time(c->arena, f[3].value, &server) ||
      orbit_field_string(c->arena, f[4].value, &token) || !token.length ||
      token.length > 16384)
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_copy(c->arena, token.data, token.length);
  r = orbit_signed_prepare(c->arena, token.length, &c->services.crypto,
                           ORBIT_SIGNED_SESSION, &pending);
  if (r)
    return ORBIT_CLIENT_UNTRUSTED;
  {
    uint32_t i;
    for (i = 0; i < c->keys.count; ++i)
      if (c->keys.keys[i].kid_length == pending.kid_length &&
          orbit_equal(c->keys.keys[i].kid, pending.kid, pending.kid_length))
        break;
    if (i == c->keys.count) {
      r = orbit_client_fetch_keys(c, c->generation);
      if (r)
        return r;
    }
  }
  r = orbit_client_clock(c, &now, &ticks);
  if (r)
    return r;
  if (ticks < started || (ticks - started) / 1000 > 120 ||
      server > INT64_C(253402300799) - (int64_t)((ticks - started) / 1000))
    return ORBIT_CLIENT_CLOCK;
  orbit_zero(&expected, sizeof(expected));
  expected.purpose = ORBIT_SIGNED_SESSION;
  expected.environment_kind = c->config.environment_kind;
  expected.session_id =
      (orbit_embedded_slice_t){e->session.id, e->session.id_length};
  expected.sequence = sequence;
  expected.scope.issuer = c->config.issuer;
  expected.scope.application_id = c->config.application_id;
  expected.scope.environment_id = c->config.environment_id;
  expected.scope.licence_id =
      (orbit_embedded_slice_t){c->record.licence, c->record.licence_length};
  expected.scope.has_licence_id = 1;
  expected.scope.activation_id = (orbit_embedded_slice_t){
      c->record.activation, c->record.activation_length};
  expected.scope.installation_id = (orbit_embedded_slice_t){
      c->record.installation, c->record.installation_length};
  expected.scope.received_unix_seconds = server;
  expected.scope.current_unix_seconds =
      server + (int64_t)((ticks - started) / 1000);
  expected.scope.has_credential_expiry = c->record.has_expiry;
  expected.scope.credential_expires_at = c->record.credential_expiry;
  expected.scope.has_licence_expiry = e->has_licence_expiry;
  expected.scope.licence_expires_at = e->licence_expires_at;
  if (c->config.fingerprint.length) {
    expected.scope.has_fingerprint = expected.scope.has_fingerprint_provider =
        1;
    expected.scope.fingerprint = c->config.fingerprint;
    expected.scope.fingerprint_provider = c->config.fingerprint_provider;
    expected.allow_unbound_fingerprint = 1;
  }
  r = orbit_signed_verify(c->arena, token.length, &pending, &c->keys, &expected,
                          &c->services.crypto, c->scratch,
                          ORBIT_GRANT_WORKSPACE_BYTES, &claims);
  if (r || claims.access.expires_at != expiry)
    return ORBIT_CLIENT_UNTRUSTED;
  r = orbit_client_clock(c, &now, &ticks);
  if (r)
    return r;
  if (c->generation != generation)
    return ORBIT_CLIENT_STALE;
  if (ticks < started ||
      (ticks - started) / 1000 >= (uint64_t)(expiry - server))
    return ORBIT_CLIENT_DENIED;
  orbit_client_apply_claims(c, &claims.access, server, started);
  e->session.sequence = sequence;
  e->session.expires_at = claims.access.expires_at;
  e->session.refresh_after = claims.access.refresh_after;
  e->session.active = 1;
  e->pending_start = 0;
  e->pending_sequence = 0;
  e->pending_started = 0;
  e->next_poll = 0;
  return 0;
}
static int32_t session_request(orbit_client_t *client, uint8_t action,
                               const orbit_operation_t *op) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  uint8_t path[512];
  orbit_writer_t route = {path, 0, sizeof(path), 0}, body;
  uint64_t started = 0, sequence;
  int64_t now = 0;
  uint16_t http;
  uint32_t n;
  int32_t r = orbit_service_begin(client, op, &c);
  if (r)
    return r;
  e = c->extension;
  r = orbit_client_clock(c, &now, &started);
  if (r)
    goto done;
  ORBIT_LITERAL(&route, "/api/client/v1/activations/");
  orbit_write(&route, c->record.activation, c->record.activation_length);
  ORBIT_LITERAL(&route, "/sessions");
  if (action) {
    ORBIT_LITERAL(&route, "/");
    orbit_write(&route, e->session.id, e->session.id_length);
    if (action == 1)
      ORBIT_LITERAL(&route, "/renew");
    else
      ORBIT_LITERAL(&route, "/end");
  }
  body = (orbit_writer_t){c->arena, 0, c->arena_capacity, 0};
  orbit_service_proof(c, &body);
  sequence = action == 1 ? e->session.sequence + 1 : 1;
  if (!action) {
    ORBIT_LITERAL(&body, ",\"session_id\":");
    orbit_write_string(
        &body, (orbit_embedded_slice_t){e->session.id, e->session.id_length});
  } else if (action == 1) {
    if (sequence > ORBIT_SAFE_INTEGER_MAX) {
      r = ORBIT_CLIENT_DENIED;
      goto done;
    }
    ORBIT_LITERAL(&body, ",\"sequence\":");
    orbit_write_uint(&body, sequence);
    e->pending_sequence = sequence;
  }
  ORBIT_LITERAL(&body, "}");
  r = route.status ? route.status : body.status;
  if (r)
    goto done;
  r = orbit_service_exchange(c, (orbit_embedded_slice_t){path, route.length},
                             body.length, op, &http, &n);
  if (!r && action == 2) {
    r = (http == 204 && n == 0) ? 0 : orbit_service_status(0, http);
    if (!r && http != 204)
      r = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  r = orbit_service_status(r, http);
  if (!r)
    r = accept_session(c, n, sequence, started);
  if (!r && op && op->cancelled && op->cancelled(op->context))
    r = ORBIT_CLIENT_CANCELLED;
done:
  if (action != 2 && r && r != ORBIT_CLIENT_STALE) {
    if (r != ORBIT_CLIENT_TRANSIENT)
      clear_session(c, r != ORBIT_CLIENT_CANCELLED);
    else {
      if (e->session.active && now >= e->session.expires_at)
        clear_session(c, 1);
      else if (!e->session.active)
        orbit_client_clear_access(c);
      e->next_poll = started > UINT64_MAX - 5000 ? UINT64_MAX : started + 5000;
    }
  }
  if (action != 2 && r && r != ORBIT_CLIENT_STALE)
    e->next_poll = started > UINT64_MAX - 5000 ? UINT64_MAX : started + 5000;
  orbit_service_finish(c);
  if (r == ORBIT_CLIENT_STALE && action != 2 && !e->session.automatic &&
      e->session.id_length)
    (void)orbit_client_end_session(client, NULL);
  if (r == ORBIT_CLIENT_CANCELLED && action != 2 && e->session.id_length)
    (void)orbit_client_end_session(client, NULL);
  return r;
}
int32_t orbit_extended_tick(orbit_client_t *client) {
  orbit_client_state_t *c = &client->private_state;
  orbit_client_extension_t *e = c->extension;
  int64_t now;
  uint64_t ticks;
  int32_t r;
  if (!e)
    return ORBIT_CLIENT_ARGUMENT;
  r = orbit_client_clock(c, &now, &ticks);
  if (r)
    return r;
#ifdef ORBIT_ENABLE_OFFLINE
  if (e->offline_mode) {
    if (now < e->offline_floor)
      return ORBIT_CLIENT_CLOCK;
    if (!c->active.valid)
      return orbit_offline_restore(c);
    if (now >= c->active.expires)
      return ORBIT_CLIENT_DENIED;
    return orbit_offline_checkpoint(c, now, 0);
  }
#endif
  if (!e->session.required)
    return 0;
  if (!e->session.automatic)
    return ORBIT_CLIENT_DENIED;
  if (e->session.active && now >= e->session.expires_at)
    clear_session(c, 1);
  if (e->session.active && now < e->session.refresh_after)
    return 0;
  if (e->next_poll && ticks < e->next_poll)
    return ORBIT_CLIENT_TRANSIENT;
  if (e->session.active)
    return session_request(client, 1, NULL);
  if (e->pending_start &&
      (ticks < e->pending_started || ticks - e->pending_started >= 120000))
    clear_session(c, 1);
  if (!e->pending_start) {
    r = orbit_operation_id(c, NULL, e->session.id, &e->session.id_length);
    if (r)
      return r;
    e->pending_start = 1;
    e->pending_started = ticks;
  }
  return session_request(client, 0, NULL);
}
int32_t orbit_client_start_session(orbit_client_t *client,
                                   const orbit_operation_t *op,
                                   orbit_session_snapshot_t *out) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  int32_t r;
  if (!client || !out || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  e = c->extension;
  if (!e)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
#ifdef ORBIT_ENABLE_OFFLINE
  if (e->offline_mode)
    return ORBIT_CLIENT_DENIED;
#endif
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
  if (!e->policy_known) {
    e->session.automatic = 0;
    r = orbit_client_tick(client);
    if (r &&
        !(r == ORBIT_CLIENT_DENIED && e->policy_known && e->session.required))
      return r;
  }
  if (op && op->cancelled && op->cancelled(op->context))
    return ORBIT_CLIENT_CANCELLED;
  e->session.automatic = 1;
  if (!e->session.required) {
    orbit_zero(out, sizeof(*out));
    return 0;
  }
  if (e->session.active) {
    r = orbit_client_session(client, out);
    if (!r && out->active)
      return 0;
  }
  {
    int64_t now;
    uint64_t ticks;
    r = orbit_client_clock(c, &now, &ticks);
    if (r)
      return r;
    if (e->pending_start &&
        (ticks < e->pending_started || ticks - e->pending_started >= 120000))
      clear_session(c, 1);
    if (!e->pending_start) {
      r = orbit_operation_id(c, NULL, e->session.id, &e->session.id_length);
      if (r)
        return r;
      e->pending_start = 1;
      e->pending_started = ticks;
    }
  }
  r = session_request(client, 0, op);
  if (!r)
    *out = e->session;
  return r;
}
int32_t orbit_client_end_session(orbit_client_t *client,
                                 const orbit_operation_t *op) {
  orbit_client_state_t *c;
  orbit_client_extension_t *e;
  int32_t r = 0;
  if (!client || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  e = c->extension;
  if (!e)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy) {
    if (e->policy_known && !e->session.required)
      return 0;
    e->session.automatic = 0;
    e->session.active = 0;
    orbit_client_clear_access(c);
    ++c->generation;
    return 0; /* Local fence only; outer request performs bounded cleanup. */
  }
#ifdef ORBIT_ENABLE_OFFLINE
  if (e->offline_mode)
    return ORBIT_CLIENT_DENIED;
#endif
  if (e->policy_known && !e->session.required)
    return 0;
  e->session.automatic = 0;
  orbit_client_clear_access(c);
  e->session.active = 0;
  ++c->generation;
  if (e->session.id_length && c->record.credential_length)
    r = session_request(client, 2, op);
  clear_session(c, 1);
  return r;
}
int32_t orbit_client_session(orbit_client_t *client,
                             orbit_session_snapshot_t *out) {
  orbit_client_state_t *c;
  int64_t now;
  uint64_t ticks;
  int32_t r;
  if (!client || !out || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (!c->extension)
    return ORBIT_CLIENT_ARGUMENT;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
  r = orbit_client_clock(c, &now, &ticks);
  if (r)
    return r;
  *out = c->extension->session;
  out->active =
      (uint8_t)(out->active && c->active.valid && now < out->expires_at);
  return 0;
}
int32_t orbit_client_close(orbit_client_t *client,
                           const orbit_operation_t *op) {
  orbit_client_state_t *c;
  int32_t r = 0;
  if (!client || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (c->busy)
    return ORBIT_CLIENT_BUSY;
#ifdef ORBIT_ENABLE_OFFLINE
  if (c->extension && c->extension->offline.transaction) {
    int64_t now;
    uint64_t ticks;
    r = orbit_client_clock(c, &now, &ticks);
    if (!r)
      r = orbit_offline_checkpoint(c, now, 1);
  }
#endif
  if (c->extension && c->extension->session.required) {
    int32_t end = orbit_client_end_session(client, op);
    if (!r)
      r = end;
  }
  orbit_client_destroy(client);
  return r;
}

#endif
