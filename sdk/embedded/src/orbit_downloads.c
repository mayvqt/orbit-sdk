#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_downloads.h"
#include "orbit_services_internal.h"
#define F(n) {n, {0, 0}}
static int target(orbit_embedded_slice_t s) {
  uint32_t i;
  if (!s.data || !s.length || s.length > 32 || s.data[0] < 'a' ||
      s.data[0] > 'z')
    return 0;
  for (i = 1; i < s.length; ++i)
    if (!((s.data[i] >= 'a' && s.data[i] <= 'z') ||
          (s.data[i] >= '0' && s.data[i] <= '9') || s.data[i] == '_' ||
          s.data[i] == '-'))
      return 0;
  return 1;
}
static int hex(uint8_t c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}
static int https_url(orbit_embedded_slice_t s, int protected_url) {
  uint32_t i, host_end;
  if (!s.data || s.length < 9 || s.length > 2048)
    return 0;
  for (i = 8; i < s.length; ++i) {
    uint8_t c = s.data[i];
    if (c <= 32 || c >= 127 || c == '\\' || c == '#' ||
        (protected_url && c == '?'))
      return 0;
  }
  for (host_end = 8; host_end < s.length && s.data[host_end] != '/' &&
                     s.data[host_end] != '?';
       ++host_end) {
  }
  if (!orbit_https_origin_valid(s.data, host_end))
    return 0;
  for (i = host_end; i < s.length; ++i)
    if (s.data[i] == '%') {
      if (i + 2 >= s.length ||
          !((hex(s.data[i + 1]) >= 0) ||
            (s.data[i + 1] >= 'A' && s.data[i + 1] <= 'F')) ||
          !((hex(s.data[i + 2]) >= 0) ||
            (s.data[i + 2] >= 'A' && s.data[i + 2] <= 'F')))
        return 0;
      i += 2;
    }
  return 1;
}
static int32_t artifact(uint8_t *b, uint32_t n, uint8_t *scratch,
                        orbit_artifact_t *a) {
  orbit_field_t f[] = {
      F("id"),       F("release_id"),      F("platform"), F("architecture"),
      F("filename"), F("byte_length"),     F("sha256"),   F("delivery_mode"),
      F("url"),      F("required_feature")};
  orbit_embedded_slice_t hash, mode;
  uint32_t i;
  if (orbit_fields(b, n, scratch, f, 10) ||
      orbit_field_string(b, f[0].value, &a->id) ||
      !orbit_client_opaque(a->id, 1, 128) ||
      orbit_field_string(b, f[1].value, &a->release_id) ||
      !orbit_client_opaque(a->release_id, 1, 128) ||
      orbit_field_string(b, f[2].value, &a->platform) || !target(a->platform) ||
      orbit_field_string(b, f[3].value, &a->architecture) ||
      !target(a->architecture) ||
      orbit_field_string(b, f[4].value, &a->filename) || !a->filename.length ||
      a->filename.length > 255 ||
      orbit_field_uint(b, f[5].value, &a->byte_length) || !a->byte_length ||
      orbit_field_string(b, f[6].value, &hash) || hash.length != 64 ||
      orbit_field_string(b, f[7].value, &mode) ||
      orbit_field_string(b, f[8].value, &a->url))
    return ORBIT_CLIENT_UNTRUSTED;
  for (i = 0; i < a->filename.length; ++i)
    if (a->filename.data[i] < 32 || a->filename.data[i] == 127 ||
        a->filename.data[i] == '/' || a->filename.data[i] == '\\')
      return ORBIT_CLIENT_UNTRUSTED;
  if ((a->filename.length == 1 && a->filename.data[0] == '.') ||
      (a->filename.length == 2 && orbit_equal(a->filename.data, "..", 2)))
    return ORBIT_CLIENT_UNTRUSTED;
  for (i = 0; i < 32; ++i) {
    int h = hex(hash.data[i * 2]), l = hex(hash.data[i * 2 + 1]);
    if (h < 0 || l < 0)
      return ORBIT_CLIENT_UNTRUSTED;
    a->sha256[i] = (uint8_t)(h * 16 + l);
  }
  if (orbit_slice_equal(
          mode, (orbit_embedded_slice_t){(const uint8_t *)"protected", 9}))
    a->protected_delivery = 1;
  else if (!orbit_slice_equal(
               mode, (orbit_embedded_slice_t){(const uint8_t *)"public", 6}))
    return ORBIT_CLIENT_UNTRUSTED;
  if (!https_url(a->url, a->protected_delivery))
    return ORBIT_CLIENT_UNTRUSTED;
  if (!orbit_field_null(b, f[9].value) &&
      (orbit_field_string(b, f[9].value, &a->required_feature) ||
       !orbit_limit_name(a->required_feature)))
    return ORBIT_CLIENT_UNTRUSTED;
  return 0;
}
static int artifact_equal(const orbit_artifact_t *a,
                          const orbit_artifact_t *b) {
  return orbit_slice_equal(a->id, b->id) &&
         orbit_slice_equal(a->release_id, b->release_id) &&
         orbit_slice_equal(a->platform, b->platform) &&
         orbit_slice_equal(a->architecture, b->architecture) &&
         orbit_slice_equal(a->filename, b->filename) &&
         orbit_slice_equal(a->url, b->url) &&
         orbit_slice_equal(a->required_feature, b->required_feature) &&
         a->byte_length == b->byte_length &&
         a->protected_delivery == b->protected_delivery &&
         orbit_equal(a->sha256, b->sha256, 32);
}
static int32_t release(uint8_t *b, uint32_t n, uint8_t *scratch,
                       orbit_release_t *r, const orbit_artifact_t *selected) {
  orbit_field_t f[] = {F("id"),         F("channel"),        F("version"),
                       F("notes"),      F("release_number"), F("state"),
                       F("created_at"), F("published_at"),   F("artifacts")};
  orbit_embedded_slice_t state;
  orbit_artifact_t nested;
  orbit_json_parser_t p;
  uint32_t start, length;
  if (orbit_fields(b, n, scratch, f, 9) ||
      orbit_field_string(b, f[0].value, &r->id) ||
      !orbit_slice_equal(r->id, selected->release_id) ||
      orbit_field_string(b, f[1].value, &r->channel) || !target(r->channel) ||
      orbit_field_string(b, f[2].value, &r->version) || !r->version.length ||
      r->version.length > 64 || orbit_field_string(b, f[3].value, &r->notes) ||
      r->notes.length > 8192 ||
      orbit_field_uint(b, f[4].value, &r->release_number) ||
      !r->release_number || orbit_field_string(b, f[5].value, &state) ||
      !orbit_slice_equal(
          state, (orbit_embedded_slice_t){(const uint8_t *)"published", 9}) ||
      orbit_field_time(b, f[6].value, &r->created_at) ||
      orbit_field_time(b, f[7].value, &r->published_at) ||
      r->published_at < r->created_at)
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_json_init(&p, b + f[8].value.start, f[8].value.length, scratch);
  orbit_json_skip_space(&p);
  if (p.position >= p.length || p.data[p.position++] != '[')
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_json_skip_space(&p);
  start = p.position;
  if (orbit_json_skip_value(&p, 1))
    return ORBIT_CLIENT_UNTRUSTED;
  length = p.position - start;
  orbit_json_skip_space(&p);
  if (p.position >= p.length || p.data[p.position++] != ']' ||
      orbit_json_finish(&p))
    return ORBIT_CLIENT_UNTRUSTED;
  orbit_zero(&nested, sizeof(nested));
  if (artifact(b + f[8].value.start + start, length, scratch, &nested) ||
      !artifact_equal(selected, &nested))
    return ORBIT_CLIENT_UNTRUSTED;
  return 0;
}
static int32_t request(orbit_client_state_t *c, const char *suffix,
                       uint32_t suffix_length, orbit_writer_t *body,
                       const orbit_operation_t *op, uint32_t *n) {
  uint8_t path[256];
  orbit_writer_t route = {path, 0, sizeof(path), 0};
  uint16_t http;
  int32_t r;
  ORBIT_LITERAL(&route, "/api/client/v1/activations/");
  orbit_write(&route, c->record.activation, c->record.activation_length);
  orbit_write(&route, suffix, suffix_length);
  ORBIT_LITERAL(body, "}");
  if (route.status || body->status)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  r = orbit_service_exchange(c, (orbit_embedded_slice_t){path, route.length},
                             body->length, op, &http, n);
  return orbit_service_status(r, http);
}
static void release_arena(orbit_client_state_t *c, int32_t r) {
  if (r)
    orbit_zero(c->arena, c->arena_capacity);
  orbit_zero(c->scratch, ORBIT_GRANT_WORKSPACE_BYTES);
  c->busy = 0;
}
int32_t orbit_client_check_for_updates(
    orbit_client_t *client, uint64_t installed, orbit_embedded_slice_t channel,
    orbit_embedded_slice_t platform, orbit_embedded_slice_t architecture,
    const orbit_operation_t *op, orbit_update_t *out) {
  orbit_client_state_t *c;
  orbit_writer_t body;
  uint32_t n;
  int32_t r;
  uint8_t targets[96];
  orbit_field_t f[] = {F("release"), F("artifact")};
  if (!channel.length)
    channel = (orbit_embedded_slice_t){(const uint8_t *)"stable", 6};
  if (!out || installed > ORBIT_SAFE_INTEGER_MAX || !target(channel) ||
      !target(platform) || !target(architecture))
    return ORBIT_CLIENT_ARGUMENT;
  if (!client || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (orbit_overlap(out, sizeof(*out), client, sizeof(*client)) ||
      orbit_overlap(out, sizeof(*out), c->arena, c->arena_capacity) ||
      orbit_overlap(out, sizeof(*out), c->scratch, ORBIT_GRANT_WORKSPACE_BYTES))
    return ORBIT_CLIENT_ARGUMENT;
  orbit_copy(targets, channel.data, channel.length);
  orbit_copy(targets + 32, platform.data, platform.length);
  orbit_copy(targets + 64, architecture.data, architecture.length);
  channel.data = targets;
  platform.data = targets + 32;
  architecture.data = targets + 64;
  orbit_zero(out, sizeof(*out));
  r = orbit_service_begin(client, op, &c);
  if (r)
    return r;
  body = (orbit_writer_t){c->arena, 0, c->arena_capacity, 0};
  orbit_service_proof(c, &body);
  ORBIT_LITERAL(&body, ",\"channel\":");
  orbit_write_string(&body, channel);
  ORBIT_LITERAL(&body, ",\"platform\":");
  orbit_write_string(&body, platform);
  ORBIT_LITERAL(&body, ",\"architecture\":");
  orbit_write_string(&body, architecture);
  ORBIT_LITERAL(&body, ",\"installed_release_number\":");
  orbit_write_uint(&body, installed);
  r = request(c, "/updates", 8, &body, op, &n);
  if (r)
    goto done;
  r = orbit_fields(c->arena, n, c->scratch, f, 2);
  if (r)
    goto done;
  if (orbit_field_null(c->arena, f[0].value) &&
      orbit_field_null(c->arena, f[1].value))
    goto done;
  r = artifact(c->arena + f[1].value.start, f[1].value.length, c->scratch,
               &out->artifact);
  if (!r)
    r = release(c->arena + f[0].value.start, f[0].value.length, c->scratch,
                &out->release, &out->artifact);
  if (!r && (!orbit_slice_equal(out->release.channel, channel) ||
             !orbit_slice_equal(out->artifact.platform, platform) ||
             !orbit_slice_equal(out->artifact.architecture, architecture) ||
             out->release.release_number <= installed))
    r = ORBIT_CLIENT_UNTRUSTED;
  if (!r)
    out->available = 1;
done:
  if (r)
    orbit_zero(out, sizeof(*out));
  release_arena(c, r);
  return r;
}
int32_t orbit_client_authorize_download(orbit_client_t *client,
                                        orbit_embedded_slice_t release_id,
                                        orbit_embedded_slice_t artifact_id,
                                        const orbit_operation_t *op,
                                        orbit_download_authorization_t *out) {
  orbit_client_state_t *c;
  uint8_t ids[256];
  orbit_writer_t body;
  uint32_t n, i;
  int32_t r;
  int64_t now;
  uint64_t ticks;
  orbit_field_t f[] = {F("artifact"), F("ticket"), F("expires_at")};
  if (!out || !orbit_client_opaque(release_id, 1, 128) ||
      !orbit_client_opaque(artifact_id, 1, 128))
    return ORBIT_CLIENT_ARGUMENT;
  if (!client || client->private_state.magic != ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_ARGUMENT;
  c = &client->private_state;
  if (orbit_overlap(out, sizeof(*out), client, sizeof(*client)) ||
      orbit_overlap(out, sizeof(*out), c->arena, c->arena_capacity) ||
      orbit_overlap(out, sizeof(*out), c->scratch, ORBIT_GRANT_WORKSPACE_BYTES))
    return ORBIT_CLIENT_ARGUMENT;
  orbit_copy(ids, release_id.data, release_id.length);
  orbit_copy(ids + 128, artifact_id.data, artifact_id.length);
  release_id.data = ids;
  artifact_id.data = ids + 128;
  orbit_zero(out, sizeof(*out));
  r = orbit_service_begin(client, op, &c);
  if (r)
    return r;
  body = (orbit_writer_t){c->arena, 0, c->arena_capacity, 0};
  orbit_service_proof(c, &body);
  ORBIT_LITERAL(&body, ",\"release_id\":");
  orbit_write_string(&body, release_id);
  ORBIT_LITERAL(&body, ",\"artifact_id\":");
  orbit_write_string(&body, artifact_id);
  r = request(c, "/downloads/authorize", 20, &body, op, &n);
  if (r)
    goto done;
  r = orbit_fields(c->arena, n, c->scratch, f, 3);
  if (r)
    goto done;
  r = artifact(c->arena + f[0].value.start, f[0].value.length, c->scratch,
               &out->artifact);
  if (!r && (!orbit_slice_equal(out->artifact.id, artifact_id) ||
             !orbit_slice_equal(out->artifact.release_id, release_id)))
    r = ORBIT_CLIENT_UNTRUSTED;
  if (r)
    goto done;
  if (out->artifact.protected_delivery) {
    if (orbit_field_string(c->arena, f[1].value, &out->ticket) ||
        !out->ticket.length || out->ticket.length > 16384 ||
        orbit_field_time(c->arena, f[2].value, &out->expires_at)) {
      r = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
    for (i = 0; i < out->ticket.length; ++i)
      if (out->ticket.data[i] <= 32 || out->ticket.data[i] >= 127) {
        r = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
    r = orbit_client_clock(c, &now, &ticks);
    if (!r && (out->expires_at <= now || out->expires_at - now > 120))
      r = ORBIT_CLIENT_UNTRUSTED;
  } else if (!orbit_field_null(c->arena, f[1].value) ||
             !orbit_field_null(c->arena, f[2].value))
    r = ORBIT_CLIENT_UNTRUSTED;
done:
  if (r)
    orbit_zero(out, sizeof(*out));
  release_arena(c, r);
  return r;
}
int32_t orbit_download_stream(const orbit_download_authorization_t *a,
                              uint64_t maximum, uint8_t replace,
                              const orbit_download_io_t *io, uint8_t *scratch,
                              uint32_t capacity) {
  orbit_embedded_slice_t url, ticket;
  orbit_download_response_t response;
  uint8_t digest[32];
  uint64_t total = 0;
  uint32_t n, redirects = 0, i;
  int32_t r;
  int opened = 0, staged = 0;
  if (!a || !io || !scratch || capacity < ORBIT_DOWNLOAD_SCRATCH_MIN_BYTES ||
      replace > 1 || !io->open || !io->read || !io->close || !io->stage_begin ||
      !io->stage_write || !io->stage_commit || !io->stage_abort ||
      !io->hash_begin || !io->hash_update || !io->hash_finish ||
      !a->artifact.byte_length || a->artifact.byte_length > maximum ||
      !https_url(a->artifact.url, a->artifact.protected_delivery) ||
      orbit_overlap(scratch, capacity, a, sizeof(*a)) ||
      orbit_overlap(scratch, capacity, a->artifact.url.data,
                    a->artifact.url.length) ||
      orbit_overlap(scratch, capacity, a->ticket.data, a->ticket.length))
    return ORBIT_CLIENT_ARGUMENT;
  if (a->artifact.protected_delivery
          ? (!a->ticket.data || !a->ticket.length || a->ticket.length > 16384)
          : a->ticket.length != 0)
    return ORBIT_CLIENT_ARGUMENT;
  for (i = 0; i < a->ticket.length; ++i)
    if (a->ticket.data[i] <= 32 || a->ticket.data[i] >= 127)
      return ORBIT_CLIENT_ARGUMENT;
  url = a->artifact.url;
  ticket = a->ticket;
  if (io->cancelled && io->cancelled(io->context))
    return ORBIT_CLIENT_CANCELLED;
  r = io->stage_begin(io->context, replace);
  if (r) {
    io->stage_abort(io->context);
    return r;
  }
  staged = 1;
  r = io->hash_begin(io->context);
  if (r)
    goto done;
  for (;;) {
    if (io->cancelled && io->cancelled(io->context)) {
      r = ORBIT_CLIENT_CANCELLED;
      goto done;
    }
    orbit_zero(&response, sizeof(response));
    r = io->open(io->context, url, ticket, &response);
    opened = 1;
    if (r)
      goto done;
    if (response.status == 301 || response.status == 302 ||
        response.status == 303 || response.status == 307 ||
        response.status == 308) {
      if (redirects++ >= 5 || !https_url(response.location, 0)) {
        r = ORBIT_CLIENT_UNTRUSTED;
        goto done;
      }
      orbit_copy(scratch, response.location.data, response.location.length);
      url = (orbit_embedded_slice_t){scratch, response.location.length};
      ticket = (orbit_embedded_slice_t){NULL, 0};
      io->close(io->context);
      opened = 0;
      continue;
    }
    if (response.status != 200 ||
        (response.content_encoding.length &&
         !orbit_slice_equal(
             response.content_encoding,
             (orbit_embedded_slice_t){(const uint8_t *)"identity", 8})) ||
        (response.has_content_length &&
         response.content_length != a->artifact.byte_length)) {
      r = ORBIT_CLIENT_UNTRUSTED;
      goto done;
    }
    break;
  }
  for (;;) {
    if (io->cancelled && io->cancelled(io->context)) {
      r = ORBIT_CLIENT_CANCELLED;
      goto done;
    }
    n = 0;
    r = io->read(io->context, scratch + 2048, capacity - 2048, &n);
    if (r)
      goto done;
    if (n > capacity - 2048 || n > a->artifact.byte_length - total ||
        n > maximum - total) {
      r = ORBIT_CLIENT_RESOURCE_LIMIT;
      goto done;
    }
    if (!n)
      break;
    r = io->hash_update(io->context, scratch + 2048, n);
    if (!r)
      r = io->stage_write(io->context, scratch + 2048, n);
    if (r)
      goto done;
    total += n;
  }
  io->close(io->context);
  opened = 0;
  if (total != a->artifact.byte_length) {
    r = ORBIT_CLIENT_UNTRUSTED;
    goto done;
  }
  r = io->hash_finish(io->context, digest);
  if (!r && !orbit_equal(digest, a->artifact.sha256, 32))
    r = ORBIT_CLIENT_UNTRUSTED;
  if (!r && io->cancelled && io->cancelled(io->context))
    r = ORBIT_CLIENT_CANCELLED;
  if (!r)
    r = io->stage_commit(io->context);
  if (!r)
    staged = 0;
done:
  if (opened)
    io->close(io->context);
  if (staged)
    io->stage_abort(io->context);
  orbit_zero(scratch, capacity);
  orbit_zero(digest, 32);
  return r;
}

#endif
