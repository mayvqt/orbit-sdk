#include "orbit_profile.h"
#ifdef ORBIT_ENABLE_SERVICES
#include "orbit_extensions.h"
#include "orbit_services_internal.h"
static int32_t extended_exchange(void *p, const orbit_http_request_t *q,
                                 uint16_t *s, orbit_receive_fn r, void *x) {
  orbit_client_extension_t *e = p;
  return e->platform.exchange(e->platform.context, q, s, r, x);
}
static int32_t extended_clock(void *p, int64_t *w, uint64_t *t) {
  orbit_client_extension_t *e = p;
  return e->platform.clock(e->platform.context, w, t);
}
static int32_t extended_entropy(void *p, uint8_t *b, uint32_t n) {
  orbit_client_extension_t *e = p;
  return e->platform.entropy(e->platform.context, b, n);
}
#ifndef ORBIT_ENABLE_OFFLINE
int32_t orbit_extension_load(void *p, uint8_t *b, uint32_t n,
                             uint32_t *length) {
  orbit_client_extension_t *e = p;
  return e->platform.load(e->platform.context, b, n, length);
}
int32_t orbit_extension_commit(void *p, uint64_t g, const uint8_t *b,
                               uint32_t n) {
  orbit_client_extension_t *e = p;
  return e->platform.commit(e->platform.context, g, b, n);
}
#endif
int32_t orbit_client_init_extended(orbit_client_t *client,
                                   const orbit_client_config_t *cfg,
                                   const orbit_client_services_t *platform,
                                   orbit_client_extension_t *e, uint8_t *arena,
                                   uint32_t arena_length, void *scratch,
                                   uint32_t scratch_length,
                                   const orbit_offline_config_t *offline) {
  orbit_client_services_t services;
  int32_t r;
  if (!client || !cfg || !platform || !e ||
      (cfg->environment_kind != 1 && cfg->environment_kind != 2) ||
      orbit_overlap(e, sizeof(*e), client, sizeof(*client)) ||
      orbit_overlap(e, sizeof(*e), arena, arena_length) ||
      orbit_overlap(e, sizeof(*e), scratch, scratch_length) ||
      orbit_overlap(e, sizeof(*e), cfg, sizeof(*cfg)) ||
      orbit_overlap(e, sizeof(*e), platform, sizeof(*platform)) ||
      orbit_overlap(e, sizeof(*e), cfg->api_origin.data,
                    cfg->api_origin.length) ||
      orbit_overlap(e, sizeof(*e), cfg->issuer.data, cfg->issuer.length) ||
      orbit_overlap(e, sizeof(*e), cfg->application_id.data,
                    cfg->application_id.length) ||
      orbit_overlap(e, sizeof(*e), cfg->environment_id.data,
                    cfg->environment_id.length) ||
      orbit_overlap(e, sizeof(*e), cfg->fingerprint.data,
                    cfg->fingerprint.length) ||
      orbit_overlap(e, sizeof(*e), cfg->fingerprint_provider.data,
                    cfg->fingerprint_provider.length))
    return ORBIT_CLIENT_ARGUMENT;
  if (client->private_state.magic == ORBIT_CLIENT_MAGIC)
    return ORBIT_CLIENT_BUSY;
#ifndef ORBIT_ENABLE_OFFLINE
  if (offline)
    return ORBIT_CLIENT_ARGUMENT;
#else
  if (offline &&
      (!offline->transaction || !offline->keys ||
       (offline->max_file_bytes != 4096 && offline->max_file_bytes != 16384) ||
       offline->max_file_bytes > ORBIT_OFFLINE_PROFILE_FILE_BYTES ||
       orbit_overlap(offline, sizeof(*offline), e, sizeof(*e)) ||
       orbit_overlap(offline->keys, sizeof(*offline->keys), e, sizeof(*e)) ||
       orbit_overlap(offline->keys, sizeof(*offline->keys), client,
                     sizeof(*client)) ||
       orbit_overlap(offline->keys, sizeof(*offline->keys), arena,
                     arena_length) ||
       orbit_overlap(offline->keys, sizeof(*offline->keys), scratch,
                     scratch_length) ||
       orbit_overlap(offline->keys, sizeof(*offline->keys),
                     offline->transaction, offline->transaction_capacity) ||
       orbit_overlap(offline->app_key.data, offline->app_key.length, e,
                     sizeof(*e)) ||
       orbit_overlap(offline->app_key.data, offline->app_key.length, client,
                     sizeof(*client)) ||
       orbit_overlap(offline->app_key.data, offline->app_key.length, arena,
                     arena_length) ||
       orbit_overlap(offline->app_key.data, offline->app_key.length, scratch,
                     scratch_length) ||
       orbit_overlap(offline->app_key.data, offline->app_key.length,
                     offline->transaction, offline->transaction_capacity) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity, cfg,
                     sizeof(*cfg)) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity,
                     platform, sizeof(*platform)) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity,
                     offline, sizeof(*offline)) ||
       offline->transaction_capacity <
           ORBIT_OFFLINE_BUFFER_BYTES(offline->max_file_bytes) ||
       arena_length < offline->max_file_bytes ||
       orbit_overlap(offline->transaction, offline->transaction_capacity,
                     client, sizeof(*client)) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity, e,
                     sizeof(*e)) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity, arena,
                     arena_length) ||
       orbit_overlap(offline->transaction, offline->transaction_capacity,
                     scratch, scratch_length) ||
       orbit_signed_keys_valid(offline->keys, ORBIT_SIGNED_OFFLINE,
                               cfg->environment_kind, &platform->crypto)))
    return ORBIT_CLIENT_ARGUMENT;
#endif
  orbit_zero(e, sizeof(*e));
  e->client = client;
  e->platform = *platform;
  e->session.automatic = 1;
#ifdef ORBIT_ENABLE_OFFLINE
  if (offline)
    e->offline = *offline;
#endif
  services = *platform;
  services.context = e;
  services.exchange = extended_exchange;
  services.clock = extended_clock;
  services.entropy = extended_entropy;
  services.load = orbit_extension_load;
  services.commit = orbit_extension_commit;
  r = orbit_client_init(client, cfg, &services, arena, arena_length, scratch,
                        scratch_length);
  if (r)
    return r;
  client->private_state.extension = e;
#ifdef ORBIT_ENABLE_OFFLINE
  if (e->offline_mode) {
    r = orbit_offline_restore(&client->private_state);
    if (r)
      orbit_client_destroy(client);
    return r;
  }
#endif
  return 0;
}

#endif
