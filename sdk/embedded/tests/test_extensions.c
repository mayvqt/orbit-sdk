#define main orbit_connected_test_main
#include "test_client.c"
#undef main
#include "orbit_downloads.h"
#include "orbit_extensions.h"

typedef struct extended_mock {
  mock_t m;
  uint8_t durable[17408];
  uint32_t durable_length, entropy_counter, starts, renews, ends;
  int floating, session_error, unknown_ended, end_during_request, cancel,
      denial_malformed;
  int slow_crypto, cancel_during_request, cancel_on_verify;
  int clock_step, commit_delay;
  int64_t issued;
  char seat[129], retry_seat[129];
  const char *reply;
  uint16_t reply_status;
} extended_mock_t;
static orbit_client_extension_t extension;
static uint8_t transaction[17408];
static orbit_grant_keyset_t offline_keys;
static char signed_file[20000], signed_payload[16000];
static void date(int64_t seconds, char out[21]) {
  time_t t = (time_t)seconds;
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, 21, "%Y-%m-%dT%H:%M:%SZ", &tm);
}
static int purpose_sign(const char *payload, const char *purpose,
                        const char *kid, char *out, size_t capacity) {
  char header[256], head[512], encoded[24000];
  uint8_t der[128], raw[64];
  size_t n = sizeof(der);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  ECDSA_SIG *sig = NULL;
  const unsigned char *cursor = der;
  const BIGNUM *r, *s;
  int length, ok = 0;
  snprintf(header, sizeof(header),
           "{\"alg\":\"ES256\",\"typ\":\"%s\",\"kid\":\"%s\"}", purpose, kid);
  b64((const uint8_t *)header, strlen(header), head);
  b64((const uint8_t *)payload, strlen(payload), encoded);
  length = snprintf(out, capacity, "%s.%s", head, encoded);
  if (length < 0 || (size_t)length + 88 >= capacity || !ctx)
    goto done;
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) != 1 ||
      EVP_DigestSign(ctx, der, &n, (uint8_t *)out, (size_t)length) != 1)
    goto done;
  sig = d2i_ECDSA_SIG(NULL, &cursor, (long)n);
  if (!sig)
    goto done;
  ECDSA_SIG_get0(sig, &r, &s);
  if (BN_bn2binpad(r, raw, 32) != 32 || BN_bn2binpad(s, raw + 32, 32) != 32)
    goto done;
  out[length++] = '.';
  b64(raw, 64, out + length);
  ok = 1;
done:
  ECDSA_SIG_free(sig);
  EVP_MD_CTX_free(ctx);
  return ok;
}
static int32_t ext_load(void *p, uint8_t *b, uint32_t cap, uint32_t *n) {
  extended_mock_t *m = p;
  if (!m->durable_length)
    return ORBIT_CLIENT_NOT_FOUND;
  if (m->durable_length > cap)
    return ORBIT_CLIENT_RESOURCE_LIMIT;
  memcpy(b, m->durable, m->durable_length);
  *n = m->durable_length;
  return 0;
}
static int32_t ext_commit(void *p, uint64_t previous, const uint8_t *b,
                          uint32_t n) {
  extended_mock_t *m = p;
  if (m->m.storage_failure)
    return ORBIT_CLIENT_STORAGE;
  if ((m->durable_length ? generation(m->durable) : 0) != previous)
    return ORBIT_CLIENT_STALE;
  if (n > sizeof(m->durable))
    return ORBIT_CLIENT_STORAGE;
  memcpy(m->durable, b, n);
  m->durable_length = n;
  ++m->m.commits;
  if (m->commit_delay)
    elapse(&m->m, m->commit_delay);
  return 0;
}
static int32_t ext_clock(void *p, int64_t *wall, uint64_t *ticks) {
  extended_mock_t *m = p;
  if (m->clock_step)
    elapse(&m->m, m->clock_step);
  return clock_read(p, wall, ticks);
}
static int32_t ext_entropy(void *p, uint8_t *b, uint32_t n) {
  extended_mock_t *m = p;
  uint32_t i;
  ++m->entropy_counter;
  for (i = 0; i < n; ++i)
    b[i] = (uint8_t)(i + m->entropy_counter);
  return 0;
}
static int32_t late_verify(void *p, const uint8_t *x, const uint8_t *y,
                           const uint8_t *digest, const uint8_t *signature) {
  extended_mock_t *m = p;
  const orbit_grant_crypto_t *crypto = orbit_test_openssl_crypto();
  int32_t r = crypto->verify_es256(crypto->context, x, y, digest, signature);
  if (m->cancel_on_verify) {
    m->cancel = 1;
    m->cancel_on_verify = 0;
  }
  if (m->slow_crypto) {
    elapse(&m->m, 120);
    m->slow_crypto = 0;
  }
  return r;
}
static int32_t session_cancelled(void *p) {
  return ((extended_mock_t *)p)->cancel;
}
static int32_t ext_exchange(void *p, const orbit_http_request_t *request,
                            uint16_t *status, orbit_receive_fn receive,
                            void *sink) {
  extended_mock_t *m = p;
  char path[512], body[4096], reply[20000], token[18000], payload[4096],
      time[21], expiry[21];
  uint64_t seq = 1;
  memcpy(path, request->path.data, request->path.length);
  path[request->path.length] = 0;
  if (request->body.length)
    memcpy(body, request->body.data, request->body.length);
  body[request->body.length] = 0;
  if (!request->post)
    return exchange(p, request, status, receive, sink);
  if (m->reply) {
    if (m->end_during_request) {
      m->end_during_request = 0;
      CHECK(orbit_client_end_session(&client, NULL) == 0);
    }
    *status = m->reply_status;
    return receive(sink, (const uint8_t *)m->reply, (uint32_t)strlen(m->reply));
  }
  if (!m->floating) {
    if (m->end_during_request) {
      m->end_during_request = 0;
      CHECK(orbit_client_end_session(&client, NULL) == 0);
    }
    return exchange(p, request, status, receive, sink);
  }
  ++m->m.posts;
  get_string(body, "installation_id", m->m.installation,
             sizeof(m->m.installation));
  date(m->m.now, time);
  if (strstr(path, "/sessions")) {
    if (!strstr(path, "/renew") && !strstr(path, "/end")) {
      ++m->starts;
      get_string(body, "session_id", m->seat, sizeof(m->seat));
      if (!m->retry_seat[0]) {
        strcpy(m->retry_seat, m->seat);
        m->issued = m->m.now;
      }
    } else if (strstr(path, "/end")) {
      ++m->ends;
      *status = 204;
      return 0;
    } else {
      const char *s = strstr(body, "\"sequence\":");
      ++m->renews;
      if (s)
        seq = strtoull(s + 11, NULL, 10);
      m->issued = m->m.now;
    }
    if (m->end_during_request) {
      m->end_during_request = 0;
      CHECK(orbit_client_end_session(&client, NULL) == 0);
    }
    if (m->session_error) {
      if (m->session_error == ORBIT_CLIENT_TRANSIENT)
        return m->session_error;
      *status = 403;
      return 0;
    }
    CHECK(m->durable_length &&
          client.private_state.record
              .credential_length); /* saved before JWKS/start */
    snprintf(payload, sizeof(payload),
             "{\"iss\":\"https://"
             "orbit.test\",\"aud\":\"orbit-session:app:env\",\"sub\":\"licence_"
             "1\",\"jti\":\"session_grant\",\"iat\":%lld,\"nbf\":%lld,\"exp\":%"
             "lld,\"application_id\":\"app\",\"environment_id\":\"env\","
             "\"activation_id\":\"activation_1\",\"installation_id\":\"%s\","
             "\"binding_mode\":\"none\",\"policy_version\":1,\"entitlements\":{"
             "\"export\":true},\"refresh_after\":%lld,\"offline_allowed\":"
             "false,\"session_id\":\"%s\",\"session_sequence\":%llu}",
             (long long)m->issued, (long long)m->issued,
             (long long)m->issued + 120, m->m.installation,
             (long long)m->issued + 60, m->seat, (unsigned long long)seq);
    CHECK(purpose_sign(payload, "orbit-session+jwt", "test-key", token,
                       sizeof(token)));
    date(m->issued + 120, expiry);
    snprintf(reply, sizeof(reply),
             "{\"session_id\":\"%s\",\"sequence\":%llu,\"expires_at\":\"%s\","
             "\"server_time\":\"%s\",\"grant\":\"%s\"}",
             m->seat, (unsigned long long)seq, expiry, time, token);
  } else {
    if (m->end_during_request) {
      m->end_during_request = 0;
      CHECK(orbit_client_end_session(&client, NULL) == 0);
    }
    snprintf(reply, sizeof(reply),
             "{\"activation_id\":\"activation_1\",\"installation_id\":\"%s\",%"
             "s\"credential_expires_at\":null,\"grant\":null,\"session_"
             "required\":true,\"licence_id\":\"licence_1\",\"server_time\":\"%"
             "s\",\"binding_mode\":\"none\",\"fingerprint_provider\":null,"
             "\"licence_expires_at\":null,\"secret_replay_expired\":false}",
             m->m.installation,
             strstr(path, "/validate") ? ""
                                       : "\"credential\":\"credential_1\",",
             time);
  }
  if (m->cancel_during_request) {
    m->cancel_during_request = 0;
    m->cancel = 1;
  }
  *status = 200;
  return receive(sink, (const uint8_t *)reply, (uint32_t)strlen(reply));
}
static int ext_init(extended_mock_t *m, uint32_t max_file) {
  orbit_client_services_t s = {m,        ext_exchange, ext_clock, ext_entropy,
                               ext_load, ext_commit,   {0}};
  orbit_client_config_t cfg = config;
  cfg.environment_kind = 1;
  s.crypto = *orbit_test_openssl_crypto();
  s.crypto.context = m;
  s.crypto.verify_es256 = late_verify;
  m->m.client = &client;
#ifdef ORBIT_ENABLE_OFFLINE
  orbit_offline_config_t off = {
      &offline_keys, transaction, sizeof(transaction), max_file,
      S("orbit_app_test_aHR0cHM6Ly9vcmJpdC50ZXN0.app.env")};
  return orbit_client_init_extended(&client, &cfg, &s, &extension, arena,
                                    sizeof(arena), scratch, sizeof(scratch),
                                    max_file ? &off : NULL);
#else
  (void)max_file;
  return orbit_client_init_extended(&client, &cfg, &s, &extension, arena,
                                    sizeof(arena), scratch, sizeof(scratch),
                                    NULL);
#endif
}
static void ext_reset(extended_mock_t *m) {
  memset(m, 0, sizeof(*m));
  reset(&m->m);
}
static int floating_tests(void) {
  extended_mock_t m;
  orbit_session_snapshot_t seat;
  uint32_t posts;
  ext_reset(&m);
  m.floating = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  CHECK(m.starts == 1);
  CHECK(orbit_client_session(&client, &seat) == 0 && seat.active &&
        seat.sequence == 1);
  posts = m.m.posts;
  CHECK(orbit_client_require_access(&client, S("export")) == 0 &&
        m.m.posts == posts);
  elapse(&m.m, 60);
  m.session_error = ORBIT_CLIENT_TRANSIENT;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_TRANSIENT);
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  elapse(&m.m, 60);
  CHECK(orbit_client_snapshot(&client, (orbit_access_snapshot_t *)&(
                                           orbit_access_snapshot_t){0}) == 0);
  CHECK(orbit_client_require_access(&client, S("export")) != 0);
  m.session_error = 0;
  m.retry_seat[0] = 0;
  CHECK(orbit_client_start_session(&client, NULL, &seat) == 0);
  CHECK(orbit_client_end_session(&client, NULL) == 0);
  posts = m.starts;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_DENIED && m.starts == posts);
  CHECK(m.ends == 1);
  CHECK(orbit_client_close(&client, NULL) == 0);
  ext_reset(&m);
  m.floating = 1;
  m.session_error = ORBIT_CLIENT_TRANSIENT;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_TRANSIENT);
  CHECK(client.private_state.record.credential_length);
  strcpy(m.retry_seat, m.seat);
  elapse(&m.m, 5);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_TRANSIENT);
  CHECK(!strcmp(m.retry_seat, m.seat));
  elapse(&m.m, 120);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_TRANSIENT);
  CHECK(strcmp(m.retry_seat, m.seat));
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.floating = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  elapse(&m.m, 60);
  m.session_error = ORBIT_CLIENT_DENIED;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_DENIED);
  CHECK(orbit_client_require_access(&client, S("export")) != 0);
  posts = m.starts;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_TRANSIENT &&
        m.starts == posts);
  elapse(&m.m, 6);
  CHECK(orbit_client_require_access(&client, S("export")) ==
            ORBIT_CLIENT_DENIED &&
        m.starts == posts);
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.floating = 1;
  m.end_during_request = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_STALE);
  CHECK(m.starts == 0 && !extension.session.automatic);
  CHECK(client.private_state.record.credential_length &&
        !client.private_state.record.pending_kind);
  CHECK(!client.private_state.active.valid);
  CHECK(orbit_client_require_access(&client, S("export")) ==
            ORBIT_CLIENT_DENIED &&
        m.starts == 0);
  CHECK(orbit_client_start_session(&client, NULL, &seat) == 0 && seat.active &&
        m.starts == 1);
  CHECK(orbit_client_end_session(&client, NULL) == 0);
  orbit_client_destroy(&client);
  m.retry_seat[0] = 0;
  CHECK(ext_init(&m, 0) == 0 && client.private_state.record.credential_length);
  CHECK(orbit_client_start_session(&client, NULL, &seat) == 0 && seat.active &&
        m.starts == 2);
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.floating = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  elapse(&m.m, 60);
  m.end_during_request = 1;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_STALE);
  CHECK(m.ends == 1 && !extension.session.active &&
        !extension.session.automatic);
  orbit_client_destroy(&client);
  ext_reset(&m);
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  posts = m.m.posts;
  CHECK(orbit_client_start_session(&client, NULL, &seat) == 0);
  CHECK(orbit_client_end_session(&client, NULL) == 0);
  CHECK(posts == m.m.posts);
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.floating = 1;
  m.slow_crypto = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_DENIED);
  CHECK(orbit_client_require_access(&client, S("export")) != 0);
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.floating = 1;
  m.session_error = ORBIT_CLIENT_TRANSIENT;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_TRANSIENT);
  m.session_error = 0;
  m.cancel_during_request = 1;
  {
    orbit_operation_t op = {{0}, &m, session_cancelled};
    CHECK(orbit_client_start_session(&client, &op, &seat) ==
          ORBIT_CLIENT_CANCELLED);
    CHECK(!extension.session.active && !extension.session.automatic &&
          m.ends == 1);
  }
  orbit_client_destroy(&client);

  ext_reset(&m);
  m.end_during_request = 1;
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_STALE);
  CHECK(client.private_state.record.credential_length &&
        !client.private_state.record.pending_kind &&
        !client.private_state.active.valid);
  CHECK(orbit_client_start_session(&client, NULL, &seat) == 0 && m.starts == 0);
  orbit_client_destroy(&client);
  ext_reset(&m);
  m.end_during_request = 1;
  m.reply_status = 200;
  m.reply = "{}";
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == ORBIT_CLIENT_STALE);
  CHECK(!client.private_state.record.credential_length &&
        client.private_state.record.pending_kind &&
        !client.private_state.active.valid);
  orbit_client_destroy(&client);
  return 0;
}
static int limit_tests(void) {
  extended_mock_t m;
  orbit_limit_result_t result;
  orbit_operation_t op = {S("job_123"), NULL, NULL};
  ext_reset(&m);
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  m.reply_status = 200;
  m.reply = "{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":10,"
            "\"used\":2,\"remaining\":8,\"period_started_at\":null,\"resets_"
            "at\":null,\"idempotency_key\":\"job_123\",\"consumed_units\":2}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) == 0 &&
        result.counter.used == 2 && !result.uncertain);
  m.reply_status = 201;
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && result.operation_id_length == 7);
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":"
            "\"capacity\",\"request_id\":\"safe\",\"counter\":{\"name\":"
            "\"exports\",\"period\":\"lifetime\",\"limit\":10,\"used\":10,"
            "\"remaining\":0,\"period_started_at\":null,\"resets_at\":null},"
            "\"idempotency_key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_CAPACITY &&
        result.capacity_denied && !result.uncertain);
  CHECK(orbit_client_consume(&client, S("exports"), 3, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied);
  m.reply_status = 200;
  m.reply = "{\"name\":\"workers\",\"limit\":5,\"used\":2,\"remaining\":3,"
            "\"allocation_id\":\"alloc1\",\"resource_id\":\"worker1\","
            "\"units\":2,\"state\":\"active\",\"idempotency_key\":\"job_123\"}";
  CHECK(orbit_client_acquire_resource(&client, S("workers"), S("worker1"), 2,
                                      &op, &result) == 0);
  m.reply = "{\"name\":\"exports\",\"period\":\"month\",\"limit\":10,\"used\":"
            "2,\"remaining\":8,\"period_started_at\":\"2024-02-01T00:00:00Z\","
            "\"resets_at\":\"2024-03-01T00:00:00Z\"}";
  CHECK(orbit_client_usage(&client, S("exports"), NULL, &result) == 0);
  m.reply = "{\"name\":\"exports\",\"period\":\"month\",\"limit\":10,\"used\":"
            "2,\"remaining\":8,\"period_started_at\":\"2024-02-02T00:00:00Z\","
            "\"resets_at\":\"2024-03-02T00:00:00Z\"}";
  CHECK(orbit_client_usage(&client, S("exports"), NULL, &result) ==
        ORBIT_CLIENT_UNTRUSTED);
  m.reply = "{\"name\":\"workers\",\"limit\":5,\"used\":1,\"remaining\":4,"
            "\"allocation_id\":\"alloc1\",\"resource_id\":\"worker1\","
            "\"units\":2,\"state\":\"active\",\"idempotency_key\":\"job_123\"}";
  CHECK(orbit_client_acquire_resource(&client, S("workers"), S("worker1"), 2,
                                      &op, &result) == ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain);
  m.reply = "{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":10,"
            "\"used\":1,\"remaining\":9,\"period_started_at\":null,\"resets_"
            "at\":null,\"idempotency_key\":\"job_123\",\"consumed_units\":2}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain);
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"unrecognized_error\"}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"unrecognized_error\",\"message\":\"safe\","
            "\"request_id\":\"request_1\"}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply =
      "{\"error\":{\"code\":\"usage_limit_reached\",\"request_id\":\"request_"
      "1\",\"counter\":{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":"
      "10,\"used\":10,\"remaining\":0,\"period_started_at\":null,\"resets_at\":"
      "null},\"idempotency_key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply =
      "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":\"safe\","
      "\"counter\":{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":10,"
      "\"used\":10,\"remaining\":0,\"period_started_at\":null,\"resets_at\":"
      "null},\"idempotency_key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":3,"
            "\"request_id\":\"request_1\",\"counter\":{\"name\":\"exports\","
            "\"period\":\"lifetime\",\"limit\":10,\"used\":10,\"remaining\":0,"
            "\"period_started_at\":null,\"resets_at\":null},\"idempotency_"
            "key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":\"safe\","
            "\"request_id\":\"bad "
            "request\",\"counter\":{\"name\":\"exports\",\"period\":"
            "\"lifetime\",\"limit\":10,\"used\":10,\"remaining\":0,\"period_"
            "started_at\":null,\"resets_at\":null},\"idempotency_key\":\"job_"
            "123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply =
      "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":\"safe\","
      "\"request_id\":"
      "\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\","
      "\"counter\":{\"name\":\"exports\",\"period\":\"lifetime\",\"limit\":10,"
      "\"used\":10,\"remaining\":0,\"period_started_at\":null,\"resets_at\":"
      "null},\"idempotency_key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 403;
  m.reply = "{\"error\":{\"code\":\"access_denied\",\"message\":\"safe\","
            "\"request_id\":\"request_1\"}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_DENIED &&
        !result.uncertain && result.operation_id_length == 7);
  m.reply_status = 403;
  m.reply =
      "{\"error\":{\"code\":\"access_denied\",\"request_id\":\"request_1\"}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain && !result.capacity_denied &&
        result.operation_id_length == 7 &&
        !memcmp(result.operation_id, "job_123", 7));
  m.reply_status = 409;
  m.reply = "{\"error\":{\"code\":\"usage_limit_reached\",\"message\":\"safe\","
            "\"request_id\":\"request_1\",\"counter\":{\"name\":\"exports\","
            "\"period\":\"lifetime\",\"limit\":10,\"used\":10,\"remaining\":0,"
            "\"period_started_at\":null,\"resets_at\":null},\"idempotency_"
            "key\":\"job_123\",\"requested_units\":2}}";
  CHECK(orbit_client_consume(&client, S("exports"), 2, &op, &result) ==
            ORBIT_CLIENT_CAPACITY &&
        !result.uncertain && result.capacity_denied);
  m.reply_status = 200;
  m.reply =
      "{\"name\":\"workers\",\"limit\":5,\"used\":0,\"remaining\":5,"
      "\"allocation_id\":\"alloc1\",\"resource_id\":\"worker1\",\"units\":99,"
      "\"state\":\"released\",\"idempotency_key\":\"job_123\"}";
  CHECK(orbit_client_acquire_resource(&client, S("workers"), S("worker1"), 99,
                                      &op, &result) == ORBIT_CLIENT_UNTRUSTED &&
        result.uncertain);
  m.reply_status = 200;
  m.reply =
      "{\"name\":\"workers\",\"limit\":5,\"used\":0,\"remaining\":5,"
      "\"allocation_id\":\"alloc1\",\"resource_id\":\"worker1\",\"units\":5,"
      "\"state\":\"released\",\"idempotency_key\":\"job_123\"}";
  CHECK(orbit_client_acquire_resource(&client, S("workers"), S("worker1"), 5,
                                      &op, &result) == 0 &&
        !result.uncertain && result.released);
  CHECK(orbit_client_consume(&client, S("exports"), UINT64_C(9007199254740992),
                             &op, &result) == ORBIT_CLIENT_ARGUMENT);
  orbit_client_destroy(&client);
  return 0;
}

static int metadata_tests(void) {
  extended_mock_t m;
  orbit_update_t update;
  orbit_download_authorization_t auth;
  char artifact[1024], response[4096], expires[21];
  uint32_t starts;
  ext_reset(&m);
  CHECK(ext_init(&m, 0) == 0);
  CHECK(orbit_client_activate(&client, S("key")) == 0);
  starts = m.starts;
  m.reply_status = 200;
  m.reply = "{\"release\":null,\"artifact\":null}";
  CHECK(orbit_client_check_for_updates(&client, 0, S(""), S("pico"),
                                       S("armv6m"), NULL, &update) == 0 &&
        !update.available);
  m.reply = "{\"release\":null}";
  CHECK(orbit_client_check_for_updates(&client, 0, S(""), S("pico"),
                                       S("armv6m"), NULL,
                                       &update) == ORBIT_CLIENT_UNTRUSTED);
  snprintf(artifact, sizeof(artifact),
           "{\"id\":\"a1\",\"release_id\":\"r1\",\"platform\":\"pico\","
           "\"architecture\":\"armv6m\",\"filename\":\"firmware.bin\",\"byte_"
           "length\":3,\"sha256\":"
           "\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
           "\",\"delivery_mode\":\"protected\",\"url\":\"https://files.test/"
           "content/a1\",\"required_feature\":null}");
  snprintf(response, sizeof(response),
           "{\"release\":{\"id\":\"r1\",\"channel\":\"stable\",\"version\":\"1."
           "0\",\"notes\":\"Firmware\",\"release_number\":2,\"state\":"
           "\"published\",\"created_at\":\"2026-01-01T00:00:00Z\",\"published_"
           "at\":\"2026-01-01T00:00:00Z\",\"artifacts\":[%s]},\"artifact\":%s}",
           artifact, artifact);
  m.reply = response;
  CHECK(orbit_client_check_for_updates(&client, 1, S(""), S("pico"),
                                       S("armv6m"), NULL, &update) == 0 &&
        update.available && update.artifact.byte_length == 3);
  CHECK(m.starts == starts);
  CHECK(orbit_client_check_for_updates(&client, 1, S(""), S("pico"),
                                       S("armv8m"), NULL,
                                       &update) == ORBIT_CLIENT_UNTRUSTED &&
        !update.available);
  CHECK(orbit_client_check_for_updates(&client, 2, S(""), S("pico"),
                                       S("armv6m"), NULL,
                                       &update) == ORBIT_CLIENT_UNTRUSTED);
  CHECK(orbit_client_check_for_updates(&client, 1, S(""), S("pico"),
                                       S("armv6m"), NULL, &update) == 0);
  date(m.m.now + 60, expires);
  snprintf(
      response, sizeof(response),
      "{\"artifact\":%s,\"ticket\":\"download_ticket\",\"expires_at\":\"%s\"}",
      artifact, expires);
  CHECK(orbit_client_authorize_download(&client, update.release.id,
                                        update.artifact.id, NULL, &auth) == 0 &&
        auth.ticket.length == 15);
  CHECK(orbit_client_authorize_download(&client, S("r2"), S("a1"), NULL,
                                        &auth) == ORBIT_CLIENT_UNTRUSTED);
  date(m.m.now, expires);
  snprintf(
      response, sizeof(response),
      "{\"artifact\":%s,\"ticket\":\"download_ticket\",\"expires_at\":\"%s\"}",
      artifact, expires);
  CHECK(orbit_client_authorize_download(&client, S("r1"), S("a1"), NULL,
                                        &auth) == ORBIT_CLIENT_UNTRUSTED);
  m.reply_status = 201;
  CHECK(orbit_client_authorize_download(&client, S("r1"), S("a1"), NULL,
                                        &auth) == ORBIT_CLIENT_UNTRUSTED);
  orbit_client_destroy(&client);
  return 0;
}
#ifdef ORBIT_ENABLE_OFFLINE
static int make_file(extended_mock_t *m, uint64_t seq, uint32_t exact) {
  char installation[129];
  size_t n, base;
  memcpy(installation, client.private_state.record.installation,
         client.private_state.record.installation_length);
  installation[client.private_state.record.installation_length] = 0;
  snprintf(signed_payload, sizeof(signed_payload),
           "{\"ver\":1,\"iss\":\"https://"
           "orbit.test\",\"aud\":\"orbit-offline:app:env\",\"sub\":\"licence_"
           "1\",\"jti\":\"offline_%llu\",\"iat\":%lld,\"nbf\":%lld,\"exp\":%"
           "lld,\"application_id\":\"app\",\"environment_id\":\"env\","
           "\"activation_id\":\"activation_1\",\"installation_id\":\"%s\","
           "\"sequence\":%llu,\"binding_mode\":\"none\",\"policy_version\":1,"
           "\"entitlements\":{\"export\":true}}",
           (unsigned long long)seq, (long long)m->m.now, (long long)m->m.now,
           (long long)m->m.now + 15552000, installation,
           (unsigned long long)seq);
  base = strlen(signed_payload);
  if (!exact)
    return purpose_sign(signed_payload, "orbit-offline+jwt", "offline-test-key",
                        signed_file, sizeof(signed_file));
  /* JWS lengths are not all representable with one fixed header length. Vary
   * harmless header JSON whitespace while preserving the exact typed header. */
  for (n = base; n < sizeof(signed_payload) - 1; ++n) {
    signed_payload[n] = 0;
    if (!purpose_sign(signed_payload, "orbit-offline+jwt", "offline-test-key",
                      signed_file, sizeof(signed_file)))
      return 0;
    if (strlen(signed_file) == exact)
      return 1;
    if (strlen(signed_file) > exact)
      return 0;
    signed_payload[n] = ' ';
  }
  return 0;
}
typedef struct file_reader {
  const uint8_t *data;
  uint32_t length, offset;
  int cancel;
} file_reader_t;
static int32_t read_file(void *p, uint8_t *b, uint32_t cap, uint32_t *n) {
  file_reader_t *r = p;
  *n = r->length - r->offset;
  if (*n > cap)
    *n = cap;
  memcpy(b, r->data + r->offset, *n);
  r->offset += *n;
  return 0;
}
static int32_t read_cancelled(void *p) {
  file_reader_t *r = p;
  return r->cancel && r->offset > 256;
}
static int offline_tests(void) {
  extended_mock_t m;
  char jwks[1024];
  uint32_t profile, n;
  orbit_access_snapshot_t snapshot;
  char x[64], y[64];
  memcpy(jwks, generated_grant_vectors[0].jwks,
         generated_grant_vectors[0].jwks_length);
  jwks[generated_grant_vectors[0].jwks_length] = 0;
  get_string(jwks, "x", x, sizeof(x));
  get_string(jwks, "y", y, sizeof(y));
  snprintf(
      jwks, sizeof(jwks),
      "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"use\":"
      "\"sig\",\"kid\":\"offline-test-key\",\"x\":\"%s\",\"y\":\"%s\"}]}",
      x, y);
  CHECK(orbit_jwks_import((const uint8_t *)jwks, (uint32_t)strlen(jwks),
                          orbit_test_openssl_crypto(), &offline_keys) == 0);
  for (profile = 4096; profile <= ORBIT_OFFLINE_PROFILE_FILE_BYTES;
       profile *= 4) {
    ext_reset(&m);
    CHECK(ext_init(&m, profile) == 0);
    CHECK(make_file(&m, 1, 0));
    CHECK(orbit_client_import_offline_file(
              &client,
              (orbit_embedded_slice_t){(uint8_t *)signed_file,
                                       (uint32_t)strlen(signed_file)}) == 0);
    CHECK(orbit_client_require_access(&client, S("export")) == 0 &&
          m.m.posts == 0);
    CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && snapshot.offline);
    CHECK(orbit_client_start_session(&client, NULL,
                                     &(orbit_session_snapshot_t){0}) ==
          ORBIT_CLIENT_DENIED);
    CHECK(orbit_client_usage(&client, S("exports"), NULL,
                             &(orbit_limit_result_t){0}) ==
          ORBIT_CLIENT_DENIED);
    CHECK(orbit_client_offline_request(&client, (uint8_t *)signed_payload,
                                       sizeof(signed_payload), &n) == 0 &&
          n < 4096);
    elapse(&m.m, 61);
    CHECK(orbit_client_require_access(&client, S("export")) == 0);
    CHECK(orbit_client_close(&client, NULL) == 0);
    CHECK(ext_init(&m, profile) == 0);
    CHECK(orbit_client_require_access(&client, S("export")) == 0);
    CHECK(make_file(&m, 2, 0));
    {
      uint64_t previous_sequence = extension.offline_sequence;
      uint64_t previous_generation = client.private_state.record.generation;
      int64_t previous_floor = extension.offline_floor;
      uint32_t previous_commits = m.m.commits;
      file_reader_t reader = {(uint8_t *)signed_file,
                              (uint32_t)strlen(signed_file), 0, 0};
      orbit_operation_t op = {{0}, &m, session_cancelled};
      m.cancel_on_verify = 1;
      CHECK(orbit_client_import_offline_reader(&client, read_file, &reader,
                                               &op) == ORBIT_CLIENT_CANCELLED);
      CHECK(m.cancel && extension.offline_sequence == previous_sequence &&
            extension.offline_floor == previous_floor &&
            client.private_state.record.generation == previous_generation &&
            m.m.commits == previous_commits);
      CHECK(orbit_client_require_access(&client, S("export")) == 0);
      orbit_client_destroy(&client);
      m.cancel = 0;
      CHECK(ext_init(&m, profile) == 0 &&
            extension.offline_sequence == previous_sequence);
      CHECK(orbit_client_require_access(&client, S("export")) == 0);
    }
    CHECK(make_file(&m, 2, 0));
    CHECK(orbit_client_import_offline_file(
              &client,
              (orbit_embedded_slice_t){(uint8_t *)signed_file,
                                       (uint32_t)strlen(signed_file)}) == 0);
    CHECK(make_file(&m, 1, 0));
    CHECK(
        orbit_client_import_offline_file(
            &client, (orbit_embedded_slice_t){(uint8_t *)signed_file,
                                              (uint32_t)strlen(signed_file)}) ==
        ORBIT_CLIENT_UNTRUSTED);
    CHECK(orbit_client_require_access(&client, S("export")) == 0);
    orbit_client_destroy(&client);
    m.m.now -= 1;
    CHECK(ext_init(&m, profile) == ORBIT_CLIENT_CLOCK);
    m.m.now += 1;
    CHECK(ext_init(&m, profile) == 0);
    elapse(&m.m, client.private_state.active.expires - m.m.now - 61);
    CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && snapshot.allowed);
    elapse(&m.m, 58);
    m.clock_step = 1;
    m.commit_delay = 2;
    CHECK(orbit_client_require_access(&client, S("export")) ==
          ORBIT_CLIENT_DENIED);
    CHECK(m.m.now >= client.private_state.active.expires);
    m.clock_step = m.commit_delay = 0;
    CHECK(orbit_client_invalidate(&client) == 0);
    CHECK(orbit_client_require_access(&client, S("export")) != 0);
    orbit_client_destroy(&client);
    ext_reset(&m);
    CHECK(ext_init(&m, profile) == 0);
    CHECK(make_file(&m, 1, profile));
    CHECK(strlen(signed_file) == profile);
    CHECK(orbit_client_import_offline_file(
              &client,
              (orbit_embedded_slice_t){(uint8_t *)signed_file, profile}) == 0);
    {
      file_reader_t reader = {(uint8_t *)signed_file, profile, 0, 0};
      orbit_operation_t op = {{0}, &reader, read_cancelled};
      CHECK(orbit_client_import_offline_reader(&client, read_file, &reader,
                                               &op) == 0);
      reader.offset = 0;
      reader.cancel = 1;
      CHECK(orbit_client_import_offline_reader(&client, read_file, &reader,
                                               &op) == ORBIT_CLIENT_CANCELLED);
      CHECK(orbit_client_require_access(&client, S("export")) == 0);
      reader.offset = 0;
      reader.cancel = 0;
      reader.length = profile + 1;
      signed_file[profile] = 'x';
      CHECK(orbit_client_import_offline_reader(&client, read_file, &reader,
                                               &op) ==
            ORBIT_CLIENT_RESOURCE_LIMIT);
      CHECK(orbit_client_require_access(&client, S("export")) == 0);
      reader.offset = 0;
      reader.length = 10;
      CHECK(orbit_client_import_offline_reader(&client, read_file, &reader,
                                               &op) == ORBIT_CLIENT_UNTRUSTED);
      CHECK(orbit_client_require_access(&client, S("export")) == 0);
      CHECK(orbit_client_deactivate(&client) == ORBIT_CLIENT_DENIED);
    }
    signed_file[profile] = 'x';
    CHECK(orbit_client_import_offline_file(
              &client,
              (orbit_embedded_slice_t){(uint8_t *)signed_file, profile + 1}) ==
          ORBIT_CLIENT_RESOURCE_LIMIT);
    CHECK(orbit_client_require_access(&client, S("export")) == 0);
    CHECK(make_file(&m, 2, 0));
    m.m.storage_failure = 1;
    CHECK(
        orbit_client_import_offline_file(
            &client, (orbit_embedded_slice_t){(uint8_t *)signed_file,
                                              (uint32_t)strlen(signed_file)}) ==
        ORBIT_CLIENT_STORAGE);
    CHECK(orbit_client_require_access(&client, S("export")) ==
          ORBIT_CLIENT_STORAGE);
    orbit_client_destroy(&client);
  }
  return 0;
}
#endif
int main(void) {
  FILE *pem = fopen(ORBIT_TEST_PRIVATE_KEY, "r");
  CHECK(pem);
  private_key = PEM_read_PrivateKey(pem, NULL, NULL, NULL);
  fclose(pem);
  CHECK(private_key);
  CHECK(floating_tests() == 0);
  CHECK(limit_tests() == 0);
  CHECK(metadata_tests() == 0);
#ifdef ORBIT_ENABLE_OFFLINE
  CHECK(offline_tests() == 0);
#endif
  EVP_PKEY_free(private_key);
  puts("extended lifecycle and limits passed");
  return 0;
}
