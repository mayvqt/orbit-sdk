#define _POSIX_C_SOURCE 200809L
#include "openssl_adapter.h"
#include "orbit_client.h"
#include "orbit_client_internal.h"
#include "orbit_generated_vectors.h"
#include "orbit_storage.h"
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "client:%d: %s\n", __LINE__, #x);                        \
      return 1;                                                                \
    }                                                                          \
  } while (0)
#define S(s)                                                                   \
  ((orbit_embedded_slice_t){(const uint8_t *)(s), (uint32_t)(sizeof(s) - 1u)})
typedef struct mock {
  int64_t now;
  uint64_t ticks;
  uint8_t record[1024];
  uint32_t record_length, commits, posts, gets;
  int post_transient, key_transient, denial, bad_signature, storage_failure,
      oversized, offline, reenter, reenter_clock, reenter_commit;
  char installation[129], operation_id[129], previous_operation[129], kid[129];
  orbit_client_t *client;
} mock_t;
static orbit_client_t client;
static uint8_t arena[ORBIT_CLIENT_ARENA_BYTES],
    scratch[ORBIT_GRANT_WORKSPACE_BYTES];
static EVP_PKEY *private_key;
static const orbit_client_config_t config = {S("https://orbit.test"),
                                             S("https://orbit.test"),
                                             S("app"),
                                             S("env"),
                                             {NULL, 0},
                                             {NULL, 0}};

static int b64(const uint8_t *in, size_t length, char *out) {
  int n = EVP_EncodeBlock((unsigned char *)out, in, (int)length), i;
  while (n > 0 && out[n - 1] == '=')
    --n;
  for (i = 0; i < n; ++i) {
    if (out[i] == '+')
      out[i] = '-';
    else if (out[i] == '/')
      out[i] = '_';
  }
  out[n] = 0;
  return n;
}
static int sign_token(const char *payload, const char *kid, char *out,
                      size_t capacity) {
  char header[256], encoded_header[512], encoded_payload[16384];
  uint8_t der[128], raw[64];
  size_t n = sizeof(der);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  ECDSA_SIG *sig = NULL;
  const unsigned char *cursor = der;
  const BIGNUM *r, *s;
  int length, result = 0;
  snprintf(header, sizeof(header),
           "{\"alg\": \"ES256\",\"typ\": \"orbit-access+jwt\",\"kid\": \"%s\"}",
           kid);
  b64((const uint8_t *)header, strlen(header), encoded_header);
  b64((const uint8_t *)payload, strlen(payload), encoded_payload);
  length = snprintf(out, capacity, "%s.%s", encoded_header, encoded_payload);
  if (length < 0 || (size_t)length + 88u >= capacity || ctx == NULL)
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
  b64(raw, 64u, out + length);
  result = 1;
done:
  ECDSA_SIG_free(sig);
  EVP_MD_CTX_free(ctx);
  return result;
}
static void get_string(const char *json, const char *field, char *out,
                       size_t capacity) {
  char marker[64];
  const char *p, *end;
  size_t n;
  snprintf(marker, sizeof(marker), "\"%s\":\"", field);
  p = strstr(json, marker);
  if (!p) {
    out[0] = 0;
    return;
  }
  p += strlen(marker);
  end = strchr(p, '"');
  n = end ? (size_t)(end - p) : 0u;
  if (n >= capacity)
    n = capacity - 1u;
  memcpy(out, p, n);
  out[n] = 0;
}
static int32_t reject_reentry(mock_t *m) {
  orbit_access_snapshot_t snapshot;
  orbit_client_services_t rejected_services = {0};
  orbit_client_destroy(m->client);
  if (orbit_client_tick(m->client) != ORBIT_CLIENT_BUSY ||
      orbit_client_snapshot(m->client, &snapshot) != ORBIT_CLIENT_BUSY ||
      orbit_client_require_access(m->client, S("export")) != ORBIT_CLIENT_BUSY ||
      orbit_client_activate(m->client, S("key")) != ORBIT_CLIENT_BUSY ||
      orbit_client_deactivate(m->client) != ORBIT_CLIENT_BUSY ||
      orbit_client_invalidate(m->client) != ORBIT_CLIENT_BUSY ||
      orbit_client_clock_lost(m->client) != ORBIT_CLIENT_BUSY ||
      orbit_client_init(m->client, &config, &rejected_services, arena,
                        sizeof(arena), scratch, sizeof(scratch)) != ORBIT_CLIENT_BUSY)
    return ORBIT_CLIENT_UNTRUSTED;
  return 0;
}
static int32_t exchange(void *context, const orbit_http_request_t *request,
                        uint16_t *http, orbit_receive_fn receive, void *sink) {
  mock_t *m = context;
  char path[512], body[4096], payload[2048], token[4096], reply[6144],
      timestamp[32], jwks[1024], x[64], y[64];
  time_t seconds = (time_t)m->now;
  struct tm utc;
  uint32_t i;
  const generated_grant_vector_t *v = &generated_grant_vectors[0];
  if (request->path.length >= sizeof(path) ||
      request->body.length >= sizeof(body))
    return ORBIT_CLIENT_UNTRUSTED;
  memcpy(path, request->path.data, request->path.length);
  path[request->path.length] = 0;
  if (request->body.length)
    memcpy(body, request->body.data, request->body.length);
  body[request->body.length] = 0;
  if (m->reenter && reject_reentry(m) != 0)
    return ORBIT_CLIENT_UNTRUSTED;
  if (!request->post) {
    ++m->gets;
    if (m->key_transient)
      return ORBIT_CLIENT_TRANSIENT;
    *http = 200u;
    if (strcmp(path,
               "/.well-known/"
               "orbit-jwks.json?application_id=app&environment_id=env") != 0)
      return ORBIT_CLIENT_UNTRUSTED;
    memcpy(jwks, v->jwks, v->jwks_length);
    jwks[v->jwks_length] = 0;
    get_string(jwks, "x", x, sizeof(x));
    get_string(jwks, "y", y, sizeof(y));
    snprintf(jwks, sizeof(jwks),
             "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\","
             "\"use\":\"sig\","
             "\"kid\":\"%s\",\"x\":\"%s\",\"y\":\"%s\"}]}",
             m->kid, x, y);
    for (i = 0; i < strlen(jwks); ++i) {
      int32_t result = receive(sink, (const uint8_t *)jwks + i, 1u);
      if (result)
        return result;
    }
    return 0;
  }
  ++m->posts;
  get_string(body, "installation_id", m->installation, sizeof(m->installation));
  get_string(body, "idempotency_key", m->operation_id, sizeof(m->operation_id));
  if (m->post_transient)
    return ORBIT_CLIENT_TRANSIENT;
  if (m->denial) {
    *http = 403u;
    return 0;
  }
  if (strstr(path, "/deactivate")) {
    *http = 204u;
    return 0;
  }
  if (strcmp(path, "/api/client/v1/activations") != 0 &&
      strcmp(path, "/api/client/v1/activations/activation_1/validate") != 0)
    return ORBIT_CLIENT_UNTRUSTED;
  *http = 200u;
  snprintf(payload, sizeof(payload),
           "{\"iss\":\"https://"
           "orbit.test\",\"aud\":\"orbit:app:env\",\"sub\":\"licence_1\","
           "\"jti\":\"grant_1\","
           "\"iat\":%lld,\"nbf\":%lld,\"exp\":%lld,\"application_id\":\"app\","
           "\"environment_id\":"
           "\"env\",\"activation_id\":\"activation_1\",\"installation_id\":\"%"
           "s\",\"binding_"
           "mode\": \"none\",\"policy_version\":1,\"entitlements\":{\"export\":"
           "true,\"disabled\":"
           "false},\"refresh_after\":%lld,\"offline_allowed\":%s}",
           (long long)m->now, (long long)m->now,
           (long long)(m->now + (m->offline ? 86400 : 300)), m->installation,
           (long long)(m->now + (m->offline ? 900 : 60)),
           m->offline ? "true" : "false");
  if (!sign_token(payload, m->kid, token, sizeof(token)))
    return ORBIT_CLIENT_UNTRUSTED;
  if (m->bad_signature) {
    char *dot = strrchr(token, '.');
    dot[1] = dot[1] == 'A' ? 'B' : 'A';
  }
  gmtime_r(&seconds, &utc);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);
  snprintf(reply, sizeof(reply),
           "{\"activation_id\":\"activation_1\",\"installation_id\":\"%s\",%"
           "s\"credential_expires_"
           "at\":null,\"grant\":\"%s\",\"server_time\":\"%s\",\"binding_mode\":"
           "\"none\",\"fingerprint_"
           "provider\":null,\"licence_expires_at\":null,\"secret_replay_"
           "expired\":false}",
           m->installation,
           strstr(path, "/validate") ? "" : "\"credential\":\"credential_1\",",
           token, timestamp);
  return receive(sink, (const uint8_t *)reply, (uint32_t)strlen(reply));
}
static int32_t clock_read(void *context, int64_t *unix_seconds,
                          uint64_t *ticks) {
  mock_t *m = context;
  if (m->reenter_clock && reject_reentry(m) != 0)
    return ORBIT_CLIENT_CLOCK;
  *unix_seconds = m->now;
  *ticks = m->ticks;
  return 0;
}
static int32_t entropy(void *context, uint8_t *bytes, uint32_t length) {
  mock_t *m = context;
  uint32_t i;
  for (i = 0; i < length; ++i)
    bytes[i] = (uint8_t)(i + m->commits + 1u);
  return 0;
}
static uint64_t generation(const uint8_t *p) {
  uint64_t value = 0;
  uint32_t i;
  for (i = 0; i < 8u; ++i)
    value |= (uint64_t)p[8u + i] << (i * 8u);
  return value;
}
static int32_t load(void *context, uint8_t *record, uint32_t capacity,
                    uint32_t *length) {
  mock_t *m = context;
  if (m->oversized) {
    *length = capacity + 1u;
    return 0;
  }
  if (!m->record_length)
    return ORBIT_CLIENT_NOT_FOUND;
  if (m->record_length > capacity)
    return ORBIT_CLIENT_STORAGE;
  memcpy(record, m->record, m->record_length);
  *length = m->record_length;
  return 0;
}
static int32_t commit(void *context, uint64_t expected, const uint8_t *record,
                      uint32_t length) {
  mock_t *m = context;
  if (m->reenter_commit && reject_reentry(m) != 0)
    return ORBIT_CLIENT_STORAGE;
  if (m->storage_failure)
    return ORBIT_CLIENT_STORAGE;
  if ((m->record_length ? generation(m->record) : 0u) != expected)
    return ORBIT_CLIENT_STALE;
  if (length > sizeof(m->record))
    return ORBIT_CLIENT_STORAGE;
  memcpy(m->record, record, length);
  m->record_length = length;
  ++m->commits;
  return 0;
}
static int init(mock_t *m) {
  orbit_client_services_t services = {m,    exchange, clock_read, entropy,
                                      load, commit,   {0}};
  services.crypto = *orbit_test_openssl_crypto();
  m->client = &client;
  return orbit_client_init(&client, &config, &services, arena, sizeof(arena),
                           scratch, sizeof(scratch));
}
static void reset(mock_t *m) {
  memset(m, 0, sizeof(*m));
  m->now = 1800000000;
  m->ticks = 1000;
  m->offline = 1;
  strcpy(m->kid, "test-key");
}
static void elapse(mock_t *m, int64_t seconds) {
  m->now += seconds;
  m->ticks += (uint64_t)seconds * 1000u;
}
static int lifecycle(void) {
  mock_t m;
  uint32_t writes, requests;
  orbit_access_snapshot_t snapshot;
  char installation[129];
  reset(&m);
  CHECK(init(&m) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_ACTIVATION_REQUIRED);
  m.reenter = m.reenter_clock = m.reenter_commit = 1;
  CHECK(orbit_client_activate(&client, S("example-key")) == 0);
  m.reenter = 0;
  CHECK(m.commits == 3u && m.posts == 1u && m.gets == 1u);
  writes = m.commits;
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  CHECK(orbit_client_require_access(&client, S("disabled")) ==
        ORBIT_CLIENT_DENIED);
  CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && snapshot.allowed &&
        snapshot.refresh_after == m.now + 900);
  CHECK(orbit_client_snapshot(&client, (orbit_access_snapshot_t *)arena) ==
        ORBIT_CLIENT_ARGUMENT);
  strcpy(installation, m.installation);
  orbit_client_destroy(&client);
  CHECK(init(&m) == 0);
  CHECK(m.commits == writes);
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  CHECK(m.posts == 2u && strcmp(installation, m.installation) == 0);
  elapse(&m, 901);
  m.post_transient = 1;
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && snapshot.allowed &&
        snapshot.offline);
  requests = m.posts;
  CHECK(orbit_client_require_access(&client, S("export")) == 0 &&
        m.posts == requests);
  elapse(&m, 31);
  m.post_transient = 0;
  CHECK(orbit_client_require_access(&client, S("export")) == 0 &&
        m.commits == writes);
  strcpy(m.kid, "rotated-key");
  elapse(&m, 901);
  m.key_transient = 1;
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_TRANSIENT);
  CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && !snapshot.allowed);
  elapse(&m, 31);
  m.key_transient = 0;
  CHECK(orbit_client_require_access(&client, S("export")) == 0 &&
        m.commits == writes);
  m.now -= 100;
  CHECK(orbit_client_require_access(&client, S("export")) ==
        ORBIT_CLIENT_CLOCK);
  m.now += 100;
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  CHECK(orbit_client_clock_lost(&client) == 0);
  CHECK(orbit_client_require_access(&client, S("export")) == 0);
  elapse(&m, 901);
  m.denial = 1;
  CHECK(orbit_client_require_access(&client, S("export")) ==
        ORBIT_CLIENT_DENIED);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_ACTIVATION_REQUIRED);
  orbit_client_destroy(&client);
  CHECK(init(&m) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_ACTIVATION_REQUIRED);
  orbit_client_destroy(&client);
  return 0;
}
static int retry_and_storage(void) {
  mock_t m;
  uint32_t requests, writes;
  orbit_access_snapshot_t snapshot;
  orbit_record_t record;
  reset(&m);
  CHECK(init(&m) == 0);
  m.post_transient = 1;
  CHECK(orbit_client_activate(&client, S("example-key")) ==
        ORBIT_CLIENT_TRANSIENT);
  strcpy(m.previous_operation, m.operation_id);
  requests = m.posts;
  writes = m.commits;
  orbit_client_destroy(&client);
  CHECK(init(&m) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_PENDING);
  CHECK(orbit_client_activate(&client, S("different-key")) ==
            ORBIT_CLIENT_PENDING &&
        m.posts == requests);
  m.post_transient = 0;
  CHECK(orbit_client_activate(&client, S("example-key")) == 0 &&
        strcmp(m.previous_operation, m.operation_id) == 0 &&
        m.commits == writes + 1u);
  m.post_transient = 1;
  CHECK(orbit_client_deactivate(&client) == ORBIT_CLIENT_TRANSIENT);
  CHECK(orbit_client_snapshot(&client, &snapshot) == 0 && !snapshot.allowed &&
        snapshot.pending == 2u);
  strcpy(m.previous_operation, m.operation_id);
  orbit_client_destroy(&client);
  CHECK(init(&m) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_PENDING);
  m.post_transient = 0;
  CHECK(orbit_client_deactivate(&client) == 0 &&
        strcmp(m.previous_operation, m.operation_id) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_ACTIVATION_REQUIRED);
  orbit_client_destroy(&client);
  reset(&m);
  CHECK(init(&m) == 0);
  m.storage_failure = 1;
  CHECK(orbit_client_activate(&client, S("example-key")) ==
            ORBIT_CLIENT_STORAGE &&
        m.posts == 0u);
  orbit_client_destroy(&client);
  reset(&m);
  m.oversized = 1;
  CHECK(init(&m) == ORBIT_CLIENT_STORAGE);
  reset(&m);
  CHECK(init(&m) == 0);
  m.bad_signature = 1;
  CHECK(orbit_client_activate(&client, S("example-key")) ==
        ORBIT_CLIENT_UNTRUSTED);
  CHECK(orbit_record_decode(m.record, m.record_length, &record) == 0 &&
        record.pending_kind == 1u && record.credential_length == 0u);
  m.bad_signature = 0;
  CHECK(orbit_client_activate(&client, S("example-key")) == 0);
  CHECK(orbit_client_invalidate(&client) == 0);
  orbit_client_destroy(&client);
  CHECK(init(&m) == 0);
  CHECK(orbit_client_tick(&client) == ORBIT_CLIENT_ACTIVATION_REQUIRED);
  orbit_client_destroy(&client);
  reset(&m);
  m.offline = 0;
  CHECK(init(&m) == 0);
  CHECK(orbit_client_activate(&client, S("example-key")) == 0);
  elapse(&m, 61);
  m.post_transient = 1;
  CHECK(orbit_client_require_access(&client, S("export")) ==
        ORBIT_CLIENT_DENIED);
  orbit_client_destroy(&client);
  return 0;
}
typedef struct flash {
  uint8_t bytes[2][4096];
  int fail, programs, zero_program, fail_erase, erases, fail_sync, syncs;
} flash_t;
static int32_t flash_read(void *ctx, uint8_t slot, uint32_t at, uint8_t *out,
                          uint32_t n) {
  flash_t *f = ctx;
  if (slot > 1u || at + n > 4096u)
    return -1;
  memcpy(out, f->bytes[slot] + at, n);
  return 0;
}
static int32_t flash_erase(void *ctx, uint8_t slot) {
  flash_t *f = ctx;
  memset(f->bytes[slot], 255, 4096);
  return ++f->erases == f->fail_erase ? -1 : 0;
}
static int32_t flash_program(void *ctx, uint8_t slot, uint32_t at,
                             const uint8_t *p, uint32_t n) {
  flash_t *f = ctx;
  uint32_t i;
  int fail = ++f->programs == f->fail;
  if (slot > 1u || at + n > 4096u || at % 8u || n % 8u)
    return -1;
  if (fail)
    n = f->zero_program ? 0u : n / 2u;
  for (i = 0; i < n; ++i)
    f->bytes[slot][at + i] &= p[i];
  return fail ? -1 : 0;
}
static int32_t flash_sync(void *ctx) {
  flash_t *f = ctx;
  return ++f->syncs == f->fail_sync ? -1 : 0;
}
static int journal_faults(void) {
  flash_t baseline, f;
  orbit_journal_t j = {&f,          4096,          flash_read,
                       flash_erase, flash_program, flash_sync};
  orbit_record_t r;
  uint8_t encoded[1024], loaded[1024];
  uint32_t n, got;
  int cut, result, programs, syncs, zero;
  memset(&baseline, 0, sizeof(baseline));
  memset(baseline.bytes, 255, sizeof(baseline.bytes));
  f = baseline;
  memset(&r, 0, sizeof(r));
  r.generation = 1u;
  r.installation_length = 32u;
  memset(r.installation, 'a', 32u);
  CHECK(orbit_record_encode(&r, encoded, &n) == 0);
  CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &got) ==
        ORBIT_CLIENT_NOT_FOUND);
  CHECK(orbit_journal_commit(&j, 0u, encoded, n) == 0);
  f.programs = f.erases = f.syncs = 0;
  baseline = f;
  CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &got) == 0 && got == n &&
        memcmp(loaded, encoded, n) == 0);
  CHECK(orbit_journal_commit(&j, 0u, encoded, n) == ORBIT_CLIENT_STALE);
  r.generation = 2u;
  CHECK(orbit_record_encode(&r, encoded, &n) == 0);
  CHECK(orbit_journal_commit(&j, 1u, encoded, n) == 0);
  programs = f.programs;
  syncs = f.syncs;
  for (zero = 0; zero <= 1; ++zero) {
    for (cut = 1; cut <= programs; ++cut) {
      f = baseline;
      f.fail = cut;
      f.zero_program = zero;
      CHECK(orbit_journal_commit(&j, 1u, encoded, n) == ORBIT_CLIENT_STORAGE);
      result = orbit_journal_load(&j, loaded, sizeof(loaded), &got);
      if (zero && cut == 1) {
        /* No successful persistent write: the caller cannot promise a durable
         * invalidation. Every later failure is fenced by the old-slot intent. */
        CHECK(result == 0 && generation(loaded) == 1u);
      } else
        CHECK(result == ORBIT_CLIENT_STORAGE ||
              (result == 0 && generation(loaded) == 2u));
    }
  }
  f = baseline;
  f.fail_erase = 1;
  CHECK(orbit_journal_commit(&j, 1u, encoded, n) == ORBIT_CLIENT_STORAGE);
  CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &got) == ORBIT_CLIENT_STORAGE);
  for (cut = 1; cut <= syncs; ++cut) {
    f = baseline;
    f.fail_sync = cut;
    CHECK(orbit_journal_commit(&j, 1u, encoded, n) == ORBIT_CLIENT_STORAGE);
    result = orbit_journal_load(&j, loaded, sizeof(loaded), &got);
    CHECK(result == ORBIT_CLIENT_STORAGE ||
          (result == 0 && generation(loaded) == 2u));
  }
  /* Reuse both slots repeatedly: a completed adjacent generation acknowledges
   * the older intent and leaves its own intent block unprogrammed. */
  f = baseline;
  for (cut = 2; cut < 6; ++cut) {
    r.generation = (uint64_t)cut;
    CHECK(orbit_record_encode(&r, encoded, &n) == 0);
    CHECK(orbit_journal_commit(&j, (uint64_t)cut - 1u, encoded, n) == 0);
    CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &got) == 0 &&
          generation(loaded) == (uint64_t)cut);
  }
  f = baseline;
  f.bytes[0][64] ^= 1u;
  CHECK(orbit_journal_load(&j, loaded, sizeof(loaded), &got) ==
        ORBIT_CLIENT_STORAGE);
  return 0;
}
int main(void) {
  FILE *file = fopen(ORBIT_TEST_PRIVATE_KEY, "r");
  CHECK(file != NULL);
  private_key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  fclose(file);
  CHECK(private_key != NULL);
  CHECK(lifecycle() == 0);
  CHECK(retry_and_storage() == 0);
  CHECK(journal_faults() == 0);
  EVP_PKEY_free(private_key);
  printf("client lifecycle/retry/clock/denial/no-reentry/storage faults "
         "passed; state=%zu "
         "public=%zu active=%zu record=%zu\n",
         sizeof(orbit_client_state_t), sizeof(orbit_client_t),
         sizeof(orbit_active_t), sizeof(orbit_record_t));
  return 0;
}
