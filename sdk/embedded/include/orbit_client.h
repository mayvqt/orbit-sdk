#ifndef ORBIT_CLIENT_H
#define ORBIT_CLIENT_H
#include "orbit_embedded.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Compile the client and its callers with the same bounded arena profile.
 * Smaller profiles reject oversized responses without weakening validation. */
#ifndef ORBIT_CLIENT_ARENA_BYTES
#define ORBIT_CLIENT_ARENA_BYTES 32768u
#endif
#if ORBIT_CLIENT_ARENA_BYTES < 8192u || ORBIT_CLIENT_ARENA_BYTES > 32768u
#error "ORBIT_CLIENT_ARENA_BYTES must be between 8192 and 32768"
#endif
#define ORBIT_CLIENT_STORAGE_BYTES 6960u
#define ORBIT_CLIENT_RECORD_BYTES 1024u
#define ORBIT_CLIENT_OK ((int32_t)0)
#define ORBIT_CLIENT_ARGUMENT ((int32_t)10)
#define ORBIT_CLIENT_STORAGE ((int32_t)11)
#define ORBIT_CLIENT_UNTRUSTED ((int32_t)12)
#define ORBIT_CLIENT_TRANSIENT ((int32_t)13)
#define ORBIT_CLIENT_DENIED ((int32_t)14)
#define ORBIT_CLIENT_ACTIVATION_REQUIRED ((int32_t)15)
#define ORBIT_CLIENT_CLOCK ((int32_t)16)
#define ORBIT_CLIENT_PENDING ((int32_t)17)
#define ORBIT_CLIENT_STALE ((int32_t)18)
#define ORBIT_CLIENT_RESOURCE_LIMIT ((int32_t)19)
#define ORBIT_CLIENT_NOT_FOUND ((int32_t)20)
#define ORBIT_CLIENT_BUSY ((int32_t)21)

/* Caller-owned, aligned state. Zero-initialize before first use. Destroy before
 * initializing again. Treat every byte as private; never copy a live
 * client. This storage and all borrowed configuration/services/arena outlive
 * it. */
typedef union orbit_client orbit_client_t;

typedef struct orbit_client_config {
  orbit_embedded_slice_t
      api_origin; /* HTTPS origin, no path/query/credentials */
  orbit_embedded_slice_t issuer;
  orbit_embedded_slice_t application_id;
  orbit_embedded_slice_t environment_id;
  orbit_embedded_slice_t fingerprint; /* empty for an unbound policy */
  orbit_embedded_slice_t fingerprint_provider;
} orbit_client_config_t;

typedef struct orbit_http_request {
  orbit_embedded_slice_t origin, path, body;
  uint8_t post; /* 0 GET, 1 POST; JSON request/response, no redirects */
} orbit_http_request_t;
typedef int32_t (*orbit_receive_fn)(void *context, const uint8_t *bytes,
                                    uint32_t length);

typedef struct orbit_client_services {
  void *context;
  /* TLS hostname, certificate-chain and trusted-time validation is mandatory.
   * Do not follow redirects or decompress an unbounded body. Deliver bytes
   * synchronously and stop if receive returns nonzero. Return TRANSIENT only
   * for network timeout/unavailability, never TLS/JSON/validation failure.
   * Set status before receive. Before the first receive call, finish sending
   * the request body and stop reading it: response bytes reuse that arena. */
  int32_t (*exchange)(void *context, const orbit_http_request_t *request,
                      uint16_t *http_status, orbit_receive_fn receive,
                      void *receive_context);
  /* Trusted UTC for TLS bootstrap and elapsed milliseconds including sleep.
   * Return CLOCK if either cannot be established. Reset/deep sleep requires
   * init and online validation; process-local ticks never survive power loss.
   */
  int32_t (*clock)(void *context, int64_t *unix_seconds, uint64_t *elapsed_ms);
  int32_t (*entropy)(void *context, uint8_t *bytes, uint32_t length);
  /* Empty storage returns NOT_FOUND, corrupt/inaccessible storage STORAGE.
   * Commit atomically compares the previous durable generation and replaces
   * the record. A torn newer write must fail closed, not restore old authority.
   * Callbacks retain no pointers. One isolated storage owner is required unless
   * the adapter implements atomic interprocess/context generation checks. */
  int32_t (*load)(void *context, uint8_t *record, uint32_t capacity,
                  uint32_t *length);
  int32_t (*commit)(void *context, uint64_t expected_generation,
                    const uint8_t *record, uint32_t length);
  orbit_grant_crypto_t crypto;
} orbit_client_services_t;

#include "detail/orbit_client_state.h"
union orbit_client {
    uint64_t alignment;
    uint8_t private_bytes[ORBIT_CLIENT_STORAGE_BYTES];
    orbit_client_state_t private_state;
};

typedef struct orbit_access_snapshot {
  int64_t expires_at, refresh_after, credential_expires_at;
  uint32_t policy_version;
  uint8_t allowed, offline, has_credential_expiry, activation_required, pending;
} orbit_access_snapshot_t;

/* No heap, threads or implicit timers. Init loads/creates stable installation
 * identity, but never restores access. The first tick validates a stored
 * bearer. All calls are serialized by the host; network callbacks must not
 * reenter. arena is at least ORBIT_CLIENT_ARENA_BYTES and scratch at least
 * ORBIT_GRANT_WORKSPACE_BYTES; all objects and borrowed config bytes must be
 * disjoint. */
int32_t orbit_client_init(orbit_client_t *client,
                          const orbit_client_config_t *config,
                          const orbit_client_services_t *services,
                          uint8_t *arena, uint32_t arena_length, void *scratch,
                          uint32_t scratch_length);
int32_t orbit_client_activate(orbit_client_t *client,
                              orbit_embedded_slice_t licence_key);
int32_t orbit_client_tick(orbit_client_t *client);
int32_t orbit_client_require_access(orbit_client_t *client,
                                    orbit_embedded_slice_t entitlement);
int32_t orbit_client_snapshot(orbit_client_t *client,
                              orbit_access_snapshot_t *snapshot);
int32_t orbit_client_deactivate(orbit_client_t *client);
/* Immediate RAM denial plus a durable authority fence, retaining installation
 * ID. */
int32_t orbit_client_invalidate(orbit_client_t *client);
/* Host reports uncertain elapsed time after resume; retained credential permits
 * online recovery once the clock adapter is trustworthy again. */
int32_t orbit_client_clock_lost(orbit_client_t *client);
void orbit_client_destroy(orbit_client_t *client);

#ifdef __cplusplus
}
#endif
#endif
