#ifndef ORBIT_EXTENSIONS_H
#define ORBIT_EXTENSIONS_H
#include "orbit_services.h"
#include "orbit_signed.h"
#ifdef __cplusplus
extern "C" {
#endif
#define ORBIT_OFFLINE_COMPACT_FILE_BYTES 4096u
#define ORBIT_OFFLINE_FULL_FILE_BYTES 16384u
#define ORBIT_OFFLINE_METADATA_BYTES 1024u
#define ORBIT_OFFLINE_BUFFER_BYTES(file_bytes)                                 \
  (ORBIT_OFFLINE_METADATA_BYTES + (file_bytes))
#define ORBIT_OFFLINE_SLOT_BYTES(file_bytes, erase_bytes)                      \
  (((64u + ORBIT_OFFLINE_BUFFER_BYTES(file_bytes) + (erase_bytes) - 1u) /      \
    (erase_bytes)) *                                                           \
   (erase_bytes))
/* Borrowed immutable trust and caller-owned transaction storage. Use exactly
 * one documented file profile. Original JWS and metadata share one atomic
 * record. */
typedef struct orbit_offline_config {
  const orbit_grant_keyset_t *keys;
  uint8_t *transaction;
  uint32_t transaction_capacity, max_file_bytes;
  orbit_embedded_slice_t app_key;
} orbit_offline_config_t;
typedef struct orbit_session_snapshot {
  uint8_t id[128];
  uint64_t sequence;
  int64_t expires_at, refresh_after;
  uint8_t id_length, required, active, automatic;
} orbit_session_snapshot_t;
/* Zero-initialize and do not copy a live extension. Same lifetime and exclusive
 * ownership as client. Session authority is never stored. */
typedef struct orbit_client_extension {
  orbit_client_t *client;
  orbit_client_services_t platform;
  orbit_session_snapshot_t session;
  uint64_t pending_sequence, pending_started, next_poll;
  int64_t licence_expires_at;
  uint8_t policy_known, has_licence_expiry, pending_start;
#ifdef ORBIT_ENABLE_OFFLINE
  orbit_offline_config_t offline;
  uint64_t offline_sequence;
  int64_t offline_floor, offline_checkpoint;
  uint32_t file_length;
  uint8_t file_digest[32], offline_mode, offline_loading;
#endif
} orbit_client_extension_t;
/* Use the normal parsed app-key config; its trusted Test/Live mode is required.
 * offline=NULL is connected mode. Offline configuration needs
 * ORBIT_ENABLE_OFFLINE. Call tick regularly to acquire/renew; warm guards only
 * inspect an active seat. */
int32_t orbit_client_init_extended(orbit_client_t *,
                                   const orbit_client_config_t *,
                                   const orbit_client_services_t *,
                                   orbit_client_extension_t *, uint8_t *arena,
                                   uint32_t arena_length, void *scratch,
                                   uint32_t scratch_length,
                                   const orbit_offline_config_t *offline);
int32_t orbit_client_start_session(orbit_client_t *, const orbit_operation_t *,
                                   orbit_session_snapshot_t *);
int32_t orbit_client_end_session(orbit_client_t *, const orbit_operation_t *);
int32_t orbit_client_session(orbit_client_t *, orbit_session_snapshot_t *);
/* Bounded release and offline clock checkpoint, then destroy. */
int32_t orbit_client_close(orbit_client_t *, const orbit_operation_t *);
#ifdef ORBIT_ENABLE_OFFLINE
int32_t orbit_client_import_offline_file(orbit_client_t *,
                                         orbit_embedded_slice_t);
/* Reader supplies up to capacity bytes and returns zero bytes at EOF. It must
 * finish promptly. Reads reuse the transaction file area; rejected input
 * reloads the previous durable pair. max_file_bytes applies to the whole input.
 * The reader must not access the client's buffers. */
typedef int32_t (*orbit_offline_read_fn)(void *, uint8_t *, uint32_t,
                                         uint32_t *);
int32_t orbit_client_import_offline_reader(orbit_client_t *,
                                           orbit_offline_read_fn, void *,
                                           const orbit_operation_t *);
int32_t orbit_client_offline_request(orbit_client_t *, uint8_t *, uint32_t,
                                     uint32_t *);
#endif
#ifdef __cplusplus
}
#endif
#endif
