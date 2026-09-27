#ifndef ORBIT_DOWNLOADS_H
#define ORBIT_DOWNLOADS_H
#include "orbit_services.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Metadata slices borrow the client's transaction arena until the next client
 * operation. Copy what the application needs before another call. */
typedef struct orbit_artifact {
  orbit_embedded_slice_t id, release_id, platform, architecture, filename, url,
      required_feature;
  uint64_t byte_length;
  uint8_t sha256[32], protected_delivery;
} orbit_artifact_t;
typedef struct orbit_release {
  orbit_embedded_slice_t id, channel, version, notes;
  uint64_t release_number;
  int64_t created_at, published_at;
} orbit_release_t;
typedef struct orbit_update {
  orbit_release_t release;
  orbit_artifact_t artifact;
  uint8_t available;
} orbit_update_t;
typedef struct orbit_download_authorization {
  orbit_artifact_t artifact;
  orbit_embedded_slice_t ticket;
  int64_t expires_at;
} orbit_download_authorization_t;
/* Empty channel means stable. Board platform and architecture are explicit. */
int32_t orbit_client_check_for_updates(orbit_client_t *,
                                       uint64_t installed_release_number,
                                       orbit_embedded_slice_t channel,
                                       orbit_embedded_slice_t platform,
                                       orbit_embedded_slice_t architecture,
                                       const orbit_operation_t *,
                                       orbit_update_t *);
int32_t orbit_client_authorize_download(orbit_client_t *,
                                        orbit_embedded_slice_t release_id,
                                        orbit_embedded_slice_t artifact_id,
                                        const orbit_operation_t *,
                                        orbit_download_authorization_t *);
typedef struct orbit_download_response {
  orbit_embedded_slice_t location, content_encoding;
  uint64_t content_length;
  uint16_t status;
  uint8_t has_content_length;
} orbit_download_response_t;
/* The port owns its TLS and staged destination. open verifies HTTPS chain,
 * hostname and trusted dates, uses identity encoding, no cookies/ambient
 * credentials, and never follows a redirect. It sends the nonempty ticket only
 * as Authorization: Bearer. Each callback has a finite timeout. close
 * invalidates header slices, so redirect Location must be copied by the helper
 * first. stage_begin refuses an existing destination unless replace is
 * explicitly true; stage_commit atomically publishes verified bytes. abort
 * preserves the old destination. Hash callbacks operate on exactly the supplied
 * raw bytes. No callback may reenter or retain a borrowed argument. */
typedef struct orbit_download_io {
  void *context;
  int32_t (*open)(void *, orbit_embedded_slice_t url,
                  orbit_embedded_slice_t ticket, orbit_download_response_t *);
  int32_t (*read)(void *, uint8_t *, uint32_t, uint32_t *);
  void (*close)(void *);
  int32_t (*stage_begin)(void *, uint8_t replace);
  int32_t (*stage_write)(void *, const uint8_t *, uint32_t);
  int32_t (*stage_commit)(void *);
  void (*stage_abort)(void *);
  int32_t (*hash_begin)(void *);
  int32_t (*hash_update)(void *, const uint8_t *, uint32_t);
  int32_t (*hash_finish)(void *, uint8_t digest[32]);
  int32_t (*cancelled)(void *);
} orbit_download_io_t;
/* Scratch is caller-owned: at least 2304 bytes (2048 URL +256 stream). At most
 * five redirects with absolute Location URLs, always HTTPS and always without
 * the ticket. No installer runs. */
#define ORBIT_DOWNLOAD_SCRATCH_MIN_BYTES 2304u
int32_t orbit_download_stream(const orbit_download_authorization_t *,
                              uint64_t maximum_bytes, uint8_t replace_existing,
                              const orbit_download_io_t *, uint8_t *scratch,
                              uint32_t scratch_length);
#ifdef __cplusplus
}
#endif
#endif
