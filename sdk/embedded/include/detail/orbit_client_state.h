#ifndef ORBIT_CLIENT_STATE_PRIVATE_H
#define ORBIT_CLIENT_STATE_PRIVATE_H
/* Private layout: included only so caller-owned storage has the correct C
 * effective type and alignment. Applications must not access or copy it. */
typedef struct orbit_record {
    uint64_t generation;
    int64_t credential_expiry, pending_created;
    uint8_t scope[32], pending_digest[32];
    uint8_t installation[128], activation[128], licence[128], credential[256], pending_id[32];
    uint16_t credential_length;
    uint8_t installation_length, activation_length, licence_length, pending_kind, has_expiry;
} orbit_record_t;
typedef struct orbit_active {
    int64_t expires, refresh;
    uint32_t policy;
    orbit_grant_text_t names[64];
    uint8_t pool[4096], enabled[8], count, valid, offline_allowed;
} orbit_active_t;
typedef struct orbit_client_state {
    uint32_t magic;
    orbit_client_config_t config;
    orbit_client_services_t services;
    uint8_t *arena, *scratch;
    orbit_record_t record;
    orbit_active_t active;
    orbit_grant_keyset_t keys;
    uint64_t generation, anchor_ticks, last_ticks, retry_ticks;
    int64_t anchor_server, last_wall;
    uint8_t busy, failed, anchored, transient;
} orbit_client_state_t;

#endif
