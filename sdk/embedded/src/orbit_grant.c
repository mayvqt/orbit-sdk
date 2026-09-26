#include "orbit_embedded.h"
#include "orbit_json.h"
#include "orbit_internal.h"

#include <stddef.h>

#define DECODED_SEGMENT_BYTES ORBIT_JSON_DECODED_SEGMENT_BYTES

typedef orbit_json_span_t json_span_t;
typedef orbit_json_parser_t parser_t;

#define skip_space orbit_json_skip_space
#define fail orbit_json_fail
#define scan_string orbit_json_scan_string
#define consume_literal orbit_json_consume_literal
#define span_equals_ascii orbit_json_span_equals_ascii
#define spans_equal orbit_json_spans_equal
#define decode_span orbit_json_decode_span
#define parse_number orbit_json_number
#define object_open orbit_json_object_open
#define object_next orbit_json_object_next
#define skip_value orbit_json_skip_value
#define finish_json orbit_json_finish
#define parser_init orbit_json_init
#define valid_utf8_no_nul orbit_json_valid_utf8_no_nul

static void bytes_zero(void *target, uint32_t length) {
    uint8_t *out = (uint8_t *)target;
    uint32_t i;
    for (i = 0; i < length; ++i) out[i] = 0;
}

static int bytes_equal(const uint8_t *left, const uint8_t *right, uint32_t length) {
    uint32_t i;
    for (i = 0; i < length; ++i) if (left[i] != right[i]) return 0;
    return 1;
}

static int32_t local_string(parser_t *parser, json_span_t span, char *output,
                            uint32_t capacity, uint32_t *length, int ascii_only) {
    uint32_t decoded = 0;
    int32_t status;
    if (capacity == 0u) return fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    status = decode_span(parser->data, span, (uint8_t *)output, capacity - 1u, &decoded, ascii_only);
    if (status != ORBIT_GRANT_STATUS_OK) return fail(parser, status);
    output[decoded] = '\0';
    *length = decoded;
    return ORBIT_GRANT_STATUS_OK;
}

static int32_t pool_string(parser_t *parser, orbit_grant_claims_t *claims,
                           json_span_t span, orbit_grant_text_t *text) {
    (void)claims;
    if (span.start > UINT16_MAX || span.length > UINT16_MAX) return fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    text->offset = (uint16_t)span.start;
    text->length = (uint16_t)span.length;
    return ORBIT_GRANT_STATUS_OK;
}

static int32_t parse_required_string(parser_t *parser, orbit_grant_claims_t *claims,
                                    orbit_grant_text_t *target) {
    json_span_t span;
    skip_space(parser);
    if (parser->position >= parser->length || parser->data[parser->position] != '"') return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    if (scan_string(parser, &span) != ORBIT_GRANT_STATUS_OK) return parser->status;
    return pool_string(parser, claims, span, target);
}

static int32_t parse_optional_string(parser_t *parser, orbit_grant_claims_t *claims,
                                     orbit_grant_text_t *target, uint8_t *present) {
    json_span_t span;
    skip_space(parser);
    if (parser->position < parser->length && parser->data[parser->position] == 'n') {
        if (consume_literal(parser, "null", 4u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        *present = 0u;
        return ORBIT_GRANT_STATUS_OK;
    }
    if (parser->position >= parser->length || parser->data[parser->position] != '"') return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    if (scan_string(parser, &span) != ORBIT_GRANT_STATUS_OK) return parser->status;
    *present = 1u;
    return pool_string(parser, claims, span, target);
}

static int32_t parse_required_integer(parser_t *parser, int64_t *target) {
    skip_space(parser);
    if (parser->position >= parser->length || (parser->data[parser->position] != '-' && (parser->data[parser->position] < '0' || parser->data[parser->position] > '9'))) return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    return parse_number(parser, 1, target);
}

static int32_t parse_optional_integer(parser_t *parser, int64_t *target, uint8_t *present) {
    skip_space(parser);
    if (parser->position < parser->length && parser->data[parser->position] == 'n') {
        if (consume_literal(parser, "null", 4u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        *present = 0u;
        return ORBIT_GRANT_STATUS_OK;
    }
    if (parse_required_integer(parser, target) != ORBIT_GRANT_STATUS_OK) return parser->status;
    *present = 1u;
    return ORBIT_GRANT_STATUS_OK;
}

static int32_t parse_bool(parser_t *parser, uint8_t *target) {
    skip_space(parser);
    if (parser->position < parser->length && parser->data[parser->position] == 't') {
        if (consume_literal(parser, "true", 4u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        *target = 1u;
        return ORBIT_GRANT_STATUS_OK;
    }
    if (parser->position < parser->length && parser->data[parser->position] == 'f') {
        if (consume_literal(parser, "false", 5u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        *target = 0u;
        return ORBIT_GRANT_STATUS_OK;
    }
    return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
}

static int32_t parse_entitlements(parser_t *parser, orbit_grant_claims_t *claims) {
    uint32_t base;
    int first, present;
    json_span_t key;
    if (object_open(parser, 1u, &base, &first) != ORBIT_GRANT_STATUS_OK) return parser->status;
    for (;;) {
        orbit_grant_entitlement_t *entry;
        uint8_t enabled = 0u;
        uint32_t name_length = 0u, i;
        uint8_t name[ORBIT_GRANT_MAX_ENTITLEMENT_NAME];
        if (object_next(parser, base, &first, &key, &present) != ORBIT_GRANT_STATUS_OK) return parser->status;
        if (!present) break;
        if (claims->entitlement_count >= ORBIT_GRANT_MAX_ENTITLEMENTS) return fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
        entry = &claims->entitlements[claims->entitlement_count];
        if (decode_span(parser->data, key, name, sizeof(name), &name_length, 1) != ORBIT_GRANT_STATUS_OK) return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        if (name_length == 0u || name_length > ORBIT_GRANT_MAX_ENTITLEMENT_NAME || name[0] < 'a' || name[0] > 'z') return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        for (i = 0; i < name_length; ++i) {
            const uint8_t c = name[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        }
        entry->name.offset = (uint16_t)key.start;
        entry->name.length = (uint16_t)key.length;
        if (parse_bool(parser, &enabled) != ORBIT_GRANT_STATUS_OK) return parser->status;
        if (enabled) claims->entitlement_enabled[claims->entitlement_count / 8u] |= (uint8_t)(1u << (claims->entitlement_count % 8u));
        ++claims->entitlement_count;
    }
    parser->member_count = base;
    return ORBIT_GRANT_STATUS_OK;
}

#define SEEN_ISS (1u << 0)
#define SEEN_AUD (1u << 1)
#define SEEN_SUB (1u << 2)
#define SEEN_JTI (1u << 3)
#define SEEN_IAT (1u << 4)
#define SEEN_NBF (1u << 5)
#define SEEN_EXP (1u << 6)
#define SEEN_APP (1u << 7)
#define SEEN_ENV (1u << 8)
#define SEEN_ACT (1u << 9)
#define SEEN_INS (1u << 10)
#define SEEN_BIND (1u << 11)
#define SEEN_FP (1u << 12)
#define SEEN_FP_PROVIDER (1u << 13)
#define SEEN_POLICY (1u << 14)
#define SEEN_ENTITLEMENTS (1u << 15)
#define SEEN_REFRESH (1u << 16)
#define SEEN_OFFLINE (1u << 17)
#define SEEN_LICENCE_EXP (1u << 18)
#define REQUIRED_CLAIMS (((1u << 12) - 1u) | SEEN_POLICY | SEEN_ENTITLEMENTS | SEEN_REFRESH | SEEN_OFFLINE)

static int32_t parse_claims_json(parser_t *parser, orbit_grant_claims_t *claims,
                                 char binding[16], uint32_t *binding_length) {
    uint32_t base, seen = 0u;
    int first, present;
    json_span_t key;
    if (object_open(parser, 0u, &base, &first) != ORBIT_GRANT_STATUS_OK) return parser->status;
    for (;;) {
        uint32_t bit = 0u;
        if (object_next(parser, base, &first, &key, &present) != ORBIT_GRANT_STATUS_OK) return parser->status;
        if (!present) break;
        if (span_equals_ascii(parser->data, key, "iss", 3u)) {
            bit = SEEN_ISS;
            if (parse_required_string(parser, claims, &claims->issuer) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "aud", 3u)) {
            bit = SEEN_AUD;
            if (parse_required_string(parser, claims, &claims->audience) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "sub", 3u)) {
            bit = SEEN_SUB;
            if (parse_required_string(parser, claims, &claims->subject) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "jti", 3u)) {
            bit = SEEN_JTI;
            if (parse_required_string(parser, claims, &claims->token_id) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "iat", 3u)) {
            bit = SEEN_IAT;
            if (parse_required_integer(parser, &claims->issued_at) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "nbf", 3u)) {
            bit = SEEN_NBF;
            if (parse_required_integer(parser, &claims->not_before) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "exp", 3u)) {
            bit = SEEN_EXP;
            if (parse_required_integer(parser, &claims->expires_at) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "application_id", 14u)) {
            bit = SEEN_APP;
            if (parse_required_string(parser, claims, &claims->application_id) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "environment_id", 14u)) {
            bit = SEEN_ENV;
            if (parse_required_string(parser, claims, &claims->environment_id) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "activation_id", 13u)) {
            bit = SEEN_ACT;
            if (parse_required_string(parser, claims, &claims->activation_id) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "installation_id", 15u)) {
            bit = SEEN_INS;
            if (parse_required_string(parser, claims, &claims->installation_id) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "binding_mode", 12u)) {
            json_span_t value;
            bit = SEEN_BIND;
            skip_space(parser);
            if (scan_string(parser, &value) != ORBIT_GRANT_STATUS_OK || local_string(parser, value, binding, 16u, binding_length, 1) != ORBIT_GRANT_STATUS_OK || pool_string(parser, claims, value, &claims->binding_mode) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "fingerprint", 11u)) {
            bit = SEEN_FP;
            if (parse_optional_string(parser, claims, &claims->fingerprint, &claims->has_fingerprint) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "fingerprint_provider", 20u)) {
            bit = SEEN_FP_PROVIDER;
            if (parse_optional_string(parser, claims, &claims->fingerprint_provider, &claims->has_fingerprint_provider) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "policy_version", 14u)) {
            int64_t value;
            bit = SEEN_POLICY;
            if (parse_required_integer(parser, &value) != ORBIT_GRANT_STATUS_OK) return parser->status;
            if (value < 1 || value > INT32_MAX) return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
            claims->policy_version = (uint32_t)value;
        } else if (span_equals_ascii(parser->data, key, "entitlements", 12u)) {
            bit = SEEN_ENTITLEMENTS;
            skip_space(parser);
            if (parser->position >= parser->length || parser->data[parser->position] != '{') return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
            if (parse_entitlements(parser, claims) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "refresh_after", 13u)) {
            bit = SEEN_REFRESH;
            if (parse_required_integer(parser, &claims->refresh_after) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "offline_allowed", 15u)) {
            bit = SEEN_OFFLINE;
            if (parse_bool(parser, &claims->offline_allowed) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else if (span_equals_ascii(parser->data, key, "licence_expires_at", 18u)) {
            bit = SEEN_LICENCE_EXP;
            if (parse_optional_integer(parser, &claims->licence_expires_at, &claims->has_licence_expiry) != ORBIT_GRANT_STATUS_OK) return parser->status;
        } else {
            if (skip_value(parser, 1u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        }
        seen |= bit;
    }
    parser->member_count = base;
    if ((seen & REQUIRED_CLAIMS) != REQUIRED_CLAIMS) return fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    return finish_json(parser);
}

static int valid_slice(orbit_embedded_slice_t slice, int required) {
    if (required && (slice.data == NULL || slice.length == 0u)) return 0;
    if (slice.length > ORBIT_GRANT_MAX_JSON_BYTES || (slice.data == NULL && slice.length != 0u)) return 0;
    return valid_utf8_no_nul(slice.data, slice.length);
}

static int valid_expected(const orbit_grant_expected_t *expected) {
    if (expected == NULL) return 0;
    if (expected->has_licence_id > 1u || expected->has_fingerprint > 1u ||
        expected->has_fingerprint_provider > 1u || expected->has_credential_expiry > 1u ||
        expected->has_licence_expiry > 1u) return 0;
    if (!valid_slice(expected->issuer, 1) || !valid_slice(expected->application_id, 1) ||
        !valid_slice(expected->environment_id, 1) || !valid_slice(expected->activation_id, 1) ||
        !valid_slice(expected->installation_id, 1)) return 0;
    if (expected->has_licence_id) {
        if (!valid_slice(expected->licence_id, 1)) return 0;
    } else if (expected->licence_id.data != NULL || expected->licence_id.length != 0u) return 0;
    if (expected->has_fingerprint != expected->has_fingerprint_provider) return 0;
    if (expected->has_fingerprint) {
        if (!valid_slice(expected->fingerprint, 1) || !valid_slice(expected->fingerprint_provider, 1)) return 0;
    } else if (expected->fingerprint.data != NULL || expected->fingerprint.length != 0u ||
               expected->fingerprint_provider.data != NULL || expected->fingerprint_provider.length != 0u) return 0;
    if (expected->has_credential_expiry) {
        if (expected->credential_expires_at < 1) return 0;
    } else if (expected->credential_expires_at != 0) return 0;
    if (expected->has_licence_expiry) {
        if (expected->licence_expires_at < 1) return 0;
    } else if (expected->licence_expires_at != 0) return 0;
    if (expected->received_unix_seconds < 0 || expected->current_unix_seconds < expected->received_unix_seconds) return 0;
    return 1;
}

static int text_equals_bytes(const uint8_t *arena, const orbit_grant_claims_t *claims,
                             orbit_grant_text_t text,
                             const uint8_t *bytes, uint32_t length) {
    if ((uint32_t)text.offset + text.length > claims->arena_length || text.length != length) return 0;
    return bytes_equal(arena + text.offset, bytes, length);
}

static int audience_matches(const uint8_t *arena, const orbit_grant_claims_t *claims,
                            const orbit_grant_expected_t *expected) {
    const uint32_t prefix_length = 6u;
    uint64_t wanted = (uint64_t)prefix_length + expected->application_id.length + 1u + expected->environment_id.length;
    const uint8_t *actual;
    uint32_t at = 0u;
    if (wanted > UINT32_MAX || claims->audience.length != (uint32_t)wanted ||
        (uint32_t)claims->audience.offset + claims->audience.length > claims->arena_length) return 0;
    actual = arena + claims->audience.offset;
    if (!bytes_equal(actual, (const uint8_t *)"orbit:", prefix_length)) return 0;
    at += prefix_length;
    if (!bytes_equal(actual + at, expected->application_id.data, expected->application_id.length)) return 0;
    at += expected->application_id.length;
    if (actual[at++] != ':') return 0;
    return bytes_equal(actual + at, expected->environment_id.data, expected->environment_id.length);
}

static int64_t saturated_add(int64_t value, int64_t delta) {
    if (delta > 0 && value > INT64_MAX - delta) return INT64_MAX;
    if (delta < 0 && value < INT64_MIN - delta) return INT64_MIN;
    return value + delta;
}

static int claims_match_context(const uint8_t *arena, const orbit_grant_claims_t *claims,
                                const orbit_grant_expected_t *expected,
                                const char *binding, uint32_t binding_length) {
    const int64_t issued = claims->issued_at;
    const int64_t allowance = claims->offline_allowed ? 86400 : 300;
    const int persistent_offline = !expected->has_credential_expiry && claims->offline_allowed;
    const int64_t refresh_minimum = persistent_offline ? 675 : 45;
    const int64_t refresh_maximum = persistent_offline ? 1125 : 75;
    if (!text_equals_bytes(arena, claims, claims->issuer, expected->issuer.data, expected->issuer.length) ||
        !audience_matches(arena, claims, expected) || !text_equals_bytes(arena, claims, claims->application_id, expected->application_id.data, expected->application_id.length) ||
        !text_equals_bytes(arena, claims, claims->environment_id, expected->environment_id.data, expected->environment_id.length) ||
        !text_equals_bytes(arena, claims, claims->activation_id, expected->activation_id.data, expected->activation_id.length) ||
        !text_equals_bytes(arena, claims, claims->installation_id, expected->installation_id.data, expected->installation_id.length)) return 0;
    if (claims->subject.length == 0u || claims->subject.length > 128u || claims->token_id.length == 0u || claims->token_id.length > 128u) return 0;
    if (expected->has_licence_id && !text_equals_bytes(arena, claims, claims->subject, expected->licence_id.data, expected->licence_id.length)) return 0;
    if (expected->has_fingerprint) {
        if (binding_length != 4u || !bytes_equal((const uint8_t *)binding, (const uint8_t *)"hwid", 4u) ||
            !claims->has_fingerprint || !claims->has_fingerprint_provider ||
            !text_equals_bytes(arena, claims, claims->fingerprint, expected->fingerprint.data, expected->fingerprint.length) ||
            !text_equals_bytes(arena, claims, claims->fingerprint_provider, expected->fingerprint_provider.data, expected->fingerprint_provider.length)) return 0;
    } else if (binding_length != 4u || !bytes_equal((const uint8_t *)binding, (const uint8_t *)"none", 4u) ||
               claims->has_fingerprint || claims->has_fingerprint_provider) return 0;
    if (claims->has_licence_expiry != expected->has_licence_expiry ||
        (claims->has_licence_expiry && claims->licence_expires_at != expected->licence_expires_at)) return 0;
    if (issued < 0 || claims->not_before != issued ||
        saturated_add(issued, 30) < expected->received_unix_seconds ||
        saturated_add(issued, -30) > expected->received_unix_seconds ||
        claims->expires_at <= expected->received_unix_seconds ||
        claims->expires_at <= expected->current_unix_seconds ||
        claims->expires_at <= issued || claims->expires_at > saturated_add(issued, allowance)) return 0;
    if (expected->has_credential_expiry && claims->expires_at > expected->credential_expires_at) return 0;
    if (claims->has_licence_expiry && claims->expires_at > claims->licence_expires_at) return 0;
    if (claims->refresh_after <= issued || claims->refresh_after > claims->expires_at ||
        claims->refresh_after > saturated_add(issued, refresh_maximum) ||
        (claims->refresh_after < saturated_add(issued, refresh_minimum) && claims->refresh_after != claims->expires_at)) return 0;
    return 1;
}

static int32_t unescape_text(uint8_t *arena, orbit_grant_text_t *text) {
    json_span_t span = {text->offset, text->length};
    uint32_t length;
    int32_t status = decode_span(arena, span, arena + span.start, span.length, &length, 0);
    if (status == 0) text->length = (uint16_t)length;
    return status;
}

int32_t orbit_grant_verify(uint8_t *arena, uint32_t arena_length,
    const orbit_grant_pending_t *pending, const orbit_grant_keyset_t *keys,
    const orbit_grant_expected_t *expected, const orbit_grant_crypto_t *crypto,
    void *scratch, uint32_t scratch_length, orbit_grant_claims_t *claims) {
    uint32_t i, j;
    const void *objects[7] = {arena, pending, keys, expected, crypto, scratch, claims};
    uint32_t sizes[7] = {arena_length, sizeof(*pending), sizeof(*keys), sizeof(*expected),
        sizeof(*crypto), scratch_length, sizeof(*claims)};
    orbit_json_parser_t parser;
    char binding[16];
    uint32_t binding_length = 0u;
    int32_t status = ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    const orbit_grant_key_t *key = NULL;
    orbit_grant_text_t *texts[11];
    uint8_t payload_digest[32];
    /* Reject overlaps before any output write or input read. */
    for (i = 0u; i < 7u; ++i) for (j = i + 1u; j < 7u; ++j)
        if (orbit_overlap(objects[i], sizes[i], objects[j], sizes[j])) return status;
    if (expected != NULL) {
        const orbit_embedded_slice_t slices[8] = {expected->issuer, expected->application_id,
            expected->environment_id, expected->licence_id, expected->activation_id,
            expected->installation_id, expected->fingerprint, expected->fingerprint_provider};
        for (i = 0u; i < 8u; ++i) {
            if (orbit_overlap(slices[i].data, slices[i].length, arena, arena_length) ||
                orbit_overlap(slices[i].data, slices[i].length, scratch, scratch_length) ||
                orbit_overlap(slices[i].data, slices[i].length, claims, sizeof(*claims))) return status;
        }
    }
    if (claims != NULL) bytes_zero(claims, sizeof(*claims));
    if (arena == NULL || pending == NULL || keys == NULL || expected == NULL || claims == NULL ||
        scratch == NULL || scratch_length < ORBIT_GRANT_WORKSPACE_BYTES || !orbit_crypto_valid(crypto) ||
        pending->prepared != 1u || pending->payload_length == 0u || pending->payload_length > arena_length ||
        pending->payload_length > DECODED_SEGMENT_BYTES || pending->kid_length == 0u || pending->kid_length > 128u ||
        keys->count == 0u || keys->count > ORBIT_GRANT_MAX_KEYS || !valid_expected(expected)) return status;
    for (i = 0u; i < keys->count; ++i) {
        if (keys->keys[i].kid_length == 0u || keys->keys[i].kid_length > 128u) return status;
        if (keys->keys[i].kid_length == pending->kid_length &&
            bytes_equal(keys->keys[i].kid, pending->kid, pending->kid_length)) key = &keys->keys[i];
    }
    if (key == NULL) return ORBIT_GRANT_STATUS_UNKNOWN_KEY;
    if (crypto->sha256(crypto->context, arena, pending->payload_length, payload_digest) != 0)
        return ORBIT_GRANT_STATUS_CRYPTO_FAILURE;
    if (!bytes_equal(payload_digest, pending->payload_digest, sizeof(payload_digest)))
        return ORBIT_GRANT_STATUS_INVALID_GRANT;
    if (crypto->verify_es256(crypto->context, key->x, key->y, pending->digest, pending->signature) != 0)
        return ORBIT_GRANT_STATUS_CRYPTO_FAILURE;
    parser_init(&parser, arena, pending->payload_length, (uint8_t *)scratch);
    bytes_zero(binding, sizeof(binding));
    if (parse_claims_json(&parser, claims, binding, &binding_length) != 0) { status = parser.status; goto failed; }
    /* Duplicate comparisons are finished before any raw JSON span changes. */
    texts[0] = &claims->issuer; texts[1] = &claims->audience; texts[2] = &claims->subject;
    texts[3] = &claims->token_id; texts[4] = &claims->application_id; texts[5] = &claims->environment_id;
    texts[6] = &claims->activation_id; texts[7] = &claims->installation_id; texts[8] = &claims->binding_mode;
    texts[9] = &claims->fingerprint; texts[10] = &claims->fingerprint_provider;
    for (i = 0u; i < 11u; ++i) {
        status = unescape_text(arena, texts[i]);
        if (status != 0) goto failed;
    }
    for (i = 0u; i < claims->entitlement_count; ++i) {
        status = unescape_text(arena, &claims->entitlements[i].name);
        if (status != 0) goto failed;
    }
    claims->arena_length = pending->payload_length;
    if (!claims_match_context(arena, claims, expected, binding, binding_length)) {
        status = ORBIT_GRANT_STATUS_INVALID_GRANT; goto failed;
    }
    return 0;
failed:
    bytes_zero(claims, sizeof(*claims));
    return status;
}
