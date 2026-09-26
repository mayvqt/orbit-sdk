#include "orbit_client_internal.h"

void orbit_write(orbit_writer_t *w, const void *bytes, uint32_t length) {
    if (w->status != 0)
        return;
    if (length > w->capacity - w->length) {
        w->status = ORBIT_CLIENT_RESOURCE_LIMIT;
        return;
    }
    orbit_copy(w->bytes + w->length, bytes, length);
    w->length += length;
}
void orbit_write_string(orbit_writer_t *w, orbit_embedded_slice_t value) {
    static const uint8_t hex[] = "0123456789abcdef";
    uint32_t i;
    ORBIT_LITERAL(w, "\"");
    for (i = 0u; i < value.length; ++i) {
        uint8_t c = value.data[i];
        if (c == '"' || c == '\\')
            ORBIT_LITERAL(w, "\\");
        if (c < 32u) {
            uint8_t escaped[6] = {'\\', 'u', '0', '0', hex[c >> 4u], hex[c & 15u]};
            orbit_write(w, escaped, sizeof(escaped));
        } else
            orbit_write(w, &c, 1u);
    }
    ORBIT_LITERAL(w, "\"");
}
int orbit_client_opaque(orbit_embedded_slice_t value, uint32_t minimum, uint32_t maximum) {
    uint32_t i;
    if (value.length < minimum || value.length > maximum ||
        (value.data == NULL && value.length != 0u))
        return 0;
    for (i = 0u; i < value.length; ++i) {
        uint8_t c = value.data[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            return 0;
    }
    return 1;
}
static void write64(orbit_writer_t *w, uint64_t value) {
    uint8_t bytes[8];
    uint32_t i;
    for (i = 0u; i < 8u; ++i)
        bytes[i] = (uint8_t)(value >> (i * 8u));
    orbit_write(w, bytes, sizeof(bytes));
}
static uint64_t read64(const uint8_t *bytes) {
    uint64_t n = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i)
        n |= (uint64_t)bytes[i] << (i * 8u);
    return n;
}
int32_t orbit_record_encode(const orbit_record_t *r, uint8_t *bytes, uint32_t *length) {
    orbit_writer_t w = {bytes, 0u, ORBIT_CLIENT_RECORD_BYTES, 0};
    uint8_t lengths[7] = {r->installation_length,
                          r->activation_length,
                          r->licence_length,
                          r->pending_kind,
                          r->has_expiry,
                          (uint8_t)r->credential_length,
                          (uint8_t)(r->credential_length >> 8u)};
    ORBIT_LITERAL(&w, "ORBITMC1");
    write64(&w, r->generation);
    write64(&w, (uint64_t)r->credential_expiry);
    write64(&w, (uint64_t)r->pending_created);
    orbit_write(&w, r->scope, 32u);
    orbit_write(&w, r->pending_digest, 32u);
    orbit_write(&w, lengths, sizeof(lengths));
    orbit_write(&w, r->installation, r->installation_length);
    orbit_write(&w, r->activation, r->activation_length);
    orbit_write(&w, r->licence, r->licence_length);
    orbit_write(&w, r->credential, r->credential_length);
    if (r->pending_kind != 0u)
        orbit_write(&w, r->pending_id, 32u);
    *length = w.length;
    return w.status;
}
int32_t orbit_record_decode(const uint8_t *b, uint32_t length, orbit_record_t *r) {
    uint32_t at = 103u, wanted;
    orbit_zero(r, sizeof(*r));
    if (length < 103u || length > ORBIT_CLIENT_RECORD_BYTES || !orbit_equal(b, "ORBITMC1", 8u))
        return ORBIT_CLIENT_STORAGE;
    r->generation = read64(b + 8u);
    if (r->generation == 0u || r->generation == UINT64_MAX || read64(b + 16u) > INT64_MAX ||
        read64(b + 24u) > INT64_MAX)
        goto invalid;
    r->credential_expiry = (int64_t)read64(b + 16u);
    r->pending_created = (int64_t)read64(b + 24u);
    orbit_copy(r->scope, b + 32u, 32u);
    orbit_copy(r->pending_digest, b + 64u, 32u);
    r->installation_length = b[96];
    r->activation_length = b[97];
    r->licence_length = b[98];
    r->pending_kind = b[99];
    r->has_expiry = b[100];
    r->credential_length = (uint16_t)(b[101] | ((uint16_t)b[102] << 8u));
    if (r->installation_length < 16u || r->installation_length > 128u ||
        r->activation_length > 128u || r->licence_length > 128u || r->credential_length > 256u ||
        r->pending_kind > 2u || r->has_expiry > 1u)
        goto invalid;
    wanted = at + r->installation_length + r->activation_length + r->licence_length +
             r->credential_length + (r->pending_kind ? 32u : 0u);
    if (wanted != length)
        goto invalid;
    orbit_copy(r->installation, b + at, r->installation_length);
    at += r->installation_length;
    orbit_copy(r->activation, b + at, r->activation_length);
    at += r->activation_length;
    orbit_copy(r->licence, b + at, r->licence_length);
    at += r->licence_length;
    orbit_copy(r->credential, b + at, r->credential_length);
    at += r->credential_length;
    if (r->pending_kind)
        orbit_copy(r->pending_id, b + at, 32u);
    if (!orbit_client_opaque((orbit_embedded_slice_t){r->installation, r->installation_length}, 16u,
                             128u) ||
        !orbit_client_opaque((orbit_embedded_slice_t){r->activation, r->activation_length}, 0u,
                             128u) ||
        !orbit_client_opaque((orbit_embedded_slice_t){r->licence, r->licence_length}, 0u, 128u) ||
        !orbit_client_opaque((orbit_embedded_slice_t){r->credential, r->credential_length}, 0u,
                             256u) ||
        (r->pending_kind &&
         !orbit_client_opaque((orbit_embedded_slice_t){r->pending_id, 32u}, 32u, 32u)))
        goto invalid;
    if ((r->credential_length != 0u) != (r->activation_length != 0u && r->licence_length != 0u) ||
        (r->has_expiry ? r->credential_expiry < 1 : r->credential_expiry != 0) ||
        (!r->credential_length && r->has_expiry) ||
        (r->pending_kind == 2u && !r->credential_length))
        goto invalid;
    return 0;
invalid:
    orbit_zero(r, sizeof(*r));
    return ORBIT_CLIENT_STORAGE;
}

static int timestamp(const uint8_t *data, orbit_json_span_t span, int64_t *out) {
    uint8_t text[20];
    uint32_t n, i;
    int year, month, day, hour, minute, second, leap;
    int adjusted, era, yoe, doy, doe;
    static const uint8_t days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (orbit_json_decode_span(data, span, text, sizeof(text), &n, 1) != 0 || n != 20u)
        return 0;
    for (i = 0u; i < 20u; ++i) {
        if (i == 4u || i == 7u) {
            if (text[i] != '-')
                return 0;
        } else if (i == 10u) {
            if (text[i] != 'T')
                return 0;
        } else if (i == 13u || i == 16u) {
            if (text[i] != ':')
                return 0;
        } else if (i == 19u) {
            if (text[i] != 'Z')
                return 0;
        } else if (text[i] < '0' || text[i] > '9')
            return 0;
    }
    year = (text[0] - '0') * 1000 + (text[1] - '0') * 100 + (text[2] - '0') * 10 + text[3] - '0';
    month = (text[5] - '0') * 10 + text[6] - '0';
    day = (text[8] - '0') * 10 + text[9] - '0';
    hour = (text[11] - '0') * 10 + text[12] - '0';
    minute = (text[14] - '0') * 10 + text[15] - '0';
    second = (text[17] - '0') * 10 + text[18] - '0';
    leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (year < 1970 || month < 1 || month > 12 || day < 1 ||
        day > days[month - 1] + (month == 2 && leap) || hour > 23 || minute > 59 || second > 59)
        return 0;
    adjusted = year - (month <= 2);
    era = adjusted / 400;
    yoe = adjusted - era * 400;
    doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    *out = ((int64_t)era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second;
    return 1;
}
int32_t orbit_reply_parse(const uint8_t *bytes, uint32_t length, uint8_t *scratch,
                          orbit_reply_t *r) {
    orbit_json_parser_t p;
    orbit_json_span_t key, value;
    uint32_t base, seen = 0u, bit;
    int first, present, is_null;
    orbit_zero(r, sizeof(*r));
    orbit_json_init(&p, bytes, length, scratch);
    if (orbit_json_object_open(&p, 0u, &base, &first) != 0)
        return ORBIT_CLIENT_UNTRUSTED;
    for (;;) {
        if (orbit_json_object_next(&p, base, &first, &key, &present) != 0)
            return ORBIT_CLIENT_UNTRUSTED;
        if (!present)
            break;
        if (orbit_json_span_equals_ascii(bytes, key, "activation_id", 13))
            bit = 1u;
        else if (orbit_json_span_equals_ascii(bytes, key, "installation_id", 15))
            bit = 2u;
        else if (orbit_json_span_equals_ascii(bytes, key, "credential", 10))
            bit = 4u;
        else if (orbit_json_span_equals_ascii(bytes, key, "grant", 5))
            bit = 8u;
        else if (orbit_json_span_equals_ascii(bytes, key, "server_time", 11))
            bit = 16u;
        else if (orbit_json_span_equals_ascii(bytes, key, "binding_mode", 12))
            bit = 32u;
        else if (orbit_json_span_equals_ascii(bytes, key, "fingerprint_provider", 20))
            bit = 64u;
        else if (orbit_json_span_equals_ascii(bytes, key, "credential_expires_at", 21))
            bit = 128u;
        else if (orbit_json_span_equals_ascii(bytes, key, "licence_expires_at", 18))
            bit = 256u;
        else if (orbit_json_span_equals_ascii(bytes, key, "secret_replay_expired", 21))
            bit = 512u;
        else {
            if (orbit_json_skip_value(&p, 1u) != 0)
                return ORBIT_CLIENT_UNTRUSTED;
            continue;
        }
        if ((seen & bit) != 0u)
            return ORBIT_CLIENT_UNTRUSTED;
        seen |= bit;
        orbit_json_skip_space(&p);
        if (bit == 512u) {
            if (p.position < p.length && bytes[p.position] == 't') {
                if (orbit_json_consume_literal(&p, "true", 4) != 0)
                    return ORBIT_CLIENT_UNTRUSTED;
                r->replay_expired = 1u;
            } else if (orbit_json_consume_literal(&p, "false", 5) != 0)
                return ORBIT_CLIENT_UNTRUSTED;
            continue;
        }
        is_null = p.position < p.length && bytes[p.position] == 'n';
        if (is_null) {
            if ((bit != 4u && bit != 8u && bit != 64u && bit != 128u && bit != 256u) ||
                orbit_json_consume_literal(&p, "null", 4) != 0)
                return ORBIT_CLIENT_UNTRUSTED;
            continue;
        }
        if (orbit_json_scan_string(&p, &value) != 0)
            return ORBIT_CLIENT_UNTRUSTED;
        if (bit == 1u)
            r->activation = value;
        else if (bit == 2u)
            r->installation = value;
        else if (bit == 4u) {
            r->credential = value;
            r->has_credential = 1u;
        } else if (bit == 8u)
            r->grant = value;
        else if (bit == 32u)
            r->binding = value;
        else if (bit == 64u) {
            r->provider = value;
            r->has_provider = 1u;
        } else if (bit == 16u) {
            if (!timestamp(bytes, value, &r->server_time))
                return ORBIT_CLIENT_UNTRUSTED;
        } else if (bit == 128u) {
            if (!timestamp(bytes, value, &r->credential_expiry))
                return ORBIT_CLIENT_UNTRUSTED;
            r->has_credential_expiry = 1u;
        } else if (bit == 256u) {
            if (!timestamp(bytes, value, &r->licence_expiry))
                return ORBIT_CLIENT_UNTRUSTED;
            r->has_licence_expiry = 1u;
        }
    }
    if ((seen & (1u | 2u | 16u | 32u | 128u | 512u)) != (1u | 2u | 16u | 32u | 128u | 512u) ||
        orbit_json_finish(&p) != 0)
        return ORBIT_CLIENT_UNTRUSTED;
    return 0;
}
