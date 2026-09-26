#include "orbit_internal.h"

enum {
    ROOT,
    ROOT_NAME,
    ROOT_COLON,
    ARRAY,
    KEY_FIRST,
    FIELD_FIRST,
    FIELD_COLON,
    FIELD_VALUE,
    FIELD_NEXT,
    KEY_NEXT,
    ROOT_END,
    DONE,
    KEY_REQUIRED,
    FIELD_REQUIRED
};
enum { STRING_TOKEN = 256 };

static int32_t rejected(orbit_jwks_importer_t *p, orbit_grant_keyset_t *keys, int32_t status) {
    if (p->status == 0)
        p->status = status;
    orbit_zero(keys, sizeof(*keys));
    return p->status;
}
static int token_is(const orbit_jwks_importer_t *p, const char *value, uint32_t length) {
    return p->token_length == length && orbit_equal(p->token, value, length);
}
static int32_t symbol(orbit_jwks_importer_t *p, orbit_grant_keyset_t *keys,
                      const orbit_grant_crypto_t *crypto, uint32_t c) {
    uint32_t i, length = 0u;
    int32_t status;
    switch (p->state) {
    case ROOT:
        if (c == '{') {
            p->state = ROOT_NAME;
            return 0;
        }
        break;
    case ROOT_NAME:
        if (c == STRING_TOKEN && token_is(p, "keys", 4)) {
            p->state = ROOT_COLON;
            return 0;
        }
        break;
    case ROOT_COLON:
        if (c == ':') {
            p->state = ARRAY;
            return 0;
        }
        break;
    case ARRAY:
        if (c == '[') {
            p->state = KEY_FIRST;
            return 0;
        }
        break;
    case KEY_FIRST:
    case KEY_REQUIRED:
        if (c != '{')
            break;
        if (p->count >= ORBIT_GRANT_MAX_KEYS)
            return ORBIT_GRANT_STATUS_RESOURCE_LIMIT;
        orbit_zero(&p->candidate, sizeof(p->candidate));
        p->seen = 0u;
        p->state = FIELD_FIRST;
        return 0;
    case FIELD_FIRST:
    case FIELD_REQUIRED:
        if (c != STRING_TOKEN)
            break;
        if (token_is(p, "kty", 3))
            p->field = 0u;
        else if (token_is(p, "crv", 3))
            p->field = 1u;
        else if (token_is(p, "alg", 3))
            p->field = 2u;
        else if (token_is(p, "use", 3))
            p->field = 3u;
        else if (token_is(p, "kid", 3))
            p->field = 4u;
        else if (token_is(p, "x", 1))
            p->field = 5u;
        else if (token_is(p, "y", 1))
            p->field = 6u;
        else
            break;
        if ((p->seen & (1u << p->field)) != 0u)
            break;
        p->state = FIELD_COLON;
        return 0;
    case FIELD_COLON:
        if (c == ':') {
            p->state = FIELD_VALUE;
            return 0;
        }
        break;
    case FIELD_VALUE:
        if (c != STRING_TOKEN)
            break;
        if (p->field == 0u && !token_is(p, "EC", 2))
            break;
        if (p->field == 1u && !token_is(p, "P-256", 5))
            break;
        if (p->field == 2u && !token_is(p, "ES256", 5))
            break;
        if (p->field == 3u && !token_is(p, "sig", 3))
            break;
        if (p->field == 4u) {
            if (p->token_length == 0u)
                break;
            orbit_copy(p->candidate.kid, p->token, p->token_length);
            p->candidate.kid_length = (uint8_t)p->token_length;
        }
        if (p->field >= 5u) {
            if (p->token_length != 43u)
                break;
            status = orbit_base64url_decode(
                p->token, 43u, p->field == 5u ? p->candidate.x : p->candidate.y, 32u, &length);
            if (status != 0 || length != 32u)
                break;
        }
        p->seen = (uint8_t)(p->seen | (1u << p->field));
        p->state = FIELD_NEXT;
        return 0;
    case FIELD_NEXT:
        if (c == ',') {
            p->state = FIELD_REQUIRED;
            return 0;
        }
        if (c != '}' || p->seen != 127u)
            break;
        for (i = 0u; i < p->count; ++i)
            if (keys->keys[i].kid_length == p->candidate.kid_length &&
                orbit_equal(keys->keys[i].kid, p->candidate.kid, p->candidate.kid_length))
                return ORBIT_GRANT_STATUS_INVALID_GRANT;
        if (crypto->validate_p256(crypto->context, p->candidate.x, p->candidate.y) != 0)
            return ORBIT_GRANT_STATUS_CRYPTO_FAILURE;
        keys->keys[p->count++] = p->candidate;
        p->state = KEY_NEXT;
        return 0;
    case KEY_NEXT:
        if (c == ',') {
            p->state = KEY_REQUIRED;
            return 0;
        }
        if (c == ']') {
            p->state = ROOT_END;
            return 0;
        }
        break;
    case ROOT_END:
        if (c == '}') {
            p->state = DONE;
            return 0;
        }
        break;
    default:
        break;
    }
    return ORBIT_GRANT_STATUS_INVALID_GRANT;
}

int32_t orbit_jwks_begin(orbit_jwks_importer_t *p, orbit_grant_keyset_t *keys) {
    if (p == NULL || keys == NULL || orbit_overlap(p, sizeof(*p), keys, sizeof(*keys)))
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    orbit_zero(p, sizeof(*p));
    orbit_zero(keys, sizeof(*keys));
    return 0;
}
int32_t orbit_jwks_feed(orbit_jwks_importer_t *p, orbit_grant_keyset_t *keys,
                        const orbit_grant_crypto_t *crypto, const uint8_t *bytes, uint32_t length) {
    uint32_t i;
    if (p == NULL || keys == NULL || !orbit_crypto_valid(crypto) ||
        (bytes == NULL && length != 0u) || orbit_overlap(p, sizeof(*p), keys, sizeof(*keys)) ||
        orbit_overlap(p, sizeof(*p), bytes, length) ||
        orbit_overlap(keys, sizeof(*keys), bytes, length) ||
        orbit_overlap(p, sizeof(*p), crypto, sizeof(*crypto)) ||
        orbit_overlap(keys, sizeof(*keys), crypto, sizeof(*crypto)))
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    if (p->status != 0)
        return p->status;
    if (p->total > ORBIT_GRANT_MAX_JSON_BYTES || length > ORBIT_GRANT_MAX_JSON_BYTES - p->total)
        return rejected(p, keys, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    p->total += length;
    for (i = 0; i < length; ++i) {
        uint8_t c = bytes[i];
        int32_t status;
        if (p->lexical == 0u) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                continue;
            if (c == '"') {
                p->lexical = 1u;
                p->token_length = 0u;
                continue;
            }
            status = symbol(p, keys, crypto, c);
            if (status != 0)
                return rejected(p, keys, status);
            continue;
        }
        if (p->lexical == 3u) {
            uint8_t digit;
            if (c >= '0' && c <= '9')
                digit = (uint8_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = (uint8_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                digit = (uint8_t)(c - 'A' + 10);
            else
                return rejected(p, keys, ORBIT_GRANT_STATUS_INVALID_GRANT);
            p->unicode_value = (uint16_t)((p->unicode_value << 4u) | digit);
            if (--p->unicode_left != 0u)
                continue;
            if (p->unicode_value == 0u || p->unicode_value > 127u)
                return rejected(p, keys, ORBIT_GRANT_STATUS_INVALID_GRANT);
            c = (uint8_t)p->unicode_value;
            p->lexical = 1u;
        } else if (p->lexical == 2u) {
            p->lexical = 1u;
            if (c == 'u') {
                p->lexical = 3u;
                p->unicode_value = 0u;
                p->unicode_left = 4u;
                continue;
            }
            if (c == 'b')
                c = 8u;
            else if (c == 'f')
                c = 12u;
            else if (c == 'n')
                c = 10u;
            else if (c == 'r')
                c = 13u;
            else if (c == 't')
                c = 9u;
            else if (c != '"' && c != '\\' && c != '/')
                return rejected(p, keys, ORBIT_GRANT_STATUS_INVALID_GRANT);
        } else {
            if (c == '"') {
                p->lexical = 0u;
                status = symbol(p, keys, crypto, STRING_TOKEN);
                if (status != 0)
                    return rejected(p, keys, status);
                continue;
            }
            if (c == '\\') {
                p->lexical = 2u;
                continue;
            }
            if (c < 32u || c > 127u)
                return rejected(p, keys, ORBIT_GRANT_STATUS_INVALID_GRANT);
        }
        if (p->token_length >= 128u)
            return rejected(p, keys, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
        p->token[p->token_length++] = c;
    }
    return 0;
}
int32_t orbit_jwks_finish(orbit_jwks_importer_t *p, orbit_grant_keyset_t *keys) {
    if (p == NULL || keys == NULL || orbit_overlap(p, sizeof(*p), keys, sizeof(*keys)))
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    if (p->status != 0)
        return p->status;
    if (p->state != DONE || p->lexical != 0u || p->count == 0u || p->count > ORBIT_GRANT_MAX_KEYS)
        return rejected(p, keys, ORBIT_GRANT_STATUS_INVALID_GRANT);
    keys->count = p->count;
    return 0;
}
int32_t orbit_jwks_import(const uint8_t *bytes, uint32_t length, const orbit_grant_crypto_t *crypto,
                          orbit_grant_keyset_t *keys) {
    orbit_jwks_importer_t importer;
    int32_t status;
    if (keys == NULL || orbit_overlap(keys, sizeof(*keys), bytes, length) ||
        orbit_overlap(keys, sizeof(*keys), crypto, sizeof(*crypto)))
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    status = orbit_jwks_begin(&importer, keys);
    if (status == 0)
        status = orbit_jwks_feed(&importer, keys, crypto, bytes, length);
    if (status == 0)
        status = orbit_jwks_finish(&importer, keys);
    return status;
}
