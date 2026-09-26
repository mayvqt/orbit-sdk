#include "orbit_internal.h"
#include "orbit_json.h"

static int base64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z')
        return (int)(c - 'A');
    if (c >= 'a' && c <= 'z')
        return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9')
        return (int)(c - '0') + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}
int32_t orbit_base64url_decode(const uint8_t *input, uint32_t input_length, uint8_t *output,
                               uint32_t capacity, uint32_t *output_length) {
    uint32_t i, accumulator = 0u, bits = 0u, length = 0u;
    if (input_length == 0u || input_length % 4u == 1u)
        return ORBIT_GRANT_STATUS_INVALID_GRANT;
    for (i = 0; i < input_length; ++i) {
        int digit = base64_value(input[i]);
        if (digit < 0)
            return ORBIT_GRANT_STATUS_INVALID_GRANT;
        accumulator = (accumulator << 6u) | (uint32_t)digit;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            if (length >= capacity)
                return ORBIT_GRANT_STATUS_RESOURCE_LIMIT;
            output[length++] = (uint8_t)(accumulator >> bits);
            accumulator &= bits == 0u ? 0u : ((1u << bits) - 1u);
        }
    }
    if (bits != 0u && accumulator != 0u)
        return ORBIT_GRANT_STATUS_INVALID_GRANT;
    *output_length = length;
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_grant_prepare(uint8_t *token, uint32_t token_length,
                            const orbit_grant_crypto_t *crypto, orbit_grant_pending_t *pending) {
    uint32_t first = UINT32_MAX, second = UINT32_MAX, i, length, base, header_length;
    uint32_t seen = 0u;
    int32_t status = ORBIT_GRANT_STATUS_INVALID_GRANT;
    int start, present;
    orbit_json_parser_t parser;
    orbit_json_span_t key, value;
    uint8_t table[12];
    if (orbit_overlap(token, token_length, pending, sizeof(*pending)) ||
        orbit_overlap(token, token_length, crypto, sizeof(*crypto)) ||
        orbit_overlap(pending, sizeof(*pending), crypto, sizeof(*crypto)))
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    if (pending != NULL)
        orbit_zero(pending, sizeof(*pending));
    if (token == NULL || pending == NULL || !orbit_crypto_valid(crypto) || token_length == 0u)
        return ORBIT_GRANT_STATUS_INVALID_ARGUMENT;
    if (token_length > ORBIT_GRANT_MAX_TOKEN_BYTES)
        return ORBIT_GRANT_STATUS_RESOURCE_LIMIT;
    for (i = 0; i < token_length; ++i)
        if (token[i] == '.') {
            if (first == UINT32_MAX)
                first = i;
            else if (second == UINT32_MAX)
                second = i;
            else
                goto failed;
        }
    if (first == UINT32_MAX || second == UINT32_MAX || first == 0u || second <= first + 1u ||
        second + 1u >= token_length)
        goto failed;
    status = orbit_base64url_decode(token + second + 1u, token_length - second - 1u,
                                    pending->signature, 64u, &length);
    if (status != 0 || length != 64u) {
        status = ORBIT_GRANT_STATUS_INVALID_GRANT;
        goto failed;
    }
    if (crypto->sha256(crypto->context, token, second, pending->digest) != 0) {
        status = ORBIT_GRANT_STATUS_CRYPTO_FAILURE;
        goto failed;
    }
    status = orbit_base64url_decode(token, first, token, 8192u, &header_length);
    if (status != 0)
        goto failed;
    orbit_json_init(&parser, token, header_length, table);
    if (orbit_json_object_open(&parser, 0, &base, &start) != 0)
        goto invalid;
    for (;;) {
        uint32_t bit;
        orbit_json_skip_space(&parser);
        if (parser.member_count >= 3u &&
            (parser.position >= header_length || token[parser.position] != '}'))
            goto invalid;
        if (orbit_json_object_next(&parser, base, &start, &key, &present) != 0)
            goto invalid;
        if (!present)
            break;
        if (orbit_json_span_equals_ascii(token, key, "alg", 3))
            bit = 1u;
        else if (orbit_json_span_equals_ascii(token, key, "typ", 3))
            bit = 2u;
        else if (orbit_json_span_equals_ascii(token, key, "kid", 3))
            bit = 4u;
        else
            goto invalid;
        orbit_json_skip_space(&parser);
        if ((seen & bit) != 0u || orbit_json_scan_string(&parser, &value) != 0)
            goto invalid;
        seen |= bit;
        if (bit == 1u && !orbit_json_span_equals_ascii(token, value, "ES256", 5))
            goto invalid;
        if (bit == 2u && !orbit_json_span_equals_ascii(token, value, "orbit-access+jwt", 16))
            goto invalid;
        if (bit == 4u) {
            if (orbit_json_decode_span(token, value, pending->kid, 128u, &length, 1) != 0 ||
                length == 0u)
                goto invalid;
            pending->kid_length = (uint8_t)length;
        }
    }
    if (seen != 7u || orbit_json_finish(&parser) != 0)
        goto invalid;
    status = orbit_base64url_decode(token + first + 1u, second - first - 1u, token,
                                    ORBIT_JSON_DECODED_SEGMENT_BYTES, &length);
    if (status != 0)
        goto failed;
    pending->payload_length = (uint16_t)length;
    if (crypto->sha256(crypto->context, token, length, pending->payload_digest) != 0) {
        status = ORBIT_GRANT_STATUS_CRYPTO_FAILURE;
        goto failed;
    }
    pending->prepared = 1u;
    return 0;
invalid:
    status = ORBIT_GRANT_STATUS_INVALID_GRANT;
failed:
    orbit_zero(pending, sizeof(*pending));
    return status;
}
