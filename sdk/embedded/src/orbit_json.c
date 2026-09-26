#include "orbit_json.h"

#include <stddef.h>

#define MAX_JSON_MEMBERS ORBIT_JSON_MAX_MEMBERS
#define MEMBER_TABLE_BYTES ORBIT_JSON_MEMBER_TABLE_BYTES
#define MAX_JSON_DEPTH ORBIT_JSON_MAX_DEPTH

_Static_assert(MEMBER_TABLE_BYTES == ORBIT_GRANT_WORKSPACE_BYTES,
               "JSON workspace must match public size");

typedef orbit_json_span_t json_span_t;
typedef orbit_json_parser_t parser_t;

static void bytes_copy(uint8_t *target, const uint8_t *source, uint32_t length) {
    uint32_t i;
    for (i = 0; i < length; ++i) target[i] = source[i];
}

void orbit_json_skip_space(parser_t *parser) {
    while (parser->position < parser->length) {
        const uint8_t c = parser->data[parser->position];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++parser->position;
    }
}

int32_t orbit_json_fail(parser_t *parser, int32_t status) {
    if (parser->status == ORBIT_GRANT_STATUS_OK) parser->status = status;
    return parser->status;
}

static int read_utf8_codepoint(const uint8_t *data, uint32_t length,
                               uint32_t *position, uint32_t *codepoint) {
    uint8_t first;
    uint32_t count, value, i;
    if (*position >= length) return 0;
    first = data[(*position)++];
    if (first <= 0x7fu) {
        *codepoint = first;
        return 1;
    }
    if ((first & 0xe0u) == 0xc0u) {
        count = 2u;
        value = (uint32_t)(first & 0x1fu);
        if (value < 2u) return 0;
    } else if ((first & 0xf0u) == 0xe0u) {
        count = 3u;
        value = (uint32_t)(first & 0x0fu);
    } else if ((first & 0xf8u) == 0xf0u) {
        count = 4u;
        value = (uint32_t)(first & 0x07u);
        if (value > 4u) return 0;
    } else {
        return 0;
    }
    if ((uint64_t)*position + (uint64_t)(count - 1u) > length) return 0;
    for (i = 1u; i < count; ++i) {
        const uint8_t next = data[(*position)++];
        if ((next & 0xc0u) != 0x80u) return 0;
        value = (value << 6u) | (uint32_t)(next & 0x3fu);
    }
    if ((count == 3u && value < 0x800u) ||
        (count == 4u && value < 0x10000u) || value > 0x10ffffu ||
        (value >= 0xd800u && value <= 0xdfffu)) return 0;
    *codepoint = value;
    return 1;
}

static int hex_value(uint8_t c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
    return -1;
}

static int read_hex4(const uint8_t *data, uint32_t length,
                     uint32_t *position, uint32_t *value) {
    uint32_t i, result = 0;
    if ((uint64_t)*position + 4u > length) return 0;
    for (i = 0; i < 4u; ++i) {
        const int digit = hex_value(data[(*position)++]);
        if (digit < 0) return 0;
        result = (result << 4u) | (uint32_t)digit;
    }
    *value = result;
    return 1;
}

static int read_json_codepoint(const uint8_t *data, uint32_t length,
                               uint32_t *position, uint32_t *codepoint) {
    uint8_t c;
    uint32_t value;
    if (*position >= length) return 0;
    c = data[(*position)++];
    if (c != '\\') {
        if (c < 0x20u) return 0;
        if (c < 0x80u) {
            *codepoint = c;
            return c != 0u;
        }
        --*position;
        if (!read_utf8_codepoint(data, length, position, &value) || value == 0u) return 0;
        *codepoint = value;
        return 1;
    }
    if (*position >= length) return 0;
    c = data[(*position)++];
    switch (c) {
        case '"': *codepoint = '"'; return 1;
        case '\\': *codepoint = '\\'; return 1;
        case '/': *codepoint = '/'; return 1;
        case 'b': *codepoint = 8u; return 1;
        case 'f': *codepoint = 12u; return 1;
        case 'n': *codepoint = 10u; return 1;
        case 'r': *codepoint = 13u; return 1;
        case 't': *codepoint = 9u; return 1;
        case 'u':
            if (!read_hex4(data, length, position, &value)) return 0;
            if (value >= 0xd800u && value <= 0xdbffu) {
                uint32_t low;
                if ((uint64_t)*position + 2u > length || data[*position] != '\\' || data[*position + 1u] != 'u') return 0;
                *position += 2u;
                if (!read_hex4(data, length, position, &low) || low < 0xdc00u || low > 0xdfffu) return 0;
                value = 0x10000u + ((value - 0xd800u) << 10u) + (low - 0xdc00u);
            } else if (value >= 0xdc00u && value <= 0xdfffu) {
                return 0;
            }
            if (value == 0u) return 0;
            *codepoint = value;
            return 1;
        default: return 0;
    }
}

int32_t orbit_json_scan_string(parser_t *parser, json_span_t *span) {
    uint32_t start, position;
    if (parser->position >= parser->length || parser->data[parser->position] != '"') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    start = ++parser->position;
    position = start;
    while (position < parser->length) {
        uint8_t c = parser->data[position];
        uint32_t cp;
        if (c == '"') {
            span->start = start;
            span->length = position - start;
            parser->position = position + 1u;
            return ORBIT_GRANT_STATUS_OK;
        }
        if (!read_json_codepoint(parser->data, parser->length, &position, &cp)) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    }
    return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
}

static int next_span_codepoint(const uint8_t *data, json_span_t span,
                               uint32_t *relative, uint32_t *codepoint) {
    uint32_t absolute = span.start + *relative;
    if (!read_json_codepoint(data, span.start + span.length, &absolute, codepoint)) return 0;
    *relative = absolute - span.start;
    return 1;
}

int orbit_json_span_equals_ascii(const uint8_t *data, json_span_t span,
                             const char *literal, uint32_t length) {
    uint32_t relative = 0, i = 0, cp;
    while (relative < span.length) {
        if (i >= length || !next_span_codepoint(data, span, &relative, &cp) || cp != (uint8_t)literal[i]) return 0;
        ++i;
    }
    return i == length;
}

int orbit_json_spans_equal(const uint8_t *data, json_span_t left, json_span_t right) {
    uint32_t li = 0, ri = 0, lc, rc;
    while (li < left.length && ri < right.length) {
        if (!next_span_codepoint(data, left, &li, &lc) || !next_span_codepoint(data, right, &ri, &rc) || lc != rc) return 0;
    }
    return li == left.length && ri == right.length;
}

int32_t orbit_json_decode_span(const uint8_t *data, json_span_t span,
                           uint8_t *output, uint32_t capacity,
                           uint32_t *output_length, int ascii_only) {
    uint32_t relative = 0, length = 0, cp;
    while (relative < span.length) {
        uint8_t encoded[4];
        uint32_t count;
        if (!next_span_codepoint(data, span, &relative, &cp)) return ORBIT_GRANT_STATUS_INVALID_GRANT;
        if (ascii_only && cp > 0x7fu) return ORBIT_GRANT_STATUS_INVALID_GRANT;
        if (cp <= 0x7fu) {
            encoded[0] = (uint8_t)cp; count = 1u;
        } else if (cp <= 0x7ffu) {
            encoded[0] = (uint8_t)(0xc0u | (cp >> 6u));
            encoded[1] = (uint8_t)(0x80u | (cp & 0x3fu)); count = 2u;
        } else if (cp <= 0xffffu) {
            encoded[0] = (uint8_t)(0xe0u | (cp >> 12u));
            encoded[1] = (uint8_t)(0x80u | ((cp >> 6u) & 0x3fu));
            encoded[2] = (uint8_t)(0x80u | (cp & 0x3fu)); count = 3u;
        } else {
            encoded[0] = (uint8_t)(0xf0u | (cp >> 18u));
            encoded[1] = (uint8_t)(0x80u | ((cp >> 12u) & 0x3fu));
            encoded[2] = (uint8_t)(0x80u | ((cp >> 6u) & 0x3fu));
            encoded[3] = (uint8_t)(0x80u | (cp & 0x3fu)); count = 4u;
        }
        if ((uint64_t)length + count > capacity) return ORBIT_GRANT_STATUS_RESOURCE_LIMIT;
        bytes_copy(output + length, encoded, count);
        length += count;
    }
    *output_length = length;
    return ORBIT_GRANT_STATUS_OK;
}


static void store_u16(uint8_t *at, uint16_t value) {
    at[0] = (uint8_t)value;
    at[1] = (uint8_t)(value >> 8u);
}

static uint16_t load_u16(const uint8_t *at) {
    return (uint16_t)((uint16_t)at[0] | ((uint16_t)at[1] << 8u));
}

static int32_t add_object_key(parser_t *parser, uint32_t base, json_span_t key) {
    uint32_t i;
    for (i = base; i < parser->member_count; ++i) {
        const uint8_t *entry = parser->member_table + i * 4u;
        const json_span_t previous = {load_u16(entry), load_u16(entry + 2u)};
        if (orbit_json_spans_equal(parser->data, previous, key)) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    }
    if (parser->member_count >= MAX_JSON_MEMBERS) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    if (key.start > UINT16_MAX || key.length > UINT16_MAX) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    store_u16(parser->member_table + parser->member_count * 4u, (uint16_t)key.start);
    store_u16(parser->member_table + parser->member_count * 4u + 2u, (uint16_t)key.length);
    ++parser->member_count;
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_json_number(parser_t *parser, int require_integer, int64_t *integer_value) {
    static const char overflow_rounding_boundary[] =
        "179769313486231580793728971405303415079934132710037826936173778980444968292764750946649017977587207096330286416692887910946555547851940402630657488671505820681908902000708383676273854845817711531764475730270069855571366959622842914819860834936475292719074168444365510704342711559699508093042880177904174497792";
    const uint32_t start = parser->position;
    const uint8_t *data = parser->data;
    uint32_t i = start, digits_before = 0u, mantissa_end, first_nonzero = UINT32_MAX;
    uint32_t digit_position = 0u;
    int negative = 0, has_fraction = 0, has_exponent = 0, exponent_negative = 0;
    int64_t explicit_exponent = 0;
    uint64_t magnitude = 0u;
    if (i < parser->length && data[i] == '-') { negative = 1; ++i; }
    if (i >= parser->length) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    if (data[i] == '0') {
        ++i;
        digits_before = 1u;
        if (i < parser->length && data[i] >= '0' && data[i] <= '9') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    } else if (data[i] >= '1' && data[i] <= '9') {
        while (i < parser->length && data[i] >= '0' && data[i] <= '9') { ++i; ++digits_before; }
    } else {
        return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    }
    if (i < parser->length && data[i] == '.') {
        has_fraction = 1;
        ++i;
        if (i >= parser->length || data[i] < '0' || data[i] > '9') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        while (i < parser->length && data[i] >= '0' && data[i] <= '9') ++i;
    }
    mantissa_end = i;
    if (i < parser->length && (data[i] == 'e' || data[i] == 'E')) {
        has_exponent = 1;
        ++i;
        if (i < parser->length && (data[i] == '+' || data[i] == '-')) { exponent_negative = data[i] == '-'; ++i; }
        if (i >= parser->length || data[i] < '0' || data[i] > '9') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        while (i < parser->length && data[i] >= '0' && data[i] <= '9') {
            const uint32_t digit = (uint32_t)(data[i++] - '0');
            if (explicit_exponent < 1000000) explicit_exponent = explicit_exponent * 10 + digit;
            if (explicit_exponent > 1000000) explicit_exponent = 1000000;
        }
        if (exponent_negative) explicit_exponent = -explicit_exponent;
    }
    parser->position = i;
    if (require_integer && (has_fraction || has_exponent)) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    if (require_integer) {
        uint32_t j = start + (negative ? 1u : 0u);
        const uint64_t limit = negative ? ((uint64_t)INT64_MAX + 1u) : (uint64_t)INT64_MAX;
        while (j < i) {
            const uint8_t c = data[j++];
            if (c < '0' || c > '9') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
            if (magnitude > limit / 10u || magnitude * 10u > limit - (uint64_t)(c - '0')) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
            magnitude = magnitude * 10u + (uint64_t)(c - '0');
        }
        if (negative) {
            if (magnitude == (uint64_t)INT64_MAX + 1u) *integer_value = INT64_MIN;
            else *integer_value = -(int64_t)magnitude;
        } else {
            *integer_value = (int64_t)magnitude;
        }
        return ORBIT_GRANT_STATUS_OK;
    }
    {
        uint32_t m = start + (negative ? 1u : 0u);
        while (m < mantissa_end) {
            const uint8_t c = data[m++];
            if (c == '.') continue;
            if (first_nonzero == UINT32_MAX && c != '0') first_nonzero = digit_position;
            ++digit_position;
        }
    }
    if (first_nonzero != UINT32_MAX) {
        const int64_t order = (int64_t)digits_before - (int64_t)first_nonzero - 1 + explicit_exponent;
        if (order > 308) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        if (order == 308) {
            const uint32_t boundary_length = (uint32_t)(sizeof(overflow_rounding_boundary) - 1u);
            uint32_t m = start + (negative ? 1u : 0u), significant_index = 0u;
            int seen_nonzero = 0, comparison = 0;
            while (m < mantissa_end) {
                const uint8_t c = data[m++];
                if (c == '.') continue;
                if (!seen_nonzero && c == '0') continue;
                seen_nonzero = 1;
                if (significant_index < boundary_length) {
                    const uint8_t threshold = (uint8_t)overflow_rounding_boundary[significant_index];
                    if (c < threshold) { comparison = -1; break; }
                    if (c > threshold) { comparison = 1; break; }
                } else if (c != '0') {
                    comparison = 1;
                    break;
                }
                ++significant_index;
            }
            if (comparison == 0 && significant_index < boundary_length) comparison = -1;
            if (comparison >= 0) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        }
    }
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_json_object_open(parser_t *parser, uint32_t depth,
                           uint32_t *base, int *first) {
    if (depth >= MAX_JSON_DEPTH) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    orbit_json_skip_space(parser);
    if (parser->position >= parser->length || parser->data[parser->position] != '{') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    ++parser->position;
    *base = parser->member_count;
    *first = 1;
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_json_object_next(parser_t *parser, uint32_t base, int *first,
                           json_span_t *key, int *present) {
    orbit_json_skip_space(parser);
    if (parser->position < parser->length && parser->data[parser->position] == '}') {
        ++parser->position;
        *present = 0;
        return ORBIT_GRANT_STATUS_OK;
    }
    if (!*first) {
        if (parser->position >= parser->length || parser->data[parser->position] != ',') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        ++parser->position;
        orbit_json_skip_space(parser);
        if (parser->position < parser->length && parser->data[parser->position] == '}') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    }
    if (orbit_json_scan_string(parser, key) != ORBIT_GRANT_STATUS_OK) return parser->status;
    if (add_object_key(parser, base, *key) != ORBIT_GRANT_STATUS_OK) return parser->status;
    orbit_json_skip_space(parser);
    if (parser->position >= parser->length || parser->data[parser->position] != ':') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    ++parser->position;
    *first = 0;
    *present = 1;
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_json_skip_value(parser_t *parser, uint32_t depth);

static int32_t skip_object(parser_t *parser, uint32_t depth) {
    uint32_t base;
    int first, present;
    json_span_t key;
    if (orbit_json_object_open(parser, depth, &base, &first) != ORBIT_GRANT_STATUS_OK) return parser->status;
    for (;;) {
        if (orbit_json_object_next(parser, base, &first, &key, &present) != ORBIT_GRANT_STATUS_OK) return parser->status;
        if (!present) break;
        if (orbit_json_skip_value(parser, depth + 1u) != ORBIT_GRANT_STATUS_OK) return parser->status;
    }
    parser->member_count = base;
    return ORBIT_GRANT_STATUS_OK;
}

static int32_t skip_array(parser_t *parser, uint32_t depth) {
    if (depth >= MAX_JSON_DEPTH) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_RESOURCE_LIMIT);
    ++parser->position;
    orbit_json_skip_space(parser);
    if (parser->position < parser->length && parser->data[parser->position] == ']') {
        ++parser->position;
        return ORBIT_GRANT_STATUS_OK;
    }
    for (;;) {
        if (orbit_json_skip_value(parser, depth + 1u) != ORBIT_GRANT_STATUS_OK) return parser->status;
        orbit_json_skip_space(parser);
        if (parser->position >= parser->length) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        if (parser->data[parser->position] == ']') {
            ++parser->position;
            return ORBIT_GRANT_STATUS_OK;
        }
        if (parser->data[parser->position] != ',') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
        ++parser->position;
        orbit_json_skip_space(parser);
        if (parser->position < parser->length && parser->data[parser->position] == ']') return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    }
}

int32_t orbit_json_consume_literal(parser_t *parser, const char *literal, uint32_t length) {
    uint32_t i;
    if ((uint64_t)parser->position + length > parser->length) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    for (i = 0; i < length; ++i) if (parser->data[parser->position + i] != (uint8_t)literal[i]) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    parser->position += length;
    return ORBIT_GRANT_STATUS_OK;
}

int32_t orbit_json_skip_value(parser_t *parser, uint32_t depth) {
    uint8_t c;
    json_span_t ignored;
    orbit_json_skip_space(parser);
    if (parser->position >= parser->length) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    c = parser->data[parser->position];
    if (c == '{') return skip_object(parser, depth);
    if (c == '[') return skip_array(parser, depth);
    if (c == '"') return orbit_json_scan_string(parser, &ignored);
    if (c == 't') return orbit_json_consume_literal(parser, "true", 4u);
    if (c == 'f') return orbit_json_consume_literal(parser, "false", 5u);
    if (c == 'n') return orbit_json_consume_literal(parser, "null", 4u);
    if (c == '-' || (c >= '0' && c <= '9')) return orbit_json_number(parser, 0, NULL);
    return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
}

int32_t orbit_json_finish(parser_t *parser) {
    orbit_json_skip_space(parser);
    if (parser->position != parser->length) return orbit_json_fail(parser, ORBIT_GRANT_STATUS_INVALID_GRANT);
    return ORBIT_GRANT_STATUS_OK;
}


void orbit_json_init(parser_t *parser, const uint8_t *data, uint32_t length,
                        uint8_t *member_table) {
    parser->data = data;
    parser->length = length;
    parser->position = 0u;
    parser->member_count = 0u;
    parser->member_table = member_table;
    parser->status = ORBIT_GRANT_STATUS_OK;
}

int orbit_json_valid_utf8_no_nul(const uint8_t *data, uint32_t length) {
    uint32_t position = 0u, codepoint;
    if (data == NULL && length != 0u) return 0;
    while (position < length) {
        if (!read_utf8_codepoint(data, length, &position, &codepoint) || codepoint == 0u) return 0;
    }
    return 1;
}
