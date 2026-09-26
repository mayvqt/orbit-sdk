#ifndef ORBIT_JSON_INTERNAL_H
#define ORBIT_JSON_INTERNAL_H

#include "orbit_embedded.h"

#include <stdint.h>

#define ORBIT_JSON_DECODED_SEGMENT_BYTES 12288u
#define ORBIT_JSON_MAX_MEMBERS 512u
#define ORBIT_JSON_MEMBER_TABLE_BYTES (ORBIT_JSON_MAX_MEMBERS * 4u)
#define ORBIT_JSON_MAX_DEPTH 16u

typedef struct orbit_json_span {
    uint32_t start;
    uint32_t length;
} orbit_json_span_t;

typedef struct orbit_json_parser {
    const uint8_t *data;
    uint32_t length;
    uint32_t position;
    uint32_t member_count;
    uint8_t *member_table;
    int32_t status;
} orbit_json_parser_t;

void orbit_json_init(orbit_json_parser_t *parser, const uint8_t *data,
                     uint32_t length, uint8_t *member_table);
void orbit_json_skip_space(orbit_json_parser_t *parser);
int32_t orbit_json_fail(orbit_json_parser_t *parser, int32_t status);
int32_t orbit_json_scan_string(orbit_json_parser_t *parser, orbit_json_span_t *span);
int32_t orbit_json_consume_literal(orbit_json_parser_t *parser, const char *literal, uint32_t length);
int orbit_json_span_equals_ascii(const uint8_t *data, orbit_json_span_t span,
                                 const char *literal, uint32_t length);
int orbit_json_spans_equal(const uint8_t *data, orbit_json_span_t left,
                           orbit_json_span_t right);
int32_t orbit_json_decode_span(const uint8_t *data, orbit_json_span_t span,
                               uint8_t *output, uint32_t capacity,
                               uint32_t *output_length, int ascii_only);
int32_t orbit_json_number(orbit_json_parser_t *parser, int require_integer,
                          int64_t *integer_value);
int32_t orbit_json_object_open(orbit_json_parser_t *parser, uint32_t depth,
                               uint32_t *base, int *first);
int32_t orbit_json_object_next(orbit_json_parser_t *parser, uint32_t base,
                               int *first, orbit_json_span_t *key, int *present);
int32_t orbit_json_skip_value(orbit_json_parser_t *parser, uint32_t depth);
int32_t orbit_json_finish(orbit_json_parser_t *parser);
int orbit_json_valid_utf8_no_nul(const uint8_t *data, uint32_t length);

#endif
