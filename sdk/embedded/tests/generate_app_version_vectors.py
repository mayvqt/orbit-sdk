"""Generate allocation-free C fixtures from the shared app-version and
credential-retention corpora."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--retention", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
corpus = json.loads(args.source.read_text(encoding="utf-8"))
if corpus.get("format_version") != 1:
    raise SystemExit("unsupported app-version vector format")
retention = json.loads(args.retention.read_text(encoding="utf-8"))
if retention.get("format_version") != 1:
    raise SystemExit("unsupported credential-retention vector format")


def c_bytes(value):
    """A C string literal and its byte length, with octal escapes for non-ASCII."""
    data = value.encode("utf-8")
    text = "".join(
        chr(b) if 32 <= b < 127 and chr(b) not in '"\\?' else f"\\{b:03o}" for b in data
    )
    return f'"{text}", {len(data)}u'


lines = [
    "/* Generated from contracts/sdk/app-versions.json and credential-retention.json; do not edit. */",
    "#ifndef ORBIT_GENERATED_APP_VERSION_VECTORS_H",
    "#define ORBIT_GENERATED_APP_VERSION_VECTORS_H",
    "#include <stdint.h>",
    "typedef struct generated_app_version_vector {",
    "  const char *value;",
    "  uint32_t length;",
    "  uint8_t valid;",
    "} generated_app_version_vector_t;",
    "typedef struct generated_client_header_vector {",
    "  const char *language;",
    "  uint32_t language_length;",
    "  const char *sdk_version;",
    "  uint32_t sdk_version_length;",
    "  const char *platform;",
    "  uint32_t platform_length;",
    "  const char *header; /* NULL when invalid */",
    "} generated_client_header_vector_t;",
    "typedef struct generated_update_vector {",
    "  const char *name;",
    "  const char *json; /* update_available member value; NULL when absent */",
    "  const char *version; /* NULL when none or invalid */",
    "  uint8_t valid;",
    "} generated_update_vector_t;",
    "static const generated_app_version_vector_t generated_app_version_vectors[] = {",
]
for case in corpus["app_versions"]:
    lines.append(f"  {{{c_bytes(case['value'])}, {1 if case['valid'] else 0}u}},")
lines.append("};")
lines.append("static const generated_client_header_vector_t generated_client_header_vectors[] = {")
for case in corpus["client_headers"]:
    header = case["header"]
    parts = ", ".join(c_bytes(case[k]) for k in ("language", "sdk_version", "platform"))
    lines.append(f"  {{{parts}, {json.dumps(header) if header is not None else 'NULL'}}},")
lines.append("};")
lines.append("static const generated_update_vector_t generated_update_vectors[] = {")
for case in corpus["update_available"]:
    value = json.dumps(json.dumps(case["value"])) if "value" in case else "NULL"
    version = json.dumps(case["version"]) if case.get("version") else "NULL"
    lines.append(
        f"  {{{json.dumps(case['name'])}, {value}, {version}, {1 if case['valid'] else 0}u}},"
    )
lines.append("};")
lines.append("typedef struct generated_retention_vector {")
lines.append("  const char *code;")
lines.append("  uint8_t discard;")
lines.append("} generated_retention_vector_t;")
lines.append("static const generated_retention_vector_t generated_retention_vectors[] = {")
for case in retention["denials"]:
    lines.append(f"  {{{json.dumps(case['code'])}, {1 if case['discard_credential'] else 0}u}},")
lines.extend([
    "};",
    "#define GENERATED_COUNT(a) (sizeof(a) / sizeof((a)[0]))",
    "#endif",
    "",
])
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("\n".join(lines), encoding="utf-8")
