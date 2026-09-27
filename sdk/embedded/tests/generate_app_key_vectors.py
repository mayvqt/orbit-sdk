"""Generate allocation-free C fixtures from the shared app-key corpus."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
corpus = json.loads(args.source.read_text(encoding="utf-8"))
if corpus.get("format_version") != 1:
    raise SystemExit("unsupported app-key vector format")

fields = ("api_origin", "issuer", "application_id", "environment_id", "environment")
lines = [
    "/* Generated from contracts/sdk/app-keys.json; do not edit. */",
    "#ifndef ORBIT_GENERATED_APP_KEY_VECTORS_H",
    "#define ORBIT_GENERATED_APP_KEY_VECTORS_H",
    "#include <stdint.h>",
    "typedef struct generated_app_key_vector {",
    "  const char *name;",
    "  const char *key;",
    "  const char *api_origin;",
    "  const char *issuer;",
    "  const char *application_id;",
    "  const char *environment_id;",
    "  const char *environment;",
    "  uint8_t valid;",
    "} generated_app_key_vector_t;",
    "static const generated_app_key_vector_t generated_app_key_vectors[] = {",
]
for case in corpus["cases"]:
    values = [case.get(field, "") for field in fields]
    valid = "1u" if case["valid"] else "0u"
    lines.append(
        "  {"
        + ", ".join(json.dumps(value, ensure_ascii=True) for value in [case["name"], case["key"], *values])
        + f", {valid}"
        + "},"
    )
lines.extend([
    "};",
    "#define GENERATED_APP_KEY_VECTOR_COUNT "
    "(sizeof(generated_app_key_vectors) / sizeof(generated_app_key_vectors[0]))",
    "#endif",
    "",
])
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("\n".join(lines), encoding="utf-8")
