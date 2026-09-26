#!/usr/bin/env python3
"""Generate a build-tree C table from the canonical shared grant corpus."""

import argparse
import json
from pathlib import Path
from typing import Optional


def c_string(value: str) -> str:
    return '"' + "".join(f"\\{byte:03o}" for byte in value.encode("utf-8")) + '"'


def c_bytes(name: str, value: bytes) -> str:
    octets = ",".join(f"0x{byte:02x}" for byte in value)
    return f"static const uint8_t {name}[] = {{{octets}}};\n"


def c_slice(value: Optional[str]) -> str:
    if value is None:
        return "{NULL, 0u}"
    encoded = value.encode("utf-8")
    return f"{{(const uint8_t *){c_string(value)}, {len(encoded)}u}}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    corpus = json.loads(args.source.read_text(encoding="utf-8"))
    base = corpus["expected"]
    default_jwks = corpus["jwks"]
    lines = [
        "/* Generated from contracts/sdk/grants.json; do not edit. */\n",
        "#ifndef ORBIT_GENERATED_GRANT_VECTORS_H\n#define ORBIT_GENERATED_GRANT_VECTORS_H\n",
        "#include <stdint.h>\n#include <stddef.h>\n#include \"orbit_embedded.h\"\n",
        "typedef struct generated_grant_vector {\n",
        "  const uint8_t *token; uint32_t token_length;\n",
        "  const uint8_t *jwks; uint32_t jwks_length;\n",
        "  orbit_grant_expected_t expected; int expected_valid; const char *name;\n",
        "} generated_grant_vector_t;\n",
    ]
    rows = []
    for index, case in enumerate(corpus["cases"]):
        token_name = f"vector_token_{index}"
        token = case["token"].encode("ascii")
        lines.append(c_bytes(token_name, token))
        jwks_name = f"vector_jwks_{index}"
        jwks_value = case.get("jwks", default_jwks)
        jwks_bytes = json.dumps(jwks_value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        lines.append(c_bytes(jwks_name, jwks_bytes))
        expected = dict(base)
        expected.update(case.get("expected", {}))
        licence = expected.get("licence")
        fingerprint = expected.get("fingerprint")
        fingerprint_provider = expected.get("fingerprint_provider")
        credential_expiry = expected.get("credential_expires_at")
        licence_expiry = expected.get("licence_expires_at")
        now = expected["now"]
        exp = f"{{.issuer={c_slice(expected['issuer'])},.application_id={c_slice(expected['application'])},.environment_id={c_slice(expected['environment'])},.licence_id={c_slice(licence)},.activation_id={c_slice(expected['activation'])},.installation_id={c_slice(expected['installation'])},.fingerprint={c_slice(fingerprint)},.fingerprint_provider={c_slice(fingerprint_provider)},.received_unix_seconds={now},.current_unix_seconds={now},.credential_expires_at={credential_expiry or 0},.licence_expires_at={licence_expiry or 0},.has_licence_id={1 if licence is not None else 0}u,.has_fingerprint={1 if fingerprint is not None else 0}u,.has_fingerprint_provider={1 if fingerprint_provider is not None else 0}u,.has_credential_expiry={1 if credential_expiry is not None else 0}u,.has_licence_expiry={1 if licence_expiry is not None else 0}u}}"
        name = c_string(case["name"])
        rows.append(f"  {{{token_name},(uint32_t)sizeof({token_name}),{jwks_name},(uint32_t)sizeof({jwks_name}),{exp},{1 if case['valid'] else 0},{name}}}")
    lines.append("static const generated_grant_vector_t generated_grant_vectors[] = {\n")
    lines.append(",\n".join(rows))
    lines.append("\n};\n#define GENERATED_GRANT_VECTOR_COUNT ((uint32_t)(sizeof(generated_grant_vectors) / sizeof(generated_grant_vectors[0])))\n#endif\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
