from __future__ import annotations

import json
from typing import Any

from .errors import INVALID_RESPONSE, error

MAX_JSON_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32


class _DuplicateKey(ValueError):
    pass


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _check_tree(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting too deep")
    if isinstance(value, str):
        value.encode("utf-8", "strict")
    elif isinstance(value, list):
        for item in value:
            _check_tree(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8", "strict")
            _check_tree(item, depth + 1)


def unique_json(data: bytes | bytearray | str) -> Any:
    """Decode bounded JSON while rejecting duplicate keys and invalid Unicode."""
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        if not raw or len(raw) > MAX_JSON_BYTES:
            raise error(INVALID_RESPONSE, "invalid_json")
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise error(INVALID_RESPONSE, "invalid_json") from exc
    elif isinstance(data, str):
        if not data or len(data.encode("utf-8", "strict")) > MAX_JSON_BYTES:
            raise error(INVALID_RESPONSE, "invalid_json")
        text = data
    else:
        raise error(INVALID_RESPONSE, "invalid_json")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
        _check_tree(value)
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise error(INVALID_RESPONSE, "invalid_json") from exc
    return value


def fields(value: Any, required: dict[str, Any], *, exact: bool = False, optional: tuple[str, ...] = ()) -> dict[str, Any]:
    """Validate named field types; type specs may be a type tuple or None for null."""
    if not isinstance(value, dict):
        raise error(INVALID_RESPONSE, "invalid_json")
    if exact and value.keys() != required.keys():
        raise error(INVALID_RESPONSE, "invalid_json")
    if not required.keys() - set(optional) <= value.keys():
        raise error(INVALID_RESPONSE, "invalid_json")
    for name in optional:
        if name not in value:
            value[name] = None
    for name in required:
        if any(key != name and key.casefold() == name.casefold() for key in value):
            raise error(INVALID_RESPONSE, "invalid_json")
    for name, spec in required.items():
        item = value[name]
        if spec is None:
            valid = item is None
        else:
            valid = isinstance(item, spec)
            if spec is int or isinstance(spec, tuple) and int in spec:
                valid = valid and not isinstance(item, bool)
        if not valid:
            raise error(INVALID_RESPONSE, "invalid_json")
    return value


def strict_int(value: Any, *, minimum: int = -(1 << 63), maximum: int = (1 << 63) - 1) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def text(value: Any, *, maximum: int, minimum: int = 0, ascii_only: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return minimum <= len(encoded) <= maximum and (not ascii_only or value.isascii())
