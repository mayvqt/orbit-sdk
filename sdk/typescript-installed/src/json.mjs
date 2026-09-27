import { fail, ErrorKind } from "./errors.mjs";

export const MAX_JSON_BYTES = 64 * 1024;
const MAX_DEPTH = 32;

export function uniqueJson(input) {
  let text;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    if (input.byteLength < 1 || input.byteLength > MAX_JSON_BYTES) invalid();
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(input);
    } catch {
      invalid();
    }
  } else if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") < 1 || Buffer.byteLength(input, "utf8") > MAX_JSON_BYTES) invalid();
    text = input;
  } else {
    invalid();
  }

  let index = 0;
  const whitespace = () => {
    while (text[index] === " " || text[index] === "\n" || text[index] === "\r" || text[index] === "\t") index++;
  };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      const code = text.charCodeAt(index++);
      if (code === 0x22) {
        try {
          const parsed = JSON.parse(text.slice(start, index));
          if (!validUnicode(parsed)) invalid();
          return parsed;
        } catch {
          invalid();
        }
      }
      if (code < 0x20) invalid();
      if (code === 0x5c) {
        const escape = text[index++];
        if (escape === "u") {
          const hex = text.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) invalid();
          index += 4;
        } else if (!'"\\/bfnrt'.includes(escape)) {
          invalid();
        }
      }
    }
    invalid();
  };
  const value = (depth = 0) => {
    if (depth > MAX_DEPTH) invalid();
    whitespace();
    const next = text[index];
    if (next === '"') return string();
    if (next === "{") {
      index++;
      whitespace();
      const result = Object.create(null);
      if (text[index] === "}") {
        index++;
        return result;
      }
      while (index < text.length) {
        whitespace();
        if (text[index] !== '"') invalid();
        const key = string();
        if (Object.hasOwn(result, key)) invalid();
        whitespace();
        if (text[index++] !== ":") invalid();
        result[key] = value(depth + 1);
        whitespace();
        if (text[index] === "}") {
          index++;
          return result;
        }
        if (text[index++] !== ",") invalid();
      }
      invalid();
    }
    if (next === "[") {
      index++;
      whitespace();
      const result = [];
      if (text[index] === "]") {
        index++;
        return result;
      }
      while (index < text.length) {
        result.push(value(depth + 1));
        whitespace();
        if (text[index] === "]") {
          index++;
          return result;
        }
        if (text[index++] !== ",") invalid();
      }
      invalid();
    }
    for (const [token, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(token, index)) {
        index += token.length;
        return parsed;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(index));
    if (!number) invalid();
    index += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) invalid();
    if (/[.eE]/.test(number[0])) return Object.freeze({ __orbit_non_integer_number: parsed });
    return parsed;
  };

  try {
    const result = value();
    whitespace();
    if (index !== text.length) invalid();
    return result;
  } catch (error) {
    if (error instanceof Error && error.kind) throw error;
    invalid();
  }
}

export function exactFields(value, required, optional = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  for (const name of Object.keys(value)) {
    if (name.toLowerCase() !== name && Object.keys(required).some((key) => key.toLowerCase() === name.toLowerCase())) invalid();
    if (!Object.hasOwn(required, name) && !optional.includes(name)) invalid();
  }
  for (const name of Object.keys(required)) if (!Object.hasOwn(value, name) && !optional.includes(name)) invalid();
  const result = Object.create(null);
  for (const [name, predicate] of Object.entries(required)) {
    const item = Object.hasOwn(value, name) ? value[name] : null;
    if (!predicate(item)) invalid();
    result[name] = item;
  }
  return result;
}

export function isInteger(value, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

export function isText(value, { min = 0, max, ascii = false } = {}) {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") >= min &&
    Buffer.byteLength(value, "utf8") <= max && (!ascii || /^[\x00-\x7f]*$/.test(value));
}

function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function invalid() {
  throw fail(ErrorKind.INVALID_RESPONSE, "invalid_json");
}
