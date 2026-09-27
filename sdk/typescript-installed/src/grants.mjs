import { createPublicKey, verify as verifySignature } from "node:crypto";
import { fail, ErrorKind } from "./errors.mjs";
import { isInteger, uniqueJson } from "./json.mjs";

const TOKEN_LIMIT = 16 * 1024;
const isRecord = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isText = (v, max = 128, min = 0) => typeof v === "string" && Buffer.byteLength(v, "utf8") >= min && Buffer.byteLength(v, "utf8") <= max;
const clampAdd = (a, b) => Math.max(Number.MIN_SAFE_INTEGER, Math.min(Number.MAX_SAFE_INTEGER, a + b));

export function parseJwks(value) {
  if ((typeof value === "string" || Buffer.isBuffer(value) || value instanceof Uint8Array) && Buffer.byteLength(value) > 16 * 1024) invalid("invalid_jwks");
  const jwks = typeof value === "string" || Buffer.isBuffer(value) || value instanceof Uint8Array ? uniqueJson(value) : value;
  if (!isRecord(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 8) invalid("invalid_jwks");
  const keys = new Map();
  for (const item of jwks.keys) {
    if (!isRecord(item) || Object.keys(item).length !== 7 ||
        item.kty !== "EC" || item.crv !== "P-256" || item.alg !== "ES256" || item.use !== "sig" ||
        !isText(item.kid, 128, 1) || keys.has(item.kid)) invalid("invalid_jwks");
    const x = decodeBase64Url(item.x);
    const y = decodeBase64Url(item.y);
    if (x.length !== 32 || y.length !== 32) invalid("invalid_jwks");
    try {
      keys.set(item.kid, createPublicKey({ key: { kty: "EC", crv: "P-256", x: item.x, y: item.y }, format: "jwk" }));
    } catch {
      invalid("invalid_jwks");
    }
  }
  return keys;
}

export function verifyGrant(token, keys, expected) {
  const { header, headerPart, payloadBytes, payloadPart, signatureBytes } = parseToken(token);
  const key = keys.get(header.kid);
  if (!key) invalid();
  const claims = uniqueJson(payloadBytes);
  if (!isRecord(claims)) invalid();
  const hasFingerprint = Object.hasOwn(claims, "fingerprint");
  const hasProvider = Object.hasOwn(claims, "fingerprint_provider");
  if (claims.binding_mode === "none" && (hasFingerprint || hasProvider)) invalid();

  const fields = {
    iss: "string", aud: "string", sub: "string", jti: "string", iat: "integer", nbf: "integer", exp: "integer",
    application_id: "string", environment_id: "string", activation_id: "string", installation_id: "string",
    binding_mode: "string", policy_version: "integer", entitlements: "object", refresh_after: "integer",
    offline_allowed: "boolean",
  };
  for (const [name, type] of Object.entries(fields)) {
    if (!Object.hasOwn(claims, name) || !matches(claims[name], type)) invalid();
  }
  for (const name of ["fingerprint", "fingerprint_provider", "licence_expires_at"]) {
    if (Object.hasOwn(claims, name) && claims[name] !== null &&
        !(name === "licence_expires_at" ? Number.isSafeInteger(claims[name]) : typeof claims[name] === "string")) invalid();
  }
  if (claims.policy_version < 1 || claims.policy_version > 0x7fffffff ||
      !validEntitlements(claims.entitlements)) invalid();
  if (!isText(claims.iss, 384, 1) || !isText(claims.aud, 263, 1)) invalid();
  for (const name of ["sub", "jti", "application_id", "environment_id", "activation_id", "installation_id", "binding_mode"]) {
    if (!isText(claims[name])) invalid();
  }
  for (const name of ["fingerprint", "fingerprint_provider"]) {
    if (claims[name] !== undefined && claims[name] !== null && !isText(claims[name])) invalid();
  }
  if (!verifySignature("sha256", Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
    { key, dsaEncoding: "ieee-p1363" }, signatureBytes)) invalid();

  const persistentOffline = expected.credential_expires_at === null && claims.offline_allowed;
  const refreshMin = persistentOffline ? 675 : 45;
  const refreshMax = persistentOffline ? 1125 : 75;
  const allowance = claims.offline_allowed ? 86400 : 300;
  const fingerprint = claims.fingerprint ?? null;
  const provider = claims.fingerprint_provider ?? null;
  const bound = claims.binding_mode === "none" && fingerprint === null && provider === null &&
    ((expected.fingerprint === null && expected.fingerprint_provider === null) ||
     (expected.allow_unbound_fingerprint === true && expected.fingerprint !== null && expected.fingerprint_provider !== null)) ||
    claims.binding_mode === "hwid" && fingerprint === expected.fingerprint && provider === expected.fingerprint_provider &&
      expected.fingerprint !== null && expected.fingerprint_provider !== null;
  if (claims.iss !== expected.issuer || claims.aud !== `orbit:${expected.application}:${expected.environment}` ||
      !claims.sub || Buffer.byteLength(claims.sub) > 128 || (expected.licence !== null && claims.sub !== expected.licence) ||
      !claims.jti || Buffer.byteLength(claims.jti) > 128 || claims.application_id !== expected.application ||
      claims.environment_id !== expected.environment || claims.activation_id !== expected.activation ||
      claims.installation_id !== expected.installation || !bound || claims.iat < 0 || claims.nbf !== claims.iat ||
      claims.iat > clampAdd(expected.now, 30) || claims.iat < clampAdd(expected.now, -30) ||
      claims.exp <= expected.now || claims.exp <= claims.iat || claims.exp > clampAdd(claims.iat, allowance) ||
      (expected.credential_expires_at !== null && claims.exp > expected.credential_expires_at) ||
      (claims.licence_expires_at ?? null) !== expected.licence_expires_at ||
      (claims.licence_expires_at != null && claims.exp > claims.licence_expires_at) ||
      claims.refresh_after <= claims.iat || claims.refresh_after > claims.exp ||
      claims.refresh_after > clampAdd(claims.iat, refreshMax) ||
      (claims.refresh_after < clampAdd(claims.iat, refreshMin) && claims.refresh_after !== claims.exp)) invalid();
  return claims;
}

export function parseToken(token) {
  if (typeof token !== "string" || !token || token.length > TOKEN_LIMIT || !/^[\x00-\x7f]*$/.test(token)) invalid();
  const parts = token.split(".");
  if (parts.length !== 3) invalid();
  const headerBytes = decodeBase64Url(parts[0]);
  const payloadBytes = decodeBase64Url(parts[1]);
  const signatureBytes = decodeBase64Url(parts[2]);
  if (signatureBytes.length !== 64) invalid();
  const header = uniqueJson(headerBytes);
  if (!isRecord(header) || Object.keys(header).length !== 3 || header.alg !== "ES256" ||
      header.typ !== "orbit-access+jwt" || !isText(header.kid, 128, 1)) invalid();
  return { header, headerPart: parts[0], payloadBytes, payloadPart: parts[1], signatureBytes };
}

export function decodeBase64Url(value) {
  if (typeof value !== "string" || !value || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) invalid();
  return bytes;
}

export function validEntitlements(value) {
  if (!isRecord(value) || Object.keys(value).length > 64) return false;
  return Object.entries(value).every(([name, enabled]) => /^[a-z][a-z0-9_]{0,63}$/.test(name) && typeof enabled === "boolean");
}

function matches(value, type) {
  if (type === "integer") return isInteger(value);
  if (type === "object") return isRecord(value);
  return typeof value === type;
}

function invalid(code = "invalid_grant") {
  throw fail(ErrorKind.INVALID_RESPONSE, code);
}
