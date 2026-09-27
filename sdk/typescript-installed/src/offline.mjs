import { createHash, verify as verifySignature } from "node:crypto";
import { fail, ErrorKind } from "./errors.mjs";
import { validProvider } from "./app-key.mjs";
import { parseJwks, validEntitlements } from "./grants.mjs";
import { isInteger, stableJson, uniqueJson } from "./json.mjs";

const MAX_FILE_BYTES = 16 * 1024;
const MAX_LIFETIME = 366 * 86400;
const MAX_TIME = 253402300799;
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;
const REQUIRED = ["ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "activation_id", "installation_id", "sequence", "binding_mode", "policy_version", "entitlements"];
const opaque = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function parseOfflineKeys(value, environment) {
  try {
    if (!["test", "live"].includes(environment)) invalidKeys();
    const raw = typeof value === "string" || Buffer.isBuffer(value) || value instanceof Uint8Array
      ? value : JSON.stringify(value);
    if (Buffer.byteLength(raw) > MAX_FILE_BYTES) invalidKeys();
    const jwksValue = uniqueJson(raw);
    if (!record(jwksValue) || Object.keys(jwksValue).length !== 1 || !Array.isArray(jwksValue.keys)) invalidKeys();
    const keys = parseJwks(jwksValue);
    const prefix = `offline-${environment}-`;
    if ([...keys.keys()].some((kid) => !/^[A-Za-z0-9_-]{1,128}$/.test(kid) || !kid.startsWith(prefix) || kid.length === prefix.length)) invalidKeys();
    return Object.freeze({ environment, keys });
  } catch {
    invalidKeys();
  }
}

export function verifyOfflineFile(value, key, binding, installationId, keys, now, minimumSequence = 1) {
  try {
    if (keys?.environment !== key.environment || !isInteger(now, 0, MAX_TIME) || !isInteger(minimumSequence, 1, MAX_SEQUENCE)) invalidFile();
    let token;
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      if (value.byteLength > MAX_FILE_BYTES) invalidFile();
      token = new TextDecoder("utf-8", { fatal: true }).decode(value);
    } else token = value;
    if (typeof token !== "string" || Buffer.byteLength(token, "utf8") > MAX_FILE_BYTES || !/^[\x00-\x7f]*$/.test(token)) invalidFile();
    token = token.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, "");
    const parts = token.split(".");
    if (parts.length !== 3 || parts.some((part) => !part || !/^[A-Za-z0-9_-]+$/.test(part))) invalidFile();
    const [headerPart, payloadPart, signaturePart] = parts;
    const headerBytes = decodeB64(headerPart);
    const payloadBytes = decodeB64(payloadPart);
    const signature = decodeB64(signaturePart);
    const header = uniqueJson(headerBytes);
    const prefix = `offline-${key.environment}-`;
    if (!record(header) || Object.keys(header).length !== 3 || header.alg !== "ES256" || header.typ !== "orbit-offline+jwt" ||
        typeof header.kid !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(header.kid) ||
        !header.kid.startsWith(prefix) || header.kid.length === prefix.length || signature.length !== 64) invalidFile();
    const publicKey = keys.keys.get(header.kid);
    if (!publicKey || !verifySignature("sha256", Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
      { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)) invalidFile();
    const claims = uniqueJson(payloadBytes);
    if (!record(claims)) invalidFile();
    const expectedFields = [...REQUIRED];
    if (Object.hasOwn(claims, "licence_expires_at")) expectedFields.push("licence_expires_at");
    if (claims.binding_mode === "hwid") expectedFields.push("fingerprint", "fingerprint_provider");
    if (Object.keys(claims).length !== expectedFields.length || Object.keys(claims).some((field) => !expectedFields.includes(field))) invalidFile();
    if (!isInteger(claims.ver, 1, 1) || !isInteger(claims.iat, 0, MAX_TIME) || !isInteger(claims.nbf, 0, MAX_TIME) ||
        !isInteger(claims.exp, 0, MAX_TIME) || !isInteger(claims.sequence, minimumSequence, MAX_SEQUENCE) ||
        !isInteger(claims.policy_version, 1, 0x7fffffff) || !validEntitlements(claims.entitlements) ||
        !["sub", "jti"].every((field) => opaque(claims[field])) ||
        !["application_id", "environment_id", "activation_id", "installation_id"].every((field) => opaque(claims[field])) ||
        claims.installation_id.length < 16) invalidFile();
    if (Object.hasOwn(claims, "licence_expires_at") && !isInteger(claims.licence_expires_at, claims.exp, MAX_TIME)) invalidFile();
    const expectedAudience = `orbit-offline:${key.application_id}:${key.environment_id}`;
    if (typeof claims.iss !== "string" || claims.iss !== key.issuer || claims.aud !== expectedAudience ||
        claims.application_id !== key.application_id || claims.environment_id !== key.environment_id ||
        claims.installation_id !== installationId || claims.nbf !== claims.iat || claims.iat > now + 30 ||
        claims.exp <= now || claims.exp <= claims.iat || claims.exp - claims.iat > MAX_LIFETIME) invalidFile();
    if (claims.binding_mode === "hwid") {
      if (typeof claims.fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(claims.fingerprint) ||
          typeof claims.fingerprint_provider !== "string" || !validProvider(claims.fingerprint_provider) ||
          claims.fingerprint !== binding.fingerprint || claims.fingerprint_provider !== binding.provider) invalidFile();
    } else if (claims.binding_mode !== "none") invalidFile();
    const canonical = stableJson(claims);
    return Object.freeze({
      token,
      keyId: header.kid,
      licenceId: claims.sub,
      activationId: claims.activation_id,
      installationId: claims.installation_id,
      issuanceId: claims.jti,
      issuedAt: claims.iat,
      expiresAt: claims.exp,
      licenceExpiresAt: Object.hasOwn(claims, "licence_expires_at") ? claims.licence_expires_at : null,
      sequence: claims.sequence,
      policyVersion: claims.policy_version,
      entitlements: Object.freeze(Object.assign(Object.create(null), claims.entitlements)),
      contentDigest: createHash("sha256").update(canonical, "utf8").digest("hex"),
    });
  } catch (error) {
    if (error?.code === "invalid_offline_file") throw error;
    invalidFile();
  }
}

export function makeOfflineRequest(key, installationId, binding) {
  const encodedOrigin = Buffer.from(key.api_origin, "utf8").toString("base64url");
  const appKey = `orbit_app_${key.environment}_${encodedOrigin}.${key.application_id}.${key.environment_id}`;
  const value = {
    format: "orbit-offline-request",
    version: 1,
    app_key: appKey,
    installation_id: installationId,
    fingerprint: binding.fingerprint,
    fingerprint_provider: binding.provider,
  };
  const serialized = Object.freeze(value);
  return Object.freeze({
    format: value.format,
    version: value.version,
    appKey: value.app_key,
    installationId: value.installation_id,
    fingerprint: value.fingerprint,
    fingerprintProvider: value.fingerprint_provider,
    toJSON() { return serialized; },
    toString() { return "OfflineRequest(<public configuration>)"; },
  });
}

export function validOfflineState(value) {
  if (value === null || !record(value) || Object.keys(value).length !== 7 ||
      !["jws", "sequence", "issuance_id", "content_digest", "verified_at", "time_high_water", "wall_high_water"].every((name) => Object.hasOwn(value, name))) return false;
  if (value.jws === null) return isInteger(value.sequence, 0, MAX_SEQUENCE) &&
    (value.sequence === 0 ? value.issuance_id === null && value.content_digest === null : opaque(value.issuance_id) &&
      typeof value.content_digest === "string" && /^[0-9a-f]{64}$/.test(value.content_digest)) &&
    isInteger(value.verified_at, 0, MAX_TIME) && isInteger(value.time_high_water, 0, MAX_TIME) && isInteger(value.wall_high_water, 0, MAX_TIME) &&
    value.time_high_water >= value.verified_at &&
    (value.sequence !== 0 || value.verified_at === 0 && value.time_high_water === 0 && value.wall_high_water === 0);
  return typeof value.jws === "string" && Buffer.byteLength(value.jws, "utf8") <= MAX_FILE_BYTES &&
    /^[\x00-\x7f]+$/.test(value.jws) &&
    typeof value.issuance_id === "string" && opaque(value.issuance_id) && typeof value.content_digest === "string" && /^[0-9a-f]{64}$/.test(value.content_digest) &&
    isInteger(value.sequence, 1, MAX_SEQUENCE) && isInteger(value.verified_at, 0, MAX_TIME) &&
    isInteger(value.time_high_water, 0, MAX_TIME) && isInteger(value.wall_high_water, 0, MAX_TIME) &&
    value.time_high_water >= value.verified_at;
}

export function emptyOfflineState() {
  return { jws: null, sequence: 0, issuance_id: null, content_digest: null, verified_at: 0, time_high_water: 0, wall_high_water: 0 };
}

function decodeB64(value) {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) invalidFile();
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) invalidFile();
  return decoded;
}
function invalidKeys() { throw fail(ErrorKind.INVALID_RESPONSE, "invalid_offline_keys"); }
function invalidFile() { throw fail(ErrorKind.INVALID_RESPONSE, "invalid_offline_file"); }
