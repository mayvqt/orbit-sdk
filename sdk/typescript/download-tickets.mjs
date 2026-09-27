import { createPublicKey, verify } from "node:crypto";
import { isIP } from "node:net";
import { uniqueJson } from "./strict-json.mjs";

const LIMIT = 16 * 1024;
const MAX_TIME = 253402300799;
const ID = /^[A-Za-z0-9_-]{1,128}$/;
const HEADER_FIELDS = ["alg", "typ", "kid"];
const KEY_FIELDS = ["kty", "crv", "alg", "use", "kid", "x", "y"];
const CLAIM_FIELDS = ["ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp",
  "application_id", "environment_id", "release_id", "artifact_id", "sha256", "byte_length"];

// Private to this package: callers can never select a different token purpose.
export function downloadVerifier(scope, endpoint, rawKeys) {
  validateEndpoint(endpoint);
  const jwks = uniqueJson(rawKeys);
  exactFields(jwks, ["keys"]);
  if (!Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 8) invalid();
  const keys = new Map();
  const prefix = `${scope.environment}-`;
  const validKeyId = (kid) => typeof kid === "string" && ID.test(kid) &&
    kid.startsWith(prefix) && kid.length > prefix.length;
  for (const key of jwks.keys) {
    exactFields(key, KEY_FIELDS);
    if (key.kty !== "EC" || key.crv !== "P-256" || key.alg !== "ES256" || key.use !== "sig" ||
        !validKeyId(key.kid) || keys.has(key.kid) || decode(key.x).length !== 32 || decode(key.y).length !== 32) invalid();
    // Native import validates every curve point, including unused retained keys.
    keys.set(key.kid, createPublicKey({ key: { kty: "EC", crv: "P-256", x: key.x, y: key.y }, format: "jwk" }));
  }
  return (token) => {
    if (typeof token !== "string" || token.length === 0 || token.length > LIMIT ||
        !/^[A-Za-z0-9_.-]+$/.test(token)) invalid();
    const parts = token.split(".");
    if (parts.length !== 3) invalid();
    const header = uniqueJson(decode(parts[0]));
    const payload = decode(parts[1]);
    const signature = decode(parts[2]);
    exactFields(header, HEADER_FIELDS);
    if (header.alg !== "ES256" || header.typ !== "orbit-download+jwt" ||
        !validKeyId(header.kid) || signature.length !== 64 || !keys.has(header.kid)) invalid();
    if (!verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
      { key: keys.get(header.kid), dsaEncoding: "ieee-p1363" }, signature)) invalid();
    const claims = uniqueJson(payload);
    exactFields(claims, CLAIM_FIELDS);
    const now = Math.floor(Date.now() / 1000);
    if (!integer(now, 0, MAX_TIME) || claims.ver !== 1 ||
        !integer(claims.iat, 0, MAX_TIME) || !integer(claims.nbf, 0, MAX_TIME) ||
        !integer(claims.exp, 0, MAX_TIME) || claims.nbf !== claims.iat ||
        claims.iat > now + 30 || claims.exp <= now || claims.exp <= claims.iat ||
        claims.exp - claims.iat > 120 || !integer(claims.byte_length, 1, Number.MAX_SAFE_INTEGER) ||
        typeof claims.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(claims.sha256) ||
        !["sub", "jti", "application_id", "environment_id", "release_id", "artifact_id"].every(
          (name) => typeof claims[name] === "string" && ID.test(claims[name])) ||
        claims.iss !== scope.apiOrigin || claims.aud !== endpoint ||
        claims.application_id !== scope.applicationId || claims.environment_id !== scope.environmentId) invalid();
    return Object.freeze({
      licenceId: claims.sub,
      ticketId: claims.jti,
      applicationId: claims.application_id,
      environmentId: claims.environment_id,
      releaseId: claims.release_id,
      artifactId: claims.artifact_id,
      sha256: claims.sha256,
      byteLength: claims.byte_length,
      issuedAt: new Date(claims.iat * 1000).toISOString(),
      expiresAt: new Date(claims.exp * 1000).toISOString(),
    });
  };
}

function validateEndpoint(endpoint) {
  if (typeof endpoint !== "string" || endpoint.length < 1 || endpoint.length > 2048 ||
      !/^[\x21-\x7e]+$/.test(endpoint) || /[\\?#]/.test(endpoint) || !endpoint.startsWith("https://")) invalid();
  const authority = endpoint.slice(8).split("/", 1)[0];
  if (!authority || /[@%]/.test(authority)) invalid();
  let port;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0 || isIP(authority.slice(1, close)) !== 6) invalid();
    const suffix = authority.slice(close + 1);
    if (suffix && !suffix.startsWith(":")) invalid();
    if (suffix) port = suffix.slice(1);
  } else {
    if (/[\[\]]/.test(authority) || authority.split(":").length > 2) invalid();
    const separator = authority.indexOf(":");
    const host = separator < 0 ? authority : authority.slice(0, separator);
    if (!host) invalid();
    if (separator >= 0) port = authority.slice(separator + 1);
  }
  if (port !== undefined && (!/^[0-9]+$/.test(port) || !integer(Number(port), 1, 65535))) invalid();
  const url = new URL(endpoint);
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.search || url.hash) invalid();
}

function decode(value) {
  if (typeof value !== "string" || !value || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const result = Buffer.from(value, "base64url");
  if (result.toString("base64url") !== value) invalid();
  return result;
}

function exactFields(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some((name) => !Object.hasOwn(value, name))) invalid();
}

function integer(value, min, max) { return Number.isSafeInteger(value) && value >= min && value <= max; }
function invalid() { throw new TypeError("Invalid download ticket configuration or token"); }
