import { verify as verifySignature } from "node:crypto";
import { fail, ErrorKind } from "./errors.mjs";
import { validProvider } from "./app-key.mjs";
import { decodeBase64Url, matches, parseJwks, validEntitlements } from "./grants.mjs";
import { isInteger, isText, uniqueJson } from "./json.mjs";

const MAX_BYTES = 16 * 1024;
const MAX_TIME = 253_402_300_799;
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER;
const REQUIRED = {
  iss: "string", aud: "string", sub: "string", jti: "string", iat: "integer", nbf: "integer", exp: "integer",
  application_id: "string", environment_id: "string", activation_id: "string", installation_id: "string",
  binding_mode: "string", policy_version: "integer", entitlements: "object", refresh_after: "integer",
  offline_allowed: "boolean", session_id: "string", session_sequence: "integer",
};
const OPTIONAL = new Set(["fingerprint", "fingerprint_provider", "licence_expires_at"]);
const KNOWN = new Set([...Object.keys(REQUIRED), ...OPTIONAL]);

function invalid(code) { throw fail(ErrorKind.INVALID_RESPONSE, code); }

export function parseSessionKeys(value, environment) {
  try {
    if (environment !== "test" && environment !== "live") invalid("invalid_session_keys");
    const raw = typeof value === "string" || Buffer.isBuffer(value) || value instanceof Uint8Array
      ? value : JSON.stringify(value);
    if (Buffer.byteLength(raw) > MAX_BYTES) invalid("invalid_session_keys");
    const jwks = uniqueJson(raw);
    if (!jwks || typeof jwks !== "object" || Array.isArray(jwks) || Object.keys(jwks).length !== 1 || !Array.isArray(jwks.keys)) {
      invalid("invalid_session_keys");
    }
    const keys = parseJwks(jwks);
    const prefix = `${environment}-`;
    if ([...keys.keys()].some((kid) => !/^[A-Za-z0-9_-]{1,128}$/.test(kid) || !kid.startsWith(prefix) || kid.length === prefix.length)) {
      invalid("invalid_session_keys");
    }
    return Object.freeze({ environment, keys });
  } catch (error) {
    if (error?.code === "invalid_session_keys") throw error;
    invalid("invalid_session_keys");
  }
}

export function verifySessionGrant(token, keys, expected) {
  try {
    if (keys?.environment !== expected.keyEnvironment || typeof token !== "string" || !/^[\x00-\x7f]+$/.test(token) ||
        Buffer.byteLength(token, "utf8") > MAX_BYTES || !/^[A-Za-z0-9_-]{16,128}$/.test(expected.sessionId) ||
        !isInteger(expected.sequence, 1, MAX_SEQUENCE) || !isInteger(expected.now, 0, MAX_TIME)) invalid("invalid_session_grant");
    const parts = token.split(".");
    if (parts.length !== 3) invalid("invalid_session_grant");
    const [headerPart, payloadPart, signaturePart] = parts;
    const header = uniqueJson(decodeBase64Url(headerPart));
    const payloadBytes = decodeBase64Url(payloadPart);
    const signature = decodeBase64Url(signaturePart);
    if (!header || typeof header !== "object" || Array.isArray(header) || Object.keys(header).length !== 3 ||
        header.alg !== "ES256" || header.typ !== "orbit-session+jwt" || typeof header.kid !== "string" ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(header.kid) || !header.kid.startsWith(`${expected.keyEnvironment}-`) || signature.length !== 64) {
      invalid("invalid_session_grant");
    }
    const publicKey = keys.keys.get(header.kid);
    if (!publicKey || !verifySignature("sha256", Buffer.from(`${headerPart}.${payloadPart}`, "ascii"),
      { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)) invalid("invalid_session_grant");
    const claims = uniqueJson(payloadBytes);
    if (!claims || typeof claims !== "object" || Array.isArray(claims)) invalid("invalid_session_grant");
    for (const name of Object.keys(claims)) {
      const canonical = [...KNOWN].find((candidate) => candidate.toLowerCase() === name.toLowerCase());
      if (canonical && canonical !== name) invalid("invalid_session_grant");
      if (!KNOWN.has(name) && name.toLowerCase() === "session_sequence") invalid("invalid_session_grant");
    }
    for (const [name, type] of Object.entries(REQUIRED)) {
      if (!Object.hasOwn(claims, name) || !matches(claims[name], type)) invalid("invalid_session_grant");
    }
    for (const name of OPTIONAL) {
      if (Object.hasOwn(claims, name) && claims[name] !== null &&
          !(name === "licence_expires_at" ? isInteger(claims[name], 0, MAX_TIME) : typeof claims[name] === "string")) {
        invalid("invalid_session_grant");
      }
    }
    if (claims.binding_mode === "none" && (Object.hasOwn(claims, "fingerprint") || Object.hasOwn(claims, "fingerprint_provider"))) {
      invalid("invalid_session_grant");
    }
    for (const name of ["sub", "jti", "application_id", "environment_id", "activation_id", "installation_id"]) {
      if (!isText(claims[name], { min: 1, max: 128 })) invalid("invalid_session_grant");
    }
    if (!isInteger(claims.iat, 0, MAX_TIME) || !isInteger(claims.nbf, 0, MAX_TIME) || !isInteger(claims.exp, 0, MAX_TIME) ||
        !isInteger(claims.refresh_after, 0, MAX_TIME) || !isInteger(claims.session_sequence, 1, MAX_SEQUENCE) ||
        !isInteger(claims.policy_version, 1, 0x7fffffff) || !validEntitlements(claims.entitlements) || claims.offline_allowed !== false ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(claims.session_id) || claims.session_id !== expected.sessionId ||
        claims.session_sequence !== expected.sequence) invalid("invalid_session_grant");
    const bound = claims.binding_mode === "none" && claims.fingerprint === undefined && claims.fingerprint_provider === undefined &&
      (expected.fingerprint === null && expected.fingerprintProvider === null ||
       expected.allowUnboundFingerprint === true && expected.fingerprint !== null && expected.fingerprintProvider !== null) ||
      claims.binding_mode === "hwid" && typeof claims.fingerprint === "string" && /^[0-9a-f]{64}$/.test(claims.fingerprint) &&
      typeof claims.fingerprint_provider === "string" && validProvider(claims.fingerprint_provider) &&
      claims.fingerprint === expected.fingerprint && claims.fingerprint_provider === expected.fingerprintProvider &&
      expected.fingerprint !== null && expected.fingerprintProvider !== null;
    const issued = claims.iat;
    if (claims.iss !== expected.issuer || claims.aud !== `orbit-session:${expected.application}:${expected.environment}` ||
        expected.licence !== null && claims.sub !== expected.licence || claims.application_id !== expected.application ||
        claims.environment_id !== expected.environment || claims.activation_id !== expected.activation ||
        claims.installation_id !== expected.installation || !bound || claims.nbf !== issued || issued > expected.now + 30 ||
        claims.exp <= expected.now || claims.exp <= issued || claims.exp - issued > 120 ||
        expected.credentialExpiresAt !== null && claims.exp > expected.credentialExpiresAt ||
        (claims.licence_expires_at ?? null) !== expected.licenceExpiresAt ||
        claims.licence_expires_at != null && claims.exp > claims.licence_expires_at ||
        claims.refresh_after <= issued || claims.refresh_after > claims.exp || claims.refresh_after > issued + 75 ||
        claims.refresh_after < issued + 45 && claims.refresh_after !== claims.exp) invalid("invalid_session_grant");
    return Object.freeze({
      sessionId: claims.session_id,
      sequence: claims.session_sequence,
      licenceId: claims.sub,
      activationId: claims.activation_id,
      installationId: claims.installation_id,
      bindingMode: claims.binding_mode,
      tokenId: claims.jti,
      issuedAt: issued,
      expiresAt: claims.exp,
      refreshAfter: claims.refresh_after,
      licenceExpiresAt: claims.licence_expires_at ?? null,
      policyVersion: claims.policy_version,
      entitlements: Object.freeze(Object.assign(Object.create(null), claims.entitlements)),
    });
  } catch (error) {
    if (error?.code === "invalid_session_grant") throw error;
    invalid("invalid_session_grant");
  }
}
