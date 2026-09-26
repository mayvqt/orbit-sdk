import { createHash } from "node:crypto";
import { fail, ErrorKind } from "./errors.mjs";

const prefixes = new Map([["orbit_app_test_", "test"], ["orbit_app_live_", "live"]]);
const idPattern = /^[A-Za-z0-9_-]{1,128}$/;

export class AppKey {
  constructor(apiOrigin, applicationId, environmentId, environment) {
    this.api_origin = apiOrigin;
    this.application_id = applicationId;
    this.environment_id = environmentId;
    this.environment = environment;
    this.issuer = apiOrigin;
    Object.freeze(this);
  }

  static parse(input) {
    if (typeof input !== "string") throw new TypeError("app key must be a string");
    const key = input.trim();
    if (Buffer.byteLength(key, "utf8") > 512 || !key) invalidKey();
    const prefix = [...prefixes.keys()].find((candidate) => key.startsWith(candidate));
    if (!prefix) invalidKey();
    const parts = key.slice(prefix.length).split(".");
    if (parts.length !== 3) invalidKey();
    const [encodedOrigin, applicationId, environmentId] = parts;
    if (!idPattern.test(applicationId) || !idPattern.test(environmentId) || !/^[A-Za-z0-9_-]+$/.test(encodedOrigin)) invalidKey();
    const originBytes = Buffer.from(encodedOrigin, "base64url");
    if (originBytes.toString("base64url") !== encodedOrigin) invalidKey();
    let apiOrigin;
    try {
      apiOrigin = new TextDecoder("utf-8", { fatal: true }).decode(originBytes);
    } catch {
      invalidKey();
    }
    validateOrigin(apiOrigin);
    return new AppKey(apiOrigin, applicationId, environmentId, prefixes.get(prefix));
  }
}

export function validateOrigin(origin) {
  if (typeof origin !== "string" || !origin || /[\x00-\x20\x7f]/.test(origin) || !origin.startsWith("https://")) invalidKey();
  let url;
  try {
    url = new URL(origin);
  } catch {
    invalidKey();
  }
  const authority = origin.slice(8);
  const stripped = authority.endsWith("/") ? authority.slice(0, -1) : authority;
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.pathname !== "/" ||
      url.search || url.hash || /[\\/@?#]/.test(stripped) || /[\u0000-\u0020\u007f]/.test(stripped) ||
      origin.endsWith("/") || (url.port && (!/^\d+$/.test(url.port) || Number(url.port) < 1 || Number(url.port) > 65535))) invalidKey();
  return origin;
}

export function validateAppKey(value) {
  if (typeof value === "string") return AppKey.parse(value);
  if (!value || Object.getPrototypeOf(value) !== AppKey.prototype) invalidKey();
  const parsed = AppKey.parse(`orbit_app_${value.environment}_${Buffer.from(value.api_origin, "utf8").toString("base64url")}.${value.application_id}.${value.environment_id}`);
  if (parsed.api_origin !== value.api_origin || parsed.environment !== value.environment || parsed.application_id !== value.application_id || parsed.environment_id !== value.environment_id) invalidKey();
  return parsed;
}

export function canonicalScope(key) {
  return { api_origin: key.api_origin, issuer: key.issuer, application_id: key.application_id, environment_id: key.environment_id };
}

export function scopeHash(key) {
  const scope = canonicalScope(key);
  const raw = JSON.stringify({ api_origin: scope.api_origin, application_id: scope.application_id, environment_id: scope.environment_id, issuer: scope.issuer });
  return createHash("sha256").update("orbit.installed-client.scope.v2\0").update(raw, "ascii").digest("hex");
}

export const isOpaqueId = (value) => typeof value === "string" && idPattern.test(value);

function invalidKey() {
  throw fail(ErrorKind.CONFIGURATION, "invalid_app_key");
}
