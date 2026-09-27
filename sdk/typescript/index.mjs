import { randomUUID } from "node:crypto";
import { CLIENT_HEADER } from "./client-header.mjs";
import { downloadVerifier } from "./download-tickets.mjs";
import { uniqueJson } from "./strict-json.mjs";
import * as online from "./online.mjs";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 5_000;
const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const ENTITLEMENT_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const IDEMPOTENCY_PATTERN = /^[!-~]{16,128}$/;
const SAFE_CODE_PATTERN = /^[a-z0-9_]{1,128}$/;
const SAFE_REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const APP_KEY_MAX_LENGTH = 512;
const APP_KEY_PATTERN =
  /^orbit_app_(test|live)_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{1,128})\.([A-Za-z0-9_-]{1,128})$/;
const APP_KEY_ERROR = "appKey must be a valid Orbit app key";
const APP_KEY_CONSTRUCTOR = Symbol("AppKey constructor");
const APP_KEY_DATA = new WeakMap();

/** A safe Orbit API error. The API's display message and response body are not exposed. */
export class OrbitApiError extends Error {
  constructor(status, code, requestId = null) {
    super(`Orbit request failed (${code})`);
    this.name = "OrbitApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export class OrbitLimitReachedError extends OrbitApiError {
  constructor(code, requestId, details) {
    super(409, code, requestId);
    this.name = "OrbitLimitReachedError";
    Object.assign(this, details);
  }
}

/** A network, timeout, redirect, or invalid-response failure. */
export class OrbitTransportError extends Error {
  constructor(code = "request_failed") {
    super(`Orbit request failed (${code})`);
    this.name = "OrbitTransportError";
    this.status = null;
    this.code = code;
    this.requestId = null;
  }
}

/** A mutation may have completed even though its response was not usable. */
export class OrbitMutationUncertainError extends Error {
  constructor(idempotencyKey, cause) {
    super("Orbit mutation result is uncertain; retry with the same idempotency key", { cause });
    this.name = "OrbitMutationUncertainError";
    this.idempotencyKey = idempotencyKey;
    this.code = cause instanceof OrbitTransportError ? cause.code : "server_error";
    this.status = cause instanceof OrbitApiError ? cause.status : null;
    this.requestId = cause instanceof OrbitApiError ? cause.requestId : null;
  }
}

/**
 * A parsed Orbit app key: the single pasted value from Orbit's Integration
 * page that names the API origin, application and environment.
 */
export class AppKey {
  #apiOrigin;
  #applicationId;
  #environmentId;
  #environment;

  constructor(secret, apiOrigin, applicationId, environmentId, environment) {
    if (secret !== APP_KEY_CONSTRUCTOR) throw new TypeError(APP_KEY_ERROR);
    this.#apiOrigin = apiOrigin;
    this.#applicationId = applicationId;
    this.#environmentId = environmentId;
    this.#environment = environment;
    APP_KEY_DATA.set(this, Object.freeze({ apiOrigin, applicationId, environmentId, environment }));
    Object.freeze(this);
  }

  /** The public API origin the key names, for example https://orbit.example.com. */
  get api_origin() {
    return this.#apiOrigin;
  }

  /** The expected grant issuer; always equal to api_origin. */
  get issuer() {
    return this.#apiOrigin;
  }

  get application_id() {
    return this.#applicationId;
  }

  get environment_id() {
    return this.#environmentId;
  }

  /** "test" or "live". */
  get environment() {
    return this.#environment;
  }

  /** Parse and validate an app key string. Throws TypeError on any invalid input. */
  static parse(key) {
    if (typeof key !== "string") throw new TypeError(APP_KEY_ERROR);
    const trimmed = key.trim();
    if (trimmed.length === 0 || trimmed.length > APP_KEY_MAX_LENGTH) {
      throw new TypeError(APP_KEY_ERROR);
    }
    const match = APP_KEY_PATTERN.exec(trimmed);
    if (!match) throw new TypeError(APP_KEY_ERROR);
    const [, environment, encodedOrigin, applicationId, environmentId] = match;
    const apiOrigin = decodeAppKeyOrigin(encodedOrigin);
    return new AppKey(APP_KEY_CONSTRUCTOR, apiOrigin, applicationId, environmentId, environment);
  }
}

/** Thrown by requireFeature when Orbit denies the requested access. */
export class OrbitAccessDeniedError extends Error {
  constructor(reason) {
    super(`Orbit denied access (${reason})`);
    this.name = "OrbitAccessDeniedError";
    this.reason = reason;
  }
}

/** A download bearer failed verification. Contains no token or claim values. */
export class OrbitDownloadTicketError extends Error {
  constructor() {
    super("Invalid Orbit download ticket");
    this.name = "OrbitDownloadTicketError";
    this.code = "invalid_download_ticket";
  }
}

/** Verify seller download bearers locally against explicitly trusted public keys. */
export class DownloadTicketVerifier {
  #verify;

  constructor({ appKey, endpoint, trustedKeys }) {
    try {
      const scope = readAppKey(typeof appKey === "string" ? AppKey.parse(appKey) : appKey);
      this.#verify = downloadVerifier(scope, endpoint, trustedKeys);
    } catch {
      throw new TypeError("Invalid Orbit download verifier configuration");
    }
  }

  verify(ticket) {
    try {
      return this.#verify(ticket);
    } catch {
      throw new OrbitDownloadTicketError();
    }
  }
}

/**
 * Online-only client for Orbit's trusted backend API.
 * Keep this instance and its management token on your server.
 */
export class OrbitBackendClient {
  #origin;
  #applicationId;
  #environmentId;
  #managementToken;
  #fetch;

  constructor(config, options = {}) {
    if (!config || typeof config !== "object") {
      throw new TypeError("config is required");
    }
    const parsed = typeof config.appKey === "string" ? AppKey.parse(config.appKey) : config.appKey;
    const appKey = readAppKey(parsed);
    this.#origin = appKey.apiOrigin;
    this.#applicationId = appKey.applicationId;
    this.#environmentId = appKey.environmentId;
    this.#managementToken = requireHeaderSecret(config.managementToken, "managementToken");
    this.#fetch = options.fetchImpl ?? globalThis.fetch;
    if (typeof this.#fetch !== "function") {
      throw new TypeError("A Fetch API implementation is required");
    }
  }

  /** Verify a customer session with Orbit and return its server-derived subject. */
  async verifyCurrentCustomerSession(customerSession) {
    const token = requireHeaderSecret(customerSession, "customerSession");
    const value = await this.#request("/api/client/v1/sessions/current", {
      bearer: token,
      method: "GET",
    });
    if (
      !isRecord(value) ||
      !isId(value.customer_id) ||
      value.application_id !== this.#applicationId ||
      value.environment_id !== this.#environmentId ||
      !isFutureTimestamp(value.expires_at)
    ) {
      throw new OrbitTransportError("invalid_response");
    }
    return Object.freeze({
      customer_id: value.customer_id,
      application_id: value.application_id,
      environment_id: value.environment_id,
      expires_at: value.expires_at,
    });
  }

  /**
   * Reverify the customer session and ask Orbit for a current feature decision.
   * The customer ID is always derived from the verified session, never caller input.
   */
  async decideFeature({ customerSession, licenceId, activationId, entitlement }) {
    const licence_id = requireId(licenceId, "licenceId");
    const activation_id = requireId(activationId, "activationId");
    if (typeof entitlement !== "string" || !ENTITLEMENT_PATTERN.test(entitlement)) {
      throw new TypeError("entitlement must be a valid Orbit entitlement name");
    }
    const subject = await this.verifyCurrentCustomerSession(customerSession);
    const decision = await this.#request("/api/management/v1/licence-decisions", {
      bearer: this.#managementToken,
      method: "POST",
      body: {
        licence_id,
        activation_id,
        customer_id: subject.customer_id,
        entitlement,
      },
    });
    if (
      !isRecord(decision) ||
      typeof decision.allowed !== "boolean" ||
      !["allowed", "licence_unavailable", "entitlement_denied"].includes(decision.reason) ||
      !isTimestamp(decision.checked_at) ||
      (decision.allowed && decision.reason !== "allowed") ||
      (!decision.allowed && decision.reason === "allowed")
    ) {
      throw new OrbitTransportError("invalid_response");
    }
    return Object.freeze({
      allowed: decision.allowed,
      reason: decision.reason,
      checked_at: decision.checked_at,
      customer_id: subject.customer_id,
    });
  }

  /**
   * Call decideFeature and throw OrbitAccessDeniedError when access is not
   * allowed, so callers do not need an if-check. Returns the allowed decision.
   */
  async requireFeature(input) {
    const decision = await this.decideFeature(input);
    if (!decision.allowed) throw new OrbitAccessDeniedError(decision.reason);
    return decision;
  }

  /** Search management licences. Full keys are sent only in this JSON body. */
  async searchLicences({ query = "", after, status } = {}) {
    if (typeof query !== "string" || utf8Length(query) > 200) {
      throw new TypeError("query must be a string of at most 200 UTF-8 bytes");
    }
    const body = { query };
    if (after !== undefined && after !== null) body.after = requireId(after, "after");
    if (status !== undefined) {
      if (!["active", "revoked", "all"].includes(status)) {
        throw new TypeError("status must be active, revoked, or all");
      }
      body.status = status;
    }
    const value = await this.#request("/api/management/v1/licences/search", {
      bearer: this.#managementToken,
      method: "POST",
      body,
    });
    if (!isPage(value)) throw new OrbitTransportError("invalid_response");
    return Object.freeze({ items: Object.freeze(value.items.map(freezeLicence)), next_cursor: value.next_cursor });
  }

  /**
   * Issue 1..100 licences. If idempotencyKey is omitted, a securely random
   * key is generated and returned as idempotencyKey on the result; keep it to
   * retry deliberately with the exact same input.
   */
  async issueLicences({ policyId, quantity, reference, note, idempotencyKey } = {}) {
    const policy_id = requireId(policyId, "policyId");
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
      throw new TypeError("quantity must be an integer from 1 to 100");
    }
    const usedIdempotencyKey = resolveIdempotencyKey(idempotencyKey);
    const body = {
      policy_id,
      quantity,
      reference: requireText(reference, "reference", 200),
      note: requireText(note, "note", 2000),
      idempotency_key: usedIdempotencyKey,
    };
    try {
      const value = await this.#request("/api/management/v1/licences", {
        bearer: this.#managementToken,
        method: "POST",
        body,
      });
      if (!isIssuedLicences(value)) throw new OrbitTransportError("invalid_response");
      return freezeIssuedLicences(value, usedIdempotencyKey);
    } catch (error) {
      throw uncertainMutation(error, usedIdempotencyKey);
    }
  }

  /** Read safe licence metadata by ID. */
  async getLicence(id) {
    const value = await this.#request(`/api/management/v1/licences/${encodeURIComponent(requireId(id, "id"))}`, {
      bearer: this.#managementToken,
      method: "GET",
    });
    if (!isLicence(value)) throw new OrbitTransportError("invalid_response");
    return freezeLicence(value);
  }

  /**
   * Replace a licence key. If idempotencyKey is omitted, a securely random
   * key is generated and returned as idempotencyKey on the result; keep it to
   * retry deliberately with the exact same input.
   */
  async replaceLicenceKey(id, { reason, idempotencyKey } = {}) {
    const licenceId = encodeURIComponent(requireId(id, "id"));
    const usedIdempotencyKey = resolveIdempotencyKey(idempotencyKey);
    const requestBody = {
      reason: requireReason(reason),
      idempotency_key: usedIdempotencyKey,
    };
    try {
      const value = await this.#request(`/api/management/v1/licences/${licenceId}/key-replacements`, {
        bearer: this.#managementToken,
        method: "POST",
        body: requestBody,
      });
      if (!isIssuedLicences(value)) throw new OrbitTransportError("invalid_response");
      return freezeIssuedLicences(value, usedIdempotencyKey);
    } catch (error) {
      throw uncertainMutation(error, usedIdempotencyKey);
    }
  }

  /** Revoke a licence. Revocation cannot be reversed. */
  async revokeLicence(id, reason) {
    const licenceId = encodeURIComponent(requireId(id, "id"));
    const value = await this.#request(`/api/management/v1/licences/${licenceId}/status`, {
      bearer: this.#managementToken,
      method: "POST",
      body: { status: "revoked", reason: requireReason(reason) },
    });
    if (!isLicence(value) || value.id !== id || value.status !== "revoked") {
      throw new OrbitTransportError("invalid_response");
    }
    return freezeLicence(value);
  }

  checkForUpdate(licenceId, installedReleaseNumber, { channel, target, signal } = {}) {
    const query = online.updateInput(installedReleaseNumber, { channel, target });
    return this.#onlineLicence(licenceId, "updates", "GET", undefined, (v) => online.parseUpdate(v, query), { query, signal });
  }

  authorizeDownload(licenceId, releaseId, artifactId, { signal } = {}) {
    requireId(releaseId, "releaseId"); requireId(artifactId, "artifactId");
    return this.#onlineLicence(licenceId, "downloads/authorize", "POST", { release_id: releaseId, artifact_id: artifactId },
      (v) => online.parseAuthorization(v, releaseId, artifactId), { signal });
  }

  usage(licenceId, name, { signal } = {}) {
    online.requireInput(name, online.limitName);
    return this.#onlineLicence(licenceId, `usage/${name}`, "GET", undefined, (v) => online.parseCounter(v, name, true), { signal });
  }

  consume(licenceId, name, units = 1, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName); online.requireInput(units, (v) => online.integer(v, 1));
    const key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineLicence(licenceId, `usage/${name}/consume`, "POST", { units, idempotency_key: key },
      (v) => online.parseConsumption(v, name, key, units), { signal, key });
  }

  resources(licenceId, name, { signal } = {}) {
    online.requireInput(name, online.limitName);
    return this.#onlineLicence(licenceId, `resources/${name}`, "GET", undefined, (v) => online.parseCounter(v, name, false), { signal });
  }

  acquireResource(licenceId, name, resourceId, units = 1, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName); requireId(resourceId, "resourceId"); online.requireInput(units, (v) => online.integer(v, 1));
    const key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineLicence(licenceId, `resources/${name}/acquire`, "POST", { resource_id: resourceId, units, idempotency_key: key },
      (v) => online.parseAllocation(v, name, key, { resourceId, units }), { signal, key });
  }

  releaseResource(licenceId, name, allocationId, { idempotencyKey, signal } = {}) {
    online.requireInput(name, online.limitName); requireId(allocationId, "allocationId");
    const key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineLicence(licenceId, `resources/${name}/allocations/${allocationId}/release`, "POST", { idempotency_key: key },
      (v) => online.parseAllocation(v, name, key, { allocationId }), { signal, key });
  }

  listResourceAllocations(licenceId, name, { state, after, limit, signal } = {}) {
    online.requireInput(name, online.limitName);
    const query = pageQuery({ after, limit });
    if (state !== undefined) query.state = online.requireInput(state, (v) => ["active", "released"].includes(v));
    return this.#onlineLicence(licenceId, `resources/${name}/allocations`, "GET", undefined, online.parseAllocationPage, { query, signal });
  }

  listReleases({ channel, after, limit, signal } = {}) {
    const query = pageQuery({ after, limit });
    if (channel !== undefined) query.channel = online.requireInput(channel, online.targetName);
    return this.#onlineCall("/api/management/v1/releases", "GET", undefined, (v) => {
      online.exact(v, ["items", "next_cursor"]);
      if (!Array.isArray(v.items) || v.items.length > 100 || v.next_cursor !== null && !online.cursor(v.next_cursor)) online.invalid();
      const items = v.items.map(online.parseRelease);
      if (new Set(items.map((x) => x.id)).size !== items.length || channel !== undefined && items.some((x) => x.channel !== channel)) online.invalid();
      return Object.freeze({ items: Object.freeze(items), nextCursor: v.next_cursor });
    }, { query, signal });
  }

  getRelease(releaseId, { signal } = {}) {
    requireId(releaseId, "releaseId");
    return this.#onlineCall(`/api/management/v1/releases/${releaseId}`, "GET", undefined, (v) => {
      const result = online.parseRelease(v); if (result.id !== releaseId) online.invalid(); return result;
    }, { signal });
  }

  createRelease(input, { idempotencyKey, signal } = {}) {
    const body = online.metadataInput(input), key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineCall("/api/management/v1/releases", "POST", { ...body, idempotency_key: key }, (v) => {
      const result = online.parseRelease(v);
      if (result.state !== "draft" || result.channel !== body.channel || result.version !== body.version || result.notes !== body.notes) online.invalid();
      return Object.freeze({ ...result, idempotencyKey: key });
    }, { signal, key, status: 201 });
  }

  updateRelease(releaseId, input, { idempotencyKey, signal } = {}) {
    requireId(releaseId, "releaseId");
    const body = online.metadataInput(input), key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineCall(`/api/management/v1/releases/${releaseId}`, "PATCH", { ...body, idempotency_key: key }, (v) => {
      const result = online.parseRelease(v);
      if (result.id !== releaseId || result.state !== "draft" || result.channel !== body.channel || result.version !== body.version || result.notes !== body.notes) online.invalid();
      return Object.freeze({ ...result, idempotencyKey: key });
    }, { signal, key });
  }

  createArtifact(releaseId, input, options = {}) {
    return this.#artifactMutation(releaseId, undefined, input, options);
  }

  updateArtifact(releaseId, artifactId, input, options = {}) {
    requireId(artifactId, "artifactId");
    return this.#artifactMutation(releaseId, artifactId, input, options);
  }

  #artifactMutation(releaseId, artifactId, input, { idempotencyKey, signal }) {
    requireId(releaseId, "releaseId");
    const body = online.artifactInput(input), key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineCall(`/api/management/v1/releases/${releaseId}/artifacts${artifactId ? `/${artifactId}` : ""}`,
      artifactId ? "PATCH" : "POST", { ...body, idempotency_key: key }, (v) => {
        const result = online.parseArtifact(v);
        if (result.releaseId !== releaseId || artifactId && result.id !== artifactId || online.artifactFields.some((k) => v[k] !== body[k])) online.invalid();
        return Object.freeze({ ...result, idempotencyKey: key });
      }, { signal, key, status: artifactId ? 200 : 201 });
  }

  deleteArtifact(releaseId, artifactId, { idempotencyKey, signal } = {}) {
    requireId(releaseId, "releaseId"); requireId(artifactId, "artifactId");
    const key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineCall(`/api/management/v1/releases/${releaseId}/artifacts/${artifactId}`, "DELETE", { idempotency_key: key },
      () => Object.freeze({ idempotencyKey: key }), { signal, key, status: 204 });
  }

  publishRelease(releaseId, options = {}) { return this.#publish(releaseId, true, options); }
  unpublishRelease(releaseId, options = {}) { return this.#publish(releaseId, false, options); }
  #publish(releaseId, publish, { idempotencyKey, signal }) {
    requireId(releaseId, "releaseId");
    const key = resolveIdempotencyKey(idempotencyKey);
    return this.#onlineCall(`/api/management/v1/releases/${releaseId}/${publish ? "publish" : "unpublish"}`, "POST", { idempotency_key: key }, (v) => {
      const result = online.parseRelease(v);
      if (result.id !== releaseId || !(publish ? ["published"] : ["draft", "unpublished"]).includes(result.state)) online.invalid();
      return Object.freeze({ ...result, idempotencyKey: key });
    }, { signal, key });
  }

  #onlineLicence(licenceId, suffix, method, body, parse, options) {
    requireId(licenceId, "licenceId");
    return this.#onlineCall(`/api/management/v1/licences/${licenceId}/${suffix}`, method, body, parse, options);
  }

  async #onlineCall(path, method, body, parse, { signal, key, query, status = 200 } = {}) {
    try {
      const value = await this.#request(path, { bearer: this.#managementToken, method, body, signal, query, expectedStatus: status });
      try { return parse(value); } catch { throw new OrbitTransportError("invalid_response"); }
    } catch (error) { throw key ? uncertainMutation(error, key) : error; }
  }

  async #request(path, { bearer, method, body, signal, query, expectedStatus }) {
    const url = new URL(path, this.#origin);
    url.searchParams.set("application_id", this.#applicationId);
    url.searchParams.set("environment_id", this.#environmentId);
    for (const [name, value] of Object.entries(query ?? {})) url.searchParams.set(name, String(value));
    const headers = new Headers({
      accept: "application/json",
      authorization: `Bearer ${bearer}`,
      "orbit-client": CLIENT_HEADER,
    });
    if (body !== undefined) headers.set("content-type", "application/json");
    const controller = new AbortController();
    const abortExternal = () => controller.abort();
    signal?.addEventListener("abort", abortExternal, { once: true });
    if (signal?.aborted) controller.abort();
    const combined = controller.signal;
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let response;
    try {
      try {
        response = await this.#fetch(url, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          redirect: "error",
          credentials: "omit",
          signal: combined,
        });
      } catch {
        throw new OrbitTransportError(signal?.aborted ? "operation_cancelled" : controller.signal.aborted ? "timeout" : "request_failed");
      }
      let value;
      try {
        if (expectedStatus === 204 && response.status === 204) {
          if (combined.aborted) throw new OrbitTransportError(signal?.aborted ? "operation_cancelled" : "timeout");
          if (response.body !== null) throw new OrbitTransportError("invalid_response");
          return null;
        }
        value = await readJsonResponse(response);
      } catch (error) {
        if (combined.aborted) throw new OrbitTransportError(signal?.aborted ? "operation_cancelled" : "timeout");
        throw error;
      }
      if (combined.aborted) throw new OrbitTransportError(signal?.aborted ? "operation_cancelled" : "timeout");
      if (!response.ok) {
        const error = isRecord(value) && isRecord(value.error) ? value.error : null;
        if (expectedStatus !== undefined && (!error || typeof error.code !== "string" || !SAFE_CODE_PATTERN.test(error.code) ||
            typeof error.message !== "string" || !error.message || typeof error.request_id !== "string" ||
            !SAFE_REQUEST_ID_PATTERN.test(error.request_id))) {
          throw new OrbitTransportError("invalid_response");
        }
        const code = error && typeof error.code === "string" && SAFE_CODE_PATTERN.test(error.code)
          ? error.code
          : "http_error";
        const requestId = error && typeof error.request_id === "string" && SAFE_REQUEST_ID_PATTERN.test(error.request_id)
          ? error.request_id
          : null;
        if (["usage_limit_reached", "resource_limit_reached"].includes(code)) {
          let details;
          try {
            if (response.status !== 409 || !requestId || typeof error.message !== "string" || !error.message) online.invalid();
            details = online.parseCapacity(error, path, body);
          } catch { throw new OrbitTransportError("invalid_response"); }
          throw new OrbitLimitReachedError(code, requestId, details);
        }
        throw new OrbitApiError(response.status, code, requestId);
      }
      if (combined.aborted) throw new OrbitTransportError(signal?.aborted ? "operation_cancelled" : "timeout");
      if (expectedStatus !== undefined && response.status !== expectedStatus) throw new OrbitTransportError("unexpected_status");
      return value;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abortExternal);
      // Stop any unread response after an early content-type/length rejection.
      controller.abort();
    }
  }
}

function decodeAppKeyOrigin(encoded) {
  if (encoded.length % 4 === 1) throw new TypeError(APP_KEY_ERROR);
  let bytes;
  try {
    bytes = Buffer.from(encoded, "base64url");
  } catch {
    throw new TypeError(APP_KEY_ERROR);
  }
  if (bytes.length === 0 || bytes.toString("base64url") !== encoded) {
    throw new TypeError(APP_KEY_ERROR);
  }
  let origin;
  try {
    origin = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(APP_KEY_ERROR);
  }
  return requireAppKeyOrigin(origin);
}

function readAppKey(value) {
  const parsed = value !== null && (typeof value === "object" || typeof value === "function")
    ? APP_KEY_DATA.get(value)
    : undefined;
  if (!parsed) throw new TypeError(APP_KEY_ERROR);
  return parsed;
}

function requireAppKeyOrigin(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new TypeError(APP_KEY_ERROR);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(APP_KEY_ERROR);
  }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.origin !== value
  ) {
    throw new TypeError(APP_KEY_ERROR);
  }
  return url.origin;
}

function resolveIdempotencyKey(value) {
  return value === undefined ? randomUUID() : requireIdempotencyKey(value);
}

function requireId(value, name) {
  if (!isId(value)) throw new TypeError(`${name} must be an Orbit identifier`);
  return value;
}

function isId(value) {
  return typeof value === "string" && ID_PATTERN.test(value);
}

function requireHeaderSecret(value, name) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4096 ||
    !/^[\x21-\x7e]+$/.test(value)
  ) {
    throw new TypeError(`${name} must be a non-empty printable ASCII credential`);
  }
  return value;
}

function requireIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_PATTERN.test(value)) {
    throw new TypeError("idempotencyKey must contain 16 to 128 printable ASCII characters");
  }
  return value;
}

function requireText(value, name, maxBytes) {
  if (typeof value !== "string" || utf8Length(value) > maxBytes) {
    throw new TypeError(`${name} must be a string of at most ${maxBytes} UTF-8 bytes`);
  }
  return value;
}

function requireReason(value) {
  const reason = requireText(value, "reason", 500);
  if (reason.trim().length === 0) throw new TypeError("reason must not be blank");
  return reason;
}

function utf8Length(value) {
  return new TextEncoder().encode(value).byteLength;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value;
}

function isFutureTimestamp(value) {
  return isTimestamp(value) && Date.parse(value) > Date.now();
}

function isPage(value) {
  return isRecord(value) && Array.isArray(value.items) && value.items.length <= 100 &&
    value.items.every(isLicence) &&
    (value.next_cursor === null || isId(value.next_cursor));
}

function isIssuedLicences(value) {
  return isRecord(value) && Array.isArray(value.licences) && value.licences.length <= 100 &&
    Array.isArray(value.keys) && value.keys.length <= 100 &&
    typeof value.secret_replay_expired === "boolean" &&
    value.licences.every(isLicence) &&
    value.keys.every((key) => isRecord(key) && isId(key.licence_id) &&
      typeof key.key === "string" && /^[\x21-\x7e]{1,256}$/.test(key.key));
}

function isLicence(value) {
  if (!isRecord(value)) return false;
  try { online.parseDefinitions(value.usage_limits, true); online.parseDefinitions(value.resource_limits, false); }
  catch { return false; }
  const nullableTimestamp = (item) => item === null || isTimestamp(item);
  const nullableDuration = (item) => item === null || isSafeInteger(item, 60, 315_360_000);
  const entitlements = value.entitlements;
  return isId(value.id) && isId(value.policy_id) &&
    isPolicyName(value.policy_name) &&
    isSafeInteger(value.policy_version, 1, 2_147_483_647) &&
    typeof value.key_suffix === "string" && /^[A-Z0-9]{6}$/.test(value.key_suffix) &&
    ["enabled", "suspended", "revoked"].includes(value.status) &&
    ["unused", "active", "expired", "suspended", "revoked"].includes(value.state) &&
    ["perpetual", "fixed", "first_activation", "payment"].includes(value.expiry_mode) &&
    nullableDuration(value.duration_seconds) &&
    nullableTimestamp(value.first_used_at) && nullableTimestamp(value.expires_at) &&
    isSafeInteger(value.device_limit, 1, 100) && typeof value.hwid_locked === "boolean" &&
    isSafeInteger(value.concurrent_session_limit, 0, 65_535) &&
    typeof value.offline_allowed === "boolean" && isSafeInteger(value.offline_seconds, 0, 86_400) &&
    (value.offline_file_seconds === 0 || isSafeInteger(value.offline_file_seconds, 86_400, 31_622_400)) &&
    isEntitlements(entitlements) &&
    typeof value.reference === "string" && utf8Length(value.reference) <= 200 &&
    typeof value.note === "string" && utf8Length(value.note) <= 2000 &&
    isTimestamp(value.created_at) && nullableTimestamp(value.transfer_retry_at) &&
    (value.customer_id === null || isId(value.customer_id)) &&
    isSafeInteger(value.key_generation, 1, Number.MAX_SAFE_INTEGER);
}

function isPolicyName(value) {
  return typeof value === "string" && value.trim().length > 0 &&
    value.trim() === value && [...value].length <= 80 && !/\p{Cc}/u.test(value);
}

function isEntitlements(value) {
  return isRecord(value) && Object.keys(value).length <= 64 &&
    Object.entries(value).every(([name, enabled]) => ENTITLEMENT_PATTERN.test(name) && typeof enabled === "boolean");
}

function isSafeInteger(value, minimum, maximum) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function freezeLicence(value) {
  return Object.freeze({
    id: value.id,
    policy_id: value.policy_id,
    policy_name: value.policy_name,
    policy_version: value.policy_version,
    key_suffix: value.key_suffix,
    status: value.status,
    state: value.state,
    expiry_mode: value.expiry_mode,
    duration_seconds: value.duration_seconds,
    first_used_at: value.first_used_at,
    expires_at: value.expires_at,
    device_limit: value.device_limit,
    concurrent_session_limit: value.concurrent_session_limit,
    hwid_locked: value.hwid_locked,
    offline_allowed: value.offline_allowed,
    offline_seconds: value.offline_seconds,
    offline_file_seconds: value.offline_file_seconds,
    entitlements: Object.freeze({ ...value.entitlements }),
    usage_limits: online.parseDefinitions(value.usage_limits, true),
    resource_limits: online.parseDefinitions(value.resource_limits, false),
    reference: value.reference,
    note: value.note,
    created_at: value.created_at,
    transfer_retry_at: value.transfer_retry_at,
    customer_id: value.customer_id,
    key_generation: value.key_generation,
  });
}

function freezeIssuedLicences(value, idempotencyKey) {
  return Object.freeze({
    licences: Object.freeze(value.licences.map(freezeLicence)),
    keys: Object.freeze(value.keys.map((entry) => Object.freeze({
      licence_id: entry.licence_id,
      key: entry.key,
    }))),
    secret_replay_expired: value.secret_replay_expired,
    idempotencyKey,
  });
}

function uncertainMutation(cause, idempotencyKey) {
  if (cause instanceof OrbitTransportError || cause instanceof OrbitApiError && cause.status >= 500) {
    return new OrbitMutationUncertainError(idempotencyKey, cause);
  }
  return cause;
}

async function readJsonResponse(response) {
  if (!response || typeof response.status !== "number" || !response.headers || !response.body) {
    throw new OrbitTransportError("invalid_response");
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType)) {
    throw new OrbitTransportError("invalid_response");
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_RESPONSE_BYTES) {
    throw new OrbitTransportError("response_too_large");
  }
  const reader = response.body.getReader();
  let bytes = new Uint8Array(0);
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new OrbitTransportError("response_too_large");
      }
      if (size > bytes.length) {
        const capacity = Math.min(MAX_RESPONSE_BYTES, Math.max(size, 1024, bytes.length * 2));
        const grown = new Uint8Array(capacity);
        grown.set(bytes.subarray(0, size - value.byteLength));
        bytes = grown;
      }
      bytes.set(value, size - value.byteLength);
    }
  } catch (error) {
    if (error instanceof OrbitTransportError) throw error;
    throw new OrbitTransportError("invalid_response");
  } finally {
    reader.releaseLock();
  }
  try {
    return uniqueJson(bytes.subarray(0, size), MAX_RESPONSE_BYTES);
  } catch {
    throw new OrbitTransportError("invalid_response");
  }
}

function pageQuery({ after, limit }) {
  const query = {};
  if (after !== undefined) query.after = online.requireInput(after, online.cursor);
  if (limit !== undefined) query.limit = online.requireInput(limit, (v) => Number.isInteger(v) && v >= 1 && v <= 100);
  return query;
}
