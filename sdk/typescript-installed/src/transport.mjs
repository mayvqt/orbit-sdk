import https from "node:https";
import { lookup as dnsLookup } from "node:dns";
import { randomInt } from "node:crypto";
import { validateOrigin } from "./app-key.mjs";
import { fail, ErrorKind } from "./errors.mjs";
import { uniqueJson, isText } from "./json.mjs";

const PREFIX = "/api/client/v1/";
const JWKS_PATH = "/.well-known/orbit-jwks.json";
const MAX_BYTES = 64 * 1024;
const MAX_ROUTE = 2048;
const DEADLINE_MS = 30000;
const ATTEMPT_MS = 10000;
const RETRYABLE_NETWORK = new Set(["EAI_AGAIN", "ECONNRESET", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "EPIPE", "ETIMEDOUT"]);
const TLS_ERRORS = new Set(["CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT", "ERR_TLS_CERT_ALTNAME_INVALID", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE"]);

export class HttpTransport {
  constructor(origin, options = {}) {
    this.origin = new URL(validateOrigin(origin));
    this.ca = options.ca;
    this._lookup = options.lookup ?? lookupAddresses;
  }

  get(route, signal) {
    return this.#request("GET", route, undefined, undefined, true, signal);
  }

  getBearer(route, token, signal) {
    if (route.split("?", 1)[0] !== `${PREFIX}licences`) invalidRoute();
    return this.#request("GET", route, undefined, token, true, signal);
  }

  deleteBearer(route, token, signal) {
    if (route.split("?", 1)[0] !== `${PREFIX}sessions/current`) invalidRoute();
    return this.#request("DELETE", route, undefined, token, false, signal).then((body) => {
      if (body !== null) throw fail(ErrorKind.INVALID_RESPONSE, "unexpected_response_body");
    });
  }

  post(route, body, retrySafe, signal) {
    let bytes;
    try {
      bytes = Buffer.from(JSON.stringify(body), "utf8");
    } catch {
      throw fail(ErrorKind.CONFIGURATION, "invalid_request");
    }
    if (bytes.length > MAX_BYTES) throw fail(ErrorKind.CONFIGURATION, "request_too_large");
    return this.#request("POST", route, bytes, undefined, retrySafe, signal);
  }

  async #request(method, route, body, token, retrySafe, externalSignal) {
    const endpoint = this.#endpoint(route);
    if (token !== undefined && (!tokenMatches(token) || token.length > 256)) {
      throw fail(ErrorKind.CONFIGURATION, "invalid_authorization");
    }
    if ((method === "DELETE" || (method === "GET" && route.split("?", 1)[0] === `${PREFIX}licences`)) && !token) {
      throw fail(ErrorKind.CONFIGURATION, "invalid_authorization");
    }
    const started = Date.now();
    const deadline = started + DEADLINE_MS;
    let addresses;
    try {
      addresses = await withTimeout(this._lookup(this.origin.hostname), Math.min(ATTEMPT_MS, deadline - Date.now()), externalSignal);
    } catch (error) {
      throw classify(error, externalSignal, "network_unavailable");
    }
    if (!Array.isArray(addresses) || addresses.length === 0 || addresses.length > 16) {
      throw fail(ErrorKind.TRANSIENT, "network_unavailable");
    }
    let last;
    for (let attempt = 0; attempt < 3; attempt++) {
      checkSignal(externalSignal);
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw fail(ErrorKind.TRANSIENT, "request_timeout");
      try {
        return await this.#attempt(method, endpoint, body, token, addresses[attempt % addresses.length], Math.min(ATTEMPT_MS, remaining), externalSignal);
      } catch (error) {
        const classified = classify(error, externalSignal);
        if (!retrySafe || attempt === 2 || classified.kind !== ErrorKind.TRANSIENT) throw classified;
        last = classified;
        const delay = Math.max(randomInt(250, 506) * (2 ** attempt), (classified.retryAfter ?? 0) * 1000);
        if (delay >= deadline - Date.now()) throw classified;
        await abortableDelay(delay, externalSignal);
      }
    }
    throw last ?? fail(ErrorKind.TRANSIENT, "request_timeout");
  }

  #endpoint(route) {
    if (typeof route !== "string" || route.length > MAX_ROUTE || route.startsWith("//") ||
        route.includes("//") || route.includes("\\") || route.includes("#") || (route.match(/\?/g) ?? []).length > 1 || /[\x00-\x20\x7f%]/.test(route)) invalidRoute();
    const [pathname, query = ""] = route.split("?");
    if (!(pathname.startsWith(PREFIX) || pathname === JWKS_PATH) || pathname.endsWith("/") ||
        pathname.split("/").some((part) => part === "." || part === "..")) invalidRoute();
    if (route.includes("?")) {
      const queryRoutes = [JWKS_PATH, `${PREFIX}licences`, `${PREFIX}sessions/current`];
      if (!queryRoutes.includes(pathname)) invalidRoute();
      const pairs = query.split("&");
      const expected = ["application_id", "environment_id"];
      if (pathname === `${PREFIX}licences` && pairs.length === 3) expected.push("after");
      if (pairs.length !== expected.length) invalidRoute();
      for (let i = 0; i < expected.length; i++) {
        const [name, value, ...rest] = pairs[i].split("=");
        if (rest.length || name !== expected[i] || !isOpaque(value)) invalidRoute();
      }
    } else if ([`${PREFIX}licences`, `${PREFIX}sessions/current`].includes(pathname)) {
      invalidRoute();
    }
    return `${pathname}${route.includes("?") ? `?${query}` : ""}`;
  }

  #attempt(method, target, body, token, address, timeoutMs, signal) {
    checkSignal(signal);
    return new Promise((resolve, reject) => {
      let settled = false;
      let received = 0;
      const chunks = [];
      const timer = setTimeout(() => request.destroy(Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" })), timeoutMs);
      timer.unref?.();
      const request = https.request({
        protocol: "https:",
        hostname: this.origin.hostname,
        port: this.origin.port || 443,
        path: target,
        method,
        agent: false,
        ca: this.ca,
        servername: this.origin.hostname,
        lookup: (_hostname, options, callback) => options?.all
          ? callback(null, [address])
          : callback(null, address.address, address.family),
        headers: {
          Accept: "application/json",
          ...(body ? { "Content-Type": "application/json" } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      }, (response) => {
        const length = response.headers["content-length"];
        if (typeof length === "string" && /^\d+$/.test(length) && Number(length) > MAX_BYTES) {
          response.destroy();
          finish(fail(ErrorKind.INVALID_RESPONSE, "response_too_large"));
          return;
        }
        response.on("data", (chunk) => {
          received += chunk.length;
          if (received > MAX_BYTES) {
            response.destroy();
            finish(fail(ErrorKind.INVALID_RESPONSE, "response_too_large"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", (error) => finish(error));
        response.on("end", () => {
          const bytes = Buffer.concat(chunks, received);
          const status = response.statusCode ?? 0;
          if (status === 204) {
            finish(bytes.length ? fail(ErrorKind.INVALID_RESPONSE, "invalid_response") : null, null);
            return;
          }
          if (status >= 200 && status < 300) {
            try {
              uniqueJson(bytes);
              finish(null, bytes);
            } catch (error) {
              finish(error);
            }
            return;
          }
          try {
            const envelope = uniqueJson(bytes);
            if (!envelope || typeof envelope !== "object" || !envelope.error || typeof envelope.error !== "object") {
              throw fail(ErrorKind.INVALID_RESPONSE, "invalid_error_response");
            }
            const item = envelope.error;
            if (typeof item.code !== "string" || !/^[a-z0-9_]{1,128}$/.test(item.code) ||
                typeof item.message !== "string" || !item.message || typeof item.request_id !== "string" ||
                !/^[A-Za-z0-9_-]{1,64}$/.test(item.request_id)) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_error_response");
            if ((status === 429 && item.code === "rate_limited") || (status === 503 && item.code === "service_unavailable")) {
              const retryAfter = parseRetryAfter(response.headers["retry-after"]);
              finish(fail(ErrorKind.TRANSIENT, item.code, item.request_id, status), undefined, retryAfter);
            } else if (status === 502 || status === 504 || status === 503) {
              finish(Object.assign(fail(ErrorKind.TRANSIENT, "service_unavailable"), { retryAfter: parseRetryAfter(response.headers["retry-after"]) }));
            } else if ([401, 403, 404, 409, 422].includes(status) || status === 429 || status >= 500) {
              finish(fail(ErrorKind.DENIED, item.code, item.request_id, status));
            } else {
              finish(fail(ErrorKind.INVALID_RESPONSE, "unexpected_status"));
            }
          } catch (error) {
            finish(error);
          }
        });
      });
      const abort = () => request.destroy(Object.assign(new Error("operation cancelled"), { name: "AbortError" }));
      signal?.addEventListener("abort", abort, { once: true });
      request.on("error", (error) => finish(error));
      request.on("timeout", () => request.destroy(Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" })));
      if (body) request.write(body);
      request.end();
      function finish(error, value, retryAfter = undefined) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        if (error) {
          if (retryAfter !== undefined) error.retryAfter = retryAfter;
          reject(error);
        } else resolve(value);
      }
    });
  }
}

async function lookupAddresses(hostname) {
  return new Promise((resolve, reject) => dnsLookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
    if (error) reject(error);
    else resolve(addresses.slice(0, 16));
  }));
}

function classify(error, signal, fallback = undefined) {
  if (signal?.aborted || error?.name === "AbortError") return fail(ErrorKind.CANCELLED, "operation_cancelled");
  if (error?.kind) return error;
  if (TLS_ERRORS.has(error?.code) || String(error?.code ?? "").startsWith("ERR_SSL")) return fail(ErrorKind.TRANSPORT_SECURITY, "tls_failure");
  if (error?.code === "ETIMEDOUT" || error?.code === "ESOCKETTIMEDOUT") return fail(ErrorKind.TRANSIENT, "request_timeout");
  if (RETRYABLE_NETWORK.has(error?.code)) return fail(ErrorKind.TRANSIENT, fallback ?? "network_unavailable");
  return fail(ErrorKind.TRANSPORT_SECURITY, "transport_failure");
}

function parseRetryAfter(value) {
  if (typeof value === "string" && /^\d+$/.test(value)) return Math.min(Number(value), 30);
  return undefined;
}

function tokenMatches(value) {
  return typeof value === "string" && value.length > 0 && /^[A-Za-z0-9_-]+$/.test(value);
}

function isOpaque(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function invalidRoute() {
  throw fail(ErrorKind.CONFIGURATION, "invalid_route");
}

function checkSignal(signal) {
  if (signal?.aborted) throw fail(ErrorKind.CANCELLED, "operation_cancelled");
}

function withTimeout(promise, timeout, signal) {
  if (timeout <= 0) return Promise.reject(fail(ErrorKind.TRANSIENT, "request_timeout"));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => finish(fail(ErrorKind.TRANSIENT, "request_timeout")), timeout);
    const abort = () => finish(fail(ErrorKind.CANCELLED, "operation_cancelled"));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    Promise.resolve(promise).then((value) => finish(null, value), (error) => finish(error));
  });
}

function abortableDelay(ms, signal) {
  checkSignal(signal);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    const abort = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      reject(fail(ErrorKind.CANCELLED, "operation_cancelled"));
    };
    signal?.addEventListener("abort", abort, { once: true });
    timer.unref?.();
  });
}
