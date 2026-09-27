export class OrbitError extends Error {
  constructor(kind, code, requestId = undefined, status = 1) {
    super(`Orbit SDK operation failed (kind=${kind}, code=${code}${requestId ? `, request_id=${requestId}` : ""})`);
    this.name = "OrbitError";
    this.kind = kind;
    this.code = code;
    this.requestId = requestId;
    this.status = status;
  }
}

export class NotActivatedError extends OrbitError {
  constructor() {
    super("denied", "access_unavailable");
    this.name = "NotActivatedError";
  }
}

export class FeatureUnavailableError extends OrbitError {
  constructor() {
    super("denied", "feature_unavailable");
    this.name = "FeatureUnavailableError";
  }
}

export class LimitReachedError extends OrbitError {
  constructor(code, requestId, details) {
    super("denied", code, requestId, 409);
    this.name = "LimitReachedError";
    Object.assign(this, details);
  }
}

export class MutationUncertainError extends OrbitError {
  constructor(idempotencyKey, cause) {
    super(cause.kind ?? "invalid_response", cause.code ?? "invalid_online_response", cause.requestId, cause.status);
    this.name = "MutationUncertainError";
    this.idempotencyKey = idempotencyKey;
    Object.defineProperty(this, "cause", { value: cause, configurable: true, writable: true });
  }
}

export function fail(kind, code, requestId, status) {
  return new OrbitError(kind, code, requestId, status);
}

export const ErrorKind = Object.freeze({
  CONFIGURATION: "configuration",
  CANCELLED: "cancelled",
  DENIED: "denied",
  INVALID_RESPONSE: "invalid_response",
  REAUTHENTICATION_REQUIRED: "reauthentication_required",
  STALE_RESPONSE: "stale_response",
  STORAGE: "storage",
  CLOCK_UNCERTAIN: "clock_uncertain",
  TRANSIENT: "transient",
  TRANSPORT_SECURITY: "transport_security",
  INTERNAL: "internal",
});
