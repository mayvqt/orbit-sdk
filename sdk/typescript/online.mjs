import { isIP } from "node:net";

const idPattern = /^[A-Za-z0-9_-]{1,128}$/;
const namePattern = /^[a-z][a-z0-9_]{0,63}$/;
const targetPattern = /^[a-z][a-z0-9_-]{0,31}$/;
export const integer = (v, min = 0) => Number.isSafeInteger(v) && v >= min;
export const identifier = (v) => typeof v === "string" && idPattern.test(v);
export const cursor = (v) => typeof v === "string" && /^[A-Za-z0-9_.-]{1,256}$/.test(v);
export const limitName = (v) => typeof v === "string" && namePattern.test(v);
export const targetName = (v) => typeof v === "string" && targetPattern.test(v);
export const record = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v, min, max) => typeof v === "string" && v.isWellFormed() && Buffer.byteLength(v) >= min && Buffer.byteLength(v) <= max;
export function invalid() { throw new TypeError("Invalid Orbit online response"); }
export function requireInput(value, predicate) {
  if (!predicate(value)) throw new TypeError("Invalid Orbit operation input");
  return value;
}
export function exact(value, names) {
  if (!record(value) || Object.keys(value).length !== names.length || !names.every((k) => Object.hasOwn(value, k))) invalid();
  return value;
}
export function instant(value) {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value)) invalid();
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || ms < 0 || new Date(ms).toISOString().slice(0, 19) !== value.slice(0, 19)) invalid();
  const date = new Date(ms);
  return new Proxy(date, { get(target, key) {
    if (typeof key === "string" && key.startsWith("set")) return () => { throw new TypeError("Read-only date"); };
    const result = Reflect.get(target, key, target);
    return typeof result === "function" ? result.bind(target) : result;
  }, set() { throw new TypeError("Read-only date"); } });
}
export function deliveryUrl(value, protectedEndpoint = false) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048 || !value.startsWith("https://") ||
      /[^\x21-\x7e]|[\\#<>"{}|^`]/.test(value) || protectedEndpoint && value.includes("?") || /%(?![a-fA-F0-9]{2})/.test(value)) invalid();
  const authority = value.slice(8).split(/[/?]/, 1)[0];
  if (!authority || /[@%]/.test(authority)) invalid();
  let port;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0 || isIP(authority.slice(1, close)) !== 6) invalid();
    const suffix = authority.slice(close + 1);
    if (suffix && !suffix.startsWith(":")) invalid();
    port = suffix ? suffix.slice(1) : undefined;
  } else {
    if (!/^[A-Za-z0-9.-]+(?::[^:]*)?$/.test(authority)) invalid();
    port = authority.includes(":") ? authority.split(":")[1] : undefined;
  }
  if (port !== undefined && (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) invalid();
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash) invalid();
  return value;
}
export function updateInput(installedReleaseNumber, { channel = "stable", target } = {}) {
  requireInput(installedReleaseNumber, integer);
  requireInput(channel, targetName);
  if (target === undefined) {
    const platform = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform];
    const architecture = { x64: "x64", arm64: "arm64", ia32: "x86" }[process.arch] ??
      (process.arch === "arm" && Number(process.config.variables.arm_version) >= 7 ? "armv7" : undefined);
    if (!platform || !architecture) throw new TypeError("An explicit update target is required");
    target = { platform, architecture };
  }
  requireInput(target, (v) => record(v) && targetName(v.platform) && targetName(v.architecture));
  return { installed_release_number: installedReleaseNumber, channel, platform: target.platform, architecture: target.architecture };
}
export const artifactFields = ["platform", "architecture", "filename", "byte_length", "sha256", "delivery_mode", "url", "required_feature"];
export function artifactInput(value) {
  requireInput(value, record);
  const wire = { platform: value.platform, architecture: value.architecture, filename: value.filename,
    byte_length: value.byteLength, sha256: value.sha256, delivery_mode: value.deliveryMode,
    url: value.url, required_feature: value.requiredFeature ?? null };
  parseArtifact({ id: "artifact", release_id: "release", ...wire });
  return wire;
}
export function parseArtifact(value) {
  const v = exact(value, ["id", "release_id", ...artifactFields]);
  if (!identifier(v.id) || !identifier(v.release_id) || !targetName(v.platform) || !targetName(v.architecture) ||
      !text(v.filename, 1, 255) || [".", ".."].includes(v.filename) || /[\x00-\x1f\x7f/\\]/.test(v.filename) ||
      !integer(v.byte_length, 1) || typeof v.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(v.sha256) ||
      !["public", "protected"].includes(v.delivery_mode) || v.required_feature !== null && !limitName(v.required_feature)) invalid();
  deliveryUrl(v.url, v.delivery_mode === "protected");
  return Object.freeze({ id: v.id, releaseId: v.release_id, platform: v.platform, architecture: v.architecture,
    filename: v.filename, byteLength: v.byte_length, sha256: v.sha256, deliveryMode: v.delivery_mode,
    url: v.url, requiredFeature: v.required_feature });
}
export function metadataInput(v) {
  requireInput(v, (x) => record(x) && targetName(x.channel) && text(x.version, 1, 64) && text(x.notes, 0, 8192));
  return { channel: v.channel, version: v.version, notes: v.notes };
}
export function parseRelease(value) {
  const v = exact(value, ["id", "channel", "version", "notes", "release_number", "state", "created_at", "published_at", "artifacts"]);
  if (!identifier(v.id) || !targetName(v.channel) || !text(v.version, 1, 64) || !text(v.notes, 0, 8192) ||
      !["draft", "published", "unpublished"].includes(v.state) || v.release_number !== null && !integer(v.release_number, 1) ||
      (v.state === "draft") !== (v.release_number === null) || (v.release_number === null) !== (v.published_at === null) ||
      !Array.isArray(v.artifacts) || v.artifacts.length > 32 || v.state === "published" && v.artifacts.length === 0) invalid();
  const artifacts = v.artifacts.map(parseArtifact);
  if (artifacts.some((a) => a.releaseId !== v.id) || new Set(artifacts.map((a) => a.id)).size !== artifacts.length ||
      new Set(artifacts.map((a) => `${a.platform}/${a.architecture}`)).size !== artifacts.length) invalid();
  return Object.freeze({ id: v.id, channel: v.channel, version: v.version, notes: v.notes, releaseNumber: v.release_number,
    state: v.state, createdAt: instant(v.created_at), publishedAt: v.published_at === null ? null : instant(v.published_at),
    artifacts: Object.freeze(artifacts) });
}
export function parseUpdate(value, expected) {
  const v = exact(value, ["release", "artifact"]);
  if (v.release === null && v.artifact === null) return null;
  const release = parseRelease(v.release), artifact = parseArtifact(v.artifact);
  if (release.state !== "published" || release.releaseNumber <= expected.installed_release_number || release.channel !== expected.channel ||
      artifact.platform !== expected.platform || artifact.architecture !== expected.architecture || release.artifacts.length !== 1 ||
      JSON.stringify(release.artifacts[0]) !== JSON.stringify(artifact)) invalid();
  return Object.freeze({ release, artifact });
}
export function parseAuthorization(value, releaseId, artifactId) {
  const v = exact(value, ["artifact", "ticket", "expires_at"]);
  const artifact = parseArtifact(v.artifact);
  if (artifact.releaseId !== releaseId || artifact.id !== artifactId) invalid();
  let expiresAt = null;
  if (artifact.deliveryMode === "public") {
    if (v.ticket !== null || v.expires_at !== null) invalid();
  } else {
    expiresAt = instant(v.expires_at);
    if (typeof v.ticket !== "string" || v.ticket.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v.ticket) ||
        +expiresAt <= Date.now() || +expiresAt > Date.now() + 150000) invalid();
  }
  const result = { artifact, expiresAt };
  // Bearers are available explicitly, but absent from incidental JSON/log inspection.
  Object.defineProperty(result, "ticket", { value: v.ticket, enumerable: false });
  return Object.freeze(result);
}
export function parseDefinitions(value, usage) {
  if (!record(value) || Object.keys(value).length > 32) invalid();
  const result = Object.create(null);
  for (const [key, item] of Object.entries(value)) {
    exact(item, usage ? ["limit", "period", "required_feature"] : ["limit", "required_feature"]);
    if (!limitName(key) || !integer(item.limit) || item.required_feature !== null && !limitName(item.required_feature) ||
        usage && !["day", "month", "lifetime"].includes(item.period)) invalid();
    result[key] = Object.freeze({ limit: item.limit, ...(usage ? { period: item.period } : {}), requiredFeature: item.required_feature });
  }
  return Object.freeze(result);
}
export function parseCounter(value, name, usage, extras = []) {
  const v = exact(value, ["name", "limit", "used", "remaining", ...(usage ? ["period", "period_started_at", "resets_at"] : []), ...extras]);
  if (v.name !== name || !limitName(v.name) || ![v.limit, v.used, v.remaining].every((x) => integer(x)) ||
      v.used > v.limit || v.remaining !== v.limit - v.used) invalid();
  const result = { name: v.name, limit: v.limit, used: v.used, remaining: v.remaining };
  if (usage) {
    let start = null, reset = null;
    if (v.period === "lifetime") {
      if (v.period_started_at !== null || v.resets_at !== null) invalid();
    } else if (["day", "month"].includes(v.period)) {
      start = instant(v.period_started_at); reset = instant(v.resets_at);
      if (start.getUTCHours() || start.getUTCMinutes() || start.getUTCSeconds() || start.getUTCMilliseconds() ||
          v.period === "day" && +reset - +start !== 86400000 ||
          v.period === "month" && (start.getUTCDate() !== 1 || reset.getUTCDate() !== 1 || reset.getUTCHours() ||
            reset.getUTCMinutes() || reset.getUTCSeconds() || reset.getUTCMilliseconds() || +reset - +start < 28 * 86400000 || +reset - +start > 31 * 86400000)) invalid();
    } else invalid();
    Object.assign(result, { period: v.period, periodStartedAt: start, resetsAt: reset });
  }
  return Object.freeze(result);
}
export function parseConsumption(value, name, key, units) {
  const counter = parseCounter(value, name, true, ["idempotency_key", "consumed_units"]);
  if (value.idempotency_key !== key || !integer(value.consumed_units, 1) || value.consumed_units !== units || counter.used < units) invalid();
  return Object.freeze({ ...counter, idempotencyKey: key, consumedUnits: units });
}
export function parseAllocation(value, name, key, expected = {}) {
  const counter = parseCounter(value, name, false, ["allocation_id", "resource_id", "units", "state", "idempotency_key"]);
  if (!identifier(value.allocation_id) || !identifier(value.resource_id) || !integer(value.units, 1) ||
      !["active", "released"].includes(value.state) || value.idempotency_key !== key ||
      expected.resourceId !== undefined && value.resource_id !== expected.resourceId || expected.units !== undefined && value.units !== expected.units ||
      expected.allocationId !== undefined && (value.allocation_id !== expected.allocationId || value.state !== "released") ||
      value.state === "active" && value.units > counter.used) invalid();
  return Object.freeze({ ...counter, allocationId: value.allocation_id, resourceId: value.resource_id, units: value.units,
    state: value.state, idempotencyKey: key });
}
export function parseCapacity(value, route, body) {
  exact(value, ["code", "message", "request_id", "counter", "idempotency_key", "requested_units"]);
  const usage = value.code === "usage_limit_reached";
  const match = /\/(usage|resources)\/([a-z][a-z0-9_]{0,63})\/(consume|acquire)$/.exec(route);
  if (!match || match[1] !== (usage ? "usage" : "resources") || match[3] !== (usage ? "consume" : "acquire") ||
      !["usage_limit_reached", "resource_limit_reached"].includes(value.code) || value.idempotency_key !== body.idempotency_key ||
      !integer(value.requested_units, 1) || value.requested_units !== body.units) invalid();
  const counter = parseCounter(value.counter, match[2], usage);
  if (value.requested_units <= counter.remaining) invalid();
  return Object.freeze({ counter, idempotencyKey: value.idempotency_key, requestedUnits: value.requested_units });
}
export function parseAllocationPage(value) {
  exact(value, ["items", "next_cursor"]);
  if (!Array.isArray(value.items) || value.items.length > 100 || value.next_cursor !== null && !cursor(value.next_cursor)) invalid();
  const items = value.items.map((v) => {
    exact(v, ["allocation_id", "resource_id", "units", "state", "created_at", "released_at"]);
    if (!identifier(v.allocation_id) || !identifier(v.resource_id) || !integer(v.units, 1) ||
        !["active", "released"].includes(v.state) || (v.state === "active") !== (v.released_at === null)) invalid();
    return Object.freeze({ allocationId: v.allocation_id, resourceId: v.resource_id, units: v.units, state: v.state,
      createdAt: instant(v.created_at), releasedAt: v.released_at === null ? null : instant(v.released_at) });
  });
  if (new Set(items.map((v) => v.allocationId)).size !== items.length) invalid();
  return Object.freeze({ items: Object.freeze(items), nextCursor: value.next_cursor });
}
