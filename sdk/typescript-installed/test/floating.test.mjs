import assert from "node:assert/strict";
import { createPrivateKey, createSign } from "node:crypto";
import { chmod, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { openClientForTesting, setClockForTesting } from "../src/client.mjs";
import { ErrorKind } from "../src/errors.mjs";

const key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g");
const signingKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));
const sessionJwks = Buffer.from(JSON.stringify(JSON.parse(await readFile(new URL("../../../contracts/sdk/session-grants.json", import.meta.url), "utf8")).jwks));
const grantJwks = JSON.parse(await readFile(new URL("../../../contracts/sdk/grants.json", import.meta.url), "utf8")).jwks;

function timestamp(seconds) { return new Date(seconds * 1000).toISOString(); }

function signedSession(body, sessionId, sequence, now) {
  const claims = {
    iss: key.issuer,
    aud: `orbit-session:${key.application_id}:${key.environment_id}`,
    sub: "licence-1",
    jti: `session-${sessionId}-${sequence}`,
    iat: now,
    nbf: now,
    exp: now + 120,
    application_id: key.application_id,
    environment_id: key.environment_id,
    activation_id: "activation-1",
    installation_id: body.installation_id,
    binding_mode: "none",
    policy_version: 1,
    entitlements: { export: true, sync: false },
    refresh_after: now + 60,
    offline_allowed: false,
    licence_expires_at: null,
    session_id: sessionId,
    session_sequence: sequence,
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-session+jwt", kid: "test-fixture" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const signer = createSign("SHA256");
  signer.update(input, "ascii");
  signer.end();
  return `${input}.${signer.sign({ key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

class FloatingTransport {
  requests = [];
  failStart = false;
  failRenew = 0;
  denyStart = false;
  denyStartCode = null;
  denyRenew = null;
  failJwks = false;
  beforeJwks = null;
  blockStart = false;
  blockRenew = false;
  entered;
  enteredRenew;
  release;
  releaseRenew;
  renewInFlight = 0;
  maxRenewInFlight = 0;
  activationCount = 0;
  nowSeconds = () => Math.floor(Date.now() / 1000);
  constructor() {
    this.entered = new Promise((resolve) => { this.signalEntered = resolve; });
    this.release = new Promise((resolve) => { this.releaseStart = resolve; });
    this.enteredRenew = new Promise((resolve) => { this.signalRenewEntered = resolve; });
    this.releaseRenew = new Promise((resolve) => { this.releaseRenewal = resolve; });
  }
  config(body) {
    return { ...body };
  }
  async post(route, body, retrySafe, signal) {
    this.requests.push({ route, body: { ...body }, retrySafe });
    if (route.endsWith("/activations")) {
      this.activationCount++;
      return activation(body, false, this.nowSeconds());
    }
    if (route.endsWith("/validate")) return activation(body, true, this.nowSeconds());
    if (route.endsWith("/sessions") && !route.endsWith("/renew") && !route.endsWith("/end")) {
      if (this.blockStart) {
        this.signalEntered();
        while (true) {
          if (signal?.aborted) {
            const error = new Error("cancelled"); error.kind = ErrorKind.CANCELLED; error.code = "operation_cancelled"; throw error;
          }
          const settled = await Promise.race([this.release.then(() => true), new Promise((resolve) => setTimeout(() => resolve(false), 5))]);
          if (settled) break;
        }
      }
      if (this.failStart) {
        this.failStart = false;
        const error = new Error("lost start reply"); error.kind = ErrorKind.TRANSIENT; error.code = "network_unavailable"; throw error;
      }
      if (this.denyStart) {
        const error = new Error("seat full"); error.kind = ErrorKind.DENIED; error.code = "concurrent_session_limit_reached"; throw error;
      }
      if (this.denyStartCode) {
        const error = new Error("terminal start denial"); error.kind = ErrorKind.DENIED; error.code = this.denyStartCode; this.denyStartCode = null; throw error;
      }
      const now = this.nowSeconds();
      return Buffer.from(JSON.stringify({ session_id: body.session_id, sequence: 1,
        expires_at: timestamp(now + 120), server_time: timestamp(now),
        grant: signedSession(body, body.session_id, 1, now) }));
    }
    if (route.endsWith("/renew")) {
      this.renewInFlight++;
      this.maxRenewInFlight = Math.max(this.maxRenewInFlight, this.renewInFlight);
      try {
        if (this.blockRenew) await this.releaseRenew;
        if (this.denyRenew) {
          const error = new Error("renewal denied"); error.kind = ErrorKind.DENIED; error.code = this.denyRenew; this.denyRenew = null; throw error;
        }
        if (this.failRenew > 0) {
          this.failRenew--;
          const error = new Error("lost renewal reply"); error.kind = ErrorKind.TRANSIENT; error.code = "network_unavailable"; throw error;
        }
        const now = this.nowSeconds();
        const sessionId = route.split("/").at(-2);
        return Buffer.from(JSON.stringify({ session_id: sessionId, sequence: body.sequence,
          expires_at: timestamp(now + 120), server_time: timestamp(now),
          grant: signedSession(body, sessionId, body.sequence, now) }));
      } finally {
        this.renewInFlight--;
      }
    }
    if (route.endsWith("/end")) return null;
    throw new Error(`unexpected route ${route}`);
  }
  async get(route) {
    this.requests.push({ route, body: null, retrySafe: true });
    if (route.startsWith("/.well-known/orbit-jwks.json?")) {
      await this.beforeJwks?.();
      if (this.failJwks) {
        this.failJwks = false;
        const error = new Error("JWKS outage"); error.kind = ErrorKind.TRANSIENT; error.code = "network_unavailable"; throw error;
      }
      return Buffer.from(sessionJwks);
    }
    throw new Error(`unexpected GET ${route}`);
  }
}

class OrdinaryTransport extends FloatingTransport {
  async post(route, body, retrySafe, signal) {
    if (route.endsWith("/activations")) {
      this.requests.push({ route, body: { ...body }, retrySafe });
      return ordinaryActivation(body, false, this.nowSeconds());
    }
    if (route.endsWith("/validate")) {
      this.requests.push({ route, body: { ...body }, retrySafe });
      return ordinaryActivation(body, true, this.nowSeconds());
    }
    return super.post(route, body, retrySafe, signal);
  }
  async get(route) {
    this.requests.push({ route, body: null, retrySafe: true });
    if (route.startsWith("/.well-known/orbit-jwks.json?")) return Buffer.from(JSON.stringify(grantJwks));
    throw new Error(`unexpected GET ${route}`);
  }
}

function activation(body, previous, now = Math.floor(Date.now() / 1000)) {
  return Buffer.from(JSON.stringify({
    activation_id: "activation-1", installation_id: body.installation_id, licence_id: "licence-1",
    credential: previous ? null : "a".repeat(43), credential_expires_at: null, grant: null,
    server_time: timestamp(now), binding_mode: "none", fingerprint_provider: body.fingerprint_provider,
    licence_expires_at: null, secret_replay_expired: false, session_required: true,
  }));
}

function ordinaryActivation(body, previous, now = Math.floor(Date.now() / 1000)) {
  const claims = {
    iss: key.issuer, aud: `orbit:${key.application_id}:${key.environment_id}`,
    sub: "licence-1", jti: `ordinary-${Math.random()}`, iat: now, nbf: now, exp: now + 300,
    application_id: key.application_id, environment_id: key.environment_id,
    activation_id: "activation-1", installation_id: body.installation_id,
    binding_mode: "none", policy_version: 1, entitlements: { export: true },
    refresh_after: now + 60, offline_allowed: false, licence_expires_at: null,
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-access+jwt", kid: "test-key" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const signer = createSign("SHA256"); signer.update(input, "ascii"); signer.end();
  return Buffer.from(JSON.stringify({
    activation_id: "activation-1", installation_id: body.installation_id,
    credential: previous ? null : "a".repeat(43), credential_expires_at: null,
    grant: `${input}.${signer.sign({ key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`,
    server_time: timestamp(now), binding_mode: "none", fingerprint_provider: body.fingerprint_provider,
    licence_expires_at: null, secret_replay_expired: false,
  }));
}

async function makeClient(statePath, transport, { lifecycle = false } = {}) {
  return openClientForTesting(key, { statePath, machineBinding: false, transport, skipInitialRefresh: true, lifecycle });
}

// Storage writes are real file I/O, so bound the wait by wall time rather than
// event-loop turns; performance.now() and setImmediate are never mocked here.
async function waitUntil(predicate, label, timeoutMs = 10_000) {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) assert.fail(`timed out waiting for ${label}`);
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function openWithFakeLifecycle(context, base, transport) {
  const fakeNow = Math.floor(Date.now() / 1000) * 1000;
  const fakeElapsed = 21_000_000_000n;
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now: fakeNow });
  const restoreClock = setClockForTesting({
    elapsedNs: () => fakeElapsed + BigInt(Date.now() - fakeNow) * 1_000_000n,
    wallSeconds: () => Math.floor(Date.now() / 1000),
  });
  transport.nowSeconds = () => Math.floor(Date.now() / 1000);
  const client = await makeClient(path.join(base, "state"), transport, { lifecycle: true });
  await client.activate("floating-key");
  return { client, restoreClock };
}

async function blockNextRenewal(context, transport) {
  transport.blockRenew = true;
  context.mock.timers.tick(60_000);
  await waitUntil(() => transport.renewInFlight === 1, "blocked renewal request");
}

test("floating activation starts a seat, never persists its session, and restart gets a fresh ID", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-restart-"));
  let client; let restarted;
  context.after(async () => { await restarted?.close().catch(() => {}); await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport();
  client = await makeClient(statePath, transport);
  const first = await client.activate("floating-key");
  assert.equal(first.access, "online");
  assert.equal(first.session.sequence, 1);
  assert.equal(first.has("export"), true);
  const firstId = first.session.sessionId;
  const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(state.access, null);
  assert.equal(JSON.stringify(state).includes(firstId), false);
  assert.equal(JSON.stringify(state).includes("orbit-session+jwt"), false);
  await client.close(); client = null;

  restarted = await makeClient(statePath, transport);
  const current = await restarted.refresh();
  assert.equal(current.access, "online");
  assert.equal(current.session.sequence, 1);
  assert.notEqual(current.session.sessionId, firstId);
});

test("seat denial keeps the durable credential and ensureAccess never prompts", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-denial-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport(); transport.denyStart = true;
  client = await makeClient(statePath, transport);
  await assert.rejects(client.activate("floating-key"), (error) => error.code === "concurrent_session_limit_reached");
  const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(state.credential.licence_id, "licence-1");
  let prompts = 0;
  await assert.rejects(client.ensureAccess("export", () => { prompts++; return "unexpected"; }),
    (error) => error.code === "concurrent_session_limit_reached");
  assert.equal(prompts, 0);
  assert.equal(transport.requests.filter((request) => request.route.endsWith("/activations")).length, 1);
});

test("floating activation credential is durable before the first session JWKS request", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-jwks-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport();
  transport.failJwks = true;
  let observed;
  transport.beforeJwks = async () => {
    observed = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  };
  client = await makeClient(statePath, transport);
  await assert.rejects(client.activate("floating-key"), (error) => error.kind === ErrorKind.TRANSIENT);
  assert.equal(observed.credential.licence_id, "licence-1");
  assert.equal(observed.access, null);
  assert.equal(observed.pending_activation, null);
  const recovered = await client.refresh();
  assert.equal(recovered.session.sequence, 1);
});

test("terminal unacknowledged start drops its retry ID", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-conflict-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = new FloatingTransport();
  transport.denyStartCode = "session_sequence_conflict";
  client = await makeClient(path.join(base, "state"), transport);
  await assert.rejects(client.activate("floating-key"), (error) => error.code === "session_sequence_conflict");
  await client.startSession();
  const starts = transport.requests.filter((request) => request.route.endsWith("/sessions") && request.body.session_id);
  assert.equal(starts.length, 2);
  assert.notEqual(starts[0].body.session_id, starts[1].body.session_id);
});

test("authoritative licence revocation removes local floating authority and credential", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-revoked-"));
  let client;
  let restoreClock;
  context.after(async () => { await client?.close().catch(() => {}); restoreClock?.(); context.mock.timers.reset(); await rm(base, { recursive: true, force: true }); });
  const transport = new FloatingTransport();
  transport.denyRenew = "licence_revoked";
  ({ client, restoreClock } = await openWithFakeLifecycle(context, base, transport));
  context.mock.timers.tick(60_000);
  await waitUntil(() => transport.requests.some((request) => request.route.endsWith("/renew")) && transport.renewInFlight === 0,
    "terminal renewal response");
  await waitUntil(() => client.snapshot().access === "denied", "durable revocation invalidation");
  assert.equal(client.snapshot().access, "denied");
  assert.equal(client.snapshot().session, null);
  const state = JSON.parse(await readFile(path.join(base, "state", "orbit-storage.bin"), "utf8"));
  assert.equal(state.credential, null);
  assert.equal(state.access, null);
  context.mock.timers.tick(10_000);
  assert.equal(transport.requests.filter((request) => request.route.endsWith("/renew")).length, 1);
});

test("requireAccess checks cancellation and the final exact-expiry snapshot", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-boundary-"));
  let client;
  let restoreClock;
  context.after(async () => { await client?.close().catch(() => {}); restoreClock?.(); context.mock.timers.reset(); await rm(base, { recursive: true, force: true }); });
  const fakeNow = Math.floor(Date.now() / 1000) * 1000;
  const baseElapsed = 31_000_000_000n;
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now: fakeNow });
  let boundary = false;
  let currentDelta = 0;
  let readCount = 0;
  restoreClock = setClockForTesting({
    elapsedNs: () => {
      if (!boundary) return baseElapsed;
      currentDelta = readCount++ < 3 ? 119 : 120;
      return baseElapsed + BigInt(currentDelta) * 1_000_000_000n;
    },
    wallSeconds: () => Math.floor(fakeNow / 1000) + currentDelta,
  });
  const transport = new FloatingTransport();
  client = await makeClient(path.join(base, "state"), transport);
  const active = await client.activate("floating-key");
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(client.requireAccess("export", { signal: controller.signal }),
    (error) => error.kind === ErrorKind.CANCELLED);
  boundary = true;
  readCount = 0;
  await assert.rejects(client.requireAccess("export"), (error) => error.code === "session_access_unavailable");
  assert.equal(active.session.sequence, 1);
});

test("blocked floating renewals are fenced by end, logout, close, and credential replacement", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-races-"));
  const fakeNow = Math.floor(Date.now() / 1000) * 1000;
  const fakeElapsed = 41_000_000_000n;
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now: fakeNow });
  const restoreClock = setClockForTesting({
    elapsedNs: () => fakeElapsed + BigInt(Date.now() - fakeNow) * 1_000_000n,
    wallSeconds: () => Math.floor(Date.now() / 1000),
  });
  const clients = [];
  context.after(async () => {
    await Promise.all(clients.map((client) => client.close().catch(() => {})));
    restoreClock(); context.mock.timers.reset(); await rm(base, { recursive: true, force: true });
  });

  for (const transition of ["end", "logout", "close", "replace"]) {
    const transport = new FloatingTransport();
    transport.nowSeconds = () => Math.floor(Date.now() / 1000);
    const client = await makeClient(path.join(base, transition), transport, { lifecycle: true });
    clients.push(client);
    const initial = await client.activate("floating-key");
    const oldId = initial.session.sessionId;
    let stateEvents = 0;
    client.on("state", () => { stateEvents++; });
    transport.blockRenew = true;
    context.mock.timers.tick(60_000);
    await waitUntil(() => transport.renewInFlight === 1, `${transition} renewal request`);
    if (transition === "end") {
      await client.endSession();
    } else if (transition === "logout") {
      await client.logout();
    } else if (transition === "close") {
      const closing = client.close();
      transport.releaseRenewal();
      await closing;
    } else {
      const replacement = client.activate("replacement-key");
      await waitUntil(() => transport.activationCount === 2, "replacement activation request");
      transport.releaseRenewal();
      await replacement;
      assert.notEqual(client.snapshot().session.sessionId, oldId);
      assert.equal(client.snapshot().session.sequence, 1);
    }
    const eventsAfterTransition = stateEvents;
    transport.releaseRenewal();
    await waitUntil(() => transport.renewInFlight === 0, "blocked renewal completion");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(transport.maxRenewInFlight, 1);
    if (transition === "end") {
      assert.equal(client.snapshot().session, null);
      assert.equal(client.snapshot().access, "refresh_required");
    } else if (transition === "logout") {
      assert.equal(client.snapshot().session, null);
      assert.equal(client.snapshot().access, "denied");
    } else if (transition === "replace") {
      assert.notEqual(client.snapshot().session.sessionId, oldId);
    }
    if (transition !== "replace") assert.equal(stateEvents, eventsAfterTransition);
    if (transition !== "close") await client.close();
  }
});

test("floating access guard fails closed immediately after lease replacement", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-lease-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  client = await makeClient(statePath, new FloatingTransport());
  await client.activate("floating-key");
  const lease = path.join(statePath, "orbit-storage.lock");
  const moved = path.join(base, "old-lease");
  await rename(lease, moved);
  await writeFile(lease, Buffer.from([1]), { mode: 0o600 });
  await chmod(lease, 0o600);
  await assert.rejects(client.requireAccess("export"), (error) => error.kind === ErrorKind.STORAGE);
});

test("lost start retries the same ID; explicit end fences it and disables reacquisition", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-retry-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = new FloatingTransport(); transport.failStart = true;
  client = await makeClient(path.join(base, "state"), transport);
  await assert.rejects(client.activate("floating-key"), (error) => error.kind === ErrorKind.TRANSIENT);
  const recovered = await client.requireAccess("export");
  const starts = transport.requests.filter((request) => request.route.endsWith("/sessions") && request.body.session_id);
  assert.equal(starts.length, 2);
  assert.equal(starts[0].body.session_id, starts[1].body.session_id);
  assert.equal(recovered.session.sessionId, starts[0].body.session_id);
  const ended = await client.endSession();
  assert.equal(ended.session, null);
  await assert.rejects(client.requireAccess("export"), (error) => error.code === "session_explicitly_ended");
});

test("expired seats are reacquired with a fresh ID and background renewal retries the same sequence", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-clock-"));
  let client;
  let restoreClock;
  context.after(async () => {
    await client?.close().catch(() => {});
    restoreClock?.();
    context.mock.timers.reset();
    await rm(base, { recursive: true, force: true });
  });

  const fakeNow = Math.floor(Date.now() / 1000) * 1000;
  const fakeElapsed = 9_000_000_000n;
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now: fakeNow });
  restoreClock = setClockForTesting({
    elapsedNs: () => fakeElapsed + BigInt(Date.now() - fakeNow) * 1_000_000n,
    wallSeconds: () => Math.floor(Date.now() / 1000),
  });
  const transport = new FloatingTransport();
  transport.nowSeconds = () => Math.floor(Date.now() / 1000);
  client = await makeClient(path.join(base, "state"), transport, { lifecycle: true });
  const first = await client.activate("floating-key");
  const firstId = first.session.sessionId;
  const initialExpiry = first.session.expiresAt.getTime();

  context.mock.timers.tick(60_000);
  await waitUntil(() => client.snapshot().session?.sequence === 2, "first renewal");
  assert.equal(transport.requests.filter((request) => request.route.endsWith("/renew")).length, 1);
  assert.equal(transport.requests.find((request) => request.route.endsWith("/renew")).body.sequence, 2);
  assert.equal(client.snapshot().session.sequence, 2);
  assert.ok(client.snapshot().session.expiresAt.getTime() > initialExpiry);

  const renewId = client.snapshot().session.sessionId;
  const renewExpiry = client.snapshot().session.expiresAt.getTime();
  transport.failRenew = 1;
  context.mock.timers.tick(60_000);
  await waitUntil(() => transport.requests.filter((request) => request.route.endsWith("/renew")).length >= 2
    && transport.renewInFlight === 0, "failed renewal");
  assert.equal(transport.requests.filter((request) => request.route.endsWith("/renew")).length, 2);
  assert.equal(client.snapshot().session.sequence, 2);
  context.mock.timers.tick(45_000);
  await waitUntil(() => client.snapshot().session?.sequence === 3, "retried renewal");
  const renewals = transport.requests.filter((request) => request.route.endsWith("/renew"));
  assert.deepEqual(renewals.map((request) => request.body.sequence), [2, 3, 3]);
  assert.equal(client.snapshot().session.sessionId, renewId);
  assert.equal(client.snapshot().session.sequence, 3);
  assert.ok(client.snapshot().session.expiresAt.getTime() > renewExpiry);

  await client.close();
  client = await makeClient(path.join(base, "expired-state"), new FloatingTransport());
  const expiring = await client.activate("floating-key");
  const expiringId = expiring.session.sessionId;
  context.mock.timers.tick(121_000);
  const reacquired = await client.requireAccess("export");
  assert.notEqual(reacquired.session.sessionId, firstId);
  assert.notEqual(reacquired.session.sessionId, expiringId);
  assert.equal(reacquired.session.sequence, 1);
});

test("logout clears a floating session locally and releases it without persisting session authority", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-logout-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = new FloatingTransport();
  client = await makeClient(path.join(base, "state"), transport);
  const active = await client.activate("floating-key");
  const sessionId = active.session.sessionId;
  await client.logout();
  assert.equal(client.snapshot().session, null);
  assert.equal(client.snapshot().access, "denied");
  assert.ok(transport.requests.some((request) => request.route.endsWith(`/sessions/${sessionId}/end`)));
  await assert.rejects(client.requireAccess("export"), (error) => error.kind === ErrorKind.DENIED);
});

test("cancelling a start after its request begins cannot expose or persist a session", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-cancel-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport(); transport.blockStart = true;
  client = await makeClient(statePath, transport);
  const controller = new AbortController();
  const activating = client.activate("floating-key", { signal: controller.signal });
  await transport.entered;
  controller.abort();
  await assert.rejects(activating, (error) => error.kind === ErrorKind.CANCELLED);
  await waitUntil(() => transport.requests.some((request) => request.route.endsWith("/end")), "abandoned session end");
  assert.equal(client.snapshot().access, "refresh_required");
  assert.equal(client.snapshot().session, null);
  const record = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(record.access, null);
  assert.equal(JSON.stringify(record).includes("orbit-session+jwt"), false);
  assert.ok(transport.requests.some((request) => request.route.endsWith("/end")));
});

test("close fences a floating start already in flight", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-close-start-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport();
  transport.blockStart = true;
  client = await makeClient(statePath, transport);
  const activation = client.activate("floating-key");
  const activationOutcome = activation.then(() => null, (error) => error);
  await transport.entered;
  const closing = client.close();
  await closing;
  const failure = await activationOutcome;
  assert.ok(failure);
  assert.ok(failure.kind === ErrorKind.CANCELLED || failure.kind === ErrorKind.STALE_RESPONSE);
  const record = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.ok(record.credential);
  assert.equal(record.access, null);
  assert.equal(JSON.stringify(record).includes("orbit-session+jwt"), false);
});

test("session authority counts fractional continuous time and wall rollback fails closed without prompting", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-clock-check-"));
  let client;
  let restoreClock;
  context.after(async () => { await client?.close().catch(() => {}); restoreClock?.(); await rm(base, { recursive: true, force: true }); });
  const fakeWall = Math.floor(Date.now() / 1000);
  let fakeElapsed = 15_000_000_000n;
  let currentWall = fakeWall;
  restoreClock = setClockForTesting({ elapsedNs: () => fakeElapsed, wallSeconds: () => currentWall });
  const transport = new FloatingTransport();
  transport.nowSeconds = () => currentWall;
  client = await makeClient(path.join(base, "state"), transport);
  const active = await client.activate("floating-key");
  const requestCount = transport.requests.length;
  fakeElapsed += 600_000_000n;
  assert.equal(client.snapshot().session.sessionId, active.session.sessionId);
  assert.equal(transport.requests.length, requestCount);
  fakeElapsed += 400_000_000n;
  currentWall += 1;
  assert.equal(client.snapshot().access, "online");
  assert.equal(transport.requests.length, requestCount);

  currentWall -= 31;
  fakeElapsed += 1_000_000_000n;
  let prompts = 0;
  await assert.rejects(client.ensureAccess("export", async () => { prompts++; return "unexpected"; }),
    (error) => error.code === "clock_uncertain");
  assert.equal(prompts, 0);
  assert.equal(transport.requests.length, requestCount);
});

test("ordinary licences make startSession and endSession idempotent no-ops", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-ordinary-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = new OrdinaryTransport();
  client = await makeClient(path.join(base, "state"), transport);
  const initial = await client.activate("ordinary-key");
  const requests = transport.requests.length;
  assert.equal(initial.access, "online");
  assert.equal(initial.session, null);
  assert.equal((await client.startSession()).access, "online");
  assert.equal((await client.endSession()).access, "online");
  assert.equal(transport.requests.length, requests);
  assert.equal(transport.requests.some((request) => request.route.includes("/sessions")), false);
});

for (const account of [false, true]) test(`end during initial ${account ? "account" : "key"} activation preserves end intent`, async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-end-activation-"));
  const transport = new FloatingTransport();
  let entered, release;
  const blocked = new Promise((resolve) => { entered = resolve; });
  const reply = new Promise((resolve) => { release = resolve; });
  let once = true;
  const post = transport.post.bind(transport);
  transport.post = async (route, body, ...args) => {
    if (route === "/api/client/v1/sessions") return Buffer.from(JSON.stringify({
      customer: { id: "alice", username: "alice", email: "alice@example.test", suspended: false, created_at: "2026-01-01T00:00:00Z" },
      session: "b".repeat(43), expires_at: "2030-01-01T00:00:00Z",
    }));
    if (route.endsWith("/activations") && once) { once = false; entered(); await reply; }
    return post(route, body, ...args);
  };
  const statePath = path.join(base, "state");
  const client = await makeClient(statePath, transport);
  context.after(async () => { release(); await client.close(); await rm(base, { recursive: true, force: true }); });
  if (account) await client.login("alice", "synthetic-password");
  const activating = account ? client.activateAccount("licence-1") : client.activate("floating-key");
  await blocked;
  await client.endSession();
  release();
  assert.notEqual((await activating).access, "online");
  assert.notEqual(client.snapshot().access, "online");
  assert.equal(transport.requests.filter((request) => request.route.endsWith("/sessions")).length, 0);
  assert.ok(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).credential);
  assert.equal((await client.startSession()).access, "online");
  await client.endSession();
  assert.equal((await client.activate("replacement-key")).access, "online");
});

for (const [kind, code, retained] of [[ErrorKind.DENIED, "licence_revoked", false],
  [ErrorKind.DENIED, "session_ended", true], [ErrorKind.INVALID_RESPONSE, "invalid_response", true]]) {
  test(`terminal start ${code} stops background retries`, async (context) => {
    if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
    const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-terminal-start-"));
    context.mock.timers.enable({ apis: ["Date", "setTimeout"], now: Math.floor(Date.now() / 1000) * 1000 });
    const transport = new FloatingTransport(); transport.failStart = true;
    const statePath = path.join(base, "state");
    const client = await makeClient(statePath, transport, { lifecycle: true });
    context.after(async () => { await client.close(); context.mock.timers.reset(); await rm(base, { recursive: true, force: true }); });
    await assert.rejects(client.activate("floating-key"), (error) => error.kind === ErrorKind.TRANSIENT);
    const post = transport.post.bind(transport);
    let starts = 0;
    transport.post = async (route, ...args) => {
      if (route.endsWith("/sessions")) { starts++; throw Object.assign(new Error(code), { kind, code }); }
      return post(route, ...args);
    };
    let errors = 0;
    client.on("error", () => { errors++; });
    context.mock.timers.tick(45_001);
    await waitUntil(() => errors === 1, "terminal start error");
    const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
    assert.equal(Boolean(state.credential), retained);
    context.mock.timers.tick(120_000);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(starts, 1);
  });
}

test("refresh keeps a validated credential after a terminal session error", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-refresh-error-"));
  const statePath = path.join(base, "state");
  const transport = new FloatingTransport(); transport.failStart = true;
  const client = await makeClient(statePath, transport);
  context.after(async () => { await client.close(); await rm(base, { recursive: true, force: true }); });
  await assert.rejects(client.activate("floating-key"), (error) => error.kind === ErrorKind.TRANSIENT);
  transport.denyStartCode = "session_expired";
  await assert.rejects(client.refresh(), (error) => error.code === "session_expired");
  assert.ok(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).credential);
  let prompts = 0;
  await assert.rejects(client.ensureAccess("export", () => { prompts++; return "unexpected"; }));
  assert.equal(prompts, 0);
  assert.equal((await client.startSession()).access, "online");
});

for (const [kind, code] of [[ErrorKind.DENIED, "session_ended"], [ErrorKind.TRANSIENT, "network_unavailable"]]) {
  test(`late start ${code} cannot poison replacement activation`, async (context) => {
    if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-storage integration test");
    const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-floating-late-start-"));
    const transport = new FloatingTransport();
    const client = await makeClient(path.join(base, "state"), transport);
    let entered, release, replaced;
    const blocked = new Promise((resolve) => { entered = resolve; });
    const reply = new Promise((resolve) => { release = resolve; });
    const replacement = new Promise((resolve) => { replaced = resolve; });
    context.after(async () => { release(); await client.close(); await rm(base, { recursive: true, force: true }); });
    await client.activate("floating-key");
    await client.endSession();
    let armed = true;
    const post = transport.post.bind(transport);
    transport.post = async (route, body, ...args) => {
      if (route.endsWith("/activations")) replaced();
      if (route.endsWith("/sessions") && armed) {
        armed = false; entered(); await reply;
        throw Object.assign(new Error(code), { kind, code });
      }
      return post(route, body, ...args);
    };
    const old = assert.rejects(client.startSession(), (error) => [ErrorKind.CANCELLED, ErrorKind.STALE_RESPONSE].includes(error.kind));
    await blocked;
    const next = client.activate("replacement-key");
    await replacement;
    release();
    await old;
    assert.equal((await next).access, "online");
    assert.equal(client.snapshot().access, "online");
  });
}
