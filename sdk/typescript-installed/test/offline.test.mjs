import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, createSign } from "node:crypto";
import { copyFile, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { copyFileSync, renameSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { Client, openClientForTesting, setClockForTesting } from "../src/client.mjs";
import { ErrorKind } from "../src/errors.mjs";
import { parseOfflineKeys, verifyOfflineFile } from "../src/offline.mjs";
import { PrivateFileStore, setStorageFaultForTesting } from "../src/storage/private-files.mjs";

const appKeyText = "orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g";
const appKey = AppKey.parse(appKeyText);
const signingKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));
const publicJwk = createPublicKey(signingKey).export({ format: "jwk" });
const offlineKeys = { keys: [{ kty: "EC", crv: "P-256", alg: "ES256", use: "sig", kid: "offline-test-installed", x: publicJwk.x, y: publicJwk.y }] };

function testClock(now = 1_800_000_000) {
  return { elapsed: 0n, wall: now, elapsedNs() { return this.elapsed; }, wallSeconds() { return this.wall; } };
}

function signFile(installationId, clock, { sequence = 1, jti = `offline_issuance_${sequence}`, exp = clock.wall + 300, enabled = true } = {}) {
  const claims = {
    ver: 1,
    iss: appKey.issuer,
    aud: `orbit-offline:${appKey.application_id}:${appKey.environment_id}`,
    sub: "licence-1",
    jti,
    iat: clock.wall,
    nbf: clock.wall,
    exp,
    application_id: appKey.application_id,
    environment_id: appKey.environment_id,
    activation_id: "activation-1",
    installation_id: installationId,
    sequence,
    binding_mode: "none",
    policy_version: 1,
    entitlements: { export: enabled },
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-offline+jwt", kid: "offline-test-installed" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signer = createSign("SHA256");
  signer.update(`${header}.${payload}`, "ascii");
  signer.end();
  const signature = signer.sign({ key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

function withClock(now = 1_800_000_000) {
  const clock = testClock(now);
  const restore = setClockForTesting(clock);
  return { clock, restore };
}

test("offline request is serializable and import, access, restart and closed-time expiry stay local", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-restart-"));
  const statePath = path.join(base, "state");
  let client;
  let calls = 0;
  const transport = { async post() { calls++; throw new Error("offline flow must not contact Orbit"); }, async get() { calls++; throw new Error("offline flow must not contact Orbit"); } };
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, machineBinding: false, offlineKeys, transport });
  const request = client.offlineRequest();
  const serialized = JSON.parse(JSON.stringify(request));
  assert.equal(serialized.format, "orbit-offline-request");
  assert.equal(serialized.app_key, appKeyText);
  assert.equal(serialized.installation_id, client.installationId);
  assert.equal(serialized.fingerprint, null);
  assert.equal(serialized.fingerprint_provider, null);
  const file = signFile(client.installationId, clock, { exp: clock.wall + 10 });
  assert.equal((await client.importOfflineFile(file)).access, "offline");
  assert.equal((await client.requireAccess("export")).has("export"), true);
  let prompts = 0;
  assert.equal((await client.ensureAccess("export", () => { prompts++; return "unused"; })).access, "offline");
  assert.equal((await client.refresh()).access, "offline");
  assert.equal(calls, 0);
  assert.equal(prompts, 0);
  await client.close();
  client = null;
  clock.wall += 11;
  clock.elapsed += 11_000_000_000n;
  client = await openClientForTesting(appKeyText, { statePath, machineBinding: false, offlineKeys, transport });
  assert.equal(client.snapshot().access, "expired");
  await assert.rejects(client.requireAccess("export"), (error) => error.kind === ErrorKind.DENIED && error.code === "offline_file_expired");
  await assert.rejects(client.ensureAccess("export", () => { prompts++; return "unused"; }),
    (error) => error.kind === ErrorKind.DENIED && error.code === "offline_file_expired");
  assert.equal(calls, 0);
  assert.equal(prompts, 0);
  await client.close();
  client = null;
  assert.equal(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).format, 3);
});

test("offline equal-sequence replay is idempotent, renewal advances floors, and logout does not reset the anchor", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-replay-"));
  context.after(async () => { await rm(base, { recursive: true, force: true }); restore(); });
  const client = await openClientForTesting(appKeyText, { statePath: path.join(base, "state"), offlineKeys });
  const first = signFile(client.installationId, clock, { exp: clock.wall + 100 });
  assert.equal((await client.importOfflineFile(first)).remainingOfflineSeconds, 100);
  clock.wall += 4;
  clock.elapsed += 4_000_000_000n;
  assert.equal((await client.importOfflineFile(first)).remainingOfflineSeconds, 96);
  await client.logout();
  assert.equal(client.snapshot().access, "denied");
  clock.wall += 3;
  clock.elapsed += 3_000_000_000n;
  assert.equal((await client.importOfflineFile(first)).remainingOfflineSeconds, 93);
  const equalSequenceConflict = signFile(client.installationId, clock, { jti: "conflicting_issuance_id", exp: clock.wall + 100 });
  await assert.rejects(client.importOfflineFile(equalSequenceConflict), (error) => error.code === "offline_sequence_conflict");
  assert.equal(client.snapshot().access, "offline");
  const renewal = signFile(client.installationId, clock, { sequence: 2, exp: clock.wall + 100 });
  assert.equal((await client.importOfflineFile(renewal)).access, "offline");
  await assert.rejects(client.importOfflineFile(first), (error) => error.code === "invalid_offline_file");
  const conflict = signFile(client.installationId, clock, { sequence: 2, jti: "different_issuance_id", exp: clock.wall + 100 });
  await assert.rejects(client.importOfflineFile(conflict), (error) => error.code === "offline_sequence_conflict");
  await client.close();
});

test("fractional repeated imports keep the original anchor and logout retains floors with a frozen wall clock", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-fractional-anchor-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  const file = signFile(client.installationId, clock, { exp: clock.wall + 100 });
  assert.equal((await client.importOfflineFile(file)).remainingOfflineSeconds, 100);
  clock.elapsed += 500_000_000n;
  assert.equal((await client.importOfflineFile(file)).remainingOfflineSeconds, 100);
  clock.elapsed += 700_000_000n;
  assert.equal((await client.importOfflineFile(file)).remainingOfflineSeconds, 99);
  clock.elapsed += 1_300_000_000n;
  await client.logout();
  const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(state.offline.jws, null);
  assert.ok(state.offline.time_high_water >= clock.wall + 2);
  assert.equal(state.offline.wall_high_water, clock.wall);
  assert.equal(client.snapshot().access, "denied");
});

test("logout clears durable offline authority even when clock evidence is uncertain", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-uncertain-logout-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  await client.importOfflineFile(signFile(client.installationId, clock));
  clock.wall -= 31;
  await client.logout();
  assert.equal(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).offline.jws, null);
  clock.wall += 31;
  await client.close();
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  assert.equal(client.snapshot().access, "denied");
});

test("a valid future-skewed renewal advances its floor without breaking the continuous clock", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-future-renewal-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath: path.join(base, "state"), offlineKeys });
  await client.importOfflineFile(signFile(client.installationId, clock));
  const renewed = signFile(client.installationId, { wall: clock.wall + 20 }, { sequence: 2 });
  assert.equal((await client.importOfflineFile(renewed)).access, "offline");
  clock.wall += 1;
  clock.elapsed += 1_000_000_000n;
  assert.equal((await client.importOfflineFile(renewed)).access, "offline");
  await client.close();
});

test("stored offline files require the configured retained key on reopen", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-retained-"));
  const statePath = path.join(base, "state");
  context.after(async () => { await rm(base, { recursive: true, force: true }); restore(); });
  let client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  const file = signFile(client.installationId, clock);
  await client.importOfflineFile(file);
  await client.close();
  client = null;
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const before = await readFile(recordPath);
  await assert.rejects(openClientForTesting(appKeyText, { statePath }),
    (error) => error.kind === ErrorKind.CONFIGURATION && error.code === "offline_keys_required");
  const rotatedWithoutOldKey = { keys: [{ ...offlineKeys.keys[0], kid: "offline-test-unretained" }] };
  await assert.rejects(openClientForTesting(appKeyText, { statePath, offlineKeys: rotatedWithoutOldKey }),
    (error) => error.code === "invalid_offline_file");
  assert.deepEqual(await readFile(recordPath), before);
});

test("offline-file byte limits reject oversized Uint8Array values before text decoding", () => {
  class OversizedBytes extends Uint8Array { get byteLength() { return 16 * 1024 + 1; } }
  const original = globalThis.TextDecoder;
  let decoded = 0;
  globalThis.TextDecoder = class extends original {
    decode(...args) { decoded++; return super.decode(...args); }
  };
  try {
    assert.throws(() => verifyOfflineFile(new OversizedBytes(1), appKey, { fingerprint: null, provider: null },
      "installation_id_123456", parseOfflineKeys(offlineKeys, "test"), 1),
    (error) => error.code === "invalid_offline_file");
  } finally { globalThis.TextDecoder = original; }
  assert.equal(decoded, 0);
});

test("explicit account mode transitions clear offline authority but retain its renewal floor", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-account-mode-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, {
    statePath: path.join(base, "state"), offlineKeys,
    transport: {
      async post(route) {
        if (route.endsWith("/sessions")) return Buffer.from(JSON.stringify({
          customer: { id: "customer-1", username: "customer_1", email: "customer@example.test", suspended: false,
            created_at: new Date(clock.wall * 1000).toISOString() },
          session: "a".repeat(43),
          expires_at: new Date((clock.wall + 3600) * 1000).toISOString(),
        }));
        throw new Error("unexpected account request");
      },
      async deleteBearer() { return null; },
    },
  });
  await client.importOfflineFile(signFile(client.installationId, clock));
  await client.login("customer_1", "not-persisted-password");
  assert.equal(client.snapshot().access, "denied");
  assert.equal(client.account()?.id, "customer-1");
  await client.logoutAccount();
  const state = JSON.parse(await readFile(path.join(base, "state", "orbit-storage.bin"), "utf8"));
  assert.equal(state.offline.jws, null);
  assert.equal(state.offline.sequence, 1);
  await client.close();
  client = null;
});

test("a changed machine binding starts a fresh offline installation instead of reusing the prior floor", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-machine-change-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, machineBinding: false, offlineKeys });
  const originalId = client.installationId;
  await client.importOfflineFile(signFile(originalId, clock));
  await client.close();
  client = await openClientForTesting(appKeyText, { statePath, machineBinding: true, offlineKeys });
  assert.notEqual(client.installationId, originalId);
  assert.equal(client.snapshot().access, "denied");
  const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(state.offline.sequence, 0);
  await client.close();
  client = null;
});

test("offline import cancellation while trusted storage encoding is blocked cannot persist authority", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-cancel-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  const file = signFile(client.installationId, clock);
  const controller = new AbortController();
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const importing = client.importOfflineFile(file, { signal: controller.signal });
  await enteredPromise;
  controller.abort();
  release();
  await assert.rejects(importing, (error) => error.kind === ErrorKind.CANCELLED);
  await client.close();
  client = null;
  const reopened = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  assert.equal(reopened.snapshot().access, "denied");
  await reopened.close();
});

test("cancellation after the durable lease marker clears leaves no offline authority to restore", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-cancel-after-commit-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  const controller = new AbortController();
  let cancelled = false;
  const restoreFault = setStorageFaultForTesting((stage) => {
    if (!cancelled && stage === "lease_marker_clear_synced") {
      cancelled = true;
      controller.abort();
    }
  });
  try {
    await assert.rejects(client.importOfflineFile(signFile(client.installationId, clock), { signal: controller.signal }),
      (error) => error.kind === ErrorKind.CANCELLED);
  } finally { restoreFault(); }
  assert.equal(cancelled, true);
  assert.equal(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).offline.jws, null);
  await client.close();
  client = null;
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  assert.equal(client.snapshot().access, "denied");
});

test("a delayed background checkpoint cannot outlive logout or restore the signed file", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-delayed-checkpoint-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  await client.importOfflineFile(signFile(client.installationId, clock));
  clock.wall += 61;
  clock.elapsed += 61_000_000_000n;
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  assert.equal(client.snapshot().access, "offline");
  await enteredPromise;
  const logout = client.logout();
  release();
  await logout;
  assert.equal(client.snapshot().access, "denied");
  const state = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(state.offline.jws, null);
  await client.close();
  client = null;
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  assert.equal(client.snapshot().access, "denied");
});

test("the postwrite lease check runs after the fresh continuous-clock sample", async (context) => {
  const clock = testClock();
  const restore = setClockForTesting(clock);
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-final-lease-"));
  const statePath = path.join(base, "state");
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const replacementPath = path.join(statePath, "replaced-record.bin");
  let replaceAfterCommit = false;
  const baseWall = clock.wallSeconds.bind(clock);
  clock.wallSeconds = function () {
    if (replaceAfterCommit) {
      replaceAfterCommit = false;
      copyFileSync(recordPath, replacementPath);
      renameSync(replacementPath, recordPath);
      writeFileSync(recordPath, "{}");
    }
    return baseWall();
  };
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
        replaceAfterCommit = true;
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const importing = client.importOfflineFile(signFile(client.installationId, clock));
  await enteredPromise;
  release();
  await assert.rejects(importing, (error) => error.kind === ErrorKind.STORAGE);
  assert.throws(() => client.snapshot(), (error) => error.kind === ErrorKind.STORAGE);
});

test("logout fences an offline import already queued behind another import", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-queued-logout-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  const file = signFile(client.installationId, clock);
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const first = client.importOfflineFile(file);
  await enteredPromise;
  const queued = client.importOfflineFile(file);
  const logout = client.logout();
  const outcomes = Promise.allSettled([first, queued, logout]);
  release();
  const result = await outcomes;
  assert.equal(result[1].status, "rejected", "the queued import must not restore authority after logout");
  assert.equal(result[2].status, "fulfilled", "logout must not be superseded by an older queued import");
  assert.equal(client.snapshot().access, "denied");
  await client.close();
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  assert.equal(client.snapshot().access, "denied");
});

test("logout fences an online activation queued behind an offline import", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-online-queued-logout-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let requests = 0;
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec,
    transport: { async post() { requests++; const error = new Error("test transient"); error.kind = ErrorKind.TRANSIENT; throw error; } },
  });
  const file = signFile(client.installationId, clock);
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const first = client.importOfflineFile(file);
  await enteredPromise;
  const queued = client.activate("TEST-12345678901234567890");
  const logout = client.logout();
  const outcomes = Promise.allSettled([first, queued, logout]);
  release();
  const result = await outcomes;
  assert.equal(result[1].status, "rejected", "the queued activation must not restore authority after logout");
  assert.equal(result[2].status, "fulfilled", "logout must not be superseded by an older queued activation");
  assert.equal(requests, 0, "logout must cancel an older queued activation before HTTP");
  assert.equal(client.snapshot().access, "denied");
  await client.close();
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  assert.equal(client.snapshot().access, "denied");
});

test("online activation fences an offline import already queued behind another import", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-queued-activation-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, {
    statePath, offlineKeys, storageCodec: codec,
    transport: { async post() { const error = new Error("test transient"); error.kind = ErrorKind.TRANSIENT; throw error; } },
  });
  const file = signFile(client.installationId, clock);
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const first = client.importOfflineFile(file);
  await enteredPromise;
  const queued = client.importOfflineFile(file);
  const activation = client.activate("TEST-12345678901234567890");
  const outcomes = Promise.allSettled([first, queued, activation]);
  release();
  const result = await outcomes;
  assert.equal(result[0].status, "fulfilled");
  assert.equal(result[1].status, "rejected", "the queued import predates online activation");
  assert.equal(result[2].status, "rejected");
  assert.equal(result[2].reason.kind, ErrorKind.TRANSIENT);
  assert.equal(client.snapshot().access, "denied");
  const saved = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.equal(saved.offline.jws, null);
  await client.close();
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  assert.equal(client.snapshot().access, "denied");
});

test("offline import rechecks the continuous clock after its durable write before exposing authority", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-postwrite-clock-"));
  const statePath = path.join(base, "state");
  let block = false;
  let entered;
  let release;
  const codec = {
    async encrypt(value) {
      if (block) {
        block = false;
        entered();
        await new Promise((resolve) => { release = resolve; });
      }
      return Buffer.from(value, "utf8");
    },
    async decrypt(value) { return { result: Buffer.from(value).toString("utf8") }; },
  };
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys, storageCodec: codec });
  const file = signFile(client.installationId, clock, { exp: clock.wall + 10 });
  const enteredPromise = new Promise((resolve) => { entered = resolve; });
  block = true;
  const importing = client.importOfflineFile(file);
  await enteredPromise;
  clock.wall += 11;
  clock.elapsed += 11_000_000_000n;
  release();
  assert.equal((await importing).access, "expired");
  await assert.rejects(client.requireAccess("export"), (error) => error.code === "offline_file_expired");
  await client.close();
  client = null;
  assert.equal(JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8")).offline.jws, file);
});

test("offline import write faults fail closed instead of accepting a partial record", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-partial-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  const file = signFile(client.installationId, clock);
  const restoreFault = setStorageFaultForTesting((stage) => { if (stage === "write") throw new Error("injected offline record write fault"); });
  try {
    await assert.rejects(client.importOfflineFile(file), (error) => error.kind === ErrorKind.STORAGE);
  } finally { restoreFault(); }
  await client.close();
  client = null;
  await assert.rejects(openClientForTesting(appKeyText, { statePath, offlineKeys }), (error) => error.kind === ErrorKind.STORAGE);
});

test("connected format 2 state upgrades transactionally without replacing installation identity", async (context) => {
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-state-upgrade-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const statePath = path.join(base, "state");
  const binding = { fingerprint: null, provider: null };
  const store = await PrivateFileStore.open(appKey, statePath, binding);
  const installationId = store.state.installation.id;
  await store.close();
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const legacy = JSON.parse(await readFile(recordPath, "utf8"));
  legacy.format = 2;
  delete legacy.offline;
  await writeFile(recordPath, JSON.stringify(legacy), { mode: 0o600 });
  const upgraded = await PrivateFileStore.open(appKey, statePath, binding);
  assert.equal(upgraded.state.format, 3);
  assert.equal(upgraded.state.installation.id, installationId);
  assert.equal(upgraded.state.offline.sequence, 0);
  await upgraded.close();
  assert.equal(JSON.parse(await readFile(recordPath, "utf8")).format, 3);
});

test("offline persistence rejects coerced digest fields without rewriting the record", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-envelope-shape-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, machineBinding: false, offlineKeys });
  await client.importOfflineFile(signFile(client.installationId, clock));
  await client.close();
  client = null;
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const value = JSON.parse(await readFile(recordPath, "utf8"));
  value.offline.content_digest = ["a".repeat(64)];
  const malformed = Buffer.from(JSON.stringify(value));
  await writeFile(recordPath, malformed, { mode: 0o600 });
  await assert.rejects(openClientForTesting(appKeyText, { statePath, machineBinding: false, offlineKeys }),
    (error) => error.kind === ErrorKind.STORAGE);
  assert.deepEqual(await readFile(recordPath), malformed);
});

test("format 3 state rejects duplicate JSON fields without rewriting the record", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-duplicate-state-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  await client.importOfflineFile(signFile(client.installationId, clock));
  await client.close();
  client = null;
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const valid = await readFile(recordPath, "utf8");
  const malformed = Buffer.from(valid.replace('"format":3', '"format":3,"format":3'));
  assert.notEqual(malformed.toString("utf8"), valid);
  await writeFile(recordPath, malformed, { mode: 0o600 });
  await assert.rejects(openClientForTesting(appKeyText, { statePath, offlineKeys }), (error) => error.kind === ErrorKind.STORAGE);
  assert.deepEqual(await readFile(recordPath), malformed);
});

test("offline clock rollback denies local access and replaced lease or record denies guards immediately", async (context) => {
  const { clock, restore } = withClock();
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-offline-clock-lease-"));
  const statePath = path.join(base, "state");
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); restore(); });
  client = await openClientForTesting(appKeyText, { statePath, offlineKeys });
  await client.importOfflineFile(signFile(client.installationId, clock, { exp: clock.wall + 100 }));
  clock.wall -= 31;
  assert.equal(client.snapshot().access, "denied");
  await assert.rejects(client.requireAccess("export"), (error) => error.kind === ErrorKind.CLOCK_UNCERTAIN);
  clock.wall += 131;
  clock.elapsed += 100_000_000_000n;
  assert.equal(client.snapshot().access, "expired");
  const recordPath = path.join(statePath, "orbit-storage.bin");
  const copyPath = path.join(statePath, "copy.bin");
  await copyFile(recordPath, copyPath);
  await rename(copyPath, recordPath);
  assert.throws(() => client.snapshot(), (error) => error.kind === ErrorKind.STORAGE);
  await client.close();
  client = null;
});
