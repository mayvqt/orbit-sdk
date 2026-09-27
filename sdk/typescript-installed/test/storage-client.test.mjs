import assert from "node:assert/strict";
import { createPrivateKey, createSign } from "node:crypto";
import { copyFile, link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { Client, openClientForTesting, setClockForTesting } from "../src/client.mjs";
import { ErrorKind } from "../src/errors.mjs";
import { PrivateFileStore, setStorageFaultForTesting } from "../src/storage/private-files.mjs";
import { posixFilesystem, setPosixFilesystemForTesting } from "../src/platform/native.mjs";
const grantVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/grants.json", import.meta.url), "utf8"));

const key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g");
const privateKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));
const keyText = "TEST-12345678901234567890";

test("private state survives restart and rejects competing leases and replaced records", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-installed-store-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const target = path.join(base, "state");
  const binding = { fingerprint: null, provider: null };
  const first = await PrivateFileStore.open(key, target, binding);
  const installation = first.state.installation.id;
  await assert.rejects(PrivateFileStore.open(key, target, binding), (error) => error.code === "installation_in_use");
  await first.close();

  const restarted = await PrivateFileStore.open(key, target, binding);
  assert.equal(restarted.state.installation.id, installation);
  const record = path.join(target, "orbit-storage.bin");
  const copied = path.join(target, "copied.bin");
  await copyFile(record, copied);
  await rename(copied, record);
  await assert.rejects(restarted.sync(), (error) => error.code === "storage_failed");
  await restarted.close();
});

test("state decoder rejects extra envelope fields", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-state-shape-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const target = path.join(base, "state");
  const store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
  await store.close();
  const record = path.join(target, "orbit-storage.bin");
  const value = JSON.parse(await readFile(record, "utf8"));
  value.unexpected = true;
  await writeFile(record, JSON.stringify(value), { mode: 0o600 });
  await assert.rejects(PrivateFileStore.open(key, target, { fingerprint: null, provider: null }),
    (error) => error.kind === ErrorKind.STORAGE);
});

test("private storage syncs new directory contents before its parent and durably syncs lease markers", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-sync-order-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const events = [];
  const restore = setStorageFaultForTesting((stage) => events.push(stage));
  try {
    const store = await PrivateFileStore.open(key, path.join(base, "state"), { fingerprint: null, provider: null });
    await store.close();
  } finally { restore(); }
  assert.ok(events.indexOf("directory_child_synced") >= 0);
  assert.ok(events.indexOf("directory_child_synced") < events.indexOf("directory_parent_synced"));
  assert.ok(events.indexOf("lease_marker_written") < events.indexOf("lease_marker_synced"));
  assert.ok(events.indexOf("lease_marker_cleared") < events.indexOf("lease_marker_clear_synced"));
});

test("injected macOS adapter exercises descriptor-relative operations on Linux", async (context) => {
  if (process.platform !== "linux") return context.skip("Linux-backed Darwin adapter simulation");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-darwin-fs-adapter-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const linux = posixFilesystem();
  const calls = [];
  const adapter = {
    ...linux,
    platform: "darwin",
    errorPlatform: "linux",
    atSymlinkNoFollow: linux.atSymlinkNoFollow,
    openat(...args) { calls.push("openat"); return linux.openat(...args); },
    mkdirat(...args) { calls.push("mkdirat"); return linux.mkdirat(...args); },
    fstatat(...args) { calls.push("fstatat"); return linux.fstatat(...args); },
    renameat(...args) { calls.push("renameat"); return linux.renameat(...args); },
    unlinkat(...args) { calls.push("unlinkat"); return linux.unlinkat(...args); },
    syncFile(fd) { calls.push("fullsync-selected"); return linux.syncFile(fd); },
  };
  const restoreAdapter = setPosixFilesystemForTesting(adapter);
  let restoreFault;
  let store;
  try {
    store = await PrivateFileStore.open(key, path.join(base, "state"), { fingerprint: null, provider: null });
    restoreFault = setStorageFaultForTesting((stage) => { if (stage === "write") throw new Error("injected pre-rename write fault"); });
    await assert.rejects(store.updateState((state) => ({ ...state, generation: state.generation + 1 })),
      (error) => error.kind === ErrorKind.STORAGE);
  } finally {
    restoreFault?.();
    await store?.close();
    restoreAdapter();
  }
  for (const operation of ["openat", "mkdirat", "fstatat", "renameat", "unlinkat", "fullsync-selected"]) {
    assert.ok(calls.includes(operation), operation);
  }
});

test("state decoder rejects coerced and array credential or pending fields without rewriting", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-state-scalars-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const cases = [
    { field: "activation_id", value: 123 },
    { field: "licence_id", value: ["licence-1"] },
    { field: "bearer", value: ["a".repeat(43)] },
  ];
  for (const [index, change] of cases.entries()) {
    const target = path.join(base, `credential-${index}`);
    const store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
    await store.commitState({ ...store.state, credential: {
      activation_id: "activation-1", licence_id: "licence-1", bearer: "a".repeat(43), expires_at: null,
    } });
    await store.close();
    const record = path.join(target, "orbit-storage.bin");
    const state = JSON.parse(await readFile(record, "utf8"));
    state.credential[change.field] = change.value;
    const malformed = Buffer.from(JSON.stringify(state));
    await writeFile(record, malformed, { mode: 0o600 });
    await assert.rejects(PrivateFileStore.open(key, target, { fingerprint: null, provider: null }),
      (error) => error.kind === ErrorKind.STORAGE);
    assert.deepEqual(await readFile(record), malformed);
  }
  for (const [index, value] of [17, ["f".repeat(64)]].entries()) {
    const target = path.join(base, `pending-${index}`);
    const store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
    await store.commitState({ ...store.state, pending_activation: {
      operation_id: "operation-id-123456", principal_kind: "key", input_digest: "f".repeat(64), created_at: 1,
    } });
    await store.close();
    const record = path.join(target, "orbit-storage.bin");
    const state = JSON.parse(await readFile(record, "utf8"));
    state.pending_activation.input_digest = value;
    const malformed = Buffer.from(JSON.stringify(state));
    await writeFile(record, malformed, { mode: 0o600 });
    await assert.rejects(PrivateFileStore.open(key, target, { fingerprint: null, provider: null }),
      (error) => error.kind === ErrorKind.STORAGE);
    assert.deepEqual(await readFile(record), malformed);
  }
});

test("private storage rejects symlink, hardlink, and parent replacement attacks", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-path-attacks-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const binding = { fingerprint: null, provider: null };
  const recordTarget = path.join(base, "record");
  const recordStore = await PrivateFileStore.open(key, recordTarget, binding);
  await recordStore.close();
  const record = path.join(recordTarget, "orbit-storage.bin");
  const recordCopy = path.join(base, "record-copy.bin");
  await rename(record, recordCopy);
  await symlink(recordCopy, record);
  await assert.rejects(PrivateFileStore.open(key, recordTarget, binding), (error) => error.kind === ErrorKind.STORAGE);

  const leaseTarget = path.join(base, "lease");
  const leaseStore = await PrivateFileStore.open(key, leaseTarget, binding);
  await leaseStore.close();
  const lease = path.join(leaseTarget, "orbit-storage.lock");
  const leaseCopy = path.join(base, "lease-copy.bin");
  await rename(lease, leaseCopy);
  await symlink(leaseCopy, lease);
  await assert.rejects(PrivateFileStore.open(key, leaseTarget, binding), (error) => error.kind === ErrorKind.STORAGE);

  const hardlinkTarget = path.join(base, "hardlink");
  const hardlinkStore = await PrivateFileStore.open(key, hardlinkTarget, binding);
  await hardlinkStore.close();
  await link(path.join(hardlinkTarget, "orbit-storage.bin"), path.join(base, "outside-link.bin"));
  await assert.rejects(PrivateFileStore.open(key, hardlinkTarget, binding), (error) => error.kind === ErrorKind.STORAGE);

  const parentTarget = path.join(base, "parent", "state");
  await mkdir(path.dirname(parentTarget), { mode: 0o700 });
  const parentStore = await PrivateFileStore.open(key, parentTarget, binding);
  await rename(path.dirname(parentTarget), path.join(base, "parent-old"));
  await mkdir(path.dirname(parentTarget), { mode: 0o700 });
  await assert.rejects(parentStore.sync(), (error) => error.kind === ErrorKind.STORAGE);
  await parentStore.close();
});

test("failed write, fsync, rename, and completion marker leave storage unreopenable", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-write-faults-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  for (const stage of ["write", "fsync", "rename", "clear"]) {
    const target = path.join(base, stage);
    const store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
    const restore = setStorageFaultForTesting((current) => {
      if (current === stage) throw new Error(`injected ${stage} failure`);
    });
    try {
      await assert.rejects(store.updateState((state) => ({ ...state, generation: state.generation + 1 })),
        (error) => error.kind === ErrorKind.STORAGE);
    } finally {
      restore();
      await store.close();
    }
    await assert.rejects(PrivateFileStore.open(key, target, { fingerprint: null, provider: null }),
      (error) => error.kind === ErrorKind.STORAGE);
  }
});

test("snapshot and access guards synchronously reject a replaced state record", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-fresh-access-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1");
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  const statePath = path.join(base, "state");
  client = await openClientForTesting(key, { statePath, machineBinding: false, transport, lifecycle: false });
  await client.activate(keyText);
  const record = path.join(statePath, "orbit-storage.bin");
  const copied = path.join(statePath, "copy.bin");
  await copyFile(record, copied);
  await rename(copied, record);
  assert.throws(() => client.snapshot(), (error) => error.kind === ErrorKind.STORAGE);
  await assert.rejects(client.requireAccess("export"), (error) => error.kind === ErrorKind.STORAGE);
});

test("logout fences refresh while its encrypted state write is blocked", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-logout-encode-race-"));
  let client;
  let restarted;
  context.after(async () => {
    await restarted?.close().catch(() => {});
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  let blockClear = false;
  let clearStarted;
  const started = new Promise((resolve) => { clearStarted = resolve; });
  let releaseClear;
  const storageCodec = {
    async encrypt(value) {
      const state = JSON.parse(value);
      if (blockClear && state.credential === null && state.access === null && state.pending_activation === null) {
        blockClear = false;
        await new Promise((resolve) => { releaseClear = resolve; clearStarted(); });
      }
      return Buffer.from(value);
    },
    async decrypt(value) { return { result: value.toString("utf8") }; },
  };
  let validated = false;
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1");
      if (route.endsWith("/validate")) {
        validated = true;
        return activationReply(body, "activation-1", "licence-1", { credential: null });
      }
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  const statePath = path.join(base, "state");
  client = await openClientForTesting(key, { statePath, machineBinding: false, transport, storageCodec, lifecycle: false });
  await client.activate(keyText);
  blockClear = true;
  const logout = client.logout();
  await started;
  const refresh = client.refresh();
  for (let i = 0; i < 50 && !validated; i++) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(validated, true, "refresh response should arrive while logout encoding is held");
  releaseClear();
  await logout;
  await assert.rejects(refresh, (error) => error.code === "stale_response");
  assert.equal(client.snapshot().access, "denied");
  await client.close();
  restarted = await openClientForTesting(key, { statePath, machineBinding: false, transport, storageCodec, lifecycle: false });
  assert.equal(restarted.snapshot().access, "denied");
});

test("cancelled refresh encoding does not persist or grant a late response", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-cancel-encode-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  let blockNextAccess = false;
  let accessStarted;
  const started = new Promise((resolve) => { accessStarted = resolve; });
  let releaseAccess;
  const storageCodec = {
    async encrypt(value) {
      const state = JSON.parse(value);
      if (blockNextAccess && state.access !== null) {
        blockNextAccess = false;
        await new Promise((resolve) => { releaseAccess = resolve; accessStarted(); });
      }
      return Buffer.from(value);
    },
    async decrypt(value) { return { result: value.toString("utf8") }; },
  };
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1");
      if (route.endsWith("/validate")) return activationReply(body, "activation-1", "licence-1", { credential: null });
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, { statePath: path.join(base, "state"), machineBinding: false, transport, storageCodec, lifecycle: false });
  await client.activate(keyText);
  blockNextAccess = true;
  const controller = new AbortController();
  const refresh = client.refresh({ signal: controller.signal });
  await started;
  controller.abort();
  releaseAccess();
  await assert.rejects(refresh, (error) => error.kind === ErrorKind.CANCELLED);
  assert.equal(client.snapshot().has("export"), true, "the previous verified grant remains usable");
});

test("checkpoint queued before logout cannot restore the old signed access", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-checkpoint-logout-"));
  let client;
  let restarted;
  let elapsed = 5_000_000_000n;
  let wall = Math.floor(Date.now() / 1000);
  const restoreClock = setClockForTesting({ elapsedNs: () => elapsed, wallSeconds: () => wall });
  context.after(async () => {
    restoreClock();
    await restarted?.close().catch(() => {});
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  let blockCheckpoint = false;
  let checkpointStarted;
  const started = new Promise((resolve) => { checkpointStarted = resolve; });
  let releaseCheckpoint;
  const storageCodec = {
    async encrypt(value) {
      const state = JSON.parse(value);
      if (blockCheckpoint && state.access?.wall_high_water === wall) {
        blockCheckpoint = false;
        await new Promise((resolve) => { releaseCheckpoint = resolve; checkpointStarted(); });
      }
      return Buffer.from(value);
    },
    async decrypt(value) { return { result: value.toString("utf8") }; },
  };
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1", { nowSeconds: wall });
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  const statePath = path.join(base, "state");
  client = await openClientForTesting(key, { statePath, machineBinding: false, transport, storageCodec, lifecycle: false });
  await client.activate(keyText);
  elapsed += 61_000_000_000n;
  wall += 61;
  blockCheckpoint = true;
  client.snapshot();
  await started;
  const logout = client.logout();
  releaseCheckpoint();
  await logout;
  assert.equal(client.snapshot().access, "denied");
  await client.close();
  restarted = await openClientForTesting(key, { statePath, machineBinding: false, transport, storageCodec, lifecycle: false });
  assert.equal(restarted.snapshot().access, "denied");
});

test("overlapping activation retries reuse the pending operation identity", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-activation-overlap-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const ids = [];
  let calls = 0;
  let releaseFirst;
  const transport = {
    async post(route, body) {
      if (!route.endsWith("/activations")) throw new Error("unexpected request");
      ids.push(body.idempotency_key);
      calls++;
      if (calls === 1) return new Promise((resolve, reject) => { releaseFirst = () => {
        const error = new Error("network unavailable");
        error.kind = ErrorKind.TRANSIENT;
        error.code = "network_unavailable";
        reject(error);
      }; });
      return activationReply(body, "activation-1", "licence-1");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, { statePath: path.join(base, "state"), machineBinding: false, transport, lifecycle: false });
  const first = client.activate(keyText);
  for (let i = 0; i < 50 && !releaseFirst; i++) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(typeof releaseFirst, "function");
  const second = client.activate(keyText);
  releaseFirst();
  await assert.rejects(first, (error) => error.kind === ErrorKind.TRANSIENT);
  assert.equal((await second).access, "online");
  assert.equal(calls, 2);
  assert.equal(ids[0], ids[1]);
});

test("overlapping logins allow only the newest response to establish a session", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-login-overlap-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  let releaseFirst;
  const transport = {
    async post(route, body) {
      if (!route.endsWith("/sessions")) throw new Error("unexpected request");
      if (body.username === "first_user") return new Promise((resolve) => { releaseFirst = () => resolve(Buffer.from(JSON.stringify(loginReply("customer-1", "first_user")))); });
      return Buffer.from(JSON.stringify(loginReply("customer-2", "second_user")));
    },
  };
  client = await openClientForTesting(key, { statePath: path.join(base, "state"), machineBinding: false, transport, lifecycle: false });
  const first = client.login("first_user", "correct horse battery staple");
  for (let i = 0; i < 50 && !releaseFirst; i++) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(typeof releaseFirst, "function");
  const second = client.login("second_user", "correct horse battery staple");
  assert.equal((await second).username, "second_user");
  releaseFirst();
  await assert.rejects(first, (error) => error.code === "stale_response");
  assert.equal(client.account().username, "second_user");
});

test("continuous and wall clocks advance together across a simulated suspend", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-simulated-suspend-"));
  let client;
  let elapsed = 1_000_000_000n;
  let wall = Math.floor(Date.now() / 1000);
  const restoreClock = setClockForTesting({ elapsedNs: () => elapsed, wallSeconds: () => wall });
  context.after(async () => { restoreClock(); await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1", {
        nowSeconds: wall, expiresAt: wall + 6, refreshAfter: wall + 6, offlineAllowed: true,
      });
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false, transport, lifecycle: false,
  });
  assert.equal((await client.activate(keyText)).access, "online");
  elapsed += 10_000_000_000n;
  wall += 10;
  assert.equal(client.snapshot().access, "expired");
});

test("previous credential retry proof is stable and never persists the secret", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-previous-credential-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const previousCredential = "p".repeat(43);
  const operationIds = [];
  let calls = 0;
  const transport = {
    async post(route, body) {
      if (!route.endsWith("/activations")) throw new Error("unexpected request");
      operationIds.push(body.idempotency_key);
      assert.equal(body.previous_credential, previousCredential);
      calls++;
      if (calls === 1) {
        const error = new Error("network unavailable");
        error.kind = ErrorKind.TRANSIENT;
        error.code = "network_unavailable";
        throw error;
      }
      return activationReply(body, "activation-1", "licence-1");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  const statePath = path.join(base, "state");
  client = await openClientForTesting(key, { statePath, machineBinding: false, transport, lifecycle: false });
  await assert.rejects(client.activate(keyText, { previousCredential }), (error) => error.kind === ErrorKind.TRANSIENT);
  await assert.rejects(client.activate(keyText, { previousCredential: "q".repeat(43) }),
    (error) => error.code === "pending_activation_conflict");
  await client.activate(keyText, { previousCredential });
  assert.equal(operationIds[0], operationIds[1]);
  const stored = await readFile(path.join(statePath, "orbit-storage.bin"), "utf8");
  assert.equal(stored.includes(previousCredential), false);
});

test("pending registration handles are bound to the complete origin scope and clear on close", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-registration-scope-"));
  let first;
  let second;
  context.after(async () => {
    await second?.close().catch(() => {});
    await first?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const sameIdsDifferentOrigin = AppKey.parse(`orbit_app_test_${Buffer.from("https://other.example.test").toString("base64url")}.${key.application_id}.${key.environment_id}`);
  let resendCalls = 0;
  const registrationTransport = {
    async post(route) {
      if (!route.endsWith("/registrations")) throw new Error("unexpected request");
      return Buffer.from(JSON.stringify({ accepted: true, expires_at: new Date(Math.floor((Date.now() + 60_000) / 1000) * 1000).toISOString(), resend_credential: "r".repeat(43) }));
    },
  };
  const otherTransport = { async post() { resendCalls++; return Buffer.from('{"accepted":true}'); } };
  first = await openClientForTesting(key, { statePath: path.join(base, "one"), machineBinding: false, transport: registrationTransport });
  second = await openClientForTesting(sameIdsDifferentOrigin, { statePath: path.join(base, "two"), machineBinding: false, transport: otherTransport });
  const result = await first.register(keyText, "registered_user", "user@example.test", "correct horse battery staple");
  await assert.rejects(second.resendRegistration(result.pending), TypeError);
  assert.equal(resendCalls, 0);
  await first.close();
  await assert.rejects(first.resendRegistration(result.pending), (error) => error.code === "client_closed");
});

test("login rejects timestamps that Date.parse would normalize", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-date-validation-"));
  let client;
  context.after(async () => { await client?.close().catch(() => {}); await rm(base, { recursive: true, force: true }); });
  const transport = {
    async post(route) {
      if (!route.endsWith("/sessions")) throw new Error("unexpected request");
      const reply = loginReply("customer-1", "registered_user");
      reply.customer.created_at = "2025-02-30T12:00:00Z";
      return Buffer.from(JSON.stringify(reply));
    },
  };
  client = await openClientForTesting(key, { statePath: path.join(base, "state"), machineBinding: false, transport });
  await assert.rejects(client.login("registered_user", "correct horse battery staple"), (error) => error.code === "invalid_timestamp");
});

test("public Client.open rejects hidden transport and storage overrides", async () => {
  await assert.rejects(Client.open(key, {
    machineBinding: false,
    _transport: { async post() { throw new Error("must not be used"); } },
  }), (error) => error.code === "invalid_client_options");
  const unsafeKey = new AppKey("http://localhost", "app", "env", "test");
  await assert.rejects(Client.open(unsafeKey, { machineBinding: false }),
    (error) => error.code === "invalid_app_key");
  class ForgedAppKey extends AppKey {}
  await assert.rejects(Client.open(new ForgedAppKey("https://localhost", "app", "env", "test"), { machineBinding: false }),
    (error) => error.code === "invalid_app_key");
  await assert.rejects(Client.open(key, { machineBinding: false }, undefined, {
    storageCodec: { encrypt: async (value) => Buffer.from(value), decrypt: async (value) => ({ result: value.toString() }) },
    transport: {}, skipInitialRefresh: true, lifecycle: false,
  }), (error) => error instanceof TypeError && /internal Client\.open arguments/.test(error.message));
  await assert.rejects(Client.open(key, { machineBinding: false }, {}, { lifecycle: false }),
    (error) => error instanceof TypeError && /internal Client\.open arguments/.test(error.message));
});

test("changed device identity rotates the installation and clears credentials", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-installed-binding-"));
  context.after(() => rm(base, { recursive: true, force: true }));
  const target = path.join(base, "state");
  const original = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
  const originalId = original.state.installation.id;
  await original.commitState({ ...original.state, credential: {
    activation_id: "activation", licence_id: "licence", bearer: "a".repeat(43), expires_at: null,
  } });
  await original.close();

  const changed = await PrivateFileStore.open(key, target, { fingerprint: "a".repeat(64), provider: "machine_v1" });
  assert.notEqual(changed.state.installation.id, originalId);
  assert.equal(changed.state.installation.fingerprint, "a".repeat(64));
  assert.equal(changed.state.credential, null);
  await changed.close();
  const restarted = await PrivateFileStore.open(key, target, { fingerprint: "a".repeat(64), provider: "machine_v1" });
  assert.equal(restarted.state.installation.id, changed.state.installation.id);
  await restarted.close();
});

test("an unresolved activation remains retryable without prompting during outage", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-installed-client-"));
  let client;
  let restarted;
  context.after(async () => {
    await restarted?.close().catch(() => {});
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  let calls = 0;
  const ids = [];
  const transport = {
    async post(route, body) {
      if (!route.endsWith("/activations")) throw new Error("unexpected route");
      ids.push(body.idempotency_key);
      calls++;
      if (calls === 1) {
        const error = new Error("network unavailable");
        error.kind = ErrorKind.TRANSIENT;
        error.code = "network_unavailable";
        throw error;
      }
      return activationReply(body, "activation-1", "licence-1");
    },
    async get(route) {
      assert.match(route, /^\/.well-known\/orbit-jwks\.json\?/);
      return Buffer.from(JSON.stringify(grantVectors.jwks));
    },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  for (const property of ["state", "store", "session", "claims", "anchor", "transport", "generation"]) {
    assert.equal(Object.hasOwn(client, property), false, `client must not expose mutable ${property}`);
  }

  await assert.rejects(client.activate(keyText), (error) => error.kind === ErrorKind.TRANSIENT);
  let prompts = 0;
  await assert.rejects(client.ensureAccess("export", () => { prompts++; return keyText; }),
    (error) => error.code === "pending_activation_recovery_required");
  assert.equal(prompts, 0);

  const snapshot = await client.activate(keyText);
  assert.equal(snapshot.access, "online");
  assert.equal(snapshot.has("export"), true);
  assert.equal(ids.length, 2);
  assert.equal(ids[0], ids[1], "retry must reuse its persisted operation ID");
  await client.close();

  restarted = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  assert.equal(restarted.snapshot().has("export"), true);
});

test("account retry proof stays bound to its verified customer", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-account-retry-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  let activations = 0;
  const transport = {
    async post(route, body) {
      if (route.endsWith("/sessions")) {
        const customerId = body.username === "first_user" ? "customer-1" : "customer-2";
        return Buffer.from(JSON.stringify(loginReply(customerId, body.username)));
      }
      if (route.endsWith("/activations")) {
        activations++;
        assert.equal(body.customer_session, "s".repeat(43));
        const error = new Error("network unavailable");
        error.kind = ErrorKind.TRANSIENT;
        error.code = "network_unavailable";
        throw error;
      }
      throw new Error("unexpected request");
    },
    async getBearer() {
      return Buffer.from(JSON.stringify({ items: [{
        id: "licence-1", policy_name: "Desktop", state: "active", expiry_mode: "first_activation",
        first_used_at: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(), expires_at: null, duration_seconds: 3600,
        device_limit: 1, concurrent_session_limit: 0, usage_limits: {}, resource_limits: {}, hwid_locked: false, offline_allowed: true, offline_seconds: 3600,
        offline_file_seconds: 86400, entitlements: { export: true },
      }], next_cursor: null }));
    },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  await client.login("first_user", "correct horse battery staple");
  const page = await client.ownedLicences();
  assert.equal(page.items[0].offlineFileDuration.seconds, 86400);
  assert.equal(Object.isFrozen(page.items), true);
  assert.equal(Object.isFrozen(page.items[0]), true);
  await assert.rejects(client.activateAccount("licence-1"), (error) => error.kind === ErrorKind.TRANSIENT);
  await client.login("second_user", "correct horse battery staple");
  const persisted = await readFile(path.join(base, "state", "orbit-storage.bin"), "utf8");
  assert.equal(persisted.includes("correct horse battery staple"), false);
  assert.equal(persisted.includes("s".repeat(43)), false);
  assert.equal(persisted.includes("customer_session"), false);
  await assert.rejects(client.activateAccount("licence-1"), (error) => error.code === "pending_activation_conflict");
  assert.equal(activations, 1, "a different customer cannot reuse the first customer's uncertain request");
});

test("cancellation fences a late activation reply while preserving its retry ID", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-cancel-activation-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const operationIds = [];
  let releaseFirst;
  let calls = 0;
  const transport = {
    async post(route, body) {
      operationIds.push(body.idempotency_key);
      calls++;
      if (calls === 1) return new Promise((resolve) => { releaseFirst = () => resolve(activationReply(body, "activation-1", "licence-1")); });
      return activationReply(body, "activation-1", "licence-1");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  const controller = new AbortController();
  const activation = client.activate(keyText, { signal: controller.signal });
  for (let i = 0; i < 50 && !releaseFirst; i++) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(typeof releaseFirst, "function", "activation request should be in flight");
  controller.abort();
  releaseFirst();
  await assert.rejects(activation, (error) => error.kind === ErrorKind.CANCELLED);
  assert.equal(client.snapshot().access, "denied");
  await client.activate(keyText);
  assert.equal(operationIds[0], operationIds[1], "retry after cancellation uses the original operation ID");
});

test("late refresh reply after logout cannot restore access", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-refresh-race-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  let holdValidation;
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1");
      if (route.endsWith("/validate")) return new Promise((resolve) => {
        holdValidation = () => resolve(activationReply(body, "activation-1", "licence-1", { credential: null }));
      });
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  await client.activate(keyText);
  const refresh = client.refresh();
  for (let i = 0; i < 50 && !holdValidation; i++) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal(typeof holdValidation, "function", "validation request should be in flight");
  await client.logout();
  holdValidation();
  await assert.rejects(refresh, (error) => error.code === "stale_response");
  assert.equal(client.snapshot().access, "denied");
});

test("short signed expiry advances while the process sleeps", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native clock and storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-sleep-expiry-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const transport = {
    async post(route, body) {
      assert.ok(route.endsWith("/activations"));
      const now = Math.floor(Date.now() / 1000);
      return activationReply(body, "activation-1", "licence-1", {
        nowSeconds: now, expiresAt: now + 6, refreshAfter: now + 6, offlineAllowed: true,
      });
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  assert.equal((await client.activate(keyText)).access, "online");
  await new Promise((resolve) => setTimeout(resolve, 6400));
  assert.equal(client.snapshot().access, "expired");
});

test("wall-clock rollback never triggers a key prompt", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX native clock and storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-clock-rollback-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const realNow = Date.now;
  const transport = {
    async post(route, body) {
      if (route.endsWith("/activations")) return activationReply(body, "activation-1", "licence-1");
      if (route.endsWith("/validate")) {
        const error = new Error("network unavailable");
        error.kind = ErrorKind.TRANSIENT;
        error.code = "network_unavailable";
        throw error;
      }
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  client = await openClientForTesting(key, {
    statePath: path.join(base, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false,
  });
  await client.activate(keyText);
  let prompts = 0;
  Date.now = () => realNow() - 120_000;
  try {
    await assert.rejects(client.ensureAccess("export", () => { prompts++; return keyText; }),
      (error) => error.kind === ErrorKind.TRANSIENT);
  } finally {
    Date.now = realNow;
  }
  assert.equal(prompts, 0);
});

function activationReply(request, activationId, licenceId, options = {}) {
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const claims = {
    iss: key.issuer,
    aud: `orbit:${key.application_id}:${key.environment_id}`,
    sub: licenceId,
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    iat: now,
    nbf: now,
    exp: options.expiresAt ?? now + 300,
    application_id: key.application_id,
    environment_id: key.environment_id,
    activation_id: activationId,
    installation_id: request.installation_id,
    binding_mode: "none",
    policy_version: 1,
    entitlements: { export: true },
    refresh_after: options.refreshAfter ?? now + 60,
    offline_allowed: options.offlineAllowed ?? false,
    licence_expires_at: null,
  };
  const token = signGrant(claims);
  return Buffer.from(JSON.stringify({
    activation_id: activationId,
    installation_id: request.installation_id,
    credential: Object.hasOwn(options, "credential") ? options.credential : "a".repeat(43),
    credential_expires_at: null,
    grant: token,
    server_time: new Date(now * 1000).toISOString(),
    binding_mode: "none",
    fingerprint_provider: request.fingerprint_provider,
    licence_expires_at: null,
    secret_replay_expired: false,
  }));
}

function loginReply(customerId, username) {
  const now = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
  return {
    customer: { id: customerId, username, email: `${username}@example.test`, suspended: false, created_at: now },
    session: "s".repeat(43),
    expires_at: new Date(Date.parse(now) + 3600_000).toISOString(),
  };
}

function signGrant(claims) {
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-access+jwt", kid: "test-key" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signing = createSign("SHA256");
  signing.update(`${header}.${payload}`, "ascii");
  signing.end();
  const signature = signing.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return `${header}.${payload}.${signature}`;
}
