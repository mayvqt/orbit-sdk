import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { ErrorKind } from "../src/errors.mjs";
import { PrivateFileStore } from "../src/storage/private-files.mjs";
import {
  assertWindowsProcessIdentityForTesting,
  checkPrivateForTesting,
  dpapiForTesting,
  setWindowsApiForTesting,
  WindowsPrivateFileStore,
} from "../src/storage/private-windows.mjs";

const key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g");

test("Windows DPAPI state is leased and survives a restart", async (context) => {
  if (process.platform !== "win32") return context.skip("Windows native storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-installed-win-"));
  const target = path.join(base, "state");
  let store;
  try {
    store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
    assert.equal(store.provider, "windows_dpapi");
    const installationId = store.state.installation.id;
    await assert.rejects(PrivateFileStore.open(key, target, { fingerprint: null, provider: null }),
      (error) => error.kind === ErrorKind.STORAGE && error.code === "installation_in_use");
    await store.close();
    store = await PrivateFileStore.open(key, target, { fingerprint: null, provider: null });
    assert.equal(store.state.installation.id, installationId);
  } finally {
    await store?.close();
    await rm(base, { recursive: true, force: true });
  }
});

test("Windows storage rejects unsupported drives and invalid native directory handles", async () => {
  const binding = { fingerprint: null, provider: null };
  let restore = setWindowsApiForTesting({ GetDriveTypeW: () => 4 });
  try {
    await assert.rejects(WindowsPrivateFileStore.open(key, "C:\\Orbit\\state", binding),
      (error) => error.kind === ErrorKind.STORAGE && error.code === "storage_failed");
  } finally { restore(); }

  restore = setWindowsApiForTesting({
    GetDriveTypeW: () => 3,
    securityAttributesSizeForTesting: 12,
    LocalFree: () => null,
    CreateFileW: () => 1n,
    GetFileInformationByHandle: () => false,
    CloseHandle: () => true,
  });
  try {
    await assert.rejects(WindowsPrivateFileStore.open(key, "C:\\Orbit\\state", binding),
      (error) => error.kind === ErrorKind.STORAGE && error.code === "storage_failed");
  } finally { restore(); }
});

test("Windows storage cancellation during codec work leaves the store usable for logout", async () => {
  const memory = memoryWindowsApi();
  const restore = setWindowsApiForTesting(memory.api);
  let store;
  try {
    let blockNext = false;
    let started;
    let release;
    const codec = {
      async encrypt(value) {
        if (blockNext) {
          blockNext = false;
          await new Promise((resolve) => { release = resolve; started(); });
        }
        return Buffer.from(value);
      },
      async decrypt(value) { return { result: value.toString("utf8") }; },
    };
    try {
      store = await WindowsPrivateFileStore.open(key, "C:\\Orbit\\state", { fingerprint: null, provider: null }, codec);
    } catch (error) {
      throw new Error(`${error.code}: ${memory.trace.join(" | ")}`, { cause: error });
    }
    await store.updateState((state) => ({ ...state, credential: {
      activation_id: "activation-1", licence_id: "licence-1", bearer: "a".repeat(43), expires_at: null,
    } }));
    let allowed = true;
    const encodingStarted = new Promise((resolve) => { started = resolve; });
    blockNext = true;
    const cancelled = store.updateState((state) => ({
      ...state, credential: null, access: null, generation: state.generation + 1,
    }), () => allowed);
    await encodingStarted;
    allowed = false;
    release();
    await assert.rejects(cancelled, (error) => error.code === "stale_response");
    assert.equal(store.poisoned, false);
    assert.ok(store.state.credential);

    await store.updateState((state) => ({
      ...state, credential: null, access: null, generation: state.generation + 1,
    }));
    assert.equal(store.state.credential, null);
    assert.equal(store.poisoned, false);
    assert.equal(memory.files.get("C:\\Orbit\\state\\orbit-storage.lock").bytes.length, 0);
  } finally {
    await store?.close();
    restore();
  }
});

test("Windows lease markers rewind, verify one-byte writes, and restore after an uncertain clear", async () => {
  const memory = memoryWindowsApi();
  const restore = setWindowsApiForTesting(memory.api);
  let store;
  try {
    const codec = { async encrypt(value) { return Buffer.from(value); }, async decrypt(value) { return { result: value.toString() }; } };
    store = await WindowsPrivateFileStore.open(key, "C:\\Orbit\\marker-state", { fingerprint: null, provider: null }, codec);
    memory.failFlushAt = memory.flushCount + 3;
    await assert.rejects(store.updateState((state) => ({ ...state, generation: state.generation + 1 })),
      (error) => error.kind === ErrorKind.STORAGE);
    const markerPath = "C:\\Orbit\\marker-state\\orbit-storage.lock";
    assert.equal(memory.files.get(markerPath).bytes.length, 1);
    const markerWrites = memory.writes.filter((write) => write.path === markerPath);
    assert.ok(markerWrites.length >= 3);
    assert.ok(markerWrites.every((write) => write.position === 0 && write.count === 1 && write.bytes.equals(Buffer.from([1]))));
  } finally {
    await store?.close();
    restore();
  }
});

test("Windows storage frees native allocations on malformed ACL and DPAPI results", () => {
  const freed = [];
  let restore = setWindowsApiForTesting({
    GetSecurityInfo(_handle, _type, _flags, _owner, _group, _dacl, _sacl, descriptor) {
      descriptor[0] = 0x1234n;
      return 5;
    },
    LocalFree(pointer) { freed.push(pointer); return null; },
  });
  try {
    assert.throws(() => checkPrivateForTesting(7n), (error) => error.kind === ErrorKind.STORAGE);
    assert.deepEqual(freed, [0x1234n]);
  } finally { restore(); }

  restore = setWindowsApiForTesting({
    assertNoThreadImpersonationForTesting() {},
    CryptProtectData(_input, _description, _entropy, _reserved, _prompt, _flags, output) {
      output.size = 70 * 1024;
      output.data = 0x5678n;
      return true;
    },
    LocalFree(pointer) { freed.push(pointer); return null; },
  });
  try {
    assert.throws(() => dpapiForTesting("CryptProtectData", Buffer.from("x"), Buffer.from("y"), 10),
      (error) => error.kind === ErrorKind.STORAGE);
    assert.equal(freed.at(-1), 0x5678n);
  } finally { restore(); }
});

test("Windows identity check rejects impersonation and permits only ERROR_NO_TOKEN", () => {
  let closed = [];
  let restore = setWindowsApiForTesting({
    GetCurrentThread: () => 1n,
    OpenThreadToken(_thread, _access, openAsSelf, token) { assert.equal(openAsSelf, true); token[0] = 2n; return true; },
    CloseHandle(handle) { closed.push(handle); return true; },
  });
  try {
    assert.throws(() => assertWindowsProcessIdentityForTesting(), (error) => error.kind === ErrorKind.STORAGE);
    assert.deepEqual(closed, [2n]);
  } finally { restore(); }

  restore = setWindowsApiForTesting({
    GetCurrentThread: () => 1n,
    OpenThreadToken: () => false,
    GetLastError: () => 1008,
  });
  try { assert.doesNotThrow(() => assertWindowsProcessIdentityForTesting()); }
  finally { restore(); }

  restore = setWindowsApiForTesting({
    GetCurrentThread: () => 1n,
    OpenThreadToken: () => false,
    GetLastError: () => 5,
  });
  try { assert.throws(() => assertWindowsProcessIdentityForTesting(), (error) => error.kind === ErrorKind.STORAGE); }
  finally { restore(); }
});

function memoryWindowsApi() {
  const directories = new Map([["C:\\", { index: 1, kind: "directory" }]]);
  const files = new Map();
  const handles = new Map();
  let nextHandle = 10n;
  let nextIndex = 2;
  let lastError = 0;
  let flushCount = 0;
  let failFlushAt = null;
  const trace = [];
  const writes = [];
  function normalize(value) { return path.win32.normalize(value); }
  function error(code) { lastError = code; return 0xffffffffffffffffn; }
  function handleFor(file) {
    const handle = nextHandle++;
    handles.set(handle, { file, position: 0 });
    return handle;
  }
  function getFile(name, disposition) {
    name = normalize(name);
    trace.push(`open:${name}:${disposition}`);
    if (directories.has(name)) return handleFor(directories.get(name));
    let file = files.get(name);
    if (disposition === 1) {
      if (file) return error(80);
      file = { index: nextIndex++, kind: "file", path: name, bytes: Buffer.alloc(0), revision: 0 };
      files.set(name, file);
      return handleFor(file);
    }
    if (!file) return error(2);
    return handleFor(file);
  }
  const api = {
    GetDriveTypeW: () => 3,
    securityAttributesSizeForTesting: 12,
    LocalFree: () => null,
    CreateFileW: (name, _access, _share, _security, disposition) => getFile(name, disposition),
    CreateDirectoryW(name) {
      name = normalize(name);
      trace.push(`mkdir:${name}`);
      if (directories.has(name)) { lastError = 183; return false; }
      directories.set(name, { index: nextIndex++, kind: "directory" });
      return true;
    },
    createPrivateSecurityDescriptorForTesting: () => 3n,
    checkPrivateForTesting() {},
    assertNoThreadImpersonationForTesting() {},
    fileInfoForTesting(handle) {
      const entry = handles.get(handle)?.file;
      if (!entry) throw new Error("unknown fake Windows handle");
      return { attributes: entry.kind === "directory" ? 0x10 : 0, volume: 1, index: BigInt(entry.index),
        size: entry.bytes?.length ?? 0, writeTime: BigInt(entry.revision ?? 0), links: 1 };
    },
    ReadFile(handle, output, count, read) {
      const state = handles.get(handle);
      if (!state) return false;
      const copied = Math.min(count, state.file.bytes.length);
      state.file.bytes.copy(output, 0, 0, copied);
      read[0] = copied;
      return true;
    },
    WriteFile(handle, input, count, written) {
      const state = handles.get(handle);
      if (!state || state.file.kind !== "file") return false;
      const actual = Math.min(count, input.length);
      const length = Math.max(state.file.bytes.length, state.position + actual);
      const next = Buffer.alloc(length);
      state.file.bytes.copy(next);
      input.copy(next, state.position, 0, actual);
      state.file.bytes = next;
      state.position += actual;
      state.file.revision++;
      written[0] = actual;
      writes.push({ path: state.file.path, position: state.position - actual, count: actual, bytes: Buffer.from(input.subarray(0, actual)) });
      return true;
    },
    FlushFileBuffers() { flushCount++; return flushCount !== failFlushAt; },
    SetFilePointerEx(handle, distance, output) {
      const state = handles.get(handle);
      if (!state) return false;
      state.position = Number(distance);
      output[0] = BigInt(state.position);
      return true;
    },
    SetEndOfFile(handle) {
      const state = handles.get(handle);
      if (!state) return false;
      state.file.bytes = state.file.bytes.subarray(0, state.position);
      state.file.revision++;
      return true;
    },
    MoveFileExW(source, destination) {
      source = normalize(source); destination = normalize(destination);
      const file = files.get(source);
      if (!file) return false;
      files.delete(source); file.path = destination; files.set(destination, file); return true;
    },
    DeleteFileW(name) { return files.delete(normalize(name)); },
    CloseHandle(handle) { handles.delete(handle); return true; },
    GetLastError: () => lastError,
  };
  return {
    api, files, handles, trace, writes,
    get flushCount() { return flushCount; },
    set failFlushAt(value) { failFlushAt = value; },
  };
}
