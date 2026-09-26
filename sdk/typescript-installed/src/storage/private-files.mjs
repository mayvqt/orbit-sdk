import { constants as fsConstants, closeSync, fstatSync, ftruncateSync, lstatSync, writeSync } from "node:fs";
import { open } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { scopeHash, canonicalScope } from "../app-key.mjs";
import { fail, ErrorKind } from "../errors.mjs";
import { uniqueJson, isInteger } from "../json.mjs";
import { parseJwks } from "../grants.mjs";
import { lockExclusive, posixFilesystem, syncDirectory, unlock } from "../platform/native.mjs";

const MAX_ENVELOPE = 64 * 1024;
const LOCK = "orbit-storage.lock";
const RECORD = "orbit-storage.bin";
const nofollow = fsConstants.O_NOFOLLOW ?? 0;
const cloexec = fsConstants.O_CLOEXEC ?? 0;
const directory = fsConstants.O_DIRECTORY ?? 0;
let storageFaultForTesting;

export function setStorageFaultForTesting(callback) {
  if (callback !== undefined && typeof callback !== "function") throw new TypeError("storage fault must be a function");
  const previous = storageFaultForTesting;
  storageFaultForTesting = callback;
  return () => { storageFaultForTesting = previous; };
}

function injectStorageFault(stage) {
  storageFaultForTesting?.(stage);
}

export function defaultStatePath(key) {
  const hash = scopeHash(key);
  if (process.platform === "darwin") return path.join(os.homedir(), "Library", "Application Support", "Orbit", hash);
  if (process.platform === "win32") {
    const base = process.env.LOCALAPPDATA;
    if (!base || !path.isAbsolute(base)) throw fail(ErrorKind.STORAGE, "storage_unavailable");
    return path.join(base, "Orbit", hash);
  }
  if (process.platform !== "linux") throw fail(ErrorKind.STORAGE, "storage_unavailable");
  const base = process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
  if (!path.isAbsolute(base)) throw fail(ErrorKind.STORAGE, "storage_failed");
  return path.join(base, "orbit", hash);
}

export class PrivateFileStore {
  static async open(key, statePath, binding, codec = undefined) {
    if (process.platform === "win32") {
      const { WindowsPrivateFileStore } = await import("./private-windows.mjs");
      return WindowsPrivateFileStore.open(key, statePath, binding, codec);
    }
    if (process.platform !== "linux" && process.platform !== "darwin") throw fail(ErrorKind.STORAGE, "storage_unavailable");
    const target = statePath ?? defaultStatePath(key);
    if (typeof target !== "string" || !path.isAbsolute(target) || target === path.parse(target).root ||
        target.includes("\0") || target.split(path.sep).includes("..")) {
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
    const store = new PrivateFileStore(key, path.normalize(target), binding, codec);
    try {
      await store.#open();
      return store;
    } catch (error) {
      await store.close().catch(() => {});
      if (error?.kind) throw error;
      if (error?.code === "EWOULDBLOCK" || error?.code === "EAGAIN") throw fail(ErrorKind.STORAGE, "installation_in_use");
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  constructor(key, target, binding, codec) {
    this.key = key;
    this.target = target;
    this.binding = binding;
    this.codec = codec;
    this.provider = codec ? "electron_safe_storage" : "private_file";
    this.state = null;
    this.lock = null;
    this.dirs = [];
    this.poisoned = false;
    this.closed = false;
    this.commitQueue = Promise.resolve();
    this.reencryptNeeded = false;
  }

  async #open() {
    await this.#openDirectories();
    const stateDirectory = this.dirs.at(-1).handle;
    let created = false;
    try {
      this.lock = await openAtHandle(stateDirectory.fd, LOCK,
        fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | nofollow | cloexec, 0o600);
      created = true;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      this.lock = await openAtHandle(stateDirectory.fd, LOCK, fsConstants.O_RDWR | nofollow | cloexec);
    }
    this.lockId = await this.#validateRegular(this.lock, stateDirectory.fd, LOCK, 0, 1, true);
    lockExclusive(this.lock.fd);
    await this.#verifyLease(0);
    if (created) {
      syncFile(this.lock.fd);
      await syncDirectory(this.dirs.at(-1).handle.fd);
      await this.#verifyLease(0);
    }
    const raw = await this.#readRecord();
    if (raw === null) {
      if (!created) throw fail(ErrorKind.STORAGE, "storage_failed");
      this.state = initialState(this.key, this.binding, this.provider);
      await this.#commit(this.state);
    } else {
      this.state = decodeState(this.key, this.provider, await this.#decode(raw));
      if (this.reencryptNeeded) await this.#commit(this.state);
      if (this.state.installation.fingerprint !== this.binding.fingerprint ||
          this.state.installation.fingerprint_provider !== this.binding.provider) {
        this.state = {
          ...this.state,
          installation: { id: installationId(), fingerprint: this.binding.fingerprint, fingerprint_provider: this.binding.provider },
          generation: checkedNextGeneration(this.state.generation),
          credential: null,
          pending_activation: null,
          access: null,
        };
        await this.#commit(this.state);
      }
    }
    await this.#check();
  }

  async #openDirectories() {
    const parts = this.target.split(path.sep).filter(Boolean);
    let current = path.parse(this.target).root;
    const root = await open(current, fsConstants.O_RDONLY | directory | nofollow | cloexec);
    this.dirs.push({ path: current, handle: root, id: null });
    this.dirs[0].id = await root.stat({ bigint: true });
    for (let index = 0; index < parts.length; index++) {
      current = path.join(current, parts[index]);
      const parent = this.dirs.at(-1).handle;
      let next;
      let created = false;
      try {
        const currentEntry = statAt(parent.fd, parts[index], true);
        if (!currentEntry.isDirectory()) throw fail(ErrorKind.STORAGE, "storage_failed");
        next = await openAtHandle(parent.fd, parts[index], fsConstants.O_RDONLY | directory | nofollow | cloexec);
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        mkdirAt(parent.fd, parts[index], 0o700);
        next = await openAtHandle(parent.fd, parts[index], fsConstants.O_RDONLY | directory | nofollow | cloexec);
        created = true;
      }
      const pinned = { path: current, handle: next, id: null, parent, name: parts[index] };
      this.dirs.push(pinned);
      const info = await next.stat({ bigint: true });
      pinned.id = info;
      if (!info.isDirectory() || info.nlink === 0n) throw fail(ErrorKind.STORAGE, "storage_failed");
      if (index === parts.length - 1 && (info.uid !== BigInt(process.getuid()) || (info.mode & 0o077n) !== 0n)) {
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      if (created) {
        await next.sync();
        injectStorageFault("directory_child_synced");
        await parent.sync();
        injectStorageFault("directory_parent_synced");
      }
    }
    if (this.dirs.at(-1).path !== this.target) throw fail(ErrorKind.STORAGE, "storage_failed");
  }

  async #validateRegular(handle, parentFd, name, minSize, maxSize, lockFile = false) {
    const info = await handle.stat({ bigint: true });
    const current = statAt(parentFd, name);
    if (!info.isFile() || !current.isFile() || info.dev !== current.dev || info.ino !== current.ino ||
        info.uid !== BigInt(process.getuid()) || current.uid !== BigInt(process.getuid()) ||
        (info.mode & 0o077n) !== 0n || (current.mode & 0o077n) !== 0n || info.nlink !== 1n || current.nlink !== 1n ||
        info.size < BigInt(minSize) || info.size > BigInt(maxSize)) throw fail(ErrorKind.STORAGE, "storage_failed");
    if (lockFile && info.size !== 0n) throw fail(ErrorKind.STORAGE, "storage_failed");
    return identity(info);
  }

  async #check(leaseSize = 0) {
    if (this.poisoned || this.closed || !this.lock) throw fail(ErrorKind.STORAGE, "storage_failed");
    for (let index = 0; index < this.dirs.length; index++) {
      const pinned = this.dirs[index];
      const opened = await pinned.handle.stat({ bigint: true });
      const current = index === 0 ? lstatSync(pinned.path, { bigint: true }) : statAt(pinned.parent.fd, pinned.name, true);
      if (!opened.isDirectory() || !current.isDirectory() || opened.dev !== pinned.id.dev || opened.ino !== pinned.id.ino ||
          current.dev !== pinned.id.dev || current.ino !== pinned.id.ino || opened.nlink === 0n || current.nlink === 0n) {
        this.poisoned = true;
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      if (index === this.dirs.length - 1 && (opened.uid !== BigInt(process.getuid()) || current.uid !== BigInt(process.getuid()) ||
          (opened.mode & 0o077n) !== 0n || (current.mode & 0o077n) !== 0n)) {
        this.poisoned = true;
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
    }
    await this.#verifyLease(leaseSize);
    await this.#verifyRecord();
  }

  assertHealthySync(leaseSize = 0) {
    if (this.poisoned || this.closed || !this.lock) throw fail(ErrorKind.STORAGE, "storage_failed");
    try {
      for (let index = 0; index < this.dirs.length; index++) {
        const pinned = this.dirs[index];
        const opened = fstatSync(pinned.handle.fd, { bigint: true });
        const named = index === 0 ? lstatSync(pinned.path, { bigint: true }) : statAt(pinned.parent.fd, pinned.name, true);
        if (!named.isDirectory() || !opened.isDirectory() || opened.dev !== pinned.id.dev || opened.ino !== pinned.id.ino ||
            named.dev !== pinned.id.dev || named.ino !== pinned.id.ino || opened.nlink === 0n || named.nlink === 0n) {
          throw new Error("directory identity changed");
        }
        if (index === this.dirs.length - 1 && (opened.uid !== BigInt(process.getuid()) || named.uid !== BigInt(process.getuid()) ||
            (opened.mode & 0o077n) !== 0n || (named.mode & 0o077n) !== 0n)) throw new Error("directory permissions changed");
      }
      const openedLease = fstatSync(this.lock.fd, { bigint: true });
      const namedLease = statAt(this.dirs.at(-1).handle.fd, LOCK);
      if (!openedLease.isFile() || !namedLease.isFile() || openedLease.dev !== this.lockId.dev ||
          openedLease.ino !== this.lockId.ino || namedLease.dev !== openedLease.dev || namedLease.ino !== openedLease.ino ||
          openedLease.uid !== BigInt(process.getuid()) || namedLease.uid !== BigInt(process.getuid()) ||
          (openedLease.mode & 0o077n) !== 0n || (namedLease.mode & 0o077n) !== 0n ||
          openedLease.nlink !== 1n || namedLease.nlink !== 1n || openedLease.size !== BigInt(leaseSize) || namedLease.size !== BigInt(leaseSize)) {
        throw new Error("lease identity changed");
      }
      try {
        const record = statAt(this.dirs.at(-1).handle.fd, RECORD);
        if (!this.recordId || !record.isFile() || !sameIdentity(record, this.recordId) ||
            record.uid !== BigInt(process.getuid()) || (record.mode & 0o077n) !== 0n || record.nlink !== 1n ||
            record.size < 1n || record.size > BigInt(MAX_ENVELOPE + 2048)) throw new Error("record identity changed");
      } catch (error) {
        if (error.code !== "ENOENT" || this.recordId) throw error;
      }
    } catch (error) {
      this.poisoned = true;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  async #verifyLease(size) {
    const info = await this.lock.stat({ bigint: true });
    const current = statAt(this.dirs.at(-1).handle.fd, LOCK);
    if (!info.isFile() || !current.isFile() || this.lockId && (info.dev !== this.lockId.dev || info.ino !== this.lockId.ino) ||
        info.dev !== current.dev || info.ino !== current.ino || info.uid !== BigInt(process.getuid()) ||
        current.uid !== BigInt(process.getuid()) || (info.mode & 0o077n) !== 0n || (current.mode & 0o077n) !== 0n ||
        info.nlink !== 1n || current.nlink !== 1n || info.size !== BigInt(size) || current.size !== BigInt(size)) {
      this.poisoned = true;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  async #verifyRecord() {
    try {
      const info = statAt(this.dirs.at(-1).handle.fd, RECORD);
      if (!this.recordId || !info.isFile() || !sameIdentity(info, this.recordId) ||
          info.uid !== BigInt(process.getuid()) || (info.mode & 0o077n) !== 0n || info.nlink !== 1n ||
          info.size < 1n || info.size > BigInt(MAX_ENVELOPE + 2048)) {
        this.poisoned = true;
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
    } catch (error) {
      if (error?.kind) throw error;
      if (error.code === "ENOENT" && !this.recordId) return;
      this.poisoned = true;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  async #readRecord() {
    await this.#verifyLease(0);
    let handle;
    try {
      handle = await openAtHandle(this.dirs.at(-1).handle.fd, RECORD,
        fsConstants.O_RDONLY | nofollow | cloexec | (fsConstants.O_NONBLOCK ?? 0));
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
    try {
      const identity = await this.#validateRegular(handle, this.dirs.at(-1).handle.fd, RECORD, 1, MAX_ENVELOPE + 2048);
      if (identity.size > BigInt(MAX_ENVELOPE + 2048)) throw fail(ErrorKind.STORAGE, "storage_failed");
      this.recordId = identity;
      const raw = Buffer.alloc(Number(identity.size));
      const { bytesRead } = await handle.read(raw, 0, raw.length, 0);
      if (bytesRead !== raw.length) throw fail(ErrorKind.STORAGE, "storage_failed");
      await this.#verifyLease(0);
      return raw;
    } finally {
      await handle.close();
    }
  }

  async #encode(state) {
    const raw = Buffer.from(JSON.stringify(state), "utf8");
    if (!raw.length || raw.length > MAX_ENVELOPE) throw fail(ErrorKind.STORAGE, "storage_failed");
    return this.codec ? this.codec.encrypt(raw.toString("utf8")) : raw;
  }

  async #decode(raw) {
    if (this.codec) {
      let decrypted = await this.codec.decrypt(raw);
      if (decrypted?.isTemporarilyUnavailable === true) throw fail(ErrorKind.STORAGE, "storage_unavailable");
      if (decrypted?.shouldReEncrypt === true) {
        this.reencryptNeeded = true;
        decrypted = await this.codec.decrypt(raw);
        if (decrypted?.isTemporarilyUnavailable === true || decrypted?.shouldReEncrypt === true) {
          throw fail(ErrorKind.STORAGE, "storage_unavailable");
        }
      }
      if (typeof decrypted?.result !== "string") throw fail(ErrorKind.STORAGE, "storage_failed");
      return Buffer.from(decrypted.result, "utf8");
    }
    return raw;
  }

  async #commit(state, guard = undefined) {
    let tempFd;
    let temporary;
    let replaced = false;
    try {
      checkGuard(guard);
      await this.#check();
      const bytes = await this.#encode(state);
      if (!bytes.length || bytes.length > MAX_ENVELOPE + 2048) throw fail(ErrorKind.STORAGE, "storage_failed");
      checkGuard(guard);
      this.assertHealthySync(0);
      writeSync(this.lock.fd, Buffer.from([1]), 0, 1, 0);
      injectStorageFault("lease_marker_written");
      syncFile(this.lock.fd);
      injectStorageFault("lease_marker_synced");
      checkGuard(guard);
      this.assertHealthySync(1);
      temporary = `.orbit-storage-${randomBytes(16).toString("hex")}.tmp`;
      const directoryHandle = this.dirs.at(-1).handle;
      tempFd = openAtFd(directoryHandle.fd, temporary,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | nofollow | cloexec, 0o600);
      injectStorageFault("write");
      let offset = 0;
      while (offset < bytes.length) {
        const written = writeSync(tempFd, bytes, offset, bytes.length - offset, offset);
        if (!written) throw new Error("short state write");
        offset += written;
      }
      injectStorageFault("fsync");
      syncFile(tempFd);
      const openedTemp = fstatSync(tempFd, { bigint: true });
      const namedTemp = statAt(directoryHandle.fd, temporary);
      if (!openedTemp.isFile() || !namedTemp.isFile() || openedTemp.dev !== namedTemp.dev || openedTemp.ino !== namedTemp.ino ||
          openedTemp.uid !== BigInt(process.getuid()) || namedTemp.uid !== BigInt(process.getuid()) ||
          (openedTemp.mode & 0o077n) !== 0n || (namedTemp.mode & 0o077n) !== 0n ||
          openedTemp.nlink !== 1n || namedTemp.nlink !== 1n || openedTemp.size !== BigInt(bytes.length) || namedTemp.size !== BigInt(bytes.length)) {
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      checkGuard(guard);
      this.assertHealthySync(1);
      injectStorageFault("rename");
      renameAt(directoryHandle.fd, temporary, directoryHandle.fd, RECORD);
      replaced = true;
      const newRecord = statAt(directoryHandle.fd, RECORD);
      if (!newRecord.isFile() || newRecord.nlink !== 1n || newRecord.uid !== BigInt(process.getuid()) ||
          (newRecord.mode & 0o077n) !== 0n) throw fail(ErrorKind.STORAGE, "storage_failed");
      this.recordId = identity(newRecord);
      syncDirectory(this.dirs.at(-1).handle.fd);
      this.assertHealthySync(1);
      try {
        ftruncateSync(this.lock.fd, 0);
        injectStorageFault("lease_marker_cleared");
        injectStorageFault("clear");
        syncFile(this.lock.fd);
        injectStorageFault("lease_marker_clear_synced");
      } catch (error) {
        try {
          writeSync(this.lock.fd, Buffer.from([1]), 0, 1, 0);
          syncFile(this.lock.fd);
          injectStorageFault("lease_marker_restored");
        } catch { /* Keep the store poisoned if even the pending marker cannot be restored. */ }
        throw error;
      }
      this.assertHealthySync(0);
      this.reencryptNeeded = false;
      this.state = state;
    } catch (error) {
      if (error?.kind !== ErrorKind.STALE_RESPONSE && error?.kind !== ErrorKind.CANCELLED) this.poisoned = true;
      if (error?.kind) throw error;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    } finally {
      if (tempFd !== undefined) closeSync(tempFd);
      if (temporary && !replaced) {
        try { unlinkAt(this.dirs.at(-1).handle.fd, temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
      }
    }
  }

  async commitState(state) {
    const commit = this.commitQueue.then(() => this.#commit(state));
    this.commitQueue = commit.catch(() => {});
    await commit;
  }

  async updateState(transform, guard = undefined) {
    const commit = this.commitQueue.then(async () => {
      checkGuard(guard);
      const next = await transform(this.state);
      checkGuard(guard);
      if (next === this.state) return this.state;
      await this.#commit(next, guard);
      return this.state;
    });
    this.commitQueue = commit.catch(() => {});
    await commit;
    return this.state;
  }

  async drain() {
    await this.commitQueue;
  }

  async sync() {
    await this.#check();
    return this.state;
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this.lock) {
      unlock(this.lock.fd);
      await this.lock.close().catch(() => {});
      this.lock = null;
    }
    for (const entry of this.dirs.reverse()) await entry.handle.close().catch(() => {});
    this.dirs = [];
  }
}

function checkGuard(guard) {
  if (guard && !guard()) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
}

export function initialState(key, binding, provider) {
  return {
    sdk: "orbit.installed-client",
    format: 2,
    provider,
    scope: canonicalScope(key),
    installation: { id: installationId(), fingerprint: binding.fingerprint, fingerprint_provider: binding.provider },
    generation: 0,
    credential: null,
    pending_activation: null,
    access: null,
  };
}

export function decodeState(key, provider, raw) {
  const state = uniqueJson(raw);
  if (!exactKeys(state, ["sdk", "format", "provider", "scope", "installation", "generation", "credential", "pending_activation", "access"]) ||
      state.sdk !== "orbit.installed-client" || state.format !== 2 || !["private_file", "electron_safe_storage", "windows_dpapi"].includes(provider) ||
      state.provider !== provider || !exactKeys(state.scope, ["api_origin", "issuer", "application_id", "environment_id"]) ||
      !sameJson(state.scope, canonicalScope(key)) || !isInteger(state.generation, 0, Number.MAX_SAFE_INTEGER) ||
      !validInstallation(state.installation) || state.credential !== null && !validCredential(state.credential) ||
      state.pending_activation !== null && !validPending(state.pending_activation) || state.access !== null && !validAccess(state.access) ||
      state.access !== null && state.credential === null ||
      state.pending_activation !== null && (state.credential !== null || state.access !== null)) {
    throw fail(ErrorKind.STORAGE, "storage_failed");
  }
  return state;
}

function validInstallation(value) {
  return exactKeys(value, ["id", "fingerprint", "fingerprint_provider"]) &&
    typeof value.id === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value.id) &&
    (value.fingerprint === null && value.fingerprint_provider === null ||
      typeof value.fingerprint === "string" && /^[0-9a-f]{64}$/.test(value.fingerprint) && validBindingProvider(value.fingerprint_provider));
}

function validCredential(value) {
  return exactKeys(value, ["activation_id", "licence_id", "bearer", "expires_at"]) && typeof value.activation_id === "string" &&
    /^[A-Za-z0-9_-]{1,128}$/.test(value.activation_id) && typeof value.licence_id === "string" &&
    /^[A-Za-z0-9_-]{1,128}$/.test(value.licence_id) && typeof value.bearer === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.bearer) &&
    (value.expires_at === null || isInteger(value.expires_at, 1));
}

function validPending(value) {
  return exactKeys(value, ["operation_id", "principal_kind", "input_digest", "created_at"]) && typeof value.operation_id === "string" &&
    Buffer.byteLength(value.operation_id, "utf8") >= 16 && Buffer.byteLength(value.operation_id, "utf8") <= 128 &&
    (value.principal_kind === "key" || value.principal_kind === "account") && typeof value.input_digest === "string" && /^[0-9a-f]{64}$/.test(value.input_digest) &&
    isInteger(value.created_at, 0);
}

function validAccess(value) {
  if (!exactKeys(value, ["jws", "jwks", "licence_expires_at", "received_server_time", "received_wall_time", "server_high_water", "wall_high_water"]) ||
      typeof value.jws !== "string" || value.jws.length < 1 || value.jws.length > 16 * 1024 || !/^[\x00-\x7f]+$/.test(value.jws) ||
      !exactKeys(value.jwks, ["keys"]) || !Array.isArray(value.jwks.keys) || value.jwks.keys.length !== 1 ||
      !isInteger(value.received_server_time, 0) || !isInteger(value.received_wall_time, 0) ||
      !isInteger(value.server_high_water, value.received_server_time) || !isInteger(value.wall_high_water, value.received_wall_time)) return false;
  try {
    if (parseJwks(value.jwks).size !== 1) return false;
  } catch {
    return false;
  }
  return (value.licence_expires_at === null || isInteger(value.licence_expires_at, 1)) &&
    ["received_server_time", "received_wall_time", "server_high_water", "wall_high_water"].every((key) => isInteger(value[key], 0)) &&
    Math.abs((value.server_high_water - value.received_server_time) - (value.wall_high_water - value.received_wall_time)) <= 30;
}

function exactKeys(value, names) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}

function validBindingProvider(value) {
  return value === "machine_v1" || typeof value === "string" && /^custom:[a-z0-9_.-]{1,48}$/.test(value);
}

function checkedNextGeneration(value) {
  if (!isInteger(value, 0, Number.MAX_SAFE_INTEGER - 1)) throw fail(ErrorKind.STORAGE, "storage_failed");
  return value + 1;
}

function installationId() {
  return randomBytes(24).toString("base64url");
}

function identity(info) {
  return { dev: info.dev, ino: info.ino, size: info.size, ctimeNs: info.ctimeNs };
}

function sameIdentity(info, expected) {
  return info.dev === expected.dev && info.ino === expected.ino && info.size === expected.size && info.ctimeNs === expected.ctimeNs;
}

function fdPath(fd) {
  return path.join("/dev/fd", String(fd));
}

async function openAtHandle(directoryFd, name, flags, mode = 0) {
  const fd = openAtFd(directoryFd, name, flags, mode);
  try {
    const duplicateFlags = flags & ~(fsConstants.O_CREAT | fsConstants.O_EXCL | nofollow);
    return await open(fdPath(fd), duplicateFlags);
  } finally {
    closeSync(fd);
  }
}

function openAtFd(directoryFd, name, flags, mode = 0) {
  const api = posixFilesystem();
  const fd = api.openat(directoryFd, name, flags, mode);
  if (fd < 0) throw nativeFsError(api);
  return fd;
}

function statAt(directoryFd, name, expectDirectory = false) {
  const api = posixFilesystem();
  const rawStat = Buffer.alloc(512);
  const noFollow = api.atSymlinkNoFollow ?? (api.platform === "darwin" ? 0x20 : 0x100);
  if (api.fstatat(directoryFd, name, rawStat, noFollow) !== 0) throw nativeFsError(api);
  const flags = fsConstants.O_RDONLY | nofollow | (fsConstants.O_NONBLOCK ?? 0) |
    (expectDirectory ? directory : 0);
  const fd = openAtFd(directoryFd, name, flags);
  try {
    return fstatSync(fd, { bigint: true });
  } finally {
    closeSync(fd);
  }
}

function mkdirAt(directoryFd, name, mode) {
  const api = posixFilesystem();
  if (api.mkdirat(directoryFd, name, mode) !== 0) throw nativeFsError(api);
}

function renameAt(sourceDirectoryFd, sourceName, destinationDirectoryFd, destinationName) {
  const api = posixFilesystem();
  if (api.renameat(sourceDirectoryFd, sourceName, destinationDirectoryFd, destinationName) !== 0) throw nativeFsError(api);
}

function unlinkAt(directoryFd, name) {
  const api = posixFilesystem();
  if (api.unlinkat(directoryFd, name, 0) !== 0) throw nativeFsError(api);
}

function syncFile(fd) {
  posixFilesystem().syncFile(fd);
}

function nativeFsError(api) {
  const value = api.errno();
  const names = (api.errorPlatform ?? api.platform) === "darwin"
    ? new Map([[2, "ENOENT"], [17, "EEXIST"], [20, "ENOTDIR"], [13, "EACCES"], [24, "EMFILE"], [30, "EROFS"], [35, "EAGAIN"], [62, "ELOOP"]])
    : new Map([[2, "ENOENT"], [17, "EEXIST"], [20, "ENOTDIR"], [13, "EACCES"], [24, "EMFILE"], [30, "EROFS"], [11, "EAGAIN"], [40, "ELOOP"]]);
  const error = new Error("descriptor-relative filesystem operation failed");
  error.code = names.get(value) ?? value;
  return error;
}

function sameJson(a, b) {
  return JSON.stringify(sortObject(a)) === JSON.stringify(sortObject(b));
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortObject(value[key])]));
  }
  return value;
}
