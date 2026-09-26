import koffi from "koffi";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { canonicalScope, scopeHash } from "../app-key.mjs";
import { fail, ErrorKind } from "../errors.mjs";
import { initialState, decodeState } from "./private-files.mjs";

const LOCK = "orbit-storage.lock";
const RECORD = "orbit-storage.bin";
const MAX_ENVELOPE = 64 * 1024;
const MAX_CIPHER = 65 * 1024;
const INVALID_HANDLE = 0xffffffffffffffffn;
const GENERIC_READ = 0x80000000;
const GENERIC_WRITE = 0x40000000;
const FILE_SHARE_READ_WRITE = 3;
const OPEN_EXISTING = 3;
const CREATE_NEW = 1;
const FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
const FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
const FILE_ATTRIBUTE_DIRECTORY = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
const FILE_BEGIN = 0;
const MOVEFILE_REPLACE_EXISTING = 1;
const MOVEFILE_WRITE_THROUGH = 8;
const TOKEN_QUERY = 0x0008;
const ERROR_NO_TOKEN = 1008;
let native;

export function setWindowsApiForTesting(api) {
  const previous = native;
  native = api;
  return () => { native = previous; };
}

export function assertWindowsProcessIdentityForTesting() {
  ensureNoThreadImpersonation();
}

export function dpapiForTesting(name, data, entropy, maximum) {
  return dpapi(name, data, entropy, maximum);
}

export function checkPrivateForTesting(handle) {
  checkPrivate(handle);
}

export class WindowsPrivateFileStore {
  static async open(key, statePath, binding, codec = undefined) {
    const target = statePath ?? defaultStatePath(key);
    validatePath(target);
    const store = new WindowsPrivateFileStore(key, path.win32.normalize(target), binding, codec);
    try {
      await store.#open();
      return store;
    } catch (error) {
      await store.close();
      if (error?.kind) throw error;
      if (error?.code === 32) throw fail(ErrorKind.STORAGE, "installation_in_use");
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  constructor(key, target, binding, codec) {
    this.key = key;
    this.target = target;
    this.binding = binding;
    this.codec = codec;
    this.provider = codec ? "electron_safe_storage" : "windows_dpapi";
    this.state = null;
    this.directories = [];
    this.lease = null;
    this.leaseId = null;
    this.recordId = null;
    this.poisoned = false;
    this.closed = false;
    this.commitQueue = Promise.resolve();
    this.reencryptNeeded = false;
    this.entropy = createHash("sha256").update("orbit.installed-client.dpapi.v2\0", "ascii")
      .update(JSON.stringify(canonicalScope(key)), "utf8").digest();
  }

  async #open() {
    const api = apiForWindows();
    const drive = path.win32.parse(this.target).root;
    const driveType = drive ? api.GetDriveTypeW(drive) : 0;
    if (![2, 3, 6].includes(driveType)) throw fail(ErrorKind.STORAGE, "storage_failed");
    const root = drive;
    this.#pinDirectory(root, false);
    let current = root;
    const relative = this.target.slice(root.length).split("\\").filter(Boolean);
    for (const [index, component] of relative.entries()) {
      current = path.win32.join(current, component);
      this.#pinDirectory(current, index === relative.length - 1);
    }
    this.#checkDirectory(this.directories.at(-1), true);
    const leasePath = path.win32.join(this.target, LOCK);
    let created = true;
    try {
      this.lease = openHandle(leasePath, GENERIC_READ | GENERIC_WRITE, 0, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, true);
    } catch (error) {
      created = false;
      if (error.code === 32) throw error;
      if (error.code !== 80 && error.code !== 183) throw error;
      this.lease = openHandle(leasePath, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT);
    }
    this.leaseId = checkRegular(this.lease, 0, 0, true);
    checkPrivate(this.lease);
    this.#check();
    if (created && !api.FlushFileBuffers(this.lease)) throw fail(ErrorKind.STORAGE, "storage_failed");
    const cipher = this.#readRecord();
    if (cipher === null) {
      if (!created) throw fail(ErrorKind.STORAGE, "storage_failed");
      this.state = initialState(this.key, this.binding, this.provider);
      await this.#commit(this.state);
    } else {
      this.state = decodeState(this.key, this.provider, await this.#decode(cipher));
      if (this.reencryptNeeded) await this.#commit(this.state);
      if (this.state.installation.fingerprint !== this.binding.fingerprint ||
          this.state.installation.fingerprint_provider !== this.binding.provider) {
        this.state = {
          ...this.state,
          installation: { id: randomBytes(24).toString("base64url"), fingerprint: this.binding.fingerprint, fingerprint_provider: this.binding.provider },
          generation: nextGeneration(this.state.generation),
          credential: null,
          pending_activation: null,
          access: null,
        };
        await this.#commit(this.state);
      }
    }
    this.#check();
  }

  #pinDirectory(directoryPath, privateDirectory) {
    const api = apiForWindows();
    let created = false;
    let handle;
    try {
      handle = openHandle(directoryPath, GENERIC_READ, FILE_SHARE_READ_WRITE, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    } catch (error) {
      if (error.code !== 2 && error.code !== 3) throw error;
      createPrivateDirectory(directoryPath);
      created = true;
      handle = openHandle(directoryPath, GENERIC_READ, FILE_SHARE_READ_WRITE, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let entry = { path: directoryPath, handle, id: null, privateDirectory: privateDirectory || created };
    this.directories.push(entry);
    entry.id = checkDirectory(handle, privateDirectory || created);
  }

  #checkDirectory(entry, privateDirectory = entry.privateDirectory) {
    const info = checkDirectory(entry.handle, privateDirectory);
    const current = openHandle(entry.path, GENERIC_READ, FILE_SHARE_READ_WRITE, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    try {
      const named = checkDirectory(current, privateDirectory);
      if (!sameFile(entry.id ?? info, info) || !sameFile(info, named)) throw fail(ErrorKind.STORAGE, "storage_failed");
      return info;
    } finally { apiForWindows().CloseHandle(current); }
  }

  #check(leaseSize = 0) {
    if (this.poisoned || this.closed || !this.lease) throw fail(ErrorKind.STORAGE, "storage_failed");
    try {
      for (const directory of this.directories) this.#checkDirectory(directory);
      const info = checkRegular(this.lease, leaseSize, leaseSize, false);
      if (!sameFile(this.leaseId, info)) throw fail(ErrorKind.STORAGE, "storage_failed");
      checkPrivate(this.lease);
      this.#verifyRecord();
    } catch (error) {
      this.poisoned = true;
      if (error?.kind) throw error;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  assertHealthySync() { this.#check(); }

  #verifyRecord() {
    if (!this.recordId) return;
    const handle = openHandle(path.win32.join(this.target, RECORD), GENERIC_READ, 0, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT);
    try {
      const info = checkRegular(handle, 1, MAX_CIPHER);
      if (!sameFile(this.recordId, info, true)) throw fail(ErrorKind.STORAGE, "storage_failed");
      checkPrivate(handle);
    } finally { apiForWindows().CloseHandle(handle); }
  }

  #readRecord() {
    let handle;
    try { handle = openHandle(path.win32.join(this.target, RECORD), GENERIC_READ, 0, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT); }
    catch (error) { if (error.code === 2) return null; throw error; }
    try {
      const info = checkRegular(handle, 1, MAX_CIPHER);
      checkPrivate(handle);
      const result = Buffer.alloc(info.size);
      const read = [0];
      if (!apiForWindows().ReadFile(handle, result, result.length, read, null) || read[0] !== result.length) {
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      this.recordId = info;
      return result;
    } finally { apiForWindows().CloseHandle(handle); }
  }

  #encode(state) {
    const raw = Buffer.from(JSON.stringify(state), "utf8");
    if (!raw.length || raw.length > MAX_ENVELOPE) throw fail(ErrorKind.STORAGE, "storage_failed");
    if (this.codec) return this.codec.encrypt(raw.toString("utf8"));
    return protectData(raw, this.entropy);
  }

  async #decode(cipher) {
    if (!this.codec) return unprotectData(cipher, this.entropy);
    let raw = await this.codec.decrypt(cipher);
    if (raw?.isTemporarilyUnavailable) throw fail(ErrorKind.STORAGE, "storage_unavailable");
    if (raw?.shouldReEncrypt) {
      this.reencryptNeeded = true;
      raw = await this.codec.decrypt(cipher);
      if (raw?.isTemporarilyUnavailable || raw?.shouldReEncrypt) throw fail(ErrorKind.STORAGE, "storage_unavailable");
    }
    if (typeof raw?.result !== "string") throw fail(ErrorKind.STORAGE, "storage_failed");
    return Buffer.from(raw.result, "utf8");
  }

  async #commit(state, guard = undefined) {
    let markerStarted = false;
    try {
      checkGuard(guard);
      this.#check();
      const encoded = await this.#encode(state);
      const bytes = Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
      if (!bytes.length || bytes.length > MAX_CIPHER) throw fail(ErrorKind.STORAGE, "storage_failed");
      checkGuard(guard);
      this.#check();
      const api = apiForWindows();
      const mark = Buffer.from([1]);
      markerStarted = true;
      if (!writeLeaseMarker(api, this.lease, mark)) throw fail(ErrorKind.STORAGE, "storage_failed");
      let temporary = path.win32.join(this.target, `.orbit-storage-${randomBytes(16).toString("hex")}.tmp`);
      let temp;
      let replaced = false;
      try {
        temp = openHandle(temporary, GENERIC_READ | GENERIC_WRITE, 0, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, true);
        checkPrivate(temp);
        let offset = 0;
        while (offset < bytes.length) {
          const written = [0];
          if (!api.WriteFile(temp, bytes.subarray(offset), bytes.length - offset, written, null) || !written[0]) {
            throw fail(ErrorKind.STORAGE, "storage_failed");
          }
          offset += written[0];
        }
        if (!api.FlushFileBuffers(temp)) throw fail(ErrorKind.STORAGE, "storage_failed");
        const tempInfo = checkRegular(temp, bytes.length, bytes.length);
        checkPrivate(temp);
        checkGuard(guard);
        this.#check(1);
        api.CloseHandle(temp);
        temp = null;
        if (!api.MoveFileExW(temporary, path.win32.join(this.target, RECORD), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
          throw fail(ErrorKind.STORAGE, "storage_failed");
        }
        replaced = true;
        const record = openHandle(path.win32.join(this.target, RECORD), GENERIC_READ, 0, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT);
        try {
          this.recordId = checkRegular(record, bytes.length, MAX_CIPHER);
          if (!sameFile(tempInfo, this.recordId, true)) throw fail(ErrorKind.STORAGE, "storage_failed");
          checkPrivate(record);
        } finally { api.CloseHandle(record); }
        this.#check(1);
        if (!api.SetFilePointerEx(this.lease, 0n, [0n], FILE_BEGIN) || !api.SetEndOfFile(this.lease) || !api.FlushFileBuffers(this.lease)) {
          try { writeLeaseMarker(api, this.lease, mark); } catch {}
          throw fail(ErrorKind.STORAGE, "storage_failed");
        }
        this.#check();
        this.state = state;
        this.reencryptNeeded = false;
      } finally {
        if (temp) api.CloseHandle(temp);
        if (!replaced) api.DeleteFileW(temporary);
      }
    } catch (error) {
      if (markerStarted || error?.kind !== ErrorKind.STALE_RESPONSE && error?.kind !== ErrorKind.CANCELLED) this.poisoned = true;
      if (error?.kind) throw error;
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  }

  async updateState(transform, guard = undefined) {
    const task = this.commitQueue.then(async () => {
      checkGuard(guard);
      const state = await transform(this.state);
      checkGuard(guard);
      if (state === this.state) return this.state;
      await this.#commit(state, guard);
      return this.state;
    });
    this.commitQueue = task.catch(() => {});
    await task;
    return this.state;
  }

  async commitState(state) { await this.updateState(() => state); }
  async sync() { this.#check(); return this.state; }
  async drain() { await this.commitQueue; }

  async close() {
    if (this.closed) return;
    this.closed = true;
    const api = apiForWindows();
    if (this.lease) { api.CloseHandle(this.lease); this.lease = null; }
    for (const entry of this.directories.reverse()) api.CloseHandle(entry.handle);
    this.directories = [];
  }
}

function defaultStatePath(key) {
  const base = process.env.LOCALAPPDATA;
  if (!base || !path.win32.isAbsolute(base)) throw fail(ErrorKind.STORAGE, "storage_unavailable");
  return path.win32.join(base, "Orbit", scopeHash(key));
}

function validatePath(target) {
  const parts = typeof target === "string" ? target.split(/[\\/]/) : [];
  if (typeof target !== "string" || !path.win32.isAbsolute(target) || /^\\\\/.test(target) ||
      path.win32.normalize(target) === path.win32.parse(target).root || target.includes("\0") ||
      parts.some((part, index) => part === ".." || index > 0 && part.includes(":"))) {
    throw fail(ErrorKind.STORAGE, "storage_failed");
  }
}

function apiForWindows() {
  if (native) return native;
  if (process.platform !== "win32") throw fail(ErrorKind.STORAGE, "storage_unavailable");
  const kernel = koffi.load("kernel32.dll");
  const advapi = koffi.load("advapi32.dll");
  const crypt = koffi.load("crypt32.dll");
  const fileInfo = koffi.struct("orbit_win_by_handle_info", {
    attributes: "uint32_t", creationLow: "uint32_t", creationHigh: "uint32_t",
    accessLow: "uint32_t", accessHigh: "uint32_t", writeLow: "uint32_t", writeHigh: "uint32_t",
    volume: "uint32_t", sizeHigh: "uint32_t", sizeLow: "uint32_t", links: "uint32_t",
    indexHigh: "uint32_t", indexLow: "uint32_t",
  });
  const securityAttributes = koffi.struct("orbit_win_security_attributes", {
    length: "uint32_t", descriptor: "void *", inherit: "int",
  });
  const dataBlob = koffi.struct("orbit_win_data_blob", { size: "uint32_t", data: "void *" });
  native = {
    fileInfo,
    securityAttributes,
    dataBlob,
    CreateFileW: kernel.func("void *__stdcall CreateFileW(const char16_t *name, uint32_t access, uint32_t share, orbit_win_security_attributes *security, uint32_t disposition, uint32_t flags, void *templateFile)"),
    CreateDirectoryW: kernel.func("bool __stdcall CreateDirectoryW(const char16_t *name, orbit_win_security_attributes *attributes)"),
    GetFileInformationByHandle: kernel.func("bool __stdcall GetFileInformationByHandle(void *handle, _Out_ orbit_win_by_handle_info *info)"),
    GetDriveTypeW: kernel.func("uint32_t __stdcall GetDriveTypeW(const char16_t *root)"),
    GetCurrentThread: kernel.func("void *__stdcall GetCurrentThread(void)"),
    ReadFile: kernel.func("bool __stdcall ReadFile(void *handle, _Out_ uint8_t *buffer, uint32_t count, _Out_ uint32_t *read, void *overlapped)"),
    WriteFile: kernel.func("bool __stdcall WriteFile(void *handle, const uint8_t *buffer, uint32_t count, _Out_ uint32_t *written, void *overlapped)"),
    FlushFileBuffers: kernel.func("bool __stdcall FlushFileBuffers(void *handle)"),
    SetFilePointerEx: kernel.func("bool __stdcall SetFilePointerEx(void *handle, int64_t distance, _Out_ int64_t *newPosition, uint32_t method)"),
    SetEndOfFile: kernel.func("bool __stdcall SetEndOfFile(void *handle)"),
    MoveFileExW: kernel.func("bool __stdcall MoveFileExW(const char16_t *existing, const char16_t *replacement, uint32_t flags)"),
    DeleteFileW: kernel.func("bool __stdcall DeleteFileW(const char16_t *name)"),
    CloseHandle: kernel.func("bool __stdcall CloseHandle(void *handle)"),
    GetLastError: kernel.func("uint32_t __stdcall GetLastError(void)"),
    OpenProcessToken: advapi.func("bool __stdcall OpenProcessToken(void *process, uint32_t access, _Out_ void **token)"),
    OpenThreadToken: advapi.func("bool __stdcall OpenThreadToken(void *thread, uint32_t access, int openAsSelf, _Out_ void **token)"),
    GetCurrentProcess: kernel.func("void *__stdcall GetCurrentProcess(void)"),
    GetTokenInformation: advapi.func("bool __stdcall GetTokenInformation(void *token, int class, _Out_ void *information, uint32_t length, _Out_ uint32_t *returnLength)"),
    ConvertSidToStringSidW: advapi.func("bool __stdcall ConvertSidToStringSidW(void *sid, _Out_ void **stringSid)"),
    ConvertStringSecurityDescriptorToSecurityDescriptorW: advapi.func("bool __stdcall ConvertStringSecurityDescriptorToSecurityDescriptorW(const char16_t *text, uint32_t revision, _Out_ void **descriptor, _Out_ uint32_t *size)"),
    GetSecurityInfo: advapi.func("uint32_t __stdcall GetSecurityInfo(void *handle, int objectType, uint32_t info, _Out_ void **owner, void *group, _Out_ void **dacl, void *sacl, _Out_ void **descriptor)"),
    GetSecurityDescriptorControl: advapi.func("bool __stdcall GetSecurityDescriptorControl(void *descriptor, _Out_ uint16_t *control, _Out_ uint32_t *revision)"),
    IsValidAcl: advapi.func("bool __stdcall IsValidAcl(void *acl)"),
    GetAce: advapi.func("bool __stdcall GetAce(void *acl, uint32_t index, _Out_ void **ace)"),
    LocalFree: kernel.func("void *__stdcall LocalFree(void *memory)"),
    CryptProtectData: crypt.func("bool __stdcall CryptProtectData(orbit_win_data_blob *input, const char16_t *description, orbit_win_data_blob *entropy, void *reserved, void *prompt, uint32_t flags, _Out_ orbit_win_data_blob *output)"),
    CryptUnprotectData: crypt.func("bool __stdcall CryptUnprotectData(orbit_win_data_blob *input, void *description, orbit_win_data_blob *entropy, void *reserved, void *prompt, uint32_t flags, _Out_ orbit_win_data_blob *output)"),
  };
  return native;
}

function openHandle(name, access, share, disposition, flags, privateCreate = false) {
  const api = apiForWindows();
  let attrs;
  let descriptor;
  try {
    if (privateCreate) {
      descriptor = currentUserSecurityDescriptor();
      attrs = { length: securityAttributesSize(api), descriptor, inherit: 0 };
    }
    const handle = api.CreateFileW(name, access, share, attrs ?? null, disposition, flags, null);
    if (handle === null || handle === INVALID_HANDLE || BigInt.asUintN(64, BigInt(handle)) === INVALID_HANDLE) {
      const code = api.GetLastError();
      const error = new Error("CreateFileW failed");
      error.code = code;
      throw error;
    }
    return handle;
  } finally { if (descriptor) api.LocalFree(descriptor); }
}

function createPrivateDirectory(directoryPath) {
  const api = apiForWindows();
  const descriptor = currentUserSecurityDescriptor();
  try {
    const attributes = { length: securityAttributesSize(api), descriptor, inherit: 0 };
    if (!api.CreateDirectoryW(directoryPath, attributes) && ![80, 183].includes(api.GetLastError())) {
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
  } finally { api.LocalFree(descriptor); }
}

function securityAttributesSize(api) {
  return api.securityAttributesSizeForTesting ?? koffi.sizeof(api.securityAttributes);
}

function currentUserSecurityDescriptor() {
  const api = apiForWindows();
  ensureNoThreadImpersonation();
  if (api.createPrivateSecurityDescriptorForTesting) return api.createPrivateSecurityDescriptorForTesting();
  const tokenOut = [null];
  if (!api.OpenProcessToken(api.GetCurrentProcess(), 8, tokenOut) || !tokenOut[0]) throw fail(ErrorKind.STORAGE, "storage_failed");
  try {
    const size = [0];
    api.GetTokenInformation(tokenOut[0], 1, null, 0, size);
    if (size[0] < 8 || size[0] > 65536) throw fail(ErrorKind.STORAGE, "storage_failed");
    const bytes = Buffer.alloc(size[0]);
    if (!api.GetTokenInformation(tokenOut[0], 1, bytes, bytes.length, size)) throw fail(ErrorKind.STORAGE, "storage_failed");
    const sid = koffi.decode(bytes, "void *");
    const sidOut = [null];
    if (!api.ConvertSidToStringSidW(sid, sidOut) || !sidOut[0]) throw fail(ErrorKind.STORAGE, "storage_failed");
    let sidString;
    try { sidString = koffi.decode.string16(sidOut[0]); } finally { api.LocalFree(sidOut[0]); }
    const sddl = `O:${sidString}D:P(A;OICI;FA;;;${sidString})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`;
    const descriptorOut = [null];
    const length = [0];
    if (!api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, descriptorOut, length) || !descriptorOut[0]) {
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
    return descriptorOut[0];
  } finally { api.CloseHandle(tokenOut[0]); }
}

function checkPrivate(handle) {
  const api = apiForWindows();
  if (api.checkPrivateForTesting) return api.checkPrivateForTesting(handle);
  const owner = [null], dacl = [null], descriptor = [null];
  const result = api.GetSecurityInfo(handle, 1, 5, owner, null, dacl, null, descriptor);
  try {
    if (result !== 0 || !owner[0] || !dacl[0] || !descriptor[0] || !api.IsValidAcl(dacl[0])) throw fail(ErrorKind.STORAGE, "storage_failed");
    const control = [0], revision = [0];
    if (!api.GetSecurityDescriptorControl(descriptor[0], control, revision) || (control[0] & 0x1004) !== 0x1004) {
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
    const current = currentUserSid();
    if (sidString(owner[0]) !== current) throw fail(ErrorKind.STORAGE, "storage_failed");
    const acl = koffi.decode(dacl[0], "uint8_t", 8);
    const aceCount = acl[4] | (acl[5] << 8);
    if (aceCount > 128) throw fail(ErrorKind.STORAGE, "storage_failed");
    let userAllowed = false;
    for (let index = 0; index < aceCount; index++) {
      const aceOut = [null];
      if (!api.GetAce(dacl[0], index, aceOut) || !aceOut[0]) throw fail(ErrorKind.STORAGE, "storage_failed");
      const header = koffi.decode(aceOut[0], "uint8_t", 8);
      const kind = header[0];
      if ((kind !== 0 && kind !== 1) || (header[2] | (header[3] << 8)) < 16 || (header[1] & 0x10) !== 0) {
        throw fail(ErrorKind.STORAGE, "storage_failed");
      }
      const sid = BigInt(aceOut[0]) + 8n;
      const trustee = sidString(sid);
      if (kind === 0 && ![current, "S-1-5-18", "S-1-5-32-544"].includes(trustee)) throw fail(ErrorKind.STORAGE, "storage_failed");
      if (kind === 0 && trustee === current && (header[1] & 8) === 0) userAllowed = true;
    }
    if (!userAllowed) throw fail(ErrorKind.STORAGE, "storage_failed");
  } finally { if (descriptor[0]) api.LocalFree(descriptor[0]); }
}

function currentUserSid() {
  const api = apiForWindows();
  ensureNoThreadImpersonation();
  const tokenOut = [null];
  if (!api.OpenProcessToken(api.GetCurrentProcess(), 8, tokenOut) || !tokenOut[0]) throw fail(ErrorKind.STORAGE, "storage_failed");
  try {
    const size = [0];
    api.GetTokenInformation(tokenOut[0], 1, null, 0, size);
    const bytes = Buffer.alloc(size[0]);
    if (!api.GetTokenInformation(tokenOut[0], 1, bytes, bytes.length, size)) throw fail(ErrorKind.STORAGE, "storage_failed");
    return sidString(koffi.decode(bytes, "void *"));
  } finally { api.CloseHandle(tokenOut[0]); }
}

function sidString(sid) {
  const api = apiForWindows();
  const out = [null];
  if (!sid || !api.ConvertSidToStringSidW(sid, out) || !out[0]) throw fail(ErrorKind.STORAGE, "storage_failed");
  try { return koffi.decode.string16(out[0]); } finally { api.LocalFree(out[0]); }
}

function checkDirectory(handle, privateDirectory = false) {
  const info = fileInfo(handle);
  if (!(info.attributes & FILE_ATTRIBUTE_DIRECTORY) || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT) throw fail(ErrorKind.STORAGE, "storage_failed");
  if (privateDirectory) checkPrivate(handle);
  return info;
}

function checkRegular(handle, minimum, maximum, lease = false) {
  const info = fileInfo(handle);
  if (info.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) || info.size < minimum || info.size > maximum || info.links !== 1) {
    throw fail(ErrorKind.STORAGE, "storage_failed");
  }
  if (lease && info.size !== 0) throw fail(ErrorKind.STORAGE, "storage_failed");
  return info;
}

function fileInfo(handle) {
  const api = apiForWindows();
  if (api.fileInfoForTesting) return api.fileInfoForTesting(handle);
  const info = {};
  if (!api.GetFileInformationByHandle(handle, info)) throw fail(ErrorKind.STORAGE, "storage_failed");
  return {
    attributes: info.attributes,
    volume: info.volume,
    index: (BigInt(info.indexHigh) << 32n) | BigInt(info.indexLow),
    size: (info.sizeHigh * 0x100000000) + info.sizeLow,
    writeTime: (BigInt(info.writeHigh) << 32n) | BigInt(info.writeLow),
    links: info.links,
  };
}

function sameFile(left, right, includeContents = false) {
  return left && right && left.volume === right.volume && left.index === right.index &&
    (!includeContents || left.size === right.size && left.writeTime === right.writeTime);
}

function protectData(data, entropy) { return dpapi("CryptProtectData", data, entropy, MAX_CIPHER); }
function unprotectData(data, entropy) { return dpapi("CryptUnprotectData", data, entropy, MAX_ENVELOPE); }

function dpapi(name, data, entropy, max) {
  const api = apiForWindows();
  ensureNoThreadImpersonation();
  const input = { size: data.length, data };
  const extra = { size: entropy.length, data: entropy };
  const output = { size: 0, data: null };
  const crypt = name === "CryptProtectData" ? api.CryptProtectData : api.CryptUnprotectData;
  const inputLimit = name === "CryptProtectData" ? MAX_ENVELOPE : MAX_CIPHER;
  try {
    if (data.length > inputLimit || !crypt(input, null, extra, null, null, 1, output) || output.size > max || output.size && !output.data) {
      throw fail(ErrorKind.STORAGE, "storage_failed");
    }
    return Buffer.from(koffi.decode(output.data, "uint8_t", output.size));
  } finally { if (output.data) api.LocalFree(output.data); }
}

function ensureNoThreadImpersonation() {
  const api = apiForWindows();
  if (api.assertNoThreadImpersonationForTesting) return api.assertNoThreadImpersonationForTesting();
  const token = [null];
  if (api.OpenThreadToken(api.GetCurrentThread(), TOKEN_QUERY, true, token)) {
    try { throw fail(ErrorKind.STORAGE, "storage_failed"); }
    finally { if (token[0]) api.CloseHandle(token[0]); }
  }
  if (api.GetLastError() !== ERROR_NO_TOKEN) throw fail(ErrorKind.STORAGE, "storage_failed");
}

function writeLeaseMarker(api, lease, mark) {
  const position = [0n];
  if (!api.SetFilePointerEx(lease, 0n, position, FILE_BEGIN)) return false;
  const written = [0];
  return api.WriteFile(lease, mark, mark.length, written, null) && written[0] === mark.length && api.FlushFileBuffers(lease);
}

function nextGeneration(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value >= Number.MAX_SAFE_INTEGER) throw fail(ErrorKind.STORAGE, "storage_failed");
  return value + 1;
}

function checkGuard(guard) {
  if (guard && !guard()) throw fail(ErrorKind.STALE_RESPONSE, "stale_response");
}
