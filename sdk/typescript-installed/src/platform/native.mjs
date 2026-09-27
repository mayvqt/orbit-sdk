import koffi from "koffi";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { fail, ErrorKind } from "../errors.mjs";

let posix;
let posixFs;
let posixFsOverride;
let macFrameworks;
let windowsApiCache;

export function posixFilesystem() {
  if (posixFsOverride) return posixFsOverride;
  if (!posixFs) posixFs = createPosixFilesystemApi(process.platform, process.arch);
  return posixFs;
}

export function setPosixFilesystemForTesting(api) {
  const previous = posixFsOverride;
  posixFsOverride = api;
  return () => { posixFsOverride = previous; };
}

export function createPosixFilesystemApi(platform, architecture, load = (name) => koffi.load(name)) {
  if (platform !== "linux" && platform !== "darwin") throw new TypeError("POSIX filesystem adapter requires Linux or macOS");
  const library = load(platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6");
  const openatRaw = library.func("openat", "int", ["int", "str", "int", "..."]);
  const mkdirat = library.func("mkdirat", "int", ["int", "str", "int"]);
  // XNU's x86_64 libc exposes the 64-bit inode variant under this symbol;
  // the returned struct is opaque here and descriptor metadata comes from fstatSync.
  const fstatatName = platform === "darwin" && architecture === "x64" ? "fstatat$INODE64" : "fstatat";
  const fstatat = library.func(fstatatName, "int", ["int", "str", "void *", "int"]);
  const renameat = library.func("renameat", "int", ["int", "str", "int", "str"]);
  const unlinkat = library.func("unlinkat", "int", ["int", "str", "int"]);
  const fsync = library.func("fsync", "int", ["int"]);
  const errnoPointer = library.func(platform === "darwin" ? "__error" : "__errno_location", "void *", []);
  const fcntl = platform === "darwin" ? library.func("fcntl", "int", ["int", "int", "..."]) : null;
  const api = {
    platform,
    errorPlatform: platform,
    architecture,
    fstatatSymbol: fstatatName,
    atSymlinkNoFollow: platform === "darwin" ? 0x20 : 0x100,
    openat(fd, name, flags, mode = 0) { return openatRaw(fd, name, flags, "int", mode); },
    mkdirat,
    fstatat,
    renameat,
    unlinkat,
    errno() { return koffi.decode(errnoPointer(), "int"); },
    syncFile(fd) {
      const result = platform === "darwin" ? fcntl(fd, 51, "int", 0) : fsync(fd);
      if (result !== 0) throw fail(ErrorKind.STORAGE, "storage_failed");
    },
  };
  return api;
}

export function lockExclusive(fd) {
  if (process.platform !== "linux" && process.platform !== "darwin") return false;
  const api = posixApi();
  const result = api.flock(fd, 2 | 4); // LOCK_EX | LOCK_NB
  if (result !== 0) {
    const error = new Error("flock failed");
    error.code = "EWOULDBLOCK";
    throw error;
  }
  return true;
}

export function unlock(fd) {
  if (process.platform === "linux" || process.platform === "darwin") posixApi().flock(fd, 8); // LOCK_UN
}

export function syncDirectory(fd) {
  const result = posixApi().fsync(fd);
  if (result !== 0) throw fail(ErrorKind.STORAGE, "storage_failed");
}

export function elapsedNs() {
  try {
    if (process.platform === "linux") {
      const output = {};
      const result = posixApi().clockGettime(7, output); // CLOCK_BOOTTIME includes suspend
      const seconds = BigInt(output.tv_sec);
      const nanoseconds = BigInt(output.tv_nsec);
      if (result !== 0 || seconds < 0n || nanoseconds < 0n || nanoseconds >= 1000000000n) throw new Error("clock failure");
      return seconds * 1000000000n + nanoseconds;
    }
    if (process.platform === "darwin") {
      const api = macApi();
      const ticks = BigInt(api.continuousTime());
      return ticks * BigInt(api.timeNumer) / BigInt(api.timeDenom);
    }
    if (process.platform === "win32") {
      const value = {};
      winApi().queryInterrupt(value);
      return BigInt(value.value) * 100n;
    }
  } catch {
    throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
  }
  throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
}

export function wallSeconds() {
  const value = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(value) || value < 0) throw fail(ErrorKind.CLOCK_UNCERTAIN, "clock_uncertain");
  return value;
}

export async function machineFingerprint(applicationId, environmentId) {
  try {
    let family;
    let identity;
    if (process.platform === "linux") {
      family = "linux";
      const handle = await open("/etc/machine-id", fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
      try {
        const info = await handle.stat();
        if (!info.isFile() || info.size > 256) throw new Error("invalid machine identity source");
        const data = Buffer.alloc(257);
        const { bytesRead } = await handle.read(data, 0, data.length, 0);
        if (bytesRead > 256) throw new Error("invalid machine identity source");
        identity = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(0, bytesRead));
      } finally {
        await handle.close();
      }
    } else if (process.platform === "darwin") {
      family = "macos";
      identity = macPlatformUuid();
    } else if (process.platform === "win32") {
      family = "windows";
      identity = windowsSystemUuid();
    } else {
      throw new Error("unsupported platform");
    }
    const normalized = normalizeUuid(identity);
    const input = `orbit-machine-v1\n${applicationId}\n${environmentId}\n${family}\n${normalized}`;
    return createHash("sha256").update(input, "ascii").digest("hex");
  } catch {
    return null;
  }
}

export function machineFingerprintFromUuid(applicationId, environmentId, family, uuid) {
  let normalized;
  try { normalized = normalizeUuid(uuid); } catch {
    throw fail(ErrorKind.CONFIGURATION, "device_identity_unavailable");
  }
  if (!/^[a-z0-9_-]{1,32}$/.test(family)) throw fail(ErrorKind.CONFIGURATION, "device_identity_unavailable");
  return createHash("sha256").update(`orbit-machine-v1\n${applicationId}\n${environmentId}\n${family}\n${normalized}`, "ascii").digest("hex");
}

function trimAscii(value) {
  return value.replace(/^[\x09-\x0d\x20]+|[\x09-\x0d\x20]+$/g, "");
}

function normalizeUuid(value) {
  if (typeof value !== "string" || !/^[\x00-\x7f]*$/.test(value)) throw new Error("invalid UUID encoding");
  const trimmed = trimAscii(value);
  if (!/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/.test(trimmed)) {
    throw new Error("invalid system UUID");
  }
  const normalized = trimmed.replaceAll("-", "").toLowerCase();
  if (normalized === "0".repeat(32) || normalized === "f".repeat(32)) throw new Error("invalid system UUID");
  return normalized;
}

function posixApi() {
  if (!posix) {
    const path = process.platform === "darwin" ? "/usr/lib/libSystem.B.dylib" : "libc.so.6";
    const lib = koffi.load(path);
    const timespec = koffi.struct("orbit_timespec", { tv_sec: "int64_t", tv_nsec: "int64_t" });
    posix = {
      flock: lib.func("int flock(int fd, int operation)"),
      fsync: lib.func("int fsync(int fd)"),
      clockGettime: lib.func("int clock_gettime(int clockid, _Out_ orbit_timespec *tp)"),
    };
  }
  return posix;
}

function macApi() {
  if (!macFrameworks) {
    const system = koffi.load("/usr/lib/libSystem.B.dylib");
    const io = koffi.load("/System/Library/Frameworks/IOKit.framework/IOKit");
    const core = koffi.load("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
    const ratio = koffi.struct("orbit_mach_timebase", { numer: "uint32_t", denom: "uint32_t" });
    const info = {};
    const machTimebaseInfo = system.func("int mach_timebase_info(_Out_ orbit_mach_timebase *info)");
    if (machTimebaseInfo(info) !== 0 || !info.numer || !info.denom) throw new Error("mach timebase unavailable");
    macFrameworks = {
      continuousTime: system.func("uint64_t mach_continuous_time(void)"),
      timeNumer: info.numer,
      timeDenom: info.denom,
      io,
      core,
      matching: io.func("void *IOServiceMatching(const char *name)"),
      service: io.func("uint32_t IOServiceGetMatchingService(uint32_t port, void *matching)"),
      property: io.func("void *IORegistryEntryCreateCFProperty(uint32_t entry, void *key, void *allocator, uint32_t options)"),
      releaseIo: io.func("int IOObjectRelease(uint32_t object)"),
      createString: core.func("void *CFStringCreateWithCString(void *allocator, const char *value, uint32_t encoding)"),
      typeId: core.func("unsigned long CFGetTypeID(void *value)"),
      stringTypeId: core.func("unsigned long CFStringGetTypeID(void)"),
      stringLength: core.func("long CFStringGetLength(void *value)"),
      stringToCString: core.func("bool CFStringGetCString(void *value, char *buffer, long size, uint32_t encoding)"),
      release: core.func("void CFRelease(void *value)"),
    };
  }
  return macFrameworks;
}

function macPlatformUuid() {
  const api = macApi();
  const matching = api.matching("IOPlatformExpertDevice");
  if (!matching) throw new Error("IOKit matching failed");
  const service = api.service(0, matching); // consumes matching dictionary
  if (!service) throw new Error("platform device unavailable");
  let key;
  let value;
  try {
    key = api.createString(null, "IOPlatformUUID", 0x08000100);
    if (!key) throw new Error("platform UUID key allocation failed");
    value = api.property(service, key, null, 0);
    if (!value || api.typeId(value) !== api.stringTypeId()) throw new Error("platform UUID missing");
    const length = api.stringLength(value);
    if (length < 1 || length > 256) throw new Error("invalid platform UUID");
    const buffer = Buffer.alloc(257);
    if (!api.stringToCString(value, buffer, buffer.length, 0x08000100)) throw new Error("platform UUID conversion failed");
    const bytes = buffer.subarray(0, buffer.indexOf(0));
    if (bytes.length !== length) throw new Error("platform UUID conversion truncated");
    return bytes.toString("ascii");
  } finally {
    if (value) api.release(value);
    if (key) api.release(key);
    api.releaseIo(service);
  }
}

function winApi() {
  if (!windowsApiCache) {
    const kernel = koffi.load("kernel32.dll");
    const valueType = koffi.struct("orbit_interrupt_time", { value: "uint64_t" });
    const queryInterrupt = kernel.func("void QueryInterruptTimePrecise(_Out_ orbit_interrupt_time *value)");
    const getTable = kernel.func("uint32_t GetSystemFirmwareTable(uint32_t provider, uint32_t table, void *buffer, uint32_t size)");
    const local = koffi.load("kernel32.dll");
    windowsApiCache = { queryInterrupt, getTable, valueType, localFree: local.func("void *LocalFree(void *mem)") };
  }
  return windowsApiCache;
}

function windowsSystemUuid() {
  const api = winApi();
  const provider = 0x52534d42;
  const size = api.getTable(provider, 0, null, 0);
  if (size < 8 || size > 1024 * 1024) throw new Error("SMBIOS size invalid");
  const buffer = Buffer.alloc(size);
  if (api.getTable(provider, 0, buffer, size) !== size) throw new Error("SMBIOS read failed");
  if (buffer[1] < 2 || (buffer[1] === 2 && buffer[2] < 6) || buffer.readUInt32LE(4) !== size - 8) throw new Error("invalid SMBIOS table");
  let identity = null;
  let offset = 8;
  while (offset < size) {
    if (size - offset < 4) throw new Error("truncated SMBIOS record");
    const type = buffer[offset];
    const length = buffer[offset + 1];
    if (length < 4 || length > size - offset) throw new Error("invalid SMBIOS record");
    let end = offset + length;
    while (end + 1 < size && !(buffer[end] === 0 && buffer[end + 1] === 0)) end++;
    if (end + 1 >= size) throw new Error("unterminated SMBIOS record");
    if (type === 1) {
      if (identity !== null || length < 25) throw new Error("invalid SMBIOS UUID record");
      const bytes = Buffer.from(buffer.subarray(offset + 8, offset + 24));
      bytes.subarray(0, 4).reverse();
      bytes.subarray(4, 6).reverse();
      bytes.subarray(6, 8).reverse();
      identity = bytes.toString("hex");
      if (identity === "0".repeat(32) || identity === "f".repeat(32)) throw new Error("invalid SMBIOS UUID");
    } else if (type === 127) {
      if (identity === null) throw new Error("SMBIOS UUID missing");
      return identity;
    }
    offset = end + 2;
  }
  throw new Error("SMBIOS end marker missing");
}
