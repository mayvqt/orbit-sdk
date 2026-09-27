import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createPosixFilesystemApi, elapsedNs, machineFingerprint, machineFingerprintFromUuid } from "../src/platform/native.mjs";

test("native continuous clock returns fresh nanosecond samples", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin" && process.platform !== "win32") {
    return context.skip("native clock runtime only");
  }
  const before = elapsedNs();
  await new Promise((resolve) => setTimeout(resolve, 12));
  const after = elapsedNs();
  assert.equal(typeof before, "bigint");
  assert.ok(after > before);
  assert.ok(after - before < 1_000_000_000n);
});

test("machine identity normalization hashes only the scoped normalized UUID", () => {
  const actual = machineFingerprintFromUuid("app", "test", "linux", "00112233-4455-6677-8899-AABBCCDDEEFF");
  const expected = createHash("sha256")
    .update("orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff", "ascii")
    .digest("hex");
  assert.equal(actual, expected);
  assert.throws(() => machineFingerprintFromUuid("app", "test", "linux", "00000000-0000-0000-0000-000000000000"));
  assert.throws(() => machineFingerprintFromUuid("app", "test", "linux", "00112233-4455-6677-8899-AABBCCDDEEFF-extra"));
  assert.throws(() => machineFingerprintFromUuid("app", "test", "linux", "00112233445566778899AABBCCDDEEFF\u00e9"));
  assert.throws(() => machineFingerprintFromUuid("app", "test", "linux!", "00112233445566778899AABBCCDDEEFF"));
});

test("macOS descriptor-relative filesystem adapter selects inode64 and ABI-safe varargs", () => {
  for (const architecture of ["x64", "arm64"]) {
    const declarations = [];
    const invocations = [];
    const library = {
      func(...declaration) {
        declarations.push(declaration);
        return (...args) => { invocations.push({ declaration, args }); return 0; };
      },
    };
    const api = createPosixFilesystemApi("darwin", architecture, () => library);
    assert.equal(api.fstatatSymbol, architecture === "x64" ? "fstatat$INODE64" : "fstatat");
    const openDeclaration = declarations.find(([name]) => name === "openat");
    assert.deepEqual(openDeclaration, ["openat", "int", ["int", "str", "int", "..."]]);
    api.openat(7, "child", 0x40, 0o700);
    assert.deepEqual(invocations.find(({ declaration }) => declaration[0] === "openat").args,
      [7, "child", 0x40, "int", 0o700]);
    api.mkdirat(7, "child", 0o700);
    api.fstatat(7, "child", Buffer.alloc(512), 0x20);
    api.renameat(7, "old", 7, "new");
    api.unlinkat(7, "new", 0);
    api.syncFile(7);
    assert.ok(declarations.some(([name]) => name === "mkdirat"));
    assert.ok(declarations.some(([name]) => name === "renameat"));
    assert.ok(declarations.some(([name]) => name === "unlinkat"));
    assert.ok(invocations.some(({ declaration }) => declaration[0] === "fstatat$INODE64" || declaration[0] === "fstatat"));
    const fcntlDeclaration = declarations.find(([name]) => name === "fcntl");
    assert.deepEqual(fcntlDeclaration, ["fcntl", "int", ["int", "int", "..."]]);
    assert.deepEqual(invocations.find(({ declaration }) => declaration[0] === "fcntl").args, [7, 51, "int", 0]);
  }
});

test("host machine binding is best-effort and never returns raw identity", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin" && process.platform !== "win32") {
    return context.skip("native device identity runtime only");
  }
  const fingerprint = await machineFingerprint("app", "test");
  assert.ok(fingerprint === null || /^[0-9a-f]{64}$/.test(fingerprint));
});
