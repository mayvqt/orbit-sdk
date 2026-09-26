import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { openElectronClient, openElectronClientForTesting } from "../src/electron.mjs";
import { ErrorKind } from "../src/errors.mjs";
import { HttpTransport } from "../src/transport.mjs";

test("Electron adapter rejects unavailable and plaintext fallback stores", async () => {
  const app = { isReady: () => true };
  const safeStorage = safeStorageMock();
  safeStorage.isAsyncEncryptionAvailable = async () => false;
  await assert.rejects(openElectronClientForTesting("not-an-app-key", { app, safeStorage }), (error) => error.kind === ErrorKind.STORAGE);
  safeStorage.isAsyncEncryptionAvailable = async () => true;
  if (process.platform === "linux") {
    safeStorage.getSelectedStorageBackend = () => "basic_text";
    await assert.rejects(openElectronClientForTesting("not-an-app-key", { app, safeStorage }), (error) => error.kind === ErrorKind.STORAGE);
    safeStorage.getSelectedStorageBackend = () => "unknown";
    await assert.rejects(openElectronClientForTesting("not-an-app-key", { app, safeStorage }), (error) => error.kind === ErrorKind.STORAGE);
    delete safeStorage.getSelectedStorageBackend;
    await assert.rejects(openElectronClientForTesting("not-an-app-key", { app, safeStorage }), (error) => error.kind === ErrorKind.STORAGE);
  }
  await assert.rejects(openElectronClient("not-an-app-key", { app, safeStorage }), (error) => error.kind === ErrorKind.STORAGE);
  await assert.rejects(openElectronClientForTesting("not-an-app-key", { app, safeStorage, machineBinding: false, statePath: "/tmp/x", transport: {} }),
    (error) => error.kind === ErrorKind.CONFIGURATION && error.code === "invalid_client_options");
  await assert.rejects(openElectronClientForTesting("not-an-app-key", null),
    (error) => error.kind === ErrorKind.CONFIGURATION && error.code === "invalid_client_options");
  await assert.rejects(openElectronClientForTesting("not-an-app-key", []),
    (error) => error.kind === ErrorKind.CONFIGURATION && error.code === "invalid_client_options");
});

test("Electron async storage durably rewrites rotated key data", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-electron-store-"));
  let client;
  context.after(async () => {
    await client?.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const storage = safeStorageMock();
  let rotate = false;
  let decryptCalls = 0;
  const originalDecrypt = storage.decryptStringAsync;
  storage.decryptStringAsync = async (buffer) => {
    decryptCalls++;
    const result = await originalDecrypt(buffer);
    const shouldReEncrypt = rotate && decryptCalls === 1;
    return { result, shouldReEncrypt };
  };
  const options = {
    app: { isReady: () => true }, safeStorage: storage,
    statePath: path.join(base, "state"), machineBinding: false,
  };
  client = await openElectronClientForTesting("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g", options);
  const installation = client.installationId;
  await client.close();

  rotate = true;
  decryptCalls = 0;
  client = await openElectronClientForTesting("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g", options);
  assert.equal(client.installationId, installation);
  assert.equal(decryptCalls, 2, "rotation path must obtain the re-encrypted plaintext");
  assert.ok(storage.encryptCalls >= 2, "rotation must commit a fresh encrypted record");
  await client.close();
});

test("HTTPS transport verifies a real loopback TLS peer and rejects an untrusted peer", async (context) => {
  const cert = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.crt", import.meta.url));
  const privateKey = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.key", import.meta.url));
  const ca = await readFile(new URL("../../cpp/tests/fixtures/transport-test-ca.pem", import.meta.url));
  const server = https.createServer({ cert, key: privateKey }, (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"ok":true}');
  });
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (error) => error ? reject(error) : resolve()));
  context.after(() => new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  const origin = `https://localhost:${server.address().port}`;
  const lookup = async () => [{ address: "127.0.0.1", family: 4 }];
  const trusted = new HttpTransport(origin, { ca, lookup });
  assert.equal((await trusted.get("/api/client/v1/health")).toString(), '{"ok":true}');
  const untrusted = new HttpTransport(origin, { lookup });
  await assert.rejects(untrusted.get("/api/client/v1/health"), (error) => error.kind === ErrorKind.TRANSPORT_SECURITY);
});

function safeStorageMock() {
  const key = randomBytes(32);
  return {
    encryptCalls: 0,
    isEncryptionAvailable: () => true,
    isAsyncEncryptionAvailable: async () => true,
    getSelectedStorageBackend: () => "gnome_libsecret",
    async encryptStringAsync(value) {
      this.encryptCalls++;
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      const body = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), body]);
    },
    async decryptStringAsync(value) {
      const nonce = value.subarray(0, 12);
      const tag = value.subarray(12, 28);
      const body = value.subarray(28);
      const decipher = createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
    },
  };
}
