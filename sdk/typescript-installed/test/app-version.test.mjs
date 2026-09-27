import assert from "node:assert/strict";
import { createPrivateKey, createSign } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { CLIENT_HEADER, SDK_VERSION, configuredAppVersion, formatClientHeader, updateHint, validAppVersion } from "../src/app-version.mjs";
import { Client, openClientForTesting } from "../src/client.mjs";
import { AppVersionUnsupportedError, ErrorKind } from "../src/errors.mjs";
import { HttpTransport } from "../src/transport.mjs";

const vectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/app-versions.json", import.meta.url), "utf8"));
const grantVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/grants.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const key = AppKey.parse("orbit_app_test_aHR0cHM6Ly9sb2NhbGhvc3Q.Q2lK7xY3bR9mT0pW4vN8sA.Zx8_c-1dKpL5qR2tU6wY0g");
const privateKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));

test("app-version grammar, client header and update hints match the shared vectors", () => {
  for (const item of vectors.app_versions) {
    assert.equal(validAppVersion(item.value), item.valid, item.value);
    if (item.valid) assert.equal(configuredAppVersion(item.value), item.value);
    else assert.throws(() => configuredAppVersion(item.value), (error) => error.kind === ErrorKind.CONFIGURATION);
  }
  assert.equal(configuredAppVersion(undefined), null);
  for (const item of vectors.client_headers) {
    assert.equal(formatClientHeader(item.language, item.sdk_version, item.platform), item.header, JSON.stringify(item));
  }
  assert.equal(SDK_VERSION, pkg.version);
  const prefix = `ts-installed/${pkg.version} (`;
  assert.ok(CLIENT_HEADER.startsWith(prefix), CLIENT_HEADER);
  assert.equal(formatClientHeader("ts-installed", pkg.version, CLIENT_HEADER.slice(prefix.length, -1)), CLIENT_HEADER);
  for (const item of vectors.update_available) {
    const reply = { activation_id: "activation" };
    if (Object.hasOwn(item, "value")) reply.update_available = item.value;
    if (item.valid) assert.equal(updateHint(reply), item.version, item.name);
    else assert.throws(() => updateHint(reply), (error) => error.kind === ErrorKind.INVALID_RESPONSE, item.name);
  }
});

test("public Client.open rejects an invalid app version", async () => {
  await assert.rejects(Client.open(key, { appVersion: "01" }), (error) => error.kind === ErrorKind.CONFIGURATION);
});

test("transport identifies the SDK and types an unsupported version without retrying", async (t) => {
  const certificate = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.crt", import.meta.url));
  const tlsKey = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.key", import.meta.url));
  const ca = await readFile(new URL("../../cpp/tests/fixtures/transport-test-ca.pem", import.meta.url));
  const headers = [];
  const server = https.createServer({ cert: certificate, key: tlsKey }, (request, response) => {
    headers.push(request.headers["orbit-client"]);
    request.resume();
    response.writeHead(403, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: { code: "app_version_unsupported", message: "Update required", request_id: "version-1" } }));
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const transport = new HttpTransport(`https://localhost:${server.address().port}`, {
    ca, lookup: async () => [{ address: "127.0.0.1", family: 4 }],
  });
  await assert.rejects(transport.post("/api/client/v1/activations/activation/validate", { app_version: "1.0" }, true),
    (error) => error instanceof AppVersionUnsupportedError && error.kind === ErrorKind.DENIED &&
      error.code === "app_version_unsupported" && error.requestId === "version-1");
  assert.deepEqual(headers, [CLIENT_HEADER]);
});

test("app version is sent and an unsupported version denies without fallback", async (context) => {
  if (process.platform !== "linux" && process.platform !== "darwin") return context.skip("POSIX private-file storage runtime only");
  const base = await mkdtemp(path.join(os.tmpdir(), "orbit-js-app-version-"));
  const clients = [];
  context.after(async () => {
    for (const client of clients) await client.close().catch(() => {});
    await rm(base, { recursive: true, force: true });
  });
  const sent = [];
  let deny = false;
  const transport = {
    async post(route, body) {
      sent.push({ route, appVersion: body.app_version });
      if (route.endsWith("/activations")) return activationReply(body, { update_available: { version: "2.5.0" } });
      if (route.endsWith("/validate")) {
        if (deny) throw new AppVersionUnsupportedError("version-1");
        return activationReply(body, { credential: null });
      }
      throw new Error("unexpected request");
    },
    async get() { return Buffer.from(JSON.stringify(grantVectors.jwks)); },
  };
  const statePath = path.join(base, "state");
  const open = () => openClientForTesting(key, { statePath, machineBinding: false, transport, lifecycle: false, appVersion: "2.4.1-beta.2" });
  const client = await open();
  clients.push(client);
  const activated = await client.activate("TEST-12345678901234567890");
  assert.equal(activated.access, "online");
  assert.equal(activated.updateAvailable, "2.5.0");
  deny = true;
  await assert.rejects(client.refresh(), (error) => error instanceof AppVersionUnsupportedError);
  assert.deepEqual(sent.map((item) => item.appVersion), ["2.4.1-beta.2", "2.4.1-beta.2"]);
  const snapshot = client.snapshot();
  assert.equal(snapshot.access, "refresh_required");
  assert.equal(snapshot.has("export"), false);
  assert.equal(snapshot.updateAvailable, null);
  let prompted = false;
  await assert.rejects(client.ensureAccess("export", () => { prompted = true; return "replacement"; }),
    (error) => error instanceof AppVersionUnsupportedError);
  assert.equal(prompted, false);
  assert.equal(sent.filter((item) => item.route.endsWith("/validate")).length, 1);
  const record = JSON.parse(await readFile(path.join(statePath, "orbit-storage.bin"), "utf8"));
  assert.notEqual(record.credential, null);
  assert.equal(record.access, null);
  await client.close();

  const reopened = await openClientForTesting(key, {
    statePath, machineBinding: false, transport, lifecycle: false, appVersion: "2.4.1-beta.2", skipInitialRefresh: false,
  });
  clients.push(reopened);
  await assert.rejects(reopened.requireAccess("export"), (error) => error instanceof AppVersionUnsupportedError);
});

function activationReply(request, extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: key.issuer, aud: `orbit:${key.application_id}:${key.environment_id}`, sub: "licence-1",
    jti: `jti-${Math.random().toString(36).slice(2)}`, iat: now, nbf: now, exp: now + 3600,
    application_id: key.application_id, environment_id: key.environment_id, activation_id: "activation-1",
    installation_id: request.installation_id, binding_mode: "none", policy_version: 1,
    entitlements: { export: true }, refresh_after: now + 900, offline_allowed: true, licence_expires_at: null,
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-access+jwt", kid: "test-key" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signing = createSign("SHA256");
  signing.update(`${header}.${payload}`, "ascii");
  signing.end();
  const signature = signing.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  return Buffer.from(JSON.stringify({
    activation_id: "activation-1",
    installation_id: request.installation_id,
    credential: "a".repeat(43),
    credential_expires_at: null,
    grant: `${header}.${payload}.${signature}`,
    server_time: new Date(now * 1000).toISOString(),
    binding_mode: "none",
    fingerprint_provider: request.fingerprint_provider,
    licence_expires_at: null,
    secret_replay_expired: false,
    ...extra,
  }));
}
