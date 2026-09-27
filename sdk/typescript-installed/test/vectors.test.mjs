import assert from "node:assert/strict";
import { createPrivateKey, createSign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { AppKey } from "../src/app-key.mjs";
import { parseJwks, verifyGrant } from "../src/grants.mjs";
import { HttpTransport } from "../src/transport.mjs";
import { parseOfflineKeys, verifyOfflineFile } from "../src/offline.mjs";
import { parseSessionKeys, verifySessionGrant } from "../src/sessions.mjs";

const appKeyVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/app-keys.json", import.meta.url), "utf8"));
const grantVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/grants.json", import.meta.url), "utf8"));
const offlineVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/offline-files.json", import.meta.url), "utf8"));
const sessionVectors = JSON.parse(await readFile(new URL("../../../contracts/sdk/session-grants.json", import.meta.url), "utf8"));
const signingKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));

test("all shared app-key vectors", () => {
  for (const item of appKeyVectors.cases) {
    let parsed;
    try { parsed = AppKey.parse(item.key); } catch (error) {
      assert.equal(item.valid, false, `${item.name}: rejected valid vector (${error.code ?? error.message})`);
      continue;
    }
    assert.equal(item.valid, true, `${item.name}: accepted an invalid vector`);
    assert.deepEqual({
      api_origin: parsed.api_origin,
      issuer: parsed.issuer,
      application_id: parsed.application_id,
      environment_id: parsed.environment_id,
      environment: parsed.environment,
    }, {
      api_origin: item.api_origin,
      issuer: item.issuer,
      application_id: item.application_id,
      environment_id: item.environment_id,
      environment: item.environment,
    }, item.name);
  }
  assert.equal(appKeyVectors.cases.length, 27);
});

test("all shared signed-grant vectors", () => {
  let accepted = 0;
  for (const item of grantVectors.cases) {
    let valid = false;
    try {
      const keys = parseJwks(item.jwks ?? grantVectors.jwks);
      verifyGrant(item.token, keys, { ...grantVectors.expected, ...item.expected });
      valid = true;
    } catch {}
    assert.equal(valid, item.valid, item.name);
    accepted += Number(valid);
  }
  assert.equal(grantVectors.cases.length, 104);
  assert.equal(accepted, 12);
});

test("all shared signed offline-file vectors", () => {
  let accepted = 0;
  for (const item of offlineVectors.cases) {
    let valid = false;
    try {
      const expected = { ...offlineVectors.expected, ...item.expected };
      const key = AppKey.parse(expected.app_key);
      const keys = parseOfflineKeys(item.jwks ?? offlineVectors.jwks, key.environment);
      verifyOfflineFile(item.token, key, {
        fingerprint: expected.fingerprint ?? null,
        provider: expected.fingerprint_provider ?? null,
      }, expected.installation_id, keys, expected.now, expected.minimum_sequence);
      valid = true;
    } catch {}
    assert.equal(valid, item.valid, item.name);
    accepted += Number(valid);
  }
  assert.equal(offlineVectors.cases.length, 104);
  assert.equal(accepted, offlineVectors.cases.filter((item) => item.valid).length);
});

test("all shared signed floating-session vectors", () => {
  let accepted = 0;
  for (const item of sessionVectors.cases) {
    let valid = false;
    try {
      const value = { ...sessionVectors.expected, ...item.expected };
      const { session_id: sessionId, sequence, key_environment: keyEnvironment, ...expected } = value;
      const keys = parseSessionKeys(item.jwks ?? sessionVectors.jwks, keyEnvironment);
      const verified = verifySessionGrant(item.token, keys, {
        issuer: expected.issuer,
        application: expected.application,
        environment: expected.environment,
        licence: expected.licence,
        activation: expected.activation,
        installation: expected.installation,
        fingerprint: expected.fingerprint ?? null,
        fingerprintProvider: expected.fingerprint_provider ?? null,
        credentialExpiresAt: expected.credential_expires_at ?? null,
        licenceExpiresAt: expected.licence_expires_at ?? null,
        now: expected.now,
        sessionId,
        sequence,
        keyEnvironment,
        allowUnboundFingerprint: expected.allow_unbound_fingerprint ?? false,
      });
      valid = true;
      assert.equal(verified.sessionId, sessionId, item.name);
      assert.equal(verified.sequence, sequence, item.name);
      assert.ok(verified.expiresAt > expected.now, item.name);
      assert.ok(verified.expiresAt - verified.issuedAt <= 120, item.name);
    } catch (error) {
      if (item.valid) assert.fail(`${item.name}: ${error.code ?? error.message}`);
    }
    assert.equal(valid, item.valid, item.name);
    accepted += Number(valid);
  }
  assert.equal(sessionVectors.cases.length, 184);
  assert.equal(accepted, sessionVectors.cases.filter((item) => item.valid).length);
});

test("long valid origin and maximum app-key IDs verify without individual-field truncation", () => {
  const origin = `https://${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(30)}.test`;
  const application = "a".repeat(128);
  const environment = "b".repeat(128);
  const key = AppKey.parse(`orbit_app_test_${Buffer.from(origin).toString("base64url")}.${application}.${environment}`);
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: origin,
    aud: `orbit:${application}:${environment}`,
    sub: "long-scope-licence",
    jti: "long-scope-grant",
    iat: now,
    nbf: now,
    exp: now + 300,
    application_id: application,
    environment_id: environment,
    activation_id: "activation-1",
    installation_id: "installation-1",
    binding_mode: "none",
    policy_version: 1,
    entitlements: {},
    refresh_after: now + 60,
    offline_allowed: false,
    licence_expires_at: null,
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", typ: "orbit-access+jwt", kid: "test-key" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signer = createSign("SHA256");
  signer.update(`${header}.${payload}`, "ascii");
  signer.end();
  const signature = signer.sign({ key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
  const token = `${header}.${payload}.${signature}`;

  assert.equal(Buffer.byteLength(key.issuer) > 128, true);
  assert.equal(key.application_id.length, 128);
  assert.equal(key.environment_id.length, 128);
  assert.equal(verifyGrant(token, parseJwks(grantVectors.jwks), {
    issuer: origin,
    application,
    environment,
    activation: claims.activation_id,
    installation: claims.installation_id,
    fingerprint: null,
    fingerprint_provider: null,
    credential_expires_at: null,
    licence_expires_at: null,
    licence: null,
    now,
  }).aud, claims.aud);
});

test("JWKS byte limit and endpoint grammar reject oversized or duplicate query separators", async () => {
  assert.throws(() => parseJwks(Buffer.alloc(16 * 1024 + 1, 0x20)), (error) => error.code === "invalid_jwks");
  const transport = new HttpTransport("https://example.test", { lookup: async () => [] });
  await assert.rejects(transport.get("/.well-known/orbit-jwks.json?application_id=app?environment_id=test"),
    (error) => error.code === "invalid_route");
});
