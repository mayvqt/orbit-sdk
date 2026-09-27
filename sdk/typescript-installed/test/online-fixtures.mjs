import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import https from "node:https";

export const payload = Buffer.from("synthetic application artifact\n".repeat(3000));
export const key = "job-20260927-000001";
export const appKey = "orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test";
export const jwks = JSON.parse(await readFile(new URL("../../../contracts/sdk/grants.json", import.meta.url), "utf8")).jwks;
const signingKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));

export function artifact(url = "https://seller.example.test/file", extra = {}) {
  return { id: "artifact", release_id: "release", platform: "linux", architecture: "x64", filename: "app.bin",
    byte_length: payload.length, sha256: createHash("sha256").update(payload).digest("hex"), delivery_mode: "public",
    url, required_feature: null, ...extra };
}
export function release(a = artifact(), extra = {}) {
  return { id: "release", channel: "stable", version: "v2", notes: "Release notes", release_number: 2, state: "published",
    created_at: "2026-09-01T00:00:00Z", published_at: "2026-09-02T00:00:00Z", artifacts: [a], ...extra };
}
export function counter(usage = true, extra = {}) {
  return { name: usage ? "exports" : "projects", limit: 10, used: 4, remaining: 6,
    ...(usage ? { period: "day", period_started_at: "2026-09-27T00:00:00Z", resets_at: "2026-09-28T00:00:00Z" } : {}), ...extra };
}
export function activation(body, origin = "https://orbit.example.test") {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: origin, aud: `orbit:${body.application_id}:${body.environment_id}`, sub: "licence", jti: "test-grant",
    iat: now, nbf: now, exp: now + 300, application_id: body.application_id, environment_id: body.environment_id,
    activation_id: "activation", installation_id: body.installation_id, binding_mode: "none", policy_version: 1,
    entitlements: { export: true }, refresh_after: now + 60, offline_allowed: false, licence_expires_at: null };
  const encode = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${encode({ alg: "ES256", typ: "orbit-access+jwt", kid: "test-key" })}.${encode(claims)}`;
  const grant = `${input}.${sign("sha256", Buffer.from(input), { key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  return { activation_id: "activation", installation_id: body.installation_id, credential: "a".repeat(43), credential_expires_at: null,
    grant, server_time: new Date(now * 1000).toISOString(), binding_mode: "none", fingerprint_provider: null,
    licence_expires_at: null, secret_replay_expired: false };
}
export async function tlsServer(t, handler) {
  const [cert, privateKey, ca] = await Promise.all([
    readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.crt", import.meta.url)),
    readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.key", import.meta.url)),
    readFile(new URL("../../cpp/tests/fixtures/transport-test-ca.pem", import.meta.url)),
  ]);
  const server = https.createServer({ cert, key: privateKey }, handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const origin = `https://localhost:${server.address().port}`;
  const lookup = (_hostname, options, callback) => options?.all ? callback(null, [{ address: "127.0.0.1", family: 4 }]) : callback(null, "127.0.0.1", 4);
  return { origin, ca, lookup };
}
