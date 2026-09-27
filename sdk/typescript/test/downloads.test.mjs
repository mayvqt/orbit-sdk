import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AppKey, DownloadTicketVerifier, OrbitDownloadTicketError } from "../index.mjs";
import { createPrivateKey, sign } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { downloadFileInternal } from "../../typescript-installed/src/download-file.mjs";
import { parseAuthorization } from "../../typescript-installed/src/online.mjs";
import { artifact, payload, tlsServer } from "../../typescript-installed/test/online-fixtures.mjs";

const corpus = JSON.parse(readFileSync(new URL("../../../contracts/sdk/download-tickets.json", import.meta.url)));
const config = {
  appKey: corpus.expected.app_key,
  endpoint: corpus.expected.endpoint,
  trustedKeys: JSON.stringify(corpus.jwks),
};

test("seller verifier passes every shared download-ticket case", (t) => {
  let now = corpus.expected.now;
  t.mock.method(Date, "now", () => now * 1000);
  for (const item of corpus.cases) {
    const expected = { ...corpus.expected, ...item.expected };
    now = expected.now;
    const check = () => new DownloadTicketVerifier({
      appKey: expected.app_key,
      endpoint: expected.endpoint,
      trustedKeys: JSON.stringify(item.jwks ?? corpus.jwks),
    }).verify(item.token);
    if (!item.valid) {
      assert.throws(check, undefined, item.name);
      continue;
    }
    const result = check();
    const claims = JSON.parse(Buffer.from(item.token.split(".")[1], "base64url"));
    assert.equal(result.artifactId, claims.artifact_id, item.name);
    assert.equal(result.releaseId, claims.release_id, item.name);
    assert.equal(result.licenceId, claims.sub, item.name);
    assert.equal(result.byteLength, claims.byte_length, item.name);
    assert.equal(result.sha256, claims.sha256, item.name);
    assert.equal(Date.parse(result.expiresAt), claims.exp * 1000, item.name);
    assert.ok(Object.isFrozen(result), item.name);
  }
  assert.equal(corpus.cases.length, 110);
});

test("raw endpoint validation precedes URL normalization", () => {
  for (const endpoint of [
    "https://example.test:/file", "https://@example.test/file", "https://%65xample.test/file",
    "https://example.test:0/file", "https://example.test:65536/file", "https://example.test:+443/file",
    "https://[::1]:/file", "https://[::1]suffix/file", "https://::1/file",
    "https://[not-ip]/file", "https://example.test/file?", "https://example.test/file#",
    "https://example.test/\\file", "https://example.test/a b", "https://éxample.test/file",
  ]) assert.throws(() => new DownloadTicketVerifier({ ...config, endpoint }), TypeError, endpoint);
  for (const endpoint of [
    "https://example.test/file%20name", "https://example.test:443/file", "https://[::1]/file",
    "https://[::ffff:192.0.2.1]:443/file", "https://xn--xample-9ua.test/file",
  ]) assert.ok(new DownloadTicketVerifier({ ...config, endpoint }), endpoint);
});

test("trusted key JSON is bounded, strict and copied at construction", (t) => {
  t.mock.method(Date, "now", () => corpus.expected.now * 1000);
  const trustedKeys = Buffer.from(config.trustedKeys);
  const verifier = new DownloadTicketVerifier({ ...config, appKey: AppKey.parse(config.appKey), trustedKeys });
  trustedKeys.fill(0);
  assert.ok(verifier.verify(corpus.cases[0].token));
  const list = JSON.stringify(corpus.jwks.keys);
  for (const keys of [
    `{"keys":${list},"keys":${list}}`, `{"keys":${list},"extra":null}`,
    new Uint8Array(16 * 1024 + 1), config.trustedKeys + " ".repeat(16 * 1024),
    new Uint8Array([0xff]), corpus.jwks, `{"keys":${list},"\\u006beys":${list}}`,
  ]) assert.throws(() => new DownloadTicketVerifier({ ...config, trustedKeys: keys }), TypeError);
  assert.throws(() => new DownloadTicketVerifier({ ...config, appKey: Object.create(AppKey.prototype) }), TypeError);
});

test("invalid bearer errors disclose no token or claims and verification uses current time", (t) => {
  let now = corpus.expected.now;
  t.mock.method(Date, "now", () => now * 1000);
  const verifier = new DownloadTicketVerifier(config);
  const token = corpus.cases[0].token;
  const ticket = verifier.verify(token);
  assert.throws(() => { ticket.artifactId = "changed"; }, TypeError);
  for (const invalid of ["sensitive-secret", ` ${token}`, `${token}\n`, "x".repeat(16 * 1024 + 1), null]) {
    assert.throws(() => verifier.verify(invalid), (error) => {
      assert.ok(error instanceof OrbitDownloadTicketError);
      assert.equal(error.code, "invalid_download_ticket");
      assert.equal(error.message, "Invalid Orbit download ticket");
      assert.equal(error.cause, undefined);
      return true;
    });
  }
  now = Date.parse(ticket.expiresAt) / 1000;
  assert.throws(() => verifier.verify(token), OrbitDownloadTicketError);
});

test("seller verifier authorizes a real TLS download and strips ticket on cross-origin storage redirect", async (t) => {
  const storageRequests = [];
  const storage = await tlsServer(t, (request, response) => {
    storageRequests.push(request.headers);
    response.writeHead(200, { "content-length": payload.length }); response.end(payload);
  });
  let verifier;
  const seller = await tlsServer(t, (request, response) => {
    try {
      const metadata = verifier.verify((request.headers.authorization ?? "").replace(/^Bearer /, ""));
      const selected = artifact();
      if (metadata.artifactId !== selected.id || metadata.releaseId !== selected.release_id ||
          metadata.byteLength !== selected.byte_length || metadata.sha256 !== selected.sha256) throw new Error();
      response.writeHead(302, { location: storage.origin + "/private-object?expires=short-lived" }); response.end();
    } catch { response.writeHead(401); response.end(); }
  });
  const endpoint = seller.origin + "/download";
  verifier = new DownloadTicketVerifier({ ...config, endpoint });
  const selected = artifact(endpoint, { delivery_mode: "protected" });
  const now = Math.floor(Date.now() / 1000);
  const claims = { ver: 1, iss: "https://orbit.example.test", aud: endpoint, sub: "licence", jti: "ticket",
    iat: now, nbf: now, exp: now + 120, application_id: "app", environment_id: "test", release_id: "release",
    artifact_id: "artifact", sha256: selected.sha256, byte_length: payload.length };
  const encode = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const input = `${encode({ alg: "ES256", typ: "orbit-download+jwt", kid: "test-fixture" })}.${encode(claims)}`;
  const signingKey = createPrivateKey(await readFile(new URL("../../rust/tests/fixtures/es256-test-private.pem", import.meta.url)));
  const token = `${input}.${sign("sha256", Buffer.from(input), { key: signingKey, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
  const authorization = parseAuthorization({ artifact: selected, ticket: token, expires_at: new Date((now + 120) * 1000).toISOString() }, "release", "artifact");
  const directory = await mkdtemp(path.join(os.tmpdir(), "orbit-seller-download-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const destination = path.join(directory, "chosen.bin");
  await downloadFileInternal(authorization, destination, { maxBytes: payload.length }, seller);
  assert.deepEqual(await readFile(destination), payload);
  assert.equal(storageRequests.length, 1);
  assert.equal(storageRequests[0].authorization, undefined);
  assert.equal(storageRequests[0].cookie, undefined);
});
