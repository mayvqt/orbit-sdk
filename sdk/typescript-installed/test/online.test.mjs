import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { openClientForTesting } from "../src/client.mjs";
import { HttpTransport } from "../src/transport.mjs";
import { LimitReachedError, MutationUncertainError, NotActivatedError, fail } from "../src/errors.mjs";
import * as online from "../src/online.mjs";
import { downloadFileInternal } from "../src/download-file.mjs";
import { activation, appKey, artifact, counter, jwks, key, payload, release, tlsServer } from "./online-fixtures.mjs";

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "orbit-online-"));
  const requests = [], handlers = new Map();
  const transport = {
    async post(route, body, safe, signal) {
      requests.push({ route, body, safe });
      const handler = handlers.get(route);
      if (handler) return Buffer.from(JSON.stringify(await handler(body, signal)));
      if (route.endsWith("/activations")) return Buffer.from(JSON.stringify(activation(body)));
      throw new Error("Unexpected fixture request");
    },
    async get() { return Buffer.from(JSON.stringify(jwks)); },
  };
  const client = await openClientForTesting(appKey, { statePath: path.join(directory, "state"), machineBinding: false,
    transport, skipInitialRefresh: true, lifecycle: false });
  t.after(async () => { await client.close(); await rm(directory, { recursive: true, force: true }); });
  await client.activate("test-key");
  return { client, requests, reply: (route, value) => handlers.set(`/api/client/v1/activations/activation/${route}`,
    typeof value === "function" ? value : () => value) };
}

test("installed discovery authenticates exact target and separates download authorization", async (t) => {
  const { client, requests, reply } = await fixture(t);
  const a = artifact();
  reply("updates", { release: release(a), artifact: a });
  const update = await client.checkForUpdate(1, { target: { platform: "linux", architecture: "x64" } });
  assert.equal(update.release.releaseNumber, 2);
  assert.equal(update.release.createdAt.toISOString(), "2026-09-01T00:00:00.000Z");
  assert.equal(requests.at(-1).body.credential, "a".repeat(43));
  assert.equal(requests.at(-1).body.channel, "stable");
  reply("downloads/authorize", { artifact: a, ticket: null, expires_at: null });
  assert.deepEqual((await client.authorizeDownload("release", "artifact")).artifact, update.artifact);
  const count = requests.length;
  await client.requireAccess("export");
  assert.equal(requests.length, count);
  for (const bad of [
    { release: release(a), artifact: artifact(undefined, { platform: "windows" }) },
    { release: release(a, { release_number: 1 }), artifact: a },
    { release: release(a, { artifacts: [a, artifact(undefined, { id: "other", architecture: "arm64" })] }), artifact: a },
    { release: null, artifact: a },
  ]) {
    reply("updates", bad);
    await assert.rejects(client.checkForUpdate(1, { target: { platform: "linux", architecture: "x64" } }), (e) => e.kind === "invalid_response");
  }
  reply("updates", { release: null, artifact: null });
  assert.equal(await client.checkForUpdate(2), null);
});

test("usage fixed replay, resource current replay, explicit release and invalid inputs", async (t) => {
  const { client, requests, reply } = await fixture(t);
  reply("usage/exports", counter());
  assert.equal((await client.usage("exports")).remaining, 6);
  reply("usage/exports/consume", counter(true, { idempotency_key: key, consumed_units: 2 }));
  const first = await client.consume("exports", 2, { idempotencyKey: key });
  assert.equal(JSON.stringify(await client.consume("exports", 2, { idempotencyKey: key })), JSON.stringify(first));
  reply("resources/projects", counter(false));
  assert.equal((await client.resources("projects")).remaining, 6);
  const allocation = counter(false, { allocation_id: "allocation", resource_id: "project", units: 2, state: "active", idempotency_key: key });
  reply("resources/projects/acquire", allocation);
  assert.equal((await client.acquireResource("projects", "project", 2, { idempotencyKey: key })).state, "active");
  const released = { ...allocation, state: "released", used: 2, remaining: 8 };
  reply("resources/projects/allocations/allocation/release", released);
  assert.equal((await client.releaseResource("projects", "allocation", { idempotencyKey: key })).state, "released");
  reply("resources/projects/acquire", released);
  assert.equal((await client.acquireResource("projects", "project", 2, { idempotencyKey: key })).state, "released");
  const count = requests.length;
  for (const units of [0, -1, true, 1.5, 2 ** 53]) assert.throws(() => client.consume("exports", units), TypeError);
  for (const idempotencyKey of ["", "short", " ".repeat(16)]) assert.throws(() => client.consume("exports", 1, { idempotencyKey }), TypeError);
  assert.throws(() => client.acquireResource("projects", "../path"), TypeError);
  assert.equal(requests.length, count);
});

test("lost replies, strict response failures, late logout and cancellation preserve mutation IDs", async (t) => {
  const { client, requests, reply } = await fixture(t);
  reply("usage/exports/consume", () => { throw fail("transient", "network_unavailable"); });
  let generated;
  await assert.rejects(client.consume("exports"), (e) => {
    assert.ok(e instanceof MutationUncertainError); generated = e.idempotencyKey; return true;
  });
  assert.equal(generated, requests.at(-1).body.idempotency_key);
  assert.ok(generated.length >= 16);
  reply("usage/exports/consume", counter(true, { idempotency_key: "wrong-job-0000001", consumed_units: 1 }));
  await assert.rejects(client.consume("exports", 1, { idempotencyKey: generated }), (e) => e instanceof MutationUncertainError && e.idempotencyKey === generated);
  const controller = new AbortController();
  reply("usage/exports/consume", (body) => { controller.abort(); return counter(true, { idempotency_key: body.idempotency_key, consumed_units: 1 }); });
  await assert.rejects(client.consume("exports", 1, { idempotencyKey: key, signal: controller.signal }),
    (e) => e instanceof MutationUncertainError && e.idempotencyKey === key && e.kind === "cancelled");
  reply("usage/exports/consume", async (body) => { await client.logout(); return counter(true, { idempotency_key: body.idempotency_key, consumed_units: 1 }); });
  await assert.rejects(client.consume("exports", 1, { idempotencyKey: key }), MutationUncertainError);
  await assert.rejects(client.usage("exports"), NotActivatedError);
});

test("real TLS transport validates nested denials and retries the same operation ID", async (t) => {
  const denied = { error: { code: "usage_limit_reached", message: "Capacity reached", request_id: "req",
    counter: counter(true, { used: 10, remaining: 0 }), idempotency_key: key, requested_units: 2 } };
  let response = denied, status = 409, transient = false;
  const bodies = [];
  const tls = await tlsServer(t, async (request, reply) => {
    let body = ""; for await (const chunk of request) body += chunk;
    bodies.push(JSON.parse(body));
    if (transient) { transient = false; reply.writeHead(503); reply.end(JSON.stringify({ error: { code: "service_unavailable", message: "Busy", request_id: "req" } })); return; }
    reply.writeHead(status, { "content-type": "application/json" }); reply.end(status === 204 ? undefined : JSON.stringify(response));
  });
  const transport = new HttpTransport(tls.origin, { ca: tls.ca, lookup: async () => [{ address: "127.0.0.1", family: 4 }] });
  const post = () => transport.post("/api/client/v1/activations/activation/usage/exports/consume", { units: 2, idempotency_key: key }, true);
  await assert.rejects(post(), (e) => e instanceof LimitReachedError && e.counter.used === 10 && e.idempotencyKey === key);
  for (const changes of [{ idempotency_key: "different-job-00001" }, { requested_units: true }, { counter: counter(true, { name: "other" }) },
    { counter: counter(true, { used: 11, remaining: -1 }) }, { counter: counter(true, { remaining: 5 }) }]) {
    response = { error: { ...denied.error, ...changes } };
    await assert.rejects(post(), (e) => e.kind === "invalid_response" && e.counter === undefined);
  }
  response = counter(true, { idempotency_key: key, consumed_units: 2 });
  for (const code of [201, 204]) { status = code; await assert.rejects(post(), (e) => e.kind === "invalid_response"); }
  status = 200; transient = true;
  await post();
  assert.deepEqual(bodies.slice(-2).map((v) => v.idempotency_key), [key, key]);
});

test("strict dates, period boundaries, definitions and unsafe numeric values", () => {
  for (const bad of [counter(true, { limit: true }), counter(true, { used: 2 ** 53 }), counter(true, { remaining: 5 }),
    counter(true, { period: "week" }), counter(true, { period_started_at: "2026-02-30T00:00:00Z" }),
    counter(true, { resets_at: "2026-09-29T00:00:00Z" })]) assert.throws(() => online.parseCounter(bad, "exports", true));
  for (const year of [2024, 2025]) assert.equal(online.parseCounter(counter(true, { period: "month",
    period_started_at: `${year}-02-01T00:00:00Z`, resets_at: `${year}-03-01T00:00:00Z` }), "exports", true).period, "month");
  assert.equal(online.parseCounter(counter(true, { period: "lifetime", period_started_at: null, resets_at: null }), "exports", true).resetsAt, null);
  assert.throws(() => online.parseDefinitions({ exports: { limit: true, period: "day", required_feature: null } }, true));
  assert.throws(() => online.parseDefinitions({ exports: { limit: 10, period: "day", required_feature: "INVALID" } }, true));
});

test("direct TLS streaming strips bearers on every redirect and atomically verifies bytes", async (t) => {
  const seen = [];
  const tls = await tlsServer(t, (request, response) => {
    seen.push({ url: request.url, headers: request.headers });
    if (request.url === "/redirect") { response.writeHead(302, { location: "/file?storage=short-lived" }); response.end(); return; }
    if (request.url === "/loop") { response.writeHead(302, { location: "/loop" }); response.end(); return; }
    response.writeHead(200, request.url === "/encoded" ? { "content-encoding": "gzip" } : {});
    response.end(request.url === "/short" ? payload.subarray(0, 10) : request.url === "/oversize" ? Buffer.concat([payload, Buffer.from("extra")]) : payload);
  });
  const directory = await mkdtemp(path.join(os.tmpdir(), "orbit-download-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, "chosen.bin");
  const auth = online.parseAuthorization({ artifact: artifact(tls.origin + "/redirect", { delivery_mode: "protected" }),
    ticket: "abc.def.sig", expires_at: new Date(Date.now() + 120000).toISOString() }, "release", "artifact");
  assert.equal(JSON.stringify(auth).includes("abc.def.sig"), false);
  await downloadFileInternal(auth, target, { maxBytes: payload.length }, tls);
  assert.deepEqual(await readFile(target), payload);
  assert.equal(seen[0].headers.authorization, "Bearer abc.def.sig");
  assert.equal(seen[1].url, "/file?storage=short-lived");
  assert.equal(seen[1].headers.authorization, undefined);
  assert.ok(seen.every((x) => x.headers["accept-encoding"] === "identity" && !x.headers.cookie));
  await assert.rejects(downloadFileInternal(auth, target, { maxBytes: payload.length }, tls), (e) => e.code === "destination_exists");
  for (const [route, changes] of [["/file", { sha256: "0".repeat(64) }], ["/short", {}], ["/oversize", {}], ["/encoded", {}], ["/loop", {}]]) {
    const bad = online.parseAuthorization({ artifact: artifact(tls.origin + route, changes), ticket: null, expires_at: null }, "release", "artifact");
    await assert.rejects(downloadFileInternal(bad, target, { maxBytes: payload.length, replace: true }, tls));
    assert.deepEqual(await readFile(target), payload); assert.deepEqual(await readdir(directory), ["chosen.bin"]);
  }
  await assert.rejects(downloadFileInternal(auth, target, { maxBytes: payload.length, replace: true }), (e) => e.kind === "transport_security");
  await assert.rejects(downloadFileInternal(auth, target, { maxBytes: payload.length - 1, replace: true }, tls));
});

test("cancel a stalled TLS stream without replacing an old destination", async (t) => {
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  const tls = await tlsServer(t, (_request, response) => { response.writeHead(200); response.write("x"); started(); });
  const directory = await mkdtemp(path.join(os.tmpdir(), "orbit-cancel-download-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = path.join(directory, "existing.bin"); await writeFile(target, "old");
  const authorization = online.parseAuthorization({ artifact: artifact(tls.origin + "/slow"), ticket: null, expires_at: null }, "release", "artifact");
  const controller = new AbortController();
  const result = downloadFileInternal(authorization, target, { maxBytes: payload.length, replace: true, signal: controller.signal }, tls);
  await entered; controller.abort();
  await assert.rejects(result, (e) => e.kind === "cancelled");
  assert.equal(await readFile(target, "utf8"), "old"); assert.deepEqual(await readdir(directory), ["existing.bin"]);
});
