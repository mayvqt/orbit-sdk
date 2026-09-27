import assert from "node:assert/strict";
import https from "node:https";
import test from "node:test";
import { OrbitBackendClient, OrbitLimitReachedError, OrbitMutationUncertainError, OrbitTransportError } from "../index.mjs";
import * as online from "../online.mjs";
import { appKey, artifact, counter, key, release, tlsServer } from "../../typescript-installed/test/online-fixtures.mjs";

function fixture() {
  const calls = [];
  let handler = () => new Response("{}", { headers: { "content-type": "application/json" } });
  const client = new OrbitBackendClient({ appKey, managementToken: "synthetic-management" }, { fetchImpl: async (url, options) => {
    calls.push({ url, ...options, body: options.body === undefined ? undefined : JSON.parse(options.body) });
    return handler(calls.at(-1));
  } });
  return { client, calls, reply(value, status = 200) {
    handler = typeof value === "function" ? value : () => new Response(status === 204 ? null : JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  } };
}

test("backend discovery and authorization retain exact scope, target and licence", async () => {
  const { client, calls, reply } = fixture();
  const a = artifact();
  reply({ release: release(a), artifact: a });
  const result = await client.checkForUpdate("licence", 1, { target: { platform: "linux", architecture: "x64" } });
  assert.equal(result.release.releaseNumber, 2);
  const request = calls.at(-1);
  assert.equal(request.method, "GET");
  assert.equal(request.url.pathname, "/api/management/v1/licences/licence/updates");
  assert.deepEqual(Object.fromEntries(request.url.searchParams), { application_id: "app", environment_id: "test",
    installed_release_number: "1", channel: "stable", platform: "linux", architecture: "x64" });
  assert.equal(request.headers.get("authorization"), "Bearer synthetic-management");
  assert.equal(request.credentials, "omit"); assert.equal(request.redirect, "error");
  reply({ artifact: a, ticket: null, expires_at: null });
  assert.equal((await client.authorizeDownload("licence", "release", "artifact")).ticket, null);
  assert.deepEqual(calls.at(-1).body, { release_id: "release", artifact_id: "artifact" });
  reply({ release: release(a), artifact: artifact(undefined, { architecture: "arm64" }) });
  await assert.rejects(client.checkForUpdate("licence", 1, { target: { platform: "linux", architecture: "x64" } }), OrbitTransportError);
});

test("backend release and artifact management use exact mutation HTTP contracts", async () => {
  const { client, calls, reply } = fixture();
  const input = { channel: "stable", version: "v2", notes: "Release notes" };
  const draft = release(undefined, { release_number: null, state: "draft", published_at: null, artifacts: [] });
  reply(draft, 201);
  const created = await client.createRelease(input, { idempotencyKey: key });
  assert.equal(created.idempotencyKey, key); assert.equal(calls.at(-1).method, "POST");
  assert.deepEqual(calls.at(-1).body, { ...input, idempotency_key: key });
  reply(draft);
  await client.updateRelease("release", input, { idempotencyKey: key });
  assert.equal(calls.at(-1).method, "PATCH");
  await client.getRelease("release"); assert.equal(calls.at(-1).method, "GET");
  const cursor = "filter_bound_scope_1234.release";
  reply({ items: [draft], next_cursor: cursor });
  assert.equal((await client.listReleases({ channel: "stable", after: cursor, limit: 100 })).nextCursor, cursor);
  assert.equal(calls.at(-1).url.searchParams.get("after"), cursor);
  const a = artifact(), artifactInput = online.parseArtifact(a);
  reply(a, 201); await client.createArtifact("release", artifactInput, { idempotencyKey: key });
  assert.equal(calls.at(-1).body.byte_length, a.byte_length);
  assert.equal(calls.at(-1).body.required_feature, null);
  reply(a); await client.updateArtifact("release", "artifact", artifactInput, { idempotencyKey: key });
  assert.equal(calls.at(-1).method, "PATCH");
  reply(null, 204); assert.equal((await client.deleteArtifact("release", "artifact", { idempotencyKey: key })).idempotencyKey, key);
  assert.equal(calls.at(-1).method, "DELETE"); assert.deepEqual(calls.at(-1).body, { idempotency_key: key });
  reply(release()); await client.publishRelease("release", { idempotencyKey: key });
  assert.equal(calls.at(-1).url.pathname, "/api/management/v1/releases/release/publish");
  reply(release(undefined, { state: "unpublished" })); await client.unpublishRelease("release", { idempotencyKey: key });
  assert.equal(calls.at(-1).url.pathname, "/api/management/v1/releases/release/unpublish");
  reply(draft); assert.equal((await client.unpublishRelease("release", { idempotencyKey: key })).state, "draft");
  reply(draft, 200);
  await assert.rejects(client.createRelease(input, { idempotencyKey: key }), (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey === key);
  reply(() => { throw new TypeError("network lost"); });
  await assert.rejects(client.publishRelease("release"), (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey.length >= 16);
});

test("backend limit methods validate fixed usage and current resource replay results", async () => {
  const { client, calls, reply } = fixture();
  reply(counter()); assert.equal((await client.usage("licence", "exports")).used, 4);
  reply(counter(true, { idempotency_key: key, consumed_units: 2 }));
  const first = await client.consume("licence", "exports", 2, { idempotencyKey: key });
  assert.equal((await client.consume("licence", "exports", 2, { idempotencyKey: key })).periodStartedAt.toISOString(), first.periodStartedAt.toISOString());
  assert.deepEqual(calls.at(-1).body, { units: 2, idempotency_key: key });
  reply(counter(false)); assert.equal((await client.resources("licence", "projects")).used, 4);
  const allocation = counter(false, { allocation_id: "allocation", resource_id: "project", units: 2, state: "active", idempotency_key: key });
  reply(allocation); assert.equal((await client.acquireResource("licence", "projects", "project", 2, { idempotencyKey: key })).state, "active");
  const released = { ...allocation, state: "released", used: 2, remaining: 8 };
  reply(released); assert.equal((await client.releaseResource("licence", "projects", "allocation", { idempotencyKey: key })).state, "released");
  assert.equal((await client.acquireResource("licence", "projects", "project", 2, { idempotencyKey: key })).state, "released");
  reply({ items: [{ allocation_id: "allocation", resource_id: "project", units: 2, state: "released",
    created_at: "2026-09-01T00:00:00Z", released_at: "2026-09-02T00:00:00Z" }], next_cursor: "scope.filter-id" });
  assert.equal((await client.listResourceAllocations("licence", "projects", { state: "released", limit: 50 })).nextCursor, "scope.filter-id");
  assert.equal(calls.at(-1).url.searchParams.get("state"), "released");
  for (const units of [true, 1.5, 0, -1, 2 ** 53]) await assert.rejects(client.consume("licence", "exports", units), TypeError);
  reply(counter(true, { idempotency_key: key, consumed_units: 2 }), 201);
  await assert.rejects(client.consume("licence", "exports", 2, { idempotencyKey: key }), OrbitMutationUncertainError);
});

test("strict nested capacity errors and duplicate JSON never expose unvalidated counters", async () => {
  const { client, reply } = fixture();
  const denied = { error: { code: "usage_limit_reached", message: "Capacity reached", request_id: "req",
    counter: counter(true, { used: 10, remaining: 0 }), idempotency_key: key, requested_units: 2 } };
  reply(denied, 409);
  await assert.rejects(client.consume("licence", "exports", 2, { idempotencyKey: key }), (e) => e instanceof OrbitLimitReachedError && e.counter.used === 10);
  for (const changes of [{ idempotency_key: "different-job-000001" }, { requested_units: true }, { counter: counter(true, { name: "other" }) },
    { counter: counter(true, { limit: 2 ** 53 }) }, { counter: counter(true, { remaining: 5 }) }]) {
    reply({ error: { ...denied.error, ...changes } }, 409);
    await assert.rejects(client.consume("licence", "exports", 2, { idempotencyKey: key }),
      (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey === key && e.counter === undefined);
  }
  reply(() => new Response('{"name":"exports","name":"exports","limit":10,"used":4,"remaining":6}', { headers: { "content-type": "application/json" } }));
  await assert.rejects(client.usage("licence", "exports"), OrbitTransportError);
  const controller = new AbortController();
  reply(() => { controller.abort(); return new Response(JSON.stringify(counter(true, { idempotency_key: key, consumed_units: 2 })), { headers: { "content-type": "application/json" } }); });
  await assert.rejects(client.consume("licence", "exports", 2, { idempotencyKey: key, signal: controller.signal }),
    (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey === key && e.code === "operation_cancelled");
  const deletion = new AbortController();
  reply(() => { deletion.abort(); return new Response(null, { status: 204 }); });
  await assert.rejects(client.deleteArtifact("release", "artifact", { idempotencyKey: key, signal: deletion.signal }),
    (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey === key && e.code === "operation_cancelled");
  const capacity = new AbortController();
  reply(() => { capacity.abort(); return new Response(JSON.stringify(denied), { status: 409, headers: { "content-type": "application/json" } }); });
  await assert.rejects(client.consume("licence", "exports", 2, { idempotencyKey: key, signal: capacity.signal }),
    (e) => e instanceof OrbitMutationUncertainError && e.idempotencyKey === key && e.code === "operation_cancelled");
});

test("management usage and resources traverse a verified TLS peer with scoped proof", async (t) => {
  const seen = [];
  const tls = await tlsServer(t, async (request, response) => {
    let body = ""; for await (const chunk of request) body += chunk;
    seen.push({ url: request.url, headers: request.headers, body: body ? JSON.parse(body) : null });
    const result = request.url.includes("/usage/") ? counter(true, { idempotency_key: key, consumed_units: 2 }) : counter(false);
    response.writeHead(200, { "content-type": "application/json" }); response.end(JSON.stringify(result));
  });
  const fetchImpl = (url, options) => new Promise((resolve, reject) => {
    const request = https.request(url, { method: options.method, headers: Object.fromEntries(options.headers), ca: tls.ca,
      lookup: tls.lookup, agent: false, signal: options.signal }, (response) => {
      const chunks = []; response.on("data", (v) => chunks.push(v)); response.on("error", reject);
      response.on("end", () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: response.headers })));
    });
    request.on("error", reject); request.end(options.body);
  });
  const scopedKey = `orbit_app_test_${Buffer.from(tls.origin).toString("base64url")}.app.test`;
  const client = new OrbitBackendClient({ appKey: scopedKey, managementToken: "synthetic-management" }, { fetchImpl });
  assert.equal((await client.consume("licence", "exports", 2, { idempotencyKey: key })).used, 4);
  assert.equal((await client.resources("licence", "projects")).remaining, 6);
  assert.ok(seen.every((v) => v.headers.authorization === "Bearer synthetic-management" && v.url.includes("application_id=app&environment_id=test")));
  assert.deepEqual(seen[0].body, { units: 2, idempotency_key: key }); assert.equal(seen[1].body, null);
});

test("malformed mutation error envelopes retain the generated operation ID as uncertain", async () => {
  const { client, calls, reply } = fixture();
  for (const value of [{}, { error: null }, { error: { code: 17, message: "Denied", request_id: "request" } },
    { error: { code: "conflict", request_id: "request" } },
    { error: { code: "conflict", message: "Denied", request_id: 17 } },
    { error: { code: "conflict", message: "Denied" } }]) {
    reply(value, 409);
    await assert.rejects(client.consume("licence", "exports", 2), (error) =>
      error instanceof OrbitMutationUncertainError && error.idempotencyKey === calls.at(-1).body.idempotency_key);
  }
  reply({ error: { code: "idempotency_conflict", message: "Conflict", request_id: "request" } }, 409);
  await assert.rejects(client.consume("licence", "exports", 2), (error) =>
    error.code === "idempotency_conflict" && !(error instanceof OrbitMutationUncertainError));
});
