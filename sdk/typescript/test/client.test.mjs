import assert from "node:assert/strict";
import test from "node:test";
import {
  OrbitApiError,
  OrbitBackendClient,
  OrbitTransportError,
} from "../index.mjs";

const config = {
  apiOrigin: "https://orbit.example.test",
  applicationId: "app_example",
  environmentId: "env_test_example",
  managementToken: "management-secret",
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function currentSession(customerId = "customer_verified") {
  return {
    customer_id: customerId,
    application_id: config.applicationId,
    environment_id: config.environmentId,
    expires_at: utcSecond(Date.now() + 60_000),
  };
}

function utcSecond(milliseconds) {
  return new Date(milliseconds).toISOString().replace(/\.\d{3}Z$/, "Z");
}

test("requires an HTTPS origin", () => {
  assert.throws(() => new OrbitBackendClient({ ...config, apiOrigin: "http://orbit.example.test" }), TypeError);
  assert.throws(() => new OrbitBackendClient({ ...config, apiOrigin: "https://orbit.example.test/path" }), TypeError);
});

test("verifies the customer session using a Bearer header and fixed scope", async () => {
  let call;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      call = { url: new URL(url), options };
      return jsonResponse(currentSession());
    },
  });

  const subject = await client.verifyCurrentCustomerSession("customer-session-secret");
  assert.equal(subject.customer_id, "customer_verified");
  assert.equal(call.url.pathname, "/api/client/v1/sessions/current");
  assert.equal(call.url.searchParams.get("application_id"), config.applicationId);
  assert.equal(call.url.searchParams.get("environment_id"), config.environmentId);
  assert.equal(call.url.href.includes("customer-session-secret"), false);
  assert.equal(call.options.headers.get("authorization"), "Bearer customer-session-secret");
  assert.equal(call.options.redirect, "error");
});

test("rejects a session subject outside configured scope", async () => {
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => jsonResponse({
      ...currentSession(),
      environment_id: "env_other",
    }),
  });

  await assert.rejects(
    client.verifyCurrentCustomerSession("customer-session-secret"),
    (error) => error instanceof OrbitTransportError && error.code === "invalid_response",
  );
});

test("decision binds the server-derived customer and keeps management auth separate", async () => {
  const calls = [];
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      calls.push({ url: new URL(url), options });
      if (calls.length === 1) return jsonResponse(currentSession("customer_from_orbit"));
      return jsonResponse({ allowed: true, reason: "allowed", checked_at: utcSecond(Date.now()) });
    },
  });

  const decision = await client.decideFeature({
    customerSession: "customer-session-secret",
    licenceId: "licence_example",
    activationId: "activation_example",
    entitlement: "export",
    customerId: "customer_from_request",
  });
  assert.equal(decision.allowed, true);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].url.pathname, "/api/management/v1/licence-decisions");
  assert.equal(calls[1].options.headers.get("authorization"), "Bearer management-secret");
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    licence_id: "licence_example",
    activation_id: "activation_example",
    customer_id: "customer_from_orbit",
    entitlement: "export",
  });
  assert.equal(calls[1].url.href.includes("management-secret"), false);
});

test("an authenticated feature denial is returned as denied", async () => {
  let callNumber = 0;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      callNumber += 1;
      return callNumber === 1
        ? jsonResponse(currentSession())
        : jsonResponse({ allowed: false, reason: "entitlement_denied", checked_at: utcSecond(Date.now()) });
    },
  });

  const decision = await client.decideFeature({
    customerSession: "customer-session-secret",
    licenceId: "licence_example",
    activationId: "activation_example",
    entitlement: "export",
  });
  assert.deepEqual(decision, {
    allowed: false,
    reason: "entitlement_denied",
    checked_at: decision.checked_at,
  });
});

test("malformed decisions fail closed", async () => {
  let callNumber = 0;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      callNumber += 1;
      return callNumber === 1
        ? jsonResponse(currentSession())
        : jsonResponse({ allowed: true, reason: "entitlement_denied", checked_at: utcSecond(Date.now()) });
    },
  });

  await assert.rejects(
    client.decideFeature({
      customerSession: "customer-session-secret",
      licenceId: "licence_example",
      activationId: "activation_example",
      entitlement: "export",
    }),
    (error) => error instanceof OrbitTransportError && error.code === "invalid_response",
  );
});

test("API errors expose safe code and request ID, not the server message", async () => {
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => jsonResponse({
      error: { code: "access_denied", request_id: "req_safe_123", message: "sensitive response" },
    }, 403),
  });

  await assert.rejects(client.getLicence("licence_example"), (error) => {
    assert.ok(error instanceof OrbitApiError);
    assert.equal(error.status, 403);
    assert.equal(error.code, "access_denied");
    assert.equal(error.requestId, "req_safe_123");
    assert.equal(error.message.includes("sensitive response"), false);
    return true;
  });
});

test("oversized and malformed JSON responses fail closed", async () => {
  const oversized = new Response(" ".repeat(1024 * 1024 + 1), {
    headers: { "content-type": "application/json" },
  });
  const tooLargeClient = new OrbitBackendClient(config, { fetchImpl: async () => oversized });
  await assert.rejects(tooLargeClient.getLicence("licence_example"), (error) =>
    error instanceof OrbitTransportError && error.code === "response_too_large");

  const malformedClient = new OrbitBackendClient(config, {
    fetchImpl: async () => new Response("{bad json", { headers: { "content-type": "application/json" } }),
  });
  await assert.rejects(malformedClient.getLicence("licence_example"), (error) =>
    error instanceof OrbitTransportError && error.code === "invalid_response");
});

test("a failed mutation is sent once without an automatic retry", async () => {
  let calls = 0;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      calls += 1;
      throw new TypeError("connection failed");
    },
  });

  await assert.rejects(client.issueLicences({
    policyId: "policy_example",
    quantity: 1,
    reference: "",
    note: "",
    idempotencyKey: "stable-operation-123",
  }), OrbitTransportError);
  assert.equal(calls, 1);
});

test("management methods use their documented paths and request bodies", async () => {
  const calls = [];
  const issued = {
    licences: [{ id: "licence_example" }],
    keys: [{ licence_id: "licence_example", key: "ephemeral-key" }],
    secret_replay_expired: false,
  };
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      const parsed = new URL(url);
      calls.push({ url: parsed, options });
      if (parsed.pathname.endsWith("/search")) return jsonResponse({ items: [], next_cursor: null });
      if (parsed.pathname.endsWith("/key-replacements") || parsed.pathname === "/api/management/v1/licences") {
        return jsonResponse(issued);
      }
      if (parsed.pathname.endsWith("/status")) return jsonResponse({ id: "licence_example", status: "revoked" });
      return jsonResponse({ id: "licence_example", status: "enabled" });
    },
  });

  await client.searchLicences({ query: "full licence key", after: "cursor_1", status: "active" });
  await client.issueLicences({
    policyId: "policy_example",
    quantity: 2,
    reference: "order-123",
    note: "initial order",
    idempotencyKey: "issue-operation-123",
  });
  await client.getLicence("licence_example");
  await client.replaceLicenceKey("licence_example", {
    reason: "customer reported a lost key",
    idempotencyKey: "replace-operation-1",
  });
  await client.revokeLicence("licence_example", "refund approved");

  assert.deepEqual(calls.map(({ url, options }) => [options.method, url.pathname]), [
    ["POST", "/api/management/v1/licences/search"],
    ["POST", "/api/management/v1/licences"],
    ["GET", "/api/management/v1/licences/licence_example"],
    ["POST", "/api/management/v1/licences/licence_example/key-replacements"],
    ["POST", "/api/management/v1/licences/licence_example/status"],
  ]);
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    query: "full licence key",
    after: "cursor_1",
    status: "active",
  });
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    policy_id: "policy_example",
    quantity: 2,
    reference: "order-123",
    note: "initial order",
    idempotency_key: "issue-operation-123",
  });
  assert.deepEqual(JSON.parse(calls[3].options.body), {
    reason: "customer reported a lost key",
    idempotency_key: "replace-operation-1",
  });
  assert.deepEqual(JSON.parse(calls[4].options.body), {
    status: "revoked",
    reason: "refund approved",
  });
  assert.equal(calls[0].url.searchParams.has("query"), false);
});
