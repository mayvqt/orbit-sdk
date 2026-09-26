import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  AppKey,
  OrbitAccessDeniedError,
  OrbitApiError,
  OrbitBackendClient,
  OrbitMutationUncertainError,
  OrbitTransportError,
} from "../index.mjs";

const API_ORIGIN = "https://orbit.example.test";
const APPLICATION_ID = "app_example";
const ENVIRONMENT_ID = "env_test_example";
const APP_KEY = `orbit_app_test_${Buffer.from(API_ORIGIN).toString("base64url")}.${APPLICATION_ID}.${ENVIRONMENT_ID}`;

const config = {
  appKey: APP_KEY,
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
    application_id: APPLICATION_ID,
    environment_id: ENVIRONMENT_ID,
    expires_at: utcSecond(Date.now() + 60_000),
  };
}

function utcSecond(milliseconds) {
  return new Date(milliseconds).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function appKeyFor(origin, applicationId = APPLICATION_ID, environmentId = ENVIRONMENT_ID) {
  return `orbit_app_test_${Buffer.from(origin).toString("base64url")}.${applicationId}.${environmentId}`;
}

function licenceShape(overrides = {}) {
  return {
    id: "licence_example",
    policy_id: "policy_example",
    policy_name: "Desktop",
    policy_version: 1,
    key_suffix: "01ABC2",
    status: "enabled",
    state: "unused",
    expiry_mode: "perpetual",
    duration_seconds: null,
    first_used_at: null,
    expires_at: null,
    device_limit: 2,
    hwid_locked: false,
    offline_allowed: true,
    offline_seconds: 900,
    entitlements: { export: true },
    reference: "",
    note: "",
    created_at: "2026-09-27T00:00:00Z",
    reset_cooldown_until: null,
    customer_id: null,
    key_generation: 1,
    ...overrides,
  };
}

function issuedShape(overrides = {}) {
  return {
    licences: [licenceShape()],
    keys: [{ licence_id: "licence_example", key: "EXAMPLE-KEY-12345" }],
    secret_replay_expired: false,
    ...overrides,
  };
}

test("AppKey.parse matches every contracts/sdk/app-keys.json vector", () => {
  const vectorsPath = new URL("../../../contracts/sdk/app-keys.json", import.meta.url);
  const { cases } = JSON.parse(readFileSync(vectorsPath, "utf-8"));
  assert.ok(cases.length > 0, "vector file should not be empty");

  for (const testCase of cases) {
    if (testCase.valid) {
      const parsed = AppKey.parse(testCase.key);
      assert.equal(parsed.api_origin, testCase.api_origin, testCase.name);
      assert.equal(parsed.issuer, testCase.issuer, testCase.name);
      assert.equal(parsed.application_id, testCase.application_id, testCase.name);
      assert.equal(parsed.environment_id, testCase.environment_id, testCase.name);
      assert.equal(parsed.environment, testCase.environment, testCase.name);
    } else {
      assert.throws(() => AppKey.parse(testCase.key), TypeError, testCase.name);
    }
  }
});

test("OrbitBackendClient accepts an already-parsed AppKey", () => {
  const parsed = AppKey.parse(APP_KEY);
  const client = new OrbitBackendClient({ appKey: parsed, managementToken: "management-secret" });
  assert.ok(client instanceof OrbitBackendClient);
});

test("runtime construction and forged AppKey instances cannot bypass HTTPS validation", () => {
  assert.throws(() => new AppKey("http://orbit.example.test", APPLICATION_ID, ENVIRONMENT_ID, "test"), TypeError);
  const forged = Object.create(AppKey.prototype);
  Object.defineProperties(forged, {
    api_origin: { value: "http://orbit.example.test" },
    application_id: { value: APPLICATION_ID },
    environment_id: { value: ENVIRONMENT_ID },
    environment: { value: "test" },
    issuer: { value: "http://orbit.example.test" },
  });
  assert.throws(() => new OrbitBackendClient({ ...config, appKey: forged }), TypeError);
});

test("requires an HTTPS origin", () => {
  assert.throws(
    () => new OrbitBackendClient({ ...config, appKey: appKeyFor("http://orbit.example.test") }),
    TypeError,
  );
  assert.throws(
    () => new OrbitBackendClient({ ...config, appKey: appKeyFor("https://orbit.example.test/path") }),
    TypeError,
  );
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
  assert.equal(call.url.searchParams.get("application_id"), APPLICATION_ID);
  assert.equal(call.url.searchParams.get("environment_id"), ENVIRONMENT_ID);
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
      return jsonResponse({ allowed: true, reason: "allowed", checked_at: utcSecond(Date.now()), customer_id: "untrusted_extra_field" });
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
  assert.equal(decision.customer_id, "customer_from_orbit");
  assert.equal(Object.isFrozen(decision), true);
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
    customer_id: "customer_verified",
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

test("requireFeature returns the decision when access is allowed", async () => {
  let callNumber = 0;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      callNumber += 1;
      return callNumber === 1
        ? jsonResponse(currentSession())
        : jsonResponse({ allowed: true, reason: "allowed", checked_at: utcSecond(Date.now()) });
    },
  });

  const decision = await client.requireFeature({
    customerSession: "customer-session-secret",
    licenceId: "licence_example",
    activationId: "activation_example",
    entitlement: "export",
  });
  assert.equal(decision.allowed, true);
  assert.equal(decision.customer_id, "customer_verified");
  assert.equal(callNumber, 2);
});

test("requireFeature throws OrbitAccessDeniedError with the reason when access is denied", async () => {
  let callNumber = 0;
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      callNumber += 1;
      return callNumber === 1
        ? jsonResponse(currentSession())
        : jsonResponse({ allowed: false, reason: "entitlement_denied", checked_at: utcSecond(Date.now()) });
    },
  });

  await assert.rejects(
    client.requireFeature({
      customerSession: "customer-session-secret",
      licenceId: "licence_example",
      activationId: "activation_example",
      entitlement: "export",
    }),
    (error) => {
      assert.ok(error instanceof OrbitAccessDeniedError);
      assert.equal(error.reason, "entitlement_denied");
      return true;
    },
  );
});

test("requireFeature propagates transport errors without wrapping them", async () => {
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => {
      throw new TypeError("connection failed");
    },
  });

  await assert.rejects(
    client.requireFeature({
      customerSession: "customer-session-secret",
      licenceId: "licence_example",
      activationId: "activation_example",
      entitlement: "export",
    }),
    OrbitTransportError,
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
  }), (error) => {
    assert.ok(error instanceof OrbitMutationUncertainError);
    assert.equal(error.idempotencyKey, "stable-operation-123");
    return true;
  });
  assert.equal(calls, 1);
});

test("lost issue and replacement responses expose their generated IDs for safe retry", async () => {
  const scenarios = [
    {
      run: (client, idempotencyKey) => client.issueLicences({
        policyId: "policy_example", quantity: 1, reference: "order", note: "initial",
        ...(idempotencyKey ? { idempotencyKey } : {}),
      }),
    },
    {
      run: (client, idempotencyKey) => client.replaceLicenceKey("licence_example", {
        reason: "customer reported a lost key",
        ...(idempotencyKey ? { idempotencyKey } : {}),
      }),
    },
  ];

  for (const scenario of scenarios) {
    let calls = 0;
    const bodies = [];
    const client = new OrbitBackendClient(config, {
      fetchImpl: async (_url, options) => {
        calls += 1;
        bodies.push(JSON.parse(options.body));
        if (calls === 1) throw new TypeError("connection failed");
        return jsonResponse(issuedShape());
      },
    });
    let uncertain;
    try {
      await scenario.run(client);
    } catch (error) {
      uncertain = error;
    }
    assert.ok(uncertain instanceof OrbitMutationUncertainError);
    assert.match(uncertain.idempotencyKey, /^[!-~]{16,128}$/);
    const recovered = await scenario.run(client, uncertain.idempotencyKey);
    assert.equal(recovered.idempotencyKey, uncertain.idempotencyKey);
    assert.equal(bodies[0].idempotency_key, bodies[1].idempotency_key);
    assert.equal(calls, 2);
  }
});

test("licence responses validate the server shape before returning typed fields", async () => {
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => jsonResponse(licenceShape({ key_generation: "1" })),
  });
  await assert.rejects(client.getLicence("licence_example"), (error) =>
    error instanceof OrbitTransportError && error.code === "invalid_response");
});

test("licence policy names follow the server's trimmed 80-character name schema", async () => {
  let policyName = "é".repeat(80);
  const client = new OrbitBackendClient(config, {
    fetchImpl: async () => jsonResponse(licenceShape({ policy_name: policyName })),
  });

  assert.equal((await client.getLicence("licence_example")).policy_name, policyName);
  for (policyName of ["", "  ", " Desktop", "Desktop\n", "é".repeat(81)]) {
    await assert.rejects(client.getLicence("licence_example"), (error) =>
      error instanceof OrbitTransportError && error.code === "invalid_response");
  }
});

test("issueLicences generates an idempotency key when omitted and returns it", async () => {
  const issued = issuedShape();
  const bodies = [];
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      bodies.push(JSON.parse(options.body));
      return jsonResponse(issued);
    },
  });

  const first = await client.issueLicences({
    policyId: "policy_example",
    quantity: 1,
    reference: "",
    note: "",
  });
  const second = await client.issueLicences({
    policyId: "policy_example",
    quantity: 1,
    reference: "",
    note: "",
  });

  assert.match(first.idempotencyKey, /^[!-~]{16,128}$/);
  assert.equal(bodies[0].idempotency_key, first.idempotencyKey);
  assert.notEqual(first.idempotencyKey, second.idempotencyKey);
  assert.equal(first.licences.length, 1);
});

test("issueLicences keeps a caller-supplied idempotency key and returns it unchanged", async () => {
  const issued = issuedShape();
  const client = new OrbitBackendClient(config, { fetchImpl: async () => jsonResponse(issued) });

  const result = await client.issueLicences({
    policyId: "policy_example",
    quantity: 1,
    reference: "",
    note: "",
    idempotencyKey: "caller-supplied-operation-key",
  });
  assert.equal(result.idempotencyKey, "caller-supplied-operation-key");
});

test("replaceLicenceKey generates an idempotency key when omitted and returns it", async () => {
  const issued = issuedShape();
  const bodies = [];
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      bodies.push(JSON.parse(options.body));
      return jsonResponse(issued);
    },
  });

  const result = await client.replaceLicenceKey("licence_example", { reason: "customer reported a lost key" });
  assert.match(result.idempotencyKey, /^[!-~]{16,128}$/);
  assert.equal(bodies[0].idempotency_key, result.idempotencyKey);
});

test("management methods use their documented paths and request bodies", async () => {
  const calls = [];
  const issued = issuedShape();
  const client = new OrbitBackendClient(config, {
    fetchImpl: async (url, options) => {
      const parsed = new URL(url);
      calls.push({ url: parsed, options });
      if (parsed.pathname.endsWith("/search")) return jsonResponse({ items: [licenceShape()], next_cursor: null });
      if (parsed.pathname.endsWith("/key-replacements") || parsed.pathname === "/api/management/v1/licences") {
        return jsonResponse(issued);
      }
      if (parsed.pathname.endsWith("/status")) return jsonResponse(licenceShape({ status: "revoked", state: "revoked" }));
      return jsonResponse(licenceShape());
    },
  });

  const page = await client.searchLicences({ query: "full licence key", after: "cursor_1", status: "active" });
  assert.ok(Object.isFrozen(page.items));
  assert.ok(Object.isFrozen(page.items[0]));
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
