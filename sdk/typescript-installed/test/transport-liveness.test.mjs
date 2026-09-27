import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import https from "node:https";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";

const run = promisify(execFile);
const transport = new URL("../src/transport.mjs", import.meta.url).href;
const caPath = fileURLToPath(new URL("../../cpp/tests/fixtures/transport-test-ca.pem", import.meta.url));
const certificate = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.crt", import.meta.url));
const privateKey = await readFile(new URL("../../cpp/tests/fixtures/transport-test-dns.key", import.meta.url));

for (const mode of ["refused address", "transient response"]) {
  test(`standalone awaited request stays alive through ${mode} retry`, async (t) => {
    const bodies = [];
    const server = https.createServer({ cert: certificate, key: privateKey }, async (request, response) => {
      let body = "";
      for await (const chunk of request) body += chunk;
      bodies.push(body);
      const retry = mode === "transient response" && bodies.length === 1;
      response.writeHead(retry ? 503 : 200, { "content-type": "application/json" });
      response.end(retry
        ? JSON.stringify({ error: { code: "service_unavailable", message: "Retry", request_id: "fixture" } })
        : '{"ok":true}');
    });
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    t.after(() => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(resolve);
    }));
    const origin = `https://localhost:${server.address().port}`;
    // The TLS server lives in the parent process. The child has no unrelated
    // referenced handle that could hide an unref'd foreground retry timer.
    const source = `
      import assert from "node:assert/strict";
      import { readFile } from "node:fs/promises";
      import { HttpTransport } from ${JSON.stringify(transport)};
      const ca = await readFile(${JSON.stringify(caPath)});
      const addresses = ${JSON.stringify(mode === "refused address"
        ? [{ address: "127.0.0.2", family: 4 }, { address: "127.0.0.1", family: 4 }]
        : [{ address: "127.0.0.1", family: 4 }])};
      const client = new HttpTransport(${JSON.stringify(origin)}, { ca, lookup: async () => addresses });
      try {
        const response = await client.post("/api/client/v1/activations", { idempotency_key: "operation_0000001" }, true);
        assert.deepEqual(JSON.parse(response), { ok: true });
        process.stdout.write("completed\\n");
      } catch { process.stderr.write("request failed\\n"); process.exitCode = 1; }
    `;
    const result = await run(process.execPath, ["--input-type=module", "--eval", source], {
      timeout: 8000, maxBuffer: 16 * 1024,
    });
    assert.equal(result.stdout, "completed\n");
    assert.equal(result.stderr, "");
    assert.equal(bodies.length, mode === "transient response" ? 2 : 1);
    assert.ok(bodies.every((body) => body === '{"idempotency_key":"operation_0000001"}'));
  });
}
