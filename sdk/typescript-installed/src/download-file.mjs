import https from "node:https";
import { createHash, randomBytes } from "node:crypto";
import { link, lstat, open, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { deliveryUrl, integer, parseAuthorization, requireInput } from "./online.mjs";
import { fail, ErrorKind } from "./errors.mjs";

export async function downloadFile(authorization, destination, options) {
  return downloadFileInternal(authorization, destination, options);
}

// The transport seam supplies a test CA only; TLS verification always stays enabled.
export async function downloadFileInternal(authorization, destination, { maxBytes, replace = false, signal } = {}, transport = {}) {
  requireInput(destination, (v) => typeof v === "string" && v.length > 0 && !v.includes("\0"));
  requireInput(maxBytes, (v) => integer(v, 1));
  requireInput(replace, (v) => typeof v === "boolean");
  let selected;
  try {
    const a = authorization.artifact;
    selected = parseAuthorization({ artifact: { id: a.id, release_id: a.releaseId, platform: a.platform,
      architecture: a.architecture, filename: a.filename, byte_length: a.byteLength, sha256: a.sha256,
      delivery_mode: a.deliveryMode, url: a.url, required_feature: a.requiredFeature },
    ticket: authorization.ticket, expires_at: authorization.expiresAt?.toISOString() ?? null }, a.releaseId, a.id);
  } catch { throw fail(ErrorKind.CONFIGURATION, "invalid_download_authorization"); }
  const artifact = selected.artifact;
  if (artifact.byteLength > maxBytes) throw fail(ErrorKind.CONFIGURATION, "download_size_limit");
  const target = path.resolve(destination);
  const local = new AbortController();
  const combined = signal ? AbortSignal.any([signal, local.signal]) : local.signal;
  const timer = setTimeout(() => local.abort(), 300000);
  let temporary, output, response;
  const check = () => {
    if (combined.aborted) throw fail(signal?.aborted ? ErrorKind.CANCELLED : ErrorKind.TRANSIENT,
      signal?.aborted ? "operation_cancelled" : "download_timeout");
  };
  try {
    check();
    if (!replace) {
      try { await lstat(target); throw fail(ErrorKind.STORAGE, "destination_exists"); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
    let current = artifact.url;
    for (let redirects = 0; redirects <= 5; redirects++) {
      check();
      deliveryUrl(current);
      response = await request(current, redirects === 0 ? selected.ticket : null, combined, transport);
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        const locations = headers(response, "location");
        if (redirects === 5 || locations.length !== 1) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_download_redirect");
        const location = locations[0];
        if (!location || /[^\x21-\x7e]|[\\#<>"{}|^`]/.test(location) || /%(?![a-fA-F0-9]{2})/.test(location)) {
          throw fail(ErrorKind.INVALID_RESPONSE, "invalid_download_redirect");
        }
        if (location.startsWith("//")) deliveryUrl(`https:${location}`);
        else if (/^[a-z][a-z0-9+.-]*:/i.test(location)) deliveryUrl(location);
        current = new URL(location, current).href;
        deliveryUrl(current);
        response.destroy(); response = undefined;
        continue;
      }
      if (response.statusCode !== 200) throw fail(ErrorKind.INVALID_RESPONSE, "download_http_error");
      const encoding = headers(response, "content-encoding"), lengths = headers(response, "content-length");
      if (encoding.length && (encoding.length !== 1 || encoding[0] !== "identity")) throw fail(ErrorKind.INVALID_RESPONSE, "unexpected_content_encoding");
      if (lengths.length && (lengths.length !== 1 || !/^\d+$/.test(lengths[0]) || Number(lengths[0]) !== artifact.byteLength)) {
        throw fail(ErrorKind.INVALID_RESPONSE, "download_length_mismatch");
      }
      if (lengths.length && headers(response, "transfer-encoding").length) throw fail(ErrorKind.INVALID_RESPONSE, "invalid_download_framing");
      temporary = path.join(path.dirname(target), `.orbit-download-${randomBytes(18).toString("hex")}`);
      output = await open(temporary, "wx", 0o600);
      const digest = createHash("sha256");
      let received = 0;
      for await (const chunk of response) {
        check(); received += chunk.length;
        if (received > maxBytes || received > artifact.byteLength) throw fail(ErrorKind.INVALID_RESPONSE, "download_size_limit");
        digest.update(chunk);
        await output.writeFile(chunk);
      }
      check();
      if (received !== artifact.byteLength || digest.digest("hex") !== artifact.sha256) throw fail(ErrorKind.INVALID_RESPONSE, "download_integrity_mismatch");
      await output.sync(); await output.close(); output = undefined;
      check();
      if (replace) await rename(temporary, target);
      else { await link(temporary, target); await unlink(temporary); }
      temporary = undefined;
      return target;
    }
    throw fail(ErrorKind.INVALID_RESPONSE, "invalid_download_redirect");
  } catch (error) {
    check();
    if (error?.kind) throw error;
    if (/CERT|TLS|SSL|SELF_SIGNED|VERIFY_LEAF/.test(error?.code ?? "")) throw fail(ErrorKind.TRANSPORT_SECURITY, "tls_failure");
    throw fail(ErrorKind.TRANSIENT, "download_failed");
  } finally {
    clearTimeout(timer); local.abort(); response?.destroy();
    await output?.close().catch(() => {});
    if (temporary) await unlink(temporary).catch(() => {});
  }
}

function headers(response, name) {
  const result = [];
  for (let i = 0; i < response.rawHeaders.length; i += 2) {
    if (response.rawHeaders[i].toLowerCase() === name) result.push(response.rawHeaders[i + 1]);
  }
  return result;
}
function request(url, ticket, signal, transport) {
  return new Promise((resolve, reject) => {
    const call = https.get(url, { agent: false, signal, rejectUnauthorized: true, ca: transport.ca,
      ...(transport.lookup ? { lookup: transport.lookup } : {}),
      headers: { Accept: "application/octet-stream", "Accept-Encoding": "identity", ...(ticket ? { Authorization: `Bearer ${ticket}` } : {}) } }, resolve);
    call.on("error", reject);
  });
}
