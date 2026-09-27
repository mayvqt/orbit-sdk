import { openClientWithStorageCodec, validateClientOptions } from "./client.mjs";
import { fail, ErrorKind } from "./errors.mjs";

/** Open a main-process client using Electron's asynchronous OS-backed storage. */
export async function openElectronClient(appKey, options = {}) {
  return openElectronClientInternal(appKey, options, false);
}

export async function openElectronClientForTesting(appKey, options = {}) {
  return openElectronClientInternal(appKey, options, true);
}

async function openElectronClientInternal(appKey, options, testMainProcess) {
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      Object.getPrototypeOf(options) !== Object.prototype && Object.getPrototypeOf(options) !== null) {
    throw fail(ErrorKind.CONFIGURATION, "invalid_client_options");
  }
  const { app, safeStorage, ...clientOptions } = options;
  validateClientOptions(clientOptions);
  if ((!testMainProcess && process.type !== "browser") || !app || typeof app.isReady !== "function" || !app.isReady() ||
      !safeStorage || typeof safeStorage.isAsyncEncryptionAvailable !== "function" ||
      typeof safeStorage.encryptStringAsync !== "function" || typeof safeStorage.decryptStringAsync !== "function") {
    throw fail(ErrorKind.STORAGE, "storage_unavailable");
  }

  try {
    if (!await safeStorage.isAsyncEncryptionAvailable()) throw fail(ErrorKind.STORAGE, "storage_unavailable");
    if (process.platform === "linux") {
      if (typeof safeStorage.getSelectedStorageBackend !== "function") throw fail(ErrorKind.STORAGE, "storage_unavailable");
      const backend = safeStorage.getSelectedStorageBackend();
      if (!["gnome_libsecret", "kwallet", "kwallet5", "kwallet6"].includes(backend)) {
        throw fail(ErrorKind.STORAGE, "storage_unavailable");
      }
    }
  } catch (error) {
    if (error?.kind) throw error;
    throw fail(ErrorKind.STORAGE, "storage_unavailable");
  }

  const codec = Object.freeze({
    async encrypt(value) {
      try {
        const result = await safeStorage.encryptStringAsync(value);
        if (!Buffer.isBuffer(result) || result.length < 1 || result.length > 66 * 1024) {
          throw fail(ErrorKind.STORAGE, "storage_failed");
        }
        return result;
      } catch (error) {
        if (error?.kind) throw error;
        throw fail(ErrorKind.STORAGE, "storage_unavailable");
      }
    },
    async decrypt(value) {
      try {
        const result = await safeStorage.decryptStringAsync(value);
        if (!result || typeof result !== "object" || typeof result.result !== "string" ||
            result.isTemporarilyUnavailable === true) throw fail(ErrorKind.STORAGE, "storage_unavailable");
        return { result: result.result, shouldReEncrypt: result.shouldReEncrypt === true };
      } catch (error) {
        if (error?.kind) throw error;
        throw fail(ErrorKind.STORAGE, "storage_unavailable");
      }
    },
  });

  try {
    return await openClientWithStorageCodec(appKey, clientOptions, codec);
  } catch (error) {
    if (error?.kind) throw error;
    throw fail(ErrorKind.STORAGE, "storage_unavailable");
  }
}
