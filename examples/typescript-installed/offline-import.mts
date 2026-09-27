import { readFile } from "node:fs/promises";
import { Client } from "../../sdk/typescript-installed/index.mjs";

const appKey = process.env.ORBIT_APP_KEY;
const trustedKeysPath = process.env.ORBIT_OFFLINE_JWKS_PATH;
const offlineFilePath = process.env.ORBIT_OFFLINE_FILE_PATH;
if (!appKey || !trustedKeysPath || !offlineFilePath) {
  throw new Error("Set ORBIT_APP_KEY, ORBIT_OFFLINE_JWKS_PATH and ORBIT_OFFLINE_FILE_PATH");
}

const offlineKeys = await readFile(trustedKeysPath);
const offlineFile = await readFile(offlineFilePath);
const client = await Client.open(appKey, { offlineKeys });
try {
  await client.importOfflineFile(offlineFile);
  await client.requireAccess("export");
  await exportProtectedData();
} finally {
  await client.close();
}

async function exportProtectedData(): Promise<void> {
  // Run the app's protected operation here; never log or display the signed file.
}
