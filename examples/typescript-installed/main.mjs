import { app, BrowserWindow, ipcMain, safeStorage } from "electron";
import { fileURLToPath } from "node:url";
import { openElectronClient } from "@orbit/installed-sdk/electron";

const appKey = process.env.ORBIT_APP_KEY;
if (!appKey) throw new Error("Set ORBIT_APP_KEY in the main process environment");

await app.whenReady();
const client = await openElectronClient(appKey, { app, safeStorage });
const preload = fileURLToPath(new URL("./preload.cjs", import.meta.url));
const window = new BrowserWindow({
  webPreferences: { preload, contextIsolation: true, nodeIntegration: false, sandbox: true },
});
const rendererUrl = process.env.ORBIT_RENDERER_URL ?? "file:///path/to/your/renderer/index.html";
ipcMain.handle("orbit:export", async (event) => {
  if (event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame ||
      event.senderFrame.url !== rendererUrl) {
    throw new Error("unauthorized renderer");
  }
  const access = await client.ensureAccess("export", async () => process.env.ORBIT_LICENCE_KEY ?? null);
  if (!access.has("export")) throw new Error("export access unavailable");
  await exportProtectedDataInMainProcess();
  return Object.freeze({ completed: true });
});
await window.loadURL(rendererUrl);

let closing = false;
app.on("before-quit", (event) => {
  if (closing) return;
  event.preventDefault();
  closing = true;
  void client.close().then(() => app.quit(), () => app.quit());
});

async function exportProtectedDataInMainProcess() {
  // Perform the real protected operation here; do not send secrets to IPC.
}
