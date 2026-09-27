const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("orbit", Object.freeze({
  exportData: () => ipcRenderer.invoke("orbit:export"),
}));
