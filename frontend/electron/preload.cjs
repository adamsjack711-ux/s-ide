// Preload runs in the renderer process *before* the page loads.
// Right now we don't need to expose anything — all backend traffic goes
// through plain fetch() to http://127.0.0.1:8765. When we add features that
// need privileged Electron APIs (e.g. native notifications, file dialogs),
// we'll expose them via contextBridge here.

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("nt", {
  platform: process.platform,
  // Open a new window pinned to an engagement (engagement-as-workspace).
  openEngagementWindow: (engagementId) =>
    ipcRenderer.invoke("open-engagement-window", engagementId),
  // Native folder picker (returns absolute path or null).
  pickDirectory: () => ipcRenderer.invoke("pick-directory"),
});
