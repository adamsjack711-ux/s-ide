// Electron main process.
//
// Dev:  user runs `npm run dev:all`; the backend is started manually in
//       another terminal (or by concurrently). Electron just loads Vite.
// Prod: this process spawns the PyInstaller-bundled Python sidecar, waits
//       for /health, then opens the window. Kills the sidecar on quit.

const { app, BrowserWindow, dialog, ipcMain, session, shell } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");
const { autoUpdater } = require("electron-updater");

const isDev = process.env.NODE_ENV === "development";
// Security-sensitive relaxations (loosened CSP, allowing the Vite origin to
// navigate the renderer) must NEVER hinge on an inheritable env var: a shipped
// .app launched from a shell that exports NODE_ENV=development would otherwise
// weaken its own CSP. Gate those on packaging state, which the bundle can't
// spoof. `isDev` still drives dev-only conveniences (dock icon, loading Vite).
const isDevUnpackaged = isDev && !app.isPackaged;
const BACKEND_PORT = parseInt(process.env.NT_BACKEND_PORT || "8765", 10);

// In dev mode the OS dock + menu bar would otherwise read the Electron binary
// name ("Electron"). Setting it before app initialisation makes macOS / Linux
// show "s-ide" everywhere it would normally show the launcher name.
// In packaged builds this is already correct via Info.plist's CFBundleName,
// but setting it twice is harmless and keeps both paths consistent.
app.setName("s-ide");

// Same story for the dock icon — `electron .` would otherwise show the
// Electron lozenge. Use the bundled PNG (works cross-platform; .icns isn't
// supported by Dock.setIcon).
if (isDev && process.platform === "darwin" && app.dock) {
  try {
    app.dock.setIcon(path.join(__dirname, "..", "build", "icon.png"));
  } catch (e) {
    console.warn("[network-tools] dock.setIcon failed:", e?.message ?? e);
  }
}

app.setAboutPanelOptions({
  applicationName: "s-ide",
  applicationVersion: app.getVersion(),
  copyright: "© s-ide contributors",
});

let backendProc = null;

function backendBinaryPath() {
  // electron-builder unpacks `extraResources` under process.resourcesPath.
  // PyInstaller's onedir layout: a folder containing the launcher binary and
  // a sibling `_internal/` directory of bundled deps. PyInstaller appends .exe
  // on Windows.
  const name = process.platform === "win32"
    ? "network-tools-backend.exe"
    : "network-tools-backend";
  return path.join(process.resourcesPath, "backend", "network-tools-backend", name);
}

function spawnBackend() {
  const binPath = backendBinaryPath();
  console.log("[network-tools] spawning backend:", binPath);
  // Pin to loopback. The backend refuses to start on a wildcard host (see
  // backend/main.py), but we set NT_BACKEND_HOST explicitly here so the
  // packaged app never depends on the default.
  //
  // PATH augmentation: macOS launchd starts GUI apps with a minimal PATH
  // (`/usr/bin:/bin:/usr/sbin:/sbin`) that excludes Homebrew and the
  // /usr/local symlinks Docker Desktop installs. Without this, the sidecar's
  // `shutil.which("docker")` returns None and Labs fail with "Docker daemon
  // is not running" — even when colima is up. Prepending the standard tool
  // install dirs makes docker / tailscale / nmap / brew / etc. all reachable.
  const TOOL_PATHS = [
    "/opt/homebrew/bin",   // Homebrew on Apple Silicon (colima, docker CLI, tailscale, nmap)
    "/opt/homebrew/sbin",
    "/usr/local/bin",      // Homebrew on Intel + /usr/local/bin/docker (Docker Desktop symlink)
    "/usr/local/sbin",
  ];
  const augmentedPath = [...TOOL_PATHS, process.env.PATH || ""].filter(Boolean).join(":");
  const sidecarEnv = {
    ...process.env,
    PATH: augmentedPath,
    NT_BACKEND_HOST: "127.0.0.1",
    NT_BACKEND_PORT: String(BACKEND_PORT),
  };
  // A shipped build must not let a stray environment variable widen the
  // sidecar's attack surface. RAMPART_EXPOSE_ALL unlocks the Tier-2/3 routers
  // held behind the capability gate; the *_ALLOW_PUBLIC_HOST flags let the
  // backend bind off-loopback. Strip them when packaged so the app ships locked
  // to its default-safe posture regardless of the launching environment.
  // (An unpackaged dev run keeps them so they remain testable.)
  if (app.isPackaged) {
    for (const k of [
      "RAMPART_EXPOSE_ALL",
      "SIDE_ALLOW_PUBLIC_HOST",
      "HACKINGPAL_ALLOW_PUBLIC_HOST",
      "MYHACKINGPAL_ALLOW_PUBLIC_HOST",
    ]) {
      delete sidecarEnv[k];
    }
  }
  backendProc = spawn(binPath, [], { env: sidecarEnv, stdio: "ignore" });
  backendProc.on("exit", (code) => {
    console.log("[network-tools] backend exited with code", code);
    backendProc = null;
  });
  backendProc.on("error", (err) => {
    console.error("[network-tools] backend error:", err);
  });
}

function killBackend() {
  if (!backendProc || backendProc.killed) return;
  const proc = backendProc;
  backendProc = null;
  console.log("[network-tools] killing backend pid", proc.pid);
  try { proc.kill("SIGTERM"); } catch (e) { /* ignore */ }
  // If SIGTERM doesn't reap the process within 3s (uvicorn lifespan shutdown
  // can stall on a stuck WS handler), escalate to SIGKILL so app quit
  // doesn't hang.
  setTimeout(() => {
    if (proc.exitCode === null && proc.signalCode === null) {
      console.log("[network-tools] backend didn't exit on SIGTERM — SIGKILL");
      try { proc.kill("SIGKILL"); } catch (e) { /* ignore */ }
    }
  }, 3000).unref?.();
}

function waitForHealth(timeoutMs = 15000) {
  const start = Date.now();
  return new Promise((resolve) => {
    const scheduleRetry = () => {
      if (Date.now() - start > timeoutMs) resolve(false);
      else setTimeout(tick, 200);
    };
    const tick = () => {
      // On timeout we both call req.destroy() (which emits 'error') AND the
      // timeout handler fires — without a per-tick guard that would queue
      // multiple retries and pile parallel requests on top of each other.
      let settled = false;
      const finishTick = (success) => {
        if (settled) return;
        settled = true;
        if (success) resolve(true);
        else scheduleRetry();
      };
      const req = http.get({ host: "127.0.0.1", port: BACKEND_PORT,
                              path: "/health", timeout: 1000 }, (res) => {
        const ok = res.statusCode === 200;
        res.resume(); // drain so the socket can be reused / closed cleanly
        finishTick(ok);
      });
      req.on("error", () => finishTick(false));
      req.on("timeout", () => { req.destroy(); finishTick(false); });
    };
    tick();
  });
}

function configureAutoUpdater() {
  // electron-updater reads publish config from package.json's `build` block
  // (provider: github, owner/repo). Skipped in dev — there's no installed
  // app to update.
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on("error", (err) => {
    // Likely causes: no network, repo unreachable, or — on macOS — the
    // unsigned bundle can't be replaced. Log and move on; the user will
    // see a "BACKEND UNREACHABLE"-style state only if the actual app is
    // broken, not because we failed to check for an update.
    console.warn("[network-tools] autoUpdater error:", err?.message ?? err);
  });
  autoUpdater.on("update-available", (info) => {
    console.log("[network-tools] update available:", info?.version);
  });
  autoUpdater.on("update-downloaded", (info) => {
    console.log("[network-tools] update downloaded:", info?.version,
                "— will install on next quit");
  });

  // Check shortly after launch so the renderer + sidecar finish booting
  // first. Then re-check every 6h to catch long-running sessions.
  setTimeout(() => {
    autoUpdater.checkForUpdates().catch((err) => {
      console.warn("[network-tools] checkForUpdates rejected:",
                   err?.message ?? err);
    });
  }, 10_000);
  setInterval(() => {
    autoUpdater.checkForUpdates().catch(() => { /* logged via 'error' */ });
  }, 6 * 60 * 60 * 1000).unref?.();
}

// `engagementId` pins a window to one engagement (the engagement-as-workspace
// model). Multiple windows share the single backend sidecar — engagement
// isolation is per-request (X-MHP-Engagement-Id), not per-process. The sidecar
// is spawned once, on the first window, not per window.
let backendStarted = false;
async function createWindow(engagementId) {
  if (app.isPackaged && !backendStarted) {
    backendStarted = true;
    spawnBackend();
    // Don't block window creation on the health check — the PyInstaller
    // backend takes several seconds to boot, and the renderer already has
    // a backend-disconnected indicator that polls until it's ready.
    waitForHealth().then((ok) => {
      if (!ok) console.error("[network-tools] backend never became ready");
    });
    configureAutoUpdater();
  }

  // Title-bar treatment per OS:
  //   darwin → hiddenInset (native traffic lights overlay the sidebar header)
  //   win32  → hidden + titleBarOverlay (native min/max/close in top-right,
  //            our app paints the rest of the bar; height matches App.tsx h-7)
  //   linux  → default (keep the native title bar; many WMs need it)
  const titleBar = process.platform === "darwin"
    ? { titleBarStyle: "hiddenInset", trafficLightPosition: { x: 14, y: 11 } }
    : process.platform === "win32"
      ? {
          titleBarStyle: "hidden",
          titleBarOverlay: {
            color: "#0a0d12",       // matches backgroundColor / bg-base
            symbolColor: "#a0a0a0", // matches ink-muted
            height: 28,             // matches the h-7 strip in App.tsx
          },
        }
      : {};

  const win = new BrowserWindow({
    title: "s-ide",
    width:  1000,
    height: 720,
    // Min sizes kept small so the window tiles comfortably beside other apps
    // (third-screen / narrow split). The shell reflows: workspace shrinks first
    // (flex min-w-0), and the copilot + explorer rails collapse by hand.
    minWidth:  380,
    minHeight: 400,
    backgroundColor: "#0a0a0f",  // matches --bg-base in the new design system
    ...titleBar,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      nodeIntegration: false,
      contextIsolation: true,
      // OS-level sandbox the renderer. Preload only reads `process.platform`
      // (sandbox-safe — see preload.cjs). Without this a renderer compromise
      // (XSS, dependency CVE) inherits the main process's ability to spawn
      // child processes and read arbitrary files.
      sandbox: true,
    },
  });

  // Linux + Windows: the OS title bar shows the document title, not the app
  // name. Pin it so window switchers / taskbar entries read "s-ide".
  win.on("page-title-updated", (e) => e.preventDefault());
  win.setTitle("s-ide");

  // Hand any window.open(http(s)://...) call off to the OS default browser
  // instead of spawning a chromeless Electron BrowserWindow. The Labs "Open ↗"
  // button relies on this; without it, lab UIs render inside a blank Electron
  // popup with no devtools / address bar.
  win.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        shell.openExternal(url);
      }
    } catch (e) { /* malformed URL — drop it */ }
    return { action: "deny" };
  });
  // Same treatment for in-page navigation that would replace the renderer
  // (e.g. accidental <a> click without target=_blank): keep the SPA mounted
  // and bounce external URLs to the browser.
  win.webContents.on("will-navigate", (e, url) => {
    try {
      const parsed = new URL(url);
      const dev = isDevUnpackaged && parsed.host === "localhost:5173";
      if (!dev && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
        e.preventDefault();
        shell.openExternal(url);
      }
    } catch (e2) { /* malformed — let Electron handle */ }
  });

  // A per-window engagement id rides in as a query param; the renderer reads
  // it (see lib/windowEngagement.ts) and pins this window to that engagement.
  const query = engagementId ? { engagement: engagementId } : undefined;
  // Gate on packaging, not NODE_ENV: a packaged build always loads its bundled
  // files (and never opens devtools), even if launched with NODE_ENV=development.
  // Loading the Vite dev origin + auto-devtools are unpackaged-dev conveniences.
  if (isDevUnpackaged) {
    const url = "http://localhost:5173" + (engagementId ? `/?engagement=${encodeURIComponent(engagementId)}` : "");
    win.loadURL(url);
    if (process.env.NT_DEVTOOLS === "1") {
      win.webContents.openDevTools({ mode: "detach" });
    }
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"), query ? { query } : undefined);
  }
  return win;
}

// Renderer asks for a new engagement window (one app instance, one sidecar,
// N windows). This is the "loosened single-instance lock" — the lock still
// blocks a second *process*, but in-app we open as many windows as needed.
ipcMain.handle("open-engagement-window", (_e, engagementId) => {
  createWindow(engagementId || undefined);
});

// Native folder picker — for "add a codebase to scan".
ipcMain.handle("pick-directory", async () => {
  const r = await dialog.showOpenDialog({ properties: ["openDirectory"] });
  return r.canceled || !r.filePaths.length ? null : r.filePaths[0];
});

// Single-instance lock — second launch would otherwise spawn a second sidecar
// that fails to bind to 8765 and silently leaves the user with a broken
// window. Instead, focus the existing window and exit the new process.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    const wins = BrowserWindow.getAllWindows();
    if (wins.length) {
      const win = wins[0];
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
  app.whenReady().then(() => {
    installContentSecurityPolicy();
    createWindow();
  });
}

// Inject a strict CSP on every response served to the renderer. Locks
// allowed-fetch origins to the local sidecar + the renderer's own bundle,
// blocks object/embed entirely, blocks framing entirely, and disallows
// inline scripts. The renderer ships compiled bundles (no eval, no inline
// <script>) so 'self' is enough; 'unsafe-inline' on styles is required for
// Vite's HMR-style style injection in dev and Tailwind's atomic classes in
// prod (Tailwind output is plain CSS but utility CSS frameworks regularly
// re-inject; keep it loose only on styles, not scripts).
function installContentSecurityPolicy() {
  const csp = [
    "default-src 'self'",
    // The Electron renderer's only network peer is the local sidecar. The
    // dev server origin (http://localhost:5173) is also allowed for HMR.
    "connect-src 'self' http://127.0.0.1:8765 ws://127.0.0.1:8765 http://localhost:5173 ws://localhost:5173",
    // Prod ships compiled bundles with no inline <script>, so 'self' is enough.
    // In dev, Vite's @vitejs/plugin-react injects an inline module "preamble"
    // (React Fast Refresh bootstrap); a strict 'self' blocks it and React never
    // mounts ("can't detect preamble"). Allow inline scripts in dev ONLY.
    isDevUnpackaged ? "script-src 'self' 'unsafe-inline'" : "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = { ...details.responseHeaders };
    headers["Content-Security-Policy"] = [csp];
    callback({ responseHeaders: headers });
  });
}

app.on("before-quit", killBackend);
app.on("will-quit",   killBackend);

app.on("window-all-closed", () => {
  killBackend();
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
