// Throwaway screenshot harness: show the IDE in a real on-screen window at a
// known position, then grab that screen region with macOS `screencapture`
// (reliable compositing, unlike webContents.capturePage on CSS bg layers).
const { app, BrowserWindow, nativeTheme } = require("electron");
const { execFile } = require("child_process");

const OUT = process.env.SHOT_OUT || "/tmp/side-shot.png";
const URL = process.env.SHOT_URL || "http://localhost:5173";
const X = 0, Y = 28, W = 1440, H = 880;

app.whenReady().then(async () => {
  nativeTheme.themeSource = "dark"; // app theme is "system"; resolve it dark
  const win = new BrowserWindow({
    show: true,
    alwaysOnTop: true,
    backgroundColor: "#0a0a0f",
  });
  win.setMenuBarVisibility(false);
  await win.loadURL(URL);
  win.setBounds({ x: X, y: Y, width: W, height: H });
  win.setAlwaysOnTop(true, "screen-saver");
  win.moveTop();
  win.focus();
  app.focus({ steal: true });
  await new Promise((r) => setTimeout(r, 4000)); // let dockview + fetches settle

  const b = win.getBounds();
  execFile("screencapture", ["-x", "-o", `-R${b.x},${b.y},${b.width},${b.height}`, OUT], (err) => {
    if (err) console.error("screencapture failed:", err.message);
    else console.log("captured", OUT);
    app.quit();
  });
});
