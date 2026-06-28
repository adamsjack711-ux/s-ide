<!DOCTYPE html>
<html><head><title>node-web</title>
<style>body{font-family:monospace;background:#0d0d0d;color:#c8c8c8;max-width:640px;margin:40px auto;padding:0 20px}h1{color:#e74c3c}a{color:#3498db}code{background:#1e1e1e;padding:2px 6px}</style>
</head><body>
<h1>node-web · 10.20.0.10</h1>
<p>This is the web host of the vulhub-net lab. Reachable only from inside the lab bridge (10.20.0.0/24).</p>
<ul>
  <li><a href="/login.php">login.php</a> — SQLi (try <code>admin' OR '1'='1' --</code>)</li>
  <li><a href="/ping.php?host=node-files">ping.php</a> — command injection</li>
  <li><a href="/server-status">/server-status</a> — Apache mod_status (if enabled)</li>
</ul>
<p>Other hosts on this bridge: <code>node-files</code> (10.20.0.20), <code>node-db</code> (10.20.0.30).</p>
</body></html>
