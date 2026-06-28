<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Metasploitable Lab</title>
<style>
  body { font-family: monospace; background: #0d0d0d; color: #c8c8c8;
         max-width: 720px; margin: 40px auto; padding: 0 20px; line-height: 1.45; }
  h1   { color: #e74c3c; border-bottom: 1px solid #333; padding-bottom: 8px; }
  h2   { color: #f1c40f; margin-top: 28px; }
  a    { color: #3498db; }
  a:hover { color: #5dade2; }
  ul   { padding-left: 20px; }
  code { background: #1e1e1e; padding: 2px 6px; border-radius: 3px; color: #ecf0f1; }
  .warn { color: #e74c3c; font-weight: bold; }
</style>
</head>
<body>
<h1>Metasploitable Lab</h1>
<p class="warn">⚠ This host is deliberately vulnerable. Do not expose it to any network you don't fully control.</p>

<p>This page is part of the HackingPal training lab. Each link below
is a separate vulnerable form intended for practice with the corresponding
HackingPal tool page.</p>

<h2>Practice targets</h2>
<ul>
  <li><a href="/login.php">login.php</a> — classic SQL injection
    (try <code>admin' OR '1'='1</code>)</li>
  <li><a href="/ping.php?host=127.0.0.1">ping.php</a> — OS command injection
    (try <code>?host=127.0.0.1;id</code>)</li>
  <li><a href="/include.php?page=home">include.php</a> — LFI / path traversal
    (try <code>?page=/etc/passwd</code>)</li>
  <li><a href="/upload.php">upload.php</a> — unrestricted file upload</li>
  <li><a href="/phpinfo.php">phpinfo.php</a> — full server info disclosure</li>
</ul>

<h2>Default credentials</h2>
<ul>
  <li>Web app: <code>admin / admin</code> &nbsp;or&nbsp; <code>user / user</code></li>
  <li>SSH / Telnet: <code>msfadmin / msfadmin</code> &nbsp;or&nbsp; <code>root / toor</code></li>
  <li>MySQL: <code>root</code> (no password)</li>
  <li>FTP: anonymous</li>
</ul>

<h2>Notable open ports</h2>
<ul>
  <li>21 FTP (vsftpd) · 22 SSH · 23 telnet · 25 SMTP · 80 HTTP</li>
  <li>139 / 445 SMB · 1524 ingreslock backdoor</li>
  <li>3306 MySQL · 3632 distccd · 6200 vsftpd backdoor</li>
</ul>
</body>
</html>
