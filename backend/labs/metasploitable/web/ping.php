<?php
// OS command injection: $host is fed straight into shell_exec via shell concatenation.
// Try ?host=127.0.0.1;id  or  ?host=127.0.0.1|whoami
$host = $_GET["host"] ?? "";
$out  = "";
if ($host !== "") {
    // VULNERABLE — no escaping.
    $out = shell_exec("ping -c 2 $host 2>&1");
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>Ping — Command injection practice</title>
<style>
  body { font-family: monospace; background: #0d0d0d; color: #c8c8c8;
         max-width: 720px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #e74c3c; }
  input { background: #1e1e1e; color: #ecf0f1; border: 1px solid #333;
          padding: 6px 8px; font-family: monospace; min-width: 320px; }
  button { background: #2ecc71; color: #0d0d0d; border: 0; padding: 6px 14px;
           font-weight: bold; cursor: pointer; }
  pre { background: #1e1e1e; padding: 12px; border-left: 3px solid #e74c3c;
        white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Ping — OS Command Injection target</h1>
<p>This form runs <code>shell_exec("ping -c 2 $host 2&gt;&amp;1")</code> with no escaping.
Try <code>?host=127.0.0.1;id</code> or <code>127.0.0.1|whoami</code>.</p>
<form method="get">
  Host: <input name="host" value="<?= htmlspecialchars($host) ?>" placeholder="127.0.0.1">
  <button type="submit">Ping</button>
</form>
<?php if ($out !== ""): ?>
<pre><?= htmlspecialchars($out) ?></pre>
<?php endif; ?>
<p><a href="/">← back</a></p>
</body>
</html>
