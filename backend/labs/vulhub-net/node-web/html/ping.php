<?php
$host = $_GET["host"] ?? "node-files";
$out = $host !== "" ? shell_exec("ping -c 2 $host 2>&1") : "";
?>
<html><head><title>node-web ping</title>
<style>body{font-family:monospace;background:#0d0d0d;color:#c8c8c8;max-width:640px;margin:40px auto;padding:0 20px}h1{color:#e74c3c}input{background:#1e1e1e;color:#ecf0f1;border:1px solid #333;padding:6px}pre{background:#1e1e1e;padding:12px;border-left:3px solid #e74c3c;white-space:pre-wrap}</style>
</head><body>
<h1>Ping (cmdi target)</h1>
<form><input name="host" value="<?= htmlspecialchars($host) ?>"><button>Ping</button></form>
<?php if ($out): ?><pre><?= htmlspecialchars($out) ?></pre><?php endif; ?>
<p><a href="/">← back</a></p>
</body></html>
