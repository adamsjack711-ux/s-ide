<?php
// LFI / path traversal: $page is appended to include() with no validation.
// Try ?page=/etc/passwd  or  ?page=../../../etc/passwd
$page = $_GET["page"] ?? "home";
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>Include — LFI practice</title>
<style>
  body { font-family: monospace; background: #0d0d0d; color: #c8c8c8;
         max-width: 720px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #e74c3c; }
  pre, .out { background: #1e1e1e; padding: 12px; border-left: 3px solid #e74c3c;
              white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Include — LFI / Path Traversal target</h1>
<p>This page does <code>include($page)</code> with no validation.
Try <code>?page=/etc/passwd</code> or <code>?page=../../../etc/passwd</code>.</p>
<p>Current page: <code><?= htmlspecialchars($page) ?></code></p>
<div class="out"><?php
    // VULNERABLE — direct include of user-supplied path.
    @include($page);
?></div>
<p><a href="?page=home">home</a> · <a href="?page=about">about</a> · <a href="/">← back</a></p>
</body>
</html>
