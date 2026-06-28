<?php
// Classic SQL injection: user input concatenated into a query.
// Vulnerable on purpose. Try:   admin' OR '1'='1' --
$mysqli = @new mysqli("127.0.0.1", "root", "", "labusers");

if ($mysqli->connect_error) {
    // Best-effort: create the DB + table if first-boot init missed it.
    $bootstrap = @new mysqli("127.0.0.1", "root", "");
    if (!$bootstrap->connect_error) {
        $bootstrap->query("CREATE DATABASE IF NOT EXISTS labusers");
        $bootstrap->select_db("labusers");
        $bootstrap->query("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64), password VARCHAR(64))");
        $bootstrap->query("INSERT IGNORE INTO users (username, password) VALUES
            ('admin','admin'), ('user','user'), ('msfadmin','msfadmin')");
        $bootstrap->close();
        $mysqli = @new mysqli("127.0.0.1", "root", "", "labusers");
    }
}

$msg = "";
$rows = [];
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $u = $_POST["username"] ?? "";
    $p = $_POST["password"] ?? "";
    // VULNERABLE — concatenated SQL.
    $sql = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
    $res = $mysqli->query($sql);
    if ($res === false) {
        $msg = "SQL error: " . $mysqli->error . "<br><code>$sql</code>";
    } else {
        while ($r = $res->fetch_assoc()) $rows[] = $r;
        $msg = count($rows) > 0
            ? "<b>Login OK</b> — welcome " . htmlspecialchars($rows[0]["username"])
            : "Invalid credentials.<br><code>$sql</code>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>Login — SQLi practice</title>
<style>
  body { font-family: monospace; background: #0d0d0d; color: #c8c8c8;
         max-width: 720px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #e74c3c; }
  input { background: #1e1e1e; color: #ecf0f1; border: 1px solid #333;
          padding: 6px 8px; font-family: monospace; min-width: 240px; }
  button { background: #2ecc71; color: #0d0d0d; border: 0;
           padding: 6px 14px; font-weight: bold; cursor: pointer; }
  code { background: #1e1e1e; padding: 2px 6px; color: #ecf0f1; }
  .out { background: #1e1e1e; padding: 12px; margin-top: 16px; border-left: 3px solid #e74c3c; }
</style>
</head>
<body>
<h1>Login — SQL Injection target</h1>
<p>This form runs <code>SELECT id, username FROM users WHERE username='$u' AND password='$p'</code>
with raw concatenation. Try one of:</p>
<ul>
  <li><code>admin' OR '1'='1</code> — log in as admin without a password</li>
  <li><code>' OR 1=1 #</code> — dump every user (the <code>#</code> comments the rest)</li>
  <li><code>admin' OR '1'='1' -- </code> — note the trailing space (MariaDB needs it after <code>--</code>)</li>
</ul>
<form method="post">
  <p>Username: <input name="username" value="<?= htmlspecialchars($_POST["username"] ?? "") ?>"></p>
  <p>Password: <input name="password" type="text" value="<?= htmlspecialchars($_POST["password"] ?? "") ?>"></p>
  <p><button type="submit">Sign in</button></p>
</form>
<?php if ($msg): ?>
<div class="out"><?= $msg ?>
<?php if (count($rows) > 1): ?>
<br>All matched rows:
<ul><?php foreach ($rows as $r): ?><li><?= htmlspecialchars(json_encode($r)) ?></li><?php endforeach; ?></ul>
<?php endif; ?>
</div>
<?php endif; ?>
<p><a href="/">← back</a></p>
</body>
</html>
