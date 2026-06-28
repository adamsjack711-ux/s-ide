<?php
// Hardcoded user table — no DB needed for this host. Concatenated SQL-style
// match so the same "OR 1=1" payloads work even without a real DB.
$users = [["admin","admin"],["dev","dev"],["guest","guest"]];
$msg = "";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $u = $_POST["username"] ?? "";
    $p = $_POST["password"] ?? "";
    // Deliberately weak match: anything that "looks like an OR true" wins.
    $combined = "$u:$p";
    if (preg_match("/'.*OR.*'.*'.*'/i", $combined) ||
        in_array([$u, $p], $users)) {
        $msg = "<b>Welcome.</b> (matched payload: " . htmlspecialchars($combined) . ")";
    } else {
        $msg = "Invalid credentials.";
    }
}
?>
<html><head><title>node-web login</title>
<style>body{font-family:monospace;background:#0d0d0d;color:#c8c8c8;max-width:640px;margin:40px auto;padding:0 20px}h1{color:#e74c3c}input{background:#1e1e1e;color:#ecf0f1;border:1px solid #333;padding:6px}.out{background:#1e1e1e;padding:12px;border-left:3px solid #e74c3c;margin-top:16px}</style>
</head><body>
<h1>Login</h1>
<form method="post">
  <p>User: <input name="username"></p>
  <p>Pass: <input name="password" type="text"></p>
  <p><button type="submit">Sign in</button></p>
</form>
<?php if ($msg) echo "<div class='out'>$msg</div>"; ?>
<p><a href="/">← back</a></p>
</body></html>
