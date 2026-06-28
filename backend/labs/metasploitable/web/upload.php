<?php
// Unrestricted file upload — any extension, including .php.
// Uploaded files land in /uploads/ which is served by Apache.
$msg = "";
if ($_SERVER["REQUEST_METHOD"] === "POST" && !empty($_FILES["f"]["name"])) {
    $name = basename($_FILES["f"]["name"]);
    $dest = __DIR__ . "/uploads/" . $name;
    if (move_uploaded_file($_FILES["f"]["tmp_name"], $dest)) {
        $msg = "Saved to <a href='/uploads/" . htmlspecialchars($name) . "'>/uploads/"
             . htmlspecialchars($name) . "</a> &mdash; if it's a .php file, Apache will execute it.";
    } else {
        $msg = "Upload failed.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>Upload — unrestricted</title>
<style>
  body { font-family: monospace; background: #0d0d0d; color: #c8c8c8;
         max-width: 720px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #e74c3c; }
  .out { background: #1e1e1e; padding: 12px; border-left: 3px solid #e74c3c; }
</style>
</head>
<body>
<h1>Unrestricted File Upload</h1>
<p>Any file. No extension check. Upload a PHP webshell and visit it at <code>/uploads/&lt;name&gt;</code>.</p>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="f">
  <button type="submit">Upload</button>
</form>
<?php if ($msg): ?>
<div class="out"><?= $msg ?></div>
<?php endif; ?>
<p><a href="/">← back</a></p>
</body>
</html>
