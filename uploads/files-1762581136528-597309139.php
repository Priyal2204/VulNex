<?php
// Simple PHP file upload with minimal checks (insecure by design for detection)
// Save as vulnerable_file_upload.php and place in isolated PHP environment.
$target_dir = "uploads/";
if (!is_dir($target_dir)) mkdir($target_dir);
$target_file = $target_dir . basename($_FILES["file_to_upload"]["name"]);

// Vulnerable: no strict MIME-type checks, no extension whitelist, no filename sanitization
if (move_uploaded_file($_FILES["file_to_upload"]["tmp_name"], $target_file)) {
    echo "Uploaded: " . basename($_FILES["file_to_upload"]["name"]);
} else {
    echo "Upload failed.";
}
?>
<!--
Form:
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file_to_upload">
  <button type="submit">Upload</button>
</form>
-->
