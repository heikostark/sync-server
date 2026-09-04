<?php

require __DIR__ . '/../lib/Storage.php';
require __DIR__ . '/../lib/Auth.php';

$config = require __DIR__ . '/../config.php';
$clientId = authenticate($config);

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method not allowed']);
    exit;
}

$relPathRaw = $_POST['relpath'] ?? '';
$mtime = isset($_POST['mtime']) ? (int)$_POST['mtime'] : time();
$isArchive = isset($_POST['is_archive']) && $_POST['is_archive'] === '1';
// SHA-256 des UNVERSCHLÜSSELTEN Inhalts, vom Client berechnet – dient nur dem
// Client zum Erkennen von Änderungen. Der Server kann den Inhalt selbst
// nicht einsehen, da er nur den Chiffretext erhält.
$plainHash = $_POST['plain_hash'] ?? '';

if ($relPathRaw === '' || !isset($_FILES['file'])) {
    http_response_code(400);
    echo json_encode(['error' => 'relpath and file required']);
    exit;
}

try {
    $relPath = Storage::sanitizeRelPath($relPathRaw);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid relpath']);
    exit;
}

$file = $_FILES['file'];
if ($file['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['error' => 'upload error', 'code' => $file['error']]);
    exit;
}

if ($file['size'] > $config['max_upload_size']) {
    http_response_code(413);
    echo json_encode(['error' => 'file too large']);
    exit;
}

// Die von PHP automatisch angelegte Upload-Tmp-Datei (bereits auf der
// Festplatte, PHP puffert Uploads nie komplett im Skript-Speicher) wird
// direkt per Streaming-Kopie übernommen – der Chiffretext wird an keiner
// Stelle als Ganzes in eine PHP-Variable geladen. Das hält den
// Speicherbedarf des Servers auch bei sehr großen Dateien konstant klein.
$storage = new Storage($config['storage_dir']);
$storage->save($relPath, $file['tmp_name'], [
    'mtime' => $mtime,
    'is_archive' => $isArchive,
    'plain_hash' => $plainHash,
    'uploaded_by' => $clientId,
]);

echo json_encode(['status' => 'ok', 'relpath' => $relPath]);
