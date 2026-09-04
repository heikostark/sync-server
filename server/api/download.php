<?php

require __DIR__ . '/../lib/Storage.php';
require __DIR__ . '/../lib/Auth.php';

$config = require __DIR__ . '/../config.php';
$clientId = authenticate($config);

$relPathRaw = $_GET['relpath'] ?? '';
if ($relPathRaw === '') {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'relpath required']);
    exit;
}

try {
    $relPath = Storage::sanitizeRelPath($relPathRaw);
} catch (Throwable $e) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'invalid relpath']);
    exit;
}

$storage = new Storage($config['storage_dir']);
$size = $storage->fileSize($relPath);

if ($size === null) {
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'not found']);
    exit;
}

// Streaming-Auslieferung: readfile() liest die Datei blockweise von der
// Festplatte und schreibt sie direkt in den Ausgabepuffer, statt sie zuvor
// komplett als PHP-String zu materialisieren. Das hält den Speicherbedarf
// des Servers auch bei sehr großen Dateien konstant klein.
header('Content-Type: application/octet-stream');
header('Content-Length: ' . $size);
// Output-Buffering abschalten, damit readfile() wirklich blockweise streamt
// und nicht durch PHPs Ausgabepuffer erst komplett gesammelt wird.
while (ob_get_level() > 0) {
    ob_end_flush();
}
$storage->outputRaw($relPath);
