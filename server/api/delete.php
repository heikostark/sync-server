<?php

require __DIR__ . '/../lib/Storage.php';
require __DIR__ . '/../lib/Auth.php';

$config = require __DIR__ . '/../config.php';
$clientId = authenticate($config);

header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$relPathRaw = (is_array($input) ? ($input['relpath'] ?? '') : '') ?: ($_POST['relpath'] ?? '');

if ($relPathRaw === '') {
    http_response_code(400);
    echo json_encode(['error' => 'relpath required']);
    exit;
}

try {
    $relPath = Storage::sanitizeRelPath($relPathRaw);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid relpath']);
    exit;
}

$storage = new Storage($config['storage_dir']);
$storage->delete($relPath);

echo json_encode(['status' => 'ok']);
