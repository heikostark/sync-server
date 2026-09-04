<?php
require __DIR__ . '/../lib/Auth.php';

$config = require __DIR__ . '/../config.php';
$clientId = authenticate($config);

header('Content-Type: application/json');

// Das Salt ist NICHT geheim (Salts sind per Definition öffentlich). Es dient
// nur dazu, dass alle Clients, die denselben Datenbestand synchronisieren,
// aus ihrem (geheimen) Passwort denselben AES-Schlüssel ableiten, und dass
// vorab berechnete Rainbow-Table-Angriffe erschwert werden. Beim allerersten
// Zugriff wird es einmalig zufällig erzeugt und danach dauerhaft gespeichert.
$storageDir = $config['storage_dir'];
if (!is_dir($storageDir)) {
    mkdir($storageDir, 0770, true);
}
$saltFile = $storageDir . '/salt.bin';

$fp = fopen($saltFile, 'c+b');
if (!$fp) {
    http_response_code(500);
    echo json_encode(['error' => 'Salt-Datei konnte nicht geöffnet werden']);
    exit;
}

if (!flock($fp, LOCK_EX)) {
    fclose($fp);
    http_response_code(500);
    echo json_encode(['error' => 'Salt-Datei konnte nicht gesperrt werden']);
    exit;
}

$size = filesize($saltFile);
if ($size === 16) {
    $salt = fread($fp, 16);
} else {
    // Noch kein Salt vorhanden (oder beschädigt) -> neu erzeugen
    $salt = random_bytes(16);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, $salt);
    fflush($fp);
}

flock($fp, LOCK_UN);
fclose($fp);

echo json_encode(['salt' => bin2hex($salt)]);
