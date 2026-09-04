<?php

require __DIR__ . '/../lib/Storage.php';
require __DIR__ . '/../lib/Auth.php';

$config = require __DIR__ . '/../config.php';
$clientId = authenticate($config);

$storage = new Storage($config['storage_dir']);
$items = $storage->listAll();

header('Content-Type: application/json');
echo json_encode(['items' => $items], JSON_UNESCAPED_SLASHES);
