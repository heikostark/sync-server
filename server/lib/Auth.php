<?php

/**
 * Prüft den API-Schlüssel aus dem Header "X-API-Key" (oder Query-Parameter
 * ?api_key=) gegen die konfigurierten Schlüssel. Beendet die Ausführung mit
 * HTTP 401, falls kein gültiger Schlüssel vorhanden ist.
 *
 * @return string Die Client-ID des authentifizierten Clients.
 */
function authenticate(array $config): string
{
    $key = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? '');

    foreach ($config['api_keys'] as $clientId => $validKey) {
        if ($key !== '' && hash_equals((string)$validKey, (string)$key)) {
            return (string)$clientId;
        }
    }

    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'unauthorized']);
    exit;
}
