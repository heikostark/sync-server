<?php
/**
 * Server-Konfiguration.
 *
 * WICHTIG: Die hier hinterlegten API-Schlüssel dienen NUR der Authentifizierung
 * mehrerer Clients gegenüber dem Server (wer darf synchronisieren). Sie haben
 * NICHTS mit der Verschlüsselung der Dateiinhalte zu tun! Die Inhalte werden
 * ausschließlich clientseitig mit einem lokalen Passwort ver- und entschlüsselt,
 * das dem Server niemals bekannt ist. Der Server sieht und speichert nur
 * Chiffretext (verschlüsselte Bytes).
 */
return [
    // clientId => geheimer API-Schlüssel (bitte für den produktiven Einsatz ändern!)
    'api_keys' => [
        'client1' => 'change-me-client1-secret',
        'client2' => 'change-me-client2-secret',
    ],

    // Verzeichnis, in dem die verschlüsselten Daten + Metadaten liegen
    'storage_dir' => __DIR__ . '/storage',

    // maximale Upload-Größe in Bytes
    'max_upload_size' => 5 * 1024 * 1024 * 1024, // 5 GB
];
