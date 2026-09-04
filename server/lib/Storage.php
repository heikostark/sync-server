<?php

/**
 * Verwaltet die Ablage der (bereits clientseitig verschlüsselten) Dateien
 * sowie deren Metadaten auf dem Server. Der Server selbst besitzt keinen
 * Schlüssel und kann die Inhalte nicht entschlüsseln.
 *
 * Metadaten liegen in einer SQLite-Datenbank (skaliert deutlich besser als
 * eine JSON-Datei pro Eintrag, sobald viele Dateien/Ordner synchronisiert
 * werden). Die verschlüsselten Chiffretext-Blobs selbst liegen weiterhin
 * als einzelne Dateien im Dateisystem (kein Sinn, große Blobs in die DB zu
 * packen).
 *
 * Löschungen werden als "Tombstones" abgebildet: Der verschlüsselte Blob
 * wird entfernt (spart Platz), der Metadaten-Eintrag bleibt aber mit
 * deleted=1 bestehen, damit alle Clients die Löschung beim nächsten Sync
 * mitbekommen und die Datei auch lokal entfernen.
 */
class Storage
{
    private string $dataDir;
    private PDO $db;

    public function __construct(string $baseDir)
    {
        $this->dataDir = $baseDir . '/data';
        if (!is_dir($this->dataDir)) {
            mkdir($this->dataDir, 0770, true);
        }
        if (!is_dir($baseDir)) {
            mkdir($baseDir, 0770, true);
        }

        $dbFile = $baseDir . '/meta.sqlite3';
        $isNew = !file_exists($dbFile);

        $this->db = new PDO('sqlite:' . $dbFile);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->db->exec('PRAGMA journal_mode = WAL;');
        $this->db->exec('PRAGMA busy_timeout = 5000;');

        if ($isNew) {
            $this->migrate();
        } else {
            $this->migrate(); // idempotent, legt fehlende Tabellen ggf. nach
        }
    }

    private function migrate(): void
    {
        $this->db->exec(<<<SQL
            CREATE TABLE IF NOT EXISTS files (
                relpath      TEXT PRIMARY KEY,
                mtime        INTEGER NOT NULL DEFAULT 0,
                is_archive   INTEGER NOT NULL DEFAULT 0,
                plain_hash   TEXT NOT NULL DEFAULT '',
                uploaded_by  TEXT NOT NULL DEFAULT '',
                size         INTEGER NOT NULL DEFAULT 0,
                content_hash TEXT NOT NULL DEFAULT '',
                updated_at   INTEGER NOT NULL DEFAULT 0,
                deleted      INTEGER NOT NULL DEFAULT 0,
                deleted_at   INTEGER NOT NULL DEFAULT 0
            );
        SQL);
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_files_updated ON files(updated_at);');
    }

    /**
     * Normalisiert und validiert einen relativen Pfad, um Path-Traversal
     * (z. B. "../../etc/passwd") zu verhindern.
     */
    public static function sanitizeRelPath(string $relPath): string
    {
        $relPath = str_replace('\\', '/', $relPath);
        $parts = [];
        foreach (explode('/', $relPath) as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                continue;
            }
            $parts[] = $part;
        }
        if (empty($parts)) {
            throw new InvalidArgumentException('invalid relpath');
        }
        return implode('/', $parts);
    }

    private function keyFor(string $relPath): string
    {
        return hash('sha256', $relPath);
    }

    public function dataPath(string $relPath): string
    {
        return $this->dataDir . '/' . $this->keyFor($relPath) . '.bin';
    }

    /**
     * Speichert den verschlüsselten Inhalt (Chiffretext) plus Metadaten.
     * $sourcePath ist eine bereits auf der Festplatte liegende Datei (z. B.
     * die von PHP automatisch angelegte Upload-Tmp-Datei) – der Inhalt wird
     * NIE komplett in den PHP-Arbeitsspeicher geladen, sondern per
     * Streaming-Kopie (`copy()`) übernommen und per `hash_file()`
     * (ebenfalls streaming) geprüft. Das hält den Speicherbedarf auch bei
     * sehr großen Dateien konstant klein. Der Inhalt wird dabei NIE
     * entschlüsselt oder interpretiert.
     * Eine eventuell vorhandene Tombstone-Markierung wird dabei aufgehoben
     * (das Wiederhochladen einer zuvor gelöschten Datei "belebt" sie neu).
     */
    public function save(string $relPath, string $sourcePath, array $meta): void
    {
        $dataFile = $this->dataPath($relPath);

        // Streaming-Kopie (PHP kopiert intern in Blöcken, lädt die Datei
        // nicht als Ganzes in den Speicher) statt file_get_contents()+fwrite().
        if (!copy($sourcePath, $dataFile)) {
            throw new RuntimeException('cannot write data file');
        }

        $size = filesize($dataFile);
        // hash_file() liest ebenfalls blockweise von der Festplatte statt
        // den kompletten Inhalt als String zu materialisieren.
        $contentHash = hash_file('sha256', $dataFile);

        $stmt = $this->db->prepare(<<<SQL
            INSERT INTO files
                (relpath, mtime, is_archive, plain_hash, uploaded_by, size, content_hash, updated_at, deleted, deleted_at)
            VALUES
                (:relpath, :mtime, :is_archive, :plain_hash, :uploaded_by, :size, :content_hash, :updated_at, 0, 0)
            ON CONFLICT(relpath) DO UPDATE SET
                mtime = excluded.mtime,
                is_archive = excluded.is_archive,
                plain_hash = excluded.plain_hash,
                uploaded_by = excluded.uploaded_by,
                size = excluded.size,
                content_hash = excluded.content_hash,
                updated_at = excluded.updated_at,
                deleted = 0,
                deleted_at = 0
        SQL);

        $stmt->execute([
            ':relpath' => $relPath,
            ':mtime' => (int)($meta['mtime'] ?? time()),
            ':is_archive' => !empty($meta['is_archive']) ? 1 : 0,
            ':plain_hash' => (string)($meta['plain_hash'] ?? ''),
            ':uploaded_by' => (string)($meta['uploaded_by'] ?? ''),
            ':size' => $size,
            ':content_hash' => $contentHash,
            ':updated_at' => time(),
        ]);
    }

    /**
     * Prüft, ob eine Einheit existiert, ohne ihren Inhalt zu laden.
     */
    public function exists(string $relPath): bool
    {
        return file_exists($this->dataPath($relPath));
    }

    /**
     * Gibt den Chiffretext direkt per readfile() an die Ausgabe aus – liest
     * dabei blockweise von der Festplatte statt die Datei komplett in den
     * PHP-Arbeitsspeicher zu laden (wichtig für große Dateien). Gibt false
     * zurück, wenn der Eintrag nicht existiert.
     */
    public function outputRaw(string $relPath): bool
    {
        $dataFile = $this->dataPath($relPath);
        if (!file_exists($dataFile)) {
            return false;
        }
        readfile($dataFile);
        return true;
    }

    public function fileSize(string $relPath): ?int
    {
        $dataFile = $this->dataPath($relPath);
        if (!file_exists($dataFile)) {
            return null;
        }
        return filesize($dataFile);
    }

    public function loadMeta(string $relPath): ?array
    {
        $stmt = $this->db->prepare('SELECT * FROM files WHERE relpath = :relpath');
        $stmt->execute([':relpath' => $relPath]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->rowToMeta($row) : null;
    }

    /**
     * Markiert einen Eintrag als gelöscht (Tombstone) statt ihn komplett zu
     * entfernen. Der verschlüsselte Blob wird gelöscht, der Metadaten-
     * Eintrag bleibt (mit deleted=1) bestehen, damit andere Clients die
     * Löschung mitbekommen und lokal nachvollziehen können.
     */
    public function delete(string $relPath): bool
    {
        $dataFile = $this->dataPath($relPath);
        if (file_exists($dataFile)) {
            @unlink($dataFile);
        }

        $stmt = $this->db->prepare(<<<SQL
            INSERT INTO files (relpath, deleted, deleted_at, updated_at)
            VALUES (:relpath, 1, :now, :now)
            ON CONFLICT(relpath) DO UPDATE SET
                deleted = 1,
                deleted_at = excluded.deleted_at,
                updated_at = excluded.updated_at,
                plain_hash = '',
                content_hash = '',
                size = 0
        SQL);
        return $stmt->execute([':relpath' => $relPath, ':now' => time()]);
    }

    /**
     * Entfernt Tombstones, die älter als $maxAgeSeconds sind, endgültig aus
     * der Datenbank (reine Aufräum-/Wartungsfunktion, z. B. per Cronjob).
     */
    public function purgeOldTombstones(int $maxAgeSeconds): int
    {
        $stmt = $this->db->prepare('DELETE FROM files WHERE deleted = 1 AND deleted_at < :cutoff');
        $stmt->execute([':cutoff' => time() - $maxAgeSeconds]);
        return $stmt->rowCount();
    }

    /**
     * Liefert die Metadaten aller gespeicherten Einheiten (Dateien/Archive),
     * einschließlich Tombstones (deleted=1), damit Clients Löschungen
     * mitbekommen.
     */
    public function listAll(): array
    {
        $stmt = $this->db->query('SELECT * FROM files ORDER BY relpath');
        $result = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $result[] = $this->rowToMeta($row);
        }
        return $result;
    }

    private function rowToMeta(array $row): array
    {
        return [
            'relpath' => $row['relpath'],
            'mtime' => (int)$row['mtime'],
            'is_archive' => (bool)$row['is_archive'],
            'plain_hash' => $row['plain_hash'],
            'uploaded_by' => $row['uploaded_by'],
            'size' => (int)$row['size'],
            'content_hash' => $row['content_hash'],
            'updated_at' => (int)$row['updated_at'],
            'deleted' => (bool)$row['deleted'],
            'deleted_at' => (int)$row['deleted_at'],
        ];
    }
}
