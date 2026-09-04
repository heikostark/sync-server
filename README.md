# Encrypted File Sync (PHP Server + Rust Client)

This project implements a simple encrypted file sync system with two components:

- `server/` – a PHP server that accepts, stores and serves encrypted files/folders from multiple clients. Metadata is stored in SQLite.
- `client/` – a Rust command-line client that synchronizes a local folder with the server. Features include deletions, `.syncignore`, parallel transfers, optional continuous operation (watch mode), network robustness (automatic retries, lockfile, livelock protection), and chunked streaming of very large files (no full-file buffering in RAM).

## How it works / Security model

- All encryption is performed on the client side only (AES-256-GCM). The password is never sent to the server.
- Keys are derived from the password using Argon2id (a memory- and CPU-hard password KDF) with a salt.
- The salt is not secret, but must be the same for all clients that synchronize the same dataset. The server generates a random salt once, stores it, and exposes it via `/api/salt.php`. The server never learns the password itself.
- The server stores and serves only encrypted blobs. It never sees plaintext or the password.
- If a folder contains multiple files directly (not nested in subfolders), the client packs those files into a ZIP archive, then encrypts and uploads that archive as a single unit. If a folder contains only a single file, that file is uploaded individually.
- Each client authenticates to the server with its own API key (this is for server authentication only — not the encryption key). Different clients that share the same encryption password can synchronize the same dataset.

Diagram:

Client A --(AES-256-GCM encrypted)--> PHP Server (stores ciphertext + metadata in SQLite) --(encrypted)--> Client B
          \------------------ shared password (never transmitted) ------------------/

## 1. Server setup

1. Open `server/config.php` and assign an API key for each client:

```php
'api_keys' => [
    'client1' => 'your-secret-key-1',
    'client2' => 'your-secret-key-2',
],
```

2. Ensure the PHP `pdo_sqlite` extension is enabled (metadata is stored in SQLite). On Debian/Ubuntu: `apt install php-sqlite3`.

3. Start the server. For local testing you can use the built-in PHP server:

```bash
cd server
php -S 0.0.0.0:8080 -t .
```

For production use Apache or Nginx + PHP-FPM behind a TLS-terminating reverse proxy (see "Known limitations"). Important: `server/storage/` must NOT be directly accessible over HTTP. The included `.htaccess` in `storage/` blocks this for Apache; for Nginx add a rule like `location /storage/ { deny all; }`.

4. The server provides the following endpoints. All requests must include the header `X-API-Key: <key>`:

| Endpoint            | Method | Purpose                                          |
|---------------------|--------|--------------------------------------------------|
| `/api/list.php`     | GET    | List all entries (including tombstones)          |
| `/api/upload.php`   | POST   | Upload an encrypted blob                         |
| `/api/download.php` | GET    | Download an encrypted blob                       |
| `/api/delete.php`   | POST   | Report a deletion (creates a tombstone)          |
| `/api/salt.php`     | GET    | Retrieve / create the public Argon2id salt       |

### Metadata storage (SQLite)

Instead of one JSON file per entry, metadata is stored in `server/storage/meta.sqlite3` (a `files` table). This scales far better than thousands of single metadata files. The encrypted ciphertext blobs themselves are stored individually under `server/storage/data/`.

### Deletions (Tombstones)

When a client deletes a file/folder locally, it informs the server via `/api/delete.php`. The server removes only the encrypted blob but retains a metadata entry with `deleted=1` (a "tombstone"). Other clients will see this tombstone on next sync and delete the file locally as well — preventing an accidental re-creation during sync.

If a file previously deleted is uploaded again with the same path, the upload automatically clears the tombstone and the entry is revived.

Tombstones are not purged automatically. For maintenance there is `Storage::purgeOldTombstones($maxAgeSeconds)`, which can be invoked by a cron job to permanently remove old tombstones (e.g. older than 90 days).

## 2. Build the client

Requirements: Rust/Cargo (tested with Rust 1.75+).

```bash
cd client
cargo build --release
```

The compiled binary will be available at `target/release/sync-client`.

## 3. Using the client

Basic one-shot sync:

```bash
./target/release/sync-client \
  --server http://localhost:8080 \
  --api-key your-secret-key-1 \
  --dir /path/to/sync-folder
```

The client securely prompts for the encryption password (no terminal echo).

CLI options:

- `--server`   Base URL of the PHP server
- `--api-key`  API key for this client (see `config.php`)
- `--dir`      Local folder to synchronize

Each sync run prints a short summary of actions:

```
Uploaded: vacation/__archive__.zip
Downloaded: report.docx
Reported deletion to server: old_draft.txt
Summary: 1 uploaded, 1 downloaded, 1 deleted, 42 unchanged.
```

This also applies to `--dry-run` (where actions are described in conditional form) and to each run inside watch mode.

#### Passing the password securely

All clients that share the same dataset must use the same encryption password. The client supports three ways to supply the password (checked in this order):

1. `--password "..."` — works but insecure: other local users can see the password via process listings (`ps aux`) and it may end up in shell history. The client warns when this is used.
2. Environment variable `SYNC_PASSWORD` — not visible in process listings, suitable for scripts/cron/CI:

```bash
export SYNC_PASSWORD="YourSecretSyncPassword"
./target/release/sync-client --server http://localhost:8080 --api-key ... --dir ...
```

3. Interactive prompt (default if neither 1 nor 2 is provided) — the safest option for manual terminal usage: the password is not echo'ed and not stored anywhere. This mode requires a terminal (won't work in a cron job without a TTY — use `SYNC_PASSWORD` there).

A single run synchronizes in both directions:

1. Local new/changed files are encrypted and uploaded.
2. New/changed entries on the server are downloaded, decrypted, and if they are archives, automatically unpacked.
3. Local deletions are reported to the server (tombstone); deletions reported by the server are applied locally.
4. On true conflicts (both sides changed since last sync), the version with the newer modification time wins.
5. Uploads/downloads/deletions are performed in parallel (by default up to 8 concurrent transfers).

### Watch mode (continuous operation)

Example:

```bash
export SYNC_PASSWORD="YourSecretSyncPassword"
./target/release/sync-client \
  --server http://localhost:8080 \
  --api-key your-secret-key-1 \
  --dir /path/to/sync-folder \
  --watch
```

In watch mode `SYNC_PASSWORD` is the practical choice (interactive prompt would block the daemon on startup).

While running in watch mode the client:

- Watches `--dir` for filesystem changes and syncs automatically (debounced via `--debounce-ms`, default 1500 ms to avoid many rapid syncs when copying many files).
- Also syncs at least every `--interval` seconds (default 30) even without local events — to pick up changes made by other clients on the server.

If you prefer not to run a continuous client, you can run the client periodically via cron or a scheduled task.

### Network robustness & concurrency

- Automatic retries for transient errors: requests that fail due to connectivity issues, timeouts or server 5xx errors are retried with exponential backoff (`--retries`, default 3 attempts; `--retry-delay-ms`, default base 500 ms, doubling each attempt: 500 ms, 1000 ms, 2000 ms, ...). Permanent client errors (4xx, e.g. wrong API key) are not retried.

Example:

```
Warning: Upload of vacation/__archive__.zip failed (attempt 1/3), retrying in 0.5s...
Warning: Upload of vacation/__archive__.zip failed (attempt 2/3), retrying in 1.0s...
Uploaded: vacation/__archive__.zip
```

- Lockfile against concurrent sync runs: the client creates `.sync.lock` inside the sync folder containing its process ID and holds it for the duration of the run. If another process tries to sync the same folder, it aborts with a clear error to avoid corrupting the local cache (`.sync_cache.json`).

Example error:

```
Error: Another sync process (PID 12345) appears to be running for this folder (lockfile: /path/to/sync-folder/.sync.lock).
If this is not the case (e.g. after a crash), delete the file manually and try again.
```

If a client crashes or is hard-killed (`kill -9`) and cannot remove the lockfile, the next client detects this: on Linux it checks whether the recorded PID still exists (`/proc/<pid>`); if not, the lock is considered stale and is claimed automatically. On systems without `/proc`, a time threshold is used (locks older than 6 hours are assumed orphaned).

- Livelock protection in watch mode: a long-running continuous write operation (for example a backup process constantly creating files) could keep re-triggering the debounce window and postpone syncing indefinitely. The client records the time of the first unsynced event and forces a sync after `--max-debounce-wait-ms` (default 60000 ms = 60 s), even if new events keep coming:

```
Ongoing activity in sync folder detected — syncing anyway (max debounce 60000 ms reached).
```

### Streaming large files

Neither client nor server ever load whole files into RAM. This applies throughout the file lifecycle:

- Hashing (change detection): files are read blockwise (64 KiB) from disk for hashing.
- ZIP creation for multi-file folders: each file is streamed to disk while building the ZIP (temporary files under `.sync_tmp/...`), never assembled fully in memory.
- Encryption/decryption: AES-256-GCM in streaming mode (`aes-gcm` crate, `EncryptorBE32`/`DecryptorBE32`) processes files in 1 MiB chunks; each chunk is individually authenticated. The encrypted file format is:

```
7-byte nonce prefix || Chunk_1 || Chunk_2 || … || last_chunk
```

Each chunk contains up to 1 MiB of plaintext plus a 16-byte auth tag.

- Transfer: uploads read the encrypted file from disk in blocks into the HTTP body (`multipart::Part::file`, no in-memory buffering); downloads write the server response blockwise to disk (`Response::copy_to`).
- Server-side PHP copies the uploaded file with `copy()` and hashes with `hash_file()` (both streaming), instead of reading the entire content into a PHP string; downloads use `readfile()`.

In tests a 500 MB file kept both client (upload and download) and PHP server memory usage in the low double-digit megabyte range, independent of file size.

Important: PHP's `upload_max_filesize` and `post_max_size` INI limits still constrain request sizes (many distributions default to 2 MB / 8 MB). For large files increase these values and `config.php`'s `max_upload_size`. Example for a temporary server process:

```bash
php -d upload_max_filesize=2G -d post_max_size=2G -S 0.0.0.0:8080 -t server
```

Or change them permanently in `php.ini` or your PHP-FPM configuration.

### Safety net against mass deletions (delete threshold) & `--dry-run`

Since deletions are propagated automatically across clients, a mistaken invocation (wrong/empty `--dir`, unmounted network volume, etc.) could otherwise cause mass deletion on all clients. To avoid accidental catastrophic deletions, the client aborts by default if more than 30% of previously known entries would be deleted:

```
$ ./target/release/sync-client --server ... --api-key ... --dir /path
Error: Aborted: 214 of 214 previously known entries (100%) would be deleted — this exceeds the delete threshold of 30%.
This often indicates a wrong or empty --dir. Inspect the planned sync with --dry-run, or force it with --force.
```

Options:

- `--dry-run` — show what the sync would do (each planned action and a summary) without making any changes: no uploads, no downloads, no deletions, not even writing the local cache. Recommended before the first sync in a new/moved folder or after changing `.syncignore`.
- `--force` — perform the sync even if the delete threshold would be exceeded (useful for intentional mass cleanups). The client still prints a warning about how many would be deleted.
- `--delete-threshold <percent>` — override the default threshold (default 30). `--delete-threshold 100` effectively disables the safeguard; `--delete-threshold 0` aborts on any deletion.

The threshold is computed relative to the entries known from the client's own last sync (local `.sync_cache.json`), not absolute numbers. For a brand-new sync folder (empty cache) the threshold does not apply.

### `.syncignore`

Place a `.syncignore` file in the sync folder to exclude files/folders from synchronization (similar to `.gitignore`, intentionally simpler):

```
# Comments start with #
*.tmp
*.log
node_modules/
.cache/
notes/secret.txt
```

- One pattern per line (glob syntax, e.g. `*.tmp`).
- A trailing `/` marks a whole folder (including contents).
- Patterns are matched against both the relative path and the basename.
- `.git` and the internal `.sync_cache.json` are always implicitly excluded.

Caution: If a file that was previously synced is later added to `.syncignore`, the client treats it as a local deletion on the next sync and reports it to the server (creates a tombstone) — it will then be removed from other clients as well. This behavior is deliberate: "stop syncing this file" is interpreted as "remove it from the shared dataset".

### Example layout

```
sync-folder/
├── .syncignore
├── report.docx          -> transferred as a single file
└── vacation-photos/
    ├── photo1.jpg
    ├── photo2.jpg
    └── photo3.jpg       -> folder with multiple files is stored on the server
                          as "vacation-photos/__archive__.zip" (encrypted)
```

## Known limitations (intentionally simple)

- If a folder flips between "one file" and "multiple files", the server will create a new entry and mark the old path as deleted (tombstone). This is automated but results in two separate historical entries in the DB.
- There is no content-versioning for true edit conflicts: if two clients independently modify the same file between syncs, the version with the newer mtime wins (depends on clients' system clocks) — the other version is lost. The lockfile protects only against concurrent sync runs of the same client/folder, not against content conflicts between different clients.
- Transport TLS is not part of this project — use a TLS-terminating reverse proxy in production.
- Metadata (filenames, paths, sizes, timestamps) are not encrypted on the server — only file contents are encrypted.
- While files are chunk-encrypted and streamed, changes cause a full re-transfer: there is no chunk-level resume or binary delta sync. A retry on an interrupted transfer repeats the entire file transfer, not just missing chunks.
