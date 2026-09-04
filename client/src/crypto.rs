use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::KeyInit;
use aes_gcm::{Aes256Gcm, Key};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Klartext-Chunkgröße für die Stream-Verschlüsselung. Bestimmt den
/// maximalen Speicherbedarf pro Datei (unabhängig von deren Gesamtgröße):
/// Es liegt nie mehr als etwa ein Chunk (plus etwas Overhead) gleichzeitig
/// im Arbeitsspeicher – auch bei mehrere Gigabyte großen Dateien.
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

/// Größe des GCM-Auth-Tags, das jedem verschlüsselten Chunk angehängt wird.
const TAG_LEN: usize = 16;

/// Länge des zufälligen Nonce-Präfixes pro Datei. Die STREAM-BE32-Konstruk-
/// tion verwendet die letzten 5 der 12 AES-GCM-Nonce-Bytes intern für einen
/// 32-Bit-Chunk-Zähler plus ein "letzter Chunk"-Flag (Schutz gegen
/// Trunkierungs-Angriffe); es bleiben 12 - 5 = 7 Byte für das Präfix.
const NONCE_PREFIX_LEN: usize = 7;

/// Kapselt die lokale Verschlüsselung. Das Passwort verlässt den Client
/// niemals und wird nur genutzt, um lokal einen 256-Bit-Schlüssel abzuleiten.
///
/// Die Schlüsselableitung erfolgt mit Argon2id (speicher- und rechenhartem
/// Passwort-KDF) unter Verwendung eines Salts. Das Salt ist nicht geheim,
/// muss aber für alle Clients, die denselben Datenbestand synchronisieren,
/// identisch sein – es wird daher vom Server verwaltet (siehe
/// `ServerClient::get_salt`) und über `/api/salt.php` bezogen.
///
/// Ver-/Entschlüsselung arbeitet ausschließlich dateibasiert und
/// chunkweise (AES-256-GCM im STREAM-Modus, siehe `encrypt_file_streaming`/
/// `decrypt_file_streaming`), damit auch sehr große Dateien nie komplett im
/// Arbeitsspeicher liegen müssen.
#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
}

/// Minimale Salt-Länge, die Argon2 akzeptiert bzw. die wir verlangen.
pub const MIN_SALT_LEN: usize = 8;

impl Crypto {
    /// Leitet den AES-256-Schlüssel per Argon2id aus Passwort + Salt ab.
    pub fn new(password: &str, salt: &[u8]) -> Result<Self> {
        if salt.len() < MIN_SALT_LEN {
            return Err(anyhow!(
                "Salt zu kurz ({} Bytes, mindestens {} nötig)",
                salt.len(),
                MIN_SALT_LEN
            ));
        }

        let mut key_bytes = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow!("Argon2-Schlüsselableitung fehlgeschlagen: {e}"))?;

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Ok(Crypto { cipher })
    }

    /// Verschlüsselt `plaintext_path` chunkweise und schreibt das Ergebnis
    /// nach `ciphertext_path`. Format der Ausgabedatei:
    /// `Nonce-Präfix (7 Byte) || Chunk_1 || Chunk_2 || … || Chunk_n`, wobei
    /// jeder Chunk aus bis zu `STREAM_CHUNK_SIZE` Byte Klartext plus einem
    /// 16-Byte-Auth-Tag besteht. Es wird zu keinem Zeitpunkt die gesamte
    /// Datei im Speicher gehalten – nur jeweils ein Chunk.
    pub fn encrypt_file_streaming(&self, plaintext_path: &Path, ciphertext_path: &Path) -> Result<()> {
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        let mut encryptor = EncryptorBE32::from_aead(self.cipher.clone(), &nonce_prefix.into());

        let mut reader = BufReader::new(
            File::open(plaintext_path)
                .map_err(|e| anyhow!("Konnte {} nicht lesen: {e}", plaintext_path.display()))?,
        );
        let mut writer = BufWriter::new(
            File::create(ciphertext_path)
                .map_err(|e| anyhow!("Konnte {} nicht anlegen: {e}", ciphertext_path.display()))?,
        );

        writer.write_all(&nonce_prefix)?;

        // Ein-Chunk-Lookahead: erst wenn feststeht, dass NACH dem aktuellen
        // Chunk keine weiteren Daten mehr folgen, wird er als "letzter
        // Chunk" verschlüsselt (nötig für die Anti-Trunkierungs-Prüfung der
        // STREAM-Konstruktion beim Entschlüsseln).
        let mut current = read_chunk(&mut reader, STREAM_CHUNK_SIZE)?;
        loop {
            let next = read_chunk(&mut reader, STREAM_CHUNK_SIZE)?;
            if next.is_empty() {
                let ct = encryptor
                    .encrypt_last(current.as_slice())
                    .map_err(|e| anyhow!("Stream-Verschlüsselung fehlgeschlagen: {e}"))?;
                writer.write_all(&ct)?;
                break;
            }
            let ct = encryptor
                .encrypt_next(current.as_slice())
                .map_err(|e| anyhow!("Stream-Verschlüsselung fehlgeschlagen: {e}"))?;
            writer.write_all(&ct)?;
            current = next;
        }

        writer.flush()?;
        Ok(())
    }

    /// Entschlüsselt eine mit `encrypt_file_streaming` erzeugte Datei
    /// chunkweise zurück nach `plaintext_path`. Bricht mit einem klaren
    /// Fehler ab, wenn das Passwort falsch ist oder die Daten beschädigt/
    /// manipuliert wurden (jeder Chunk ist einzeln authentifiziert).
    pub fn decrypt_file_streaming(&self, ciphertext_path: &Path, plaintext_path: &Path) -> Result<()> {
        let mut reader = BufReader::new(
            File::open(ciphertext_path)
                .map_err(|e| anyhow!("Konnte {} nicht lesen: {e}", ciphertext_path.display()))?,
        );

        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        reader
            .read_exact(&mut nonce_prefix)
            .map_err(|e| anyhow!("Ungültiges verschlüsseltes Format (Nonce-Präfix fehlt): {e}"))?;

        let mut decryptor = DecryptorBE32::from_aead(self.cipher.clone(), &nonce_prefix.into());

        let mut writer = BufWriter::new(
            File::create(plaintext_path)
                .map_err(|e| anyhow!("Konnte {} nicht anlegen: {e}", plaintext_path.display()))?,
        );

        let cipher_chunk_size = STREAM_CHUNK_SIZE + TAG_LEN;
        let mut current = read_chunk(&mut reader, cipher_chunk_size)?;
        if current.is_empty() {
            return Err(anyhow!(
                "Verschlüsselte Datei ist leer oder beschädigt (kein Chunk vorhanden)"
            ));
        }

        loop {
            let next = read_chunk(&mut reader, cipher_chunk_size)?;
            if next.is_empty() {
                let pt = decryptor.decrypt_last(current.as_slice()).map_err(|_| {
                    anyhow!("Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte/manipulierte Daten?)")
                })?;
                writer.write_all(&pt)?;
                break;
            }
            let pt = decryptor.decrypt_next(current.as_slice()).map_err(|_| {
                anyhow!("Entschlüsselung fehlgeschlagen (falsches Passwort oder beschädigte/manipulierte Daten?)")
            })?;
            writer.write_all(&pt)?;
            current = next;
        }

        writer.flush()?;
        Ok(())
    }
}

/// Liest bis zu `size` Byte aus `reader` (kann weniger sein, am Dateiende
/// auch 0). Wird für das Chunk-für-Chunk-Lesen beim Ver-/Entschlüsseln
/// verwendet, damit nie mehr als ein Chunk gleichzeitig im Speicher liegt.
fn read_chunk<R: Read>(reader: &mut R, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut total = 0;
    while total < size {
        let n = reader.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    buf.truncate(total);
    Ok(buf)
}

/// Hasht eine Datei chunkweise (SHA-256), ohne sie komplett in den
/// Arbeitsspeicher zu laden – Grundlage für die Änderungserkennung beim
/// Sync auch bei großen Dateien.
pub fn hash_file_streaming(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|e| anyhow!("Konnte {} nicht lesen: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Hasht einen kurzen In-Memory-Bytestring (z. B. für interne Zwecke wie
/// stabile temporäre Dateinamen) – NICHT für Dateiinhalte, dafür
/// `hash_file_streaming` verwenden.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
