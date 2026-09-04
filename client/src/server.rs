use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::thread::sleep;
use std::time::Duration;

/// Metadaten, wie sie der Server über /api/list.php ausliefert.
/// Der Server kennt nur diese Metadaten und den Chiffretext, niemals den
/// Klartext-Inhalt der Dateien.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteMeta {
    pub relpath: String,
    pub size: u64,
    pub content_hash: String,
    pub updated_at: i64,
    pub mtime: i64,
    pub is_archive: bool,
    #[serde(default)]
    pub plain_hash: String,
    #[serde(default)]
    pub uploaded_by: String,
    /// Tombstone-Markierung: true, wenn diese Einheit auf einem anderen
    /// Client gelöscht wurde. Der Chiffretext existiert dann nicht mehr,
    /// der Metadaten-Eintrag bleibt aber bestehen, damit alle Clients die
    /// Löschung mitbekommen.
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub deleted_at: i64,
}

/// Unterscheidet innerhalb der Retry-Logik zwischen Fehlern, bei denen ein
/// erneuter Versuch sinnvoll ist (Netzwerk, Timeout, 5xx-Serverfehler), und
/// dauerhaften Fehlern (4xx, z. B. falscher API-Key oder ungültiger Pfad),
/// bei denen ein Retry nichts ändern würde.
enum AttemptError {
    Permanent(anyhow::Error),
    Transient(anyhow::Error),
}

impl From<reqwest::Error> for AttemptError {
    fn from(e: reqwest::Error) -> Self {
        // Verbindungsfehler/Timeouts sind praktisch immer transient.
        AttemptError::Transient(anyhow!("Netzwerkfehler: {e}"))
    }
}

#[derive(Clone)]
pub struct ServerClient {
    base_url: String,
    api_key: String,
    http: reqwest::blocking::Client,
    /// Maximale Anzahl an Versuchen (inkl. dem ersten) bei transienten
    /// Netzwerk-/Serverfehlern.
    max_attempts: u32,
    /// Basis-Wartezeit für den exponentiellen Backoff zwischen Versuchen.
    retry_base_delay: Duration,
}

impl ServerClient {
    pub fn new(base_url: &str, api_key: &str, max_attempts: u32, retry_base_delay_ms: u64) -> Self {
        ServerClient {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            // Eigenes Timeout, damit ein hängender Server nicht ewig blockiert
            // und die Retry-Logik überhaupt zum Tragen kommt. Bewusst
            // grosszügig bemessen, da Uploads/Downloads großer Dateien lange
            // dauern können.
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(600))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
            max_attempts: max_attempts.max(1),
            retry_base_delay: Duration::from_millis(retry_base_delay_ms.max(1)),
        }
    }

    /// Führt eine Operation mit Wiederholungen bei **transienten** Fehlern
    /// aus (Verbindungsfehler, Timeouts, 5xx-Serverfehler, abgebrochene
    /// Streams). Bei **dauerhaften** Fehlern (4xx – z. B. falscher API-Key,
    /// ungültiger Pfad) wird sofort ohne Wiederholung abgebrochen. Zwischen
    /// den Versuchen wird exponentiell länger gewartet (Backoff).
    ///
    /// Generisch über den Rückgabetyp, damit nicht nur die reine HTTP-
    /// Antwort, sondern die komplette Operation (inkl. z. B. dem
    /// Streaming des Response-Bodys in eine Datei) im Fehlerfall komplett
    /// wiederholt wird – ein Abbruch mitten im Datei-Stream soll denselben
    /// Retry-Mechanismus auslösen wie ein Verbindungsfehler.
    fn with_retry<T, F>(&self, operation_name: &str, mut attempt: F) -> Result<T>
    where
        F: FnMut() -> std::result::Result<T, AttemptError>,
    {
        let mut last_err: Option<anyhow::Error> = None;

        for attempt_num in 1..=self.max_attempts {
            match attempt() {
                Ok(v) => return Ok(v),
                Err(AttemptError::Permanent(e)) => {
                    return Err(anyhow!("{operation_name} fehlgeschlagen: {e}"));
                }
                Err(AttemptError::Transient(e)) => {
                    last_err = Some(anyhow!("{operation_name} fehlgeschlagen: {e}"));
                }
            }

            if attempt_num < self.max_attempts {
                let delay = self.retry_base_delay * 2u32.pow(attempt_num - 1);
                eprintln!(
                    "Warnung: {operation_name} fehlgeschlagen (Versuch {attempt_num}/{}), \
                     erneuter Versuch in {:.1}s...",
                    self.max_attempts,
                    delay.as_secs_f32()
                );
                sleep(delay);
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("{operation_name} fehlgeschlagen")))
    }

    /// Prüft den HTTP-Status einer Antwort und klassifiziert einen
    /// Fehlerstatus als dauerhaft (4xx) oder transient (5xx/sonstige).
    fn check_status(
        resp: reqwest::blocking::Response,
    ) -> std::result::Result<reqwest::blocking::Response, AttemptError> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else if status.is_client_error() {
            Err(AttemptError::Permanent(anyhow!("{status}")))
        } else {
            Err(AttemptError::Transient(anyhow!("{status}")))
        }
    }

    /// Holt die Liste aller auf dem Server vorhandenen Einheiten (Dateien/Archive).
    pub fn list(&self) -> Result<HashMap<String, RemoteMeta>> {
        let url = format!("{}/api/list.php", self.base_url);
        let parsed: ListResp = self.with_retry("Abrufen der Liste", || {
            let resp = self.http.get(&url).header("X-API-Key", &self.api_key).send()?;
            let resp = Self::check_status(resp)?;
            resp.json::<ListResp>()
                .map_err(|e| AttemptError::Transient(anyhow!("ungültige Antwort: {e}")))
        })?;

        Ok(parsed
            .items
            .into_iter()
            .map(|m| (m.relpath.clone(), m))
            .collect())
    }

    /// Verschlüsselte Datei (`ciphertext_path`, bereits fertig chunk-
    /// verschlüsselt auf der Festplatte) zu `relpath` hochladen. Der Inhalt
    /// wird dabei per `multipart::Part::file` direkt von der Festplatte
    /// gestreamt – reqwest lädt die Datei nicht komplett in den
    /// Arbeitsspeicher, sondern liest sie blockweise während des Sendens.
    /// Das hält den Speicherbedarf auch bei sehr großen Dateien konstant
    /// klein.
    pub fn upload_from_file(
        &self,
        relpath: &str,
        mtime: i64,
        is_archive: bool,
        plain_hash: &str,
        ciphertext_path: &Path,
    ) -> Result<()> {
        let url = format!("{}/api/upload.php", self.base_url);
        self.with_retry(&format!("Upload von {relpath}"), || {
            let part = reqwest::blocking::multipart::Part::file(ciphertext_path)
                .map_err(|e| {
                    AttemptError::Transient(anyhow!("Konnte Datei nicht zum Senden öffnen: {e}"))
                })?
                .file_name("blob.bin");
            let form = reqwest::blocking::multipart::Form::new()
                .text("relpath", relpath.to_string())
                .text("mtime", mtime.to_string())
                .text("is_archive", if is_archive { "1" } else { "0" })
                .text("plain_hash", plain_hash.to_string())
                .part("file", part);

            let resp = self
                .http
                .post(&url)
                .header("X-API-Key", &self.api_key)
                .multipart(form)
                .send()?;
            Self::check_status(resp)?;
            Ok(())
        })
    }

    /// Holt das serverseitig verwaltete, öffentliche KDF-Salt (wird beim
    /// ersten Aufruf serverseitig einmalig zufällig erzeugt und danach
    /// dauerhaft wiederverwendet, damit alle Clients denselben Schlüssel
    /// aus ihrem Passwort ableiten können). Das Salt ist kein Geheimnis.
    pub fn get_salt(&self) -> Result<Vec<u8>> {
        let url = format!("{}/api/salt.php", self.base_url);
        let parsed: SaltResp = self.with_retry("Abrufen des Salts", || {
            let resp = self.http.get(&url).header("X-API-Key", &self.api_key).send()?;
            let resp = Self::check_status(resp)?;
            resp.json::<SaltResp>()
                .map_err(|e| AttemptError::Transient(anyhow!("ungültige Antwort: {e}")))
        })?;

        hex::decode(&parsed.salt)
            .map_err(|e| anyhow!("Ungültiges Salt-Format vom Server: {e}"))
    }

    /// Meldet dem Server, dass eine Einheit lokal gelöscht wurde. Der Server
    /// legt daraufhin einen Tombstone an (siehe `Storage::delete` in PHP),
    /// damit andere Clients die Löschung beim nächsten Sync übernehmen.
    pub fn delete(&self, relpath: &str) -> Result<()> {
        let url = format!("{}/api/delete.php", self.base_url);
        self.with_retry(&format!("Löschen von {relpath}"), || {
            let resp = self
                .http
                .post(&url)
                .header("X-API-Key", &self.api_key)
                .json(&serde_json::json!({ "relpath": relpath }))
                .send()?;
            Self::check_status(resp)?;
            Ok(())
        })
    }

    /// Lädt den verschlüsselten Blob zu `relpath` herunter und schreibt ihn
    /// direkt nach `dest` – der Response-Body wird dabei per
    /// `Response::copy_to` blockweise auf die Festplatte gestreamt, statt
    /// zuvor komplett im Arbeitsspeicher gesammelt zu werden. Schlägt der
    /// Stream mitten in der Übertragung fehl, wird die komplette Operation
    /// (inkl. erneutem Öffnen der Zieldatei) wiederholt.
    pub fn download_to_file(&self, relpath: &str, dest: &Path) -> Result<()> {
        let url = format!("{}/api/download.php", self.base_url);
        self.with_retry(&format!("Download von {relpath}"), || {
            let resp = self
                .http
                .get(&url)
                .header("X-API-Key", &self.api_key)
                .query(&[("relpath", relpath)])
                .send()?;
            let mut resp = Self::check_status(resp)?;

            let mut file = File::create(dest).map_err(|e| {
                AttemptError::Transient(anyhow!("Konnte Zieldatei nicht anlegen: {e}"))
            })?;
            resp.copy_to(&mut file).map_err(|e| {
                AttemptError::Transient(anyhow!("Download-Stream abgebrochen: {e}"))
            })?;
            Ok(())
        })
    }
}

#[derive(Deserialize)]
struct ListResp {
    items: Vec<RemoteMeta>,
}

#[derive(Deserialize)]
struct SaltResp {
    salt: String,
}
