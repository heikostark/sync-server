use anyhow::{anyhow, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Name der Lockdatei im Sync-Ordner. Wird von `IgnoreList` immer implizit
/// von der Synchronisation ausgeschlossen (wie `.sync_cache.json`).
pub const LOCK_FILE_NAME: &str = ".sync.lock";

/// Verhindert, dass zwei Sync-Prozesse (z. B. ein manueller Aufruf und ein
/// laufender `--watch`-Prozess, oder zwei parallel gestartete Cronjobs)
/// gleichzeitig denselben Ordner bearbeiten und sich dabei den lokalen
/// Cache (`.sync_cache.json`) gegenseitig überschreiben.
///
/// Wird als PID-Datei realisiert (kein plattformspezifisches `flock`
/// nötig): Beim Erwerb wird `.sync.lock` mit der eigenen Prozess-ID exklusiv
/// angelegt (`create_new`). Existiert die Datei bereits, wird geprüft, ob
/// der darin vermerkte Prozess noch läuft (unter Linux über `/proc/<pid>`,
/// sonst anhand des Dateialters) – ein verwaister Lock nach einem Absturz
/// wird so automatisch erkannt und übernommen. Beim Beenden (regulär, via
/// `Drop`) wird die Datei wieder entfernt.
pub struct SyncLock {
    path: PathBuf,
}

impl SyncLock {
    /// Versucht, den Lock für `root` zu erwerben. Schlägt fehl, wenn ein
    /// anderer, noch aktiver Prozess ihn bereits hält.
    pub fn acquire(root: &Path) -> Result<Self> {
        let path = root.join(LOCK_FILE_NAME);

        // Zwei Versuche: falls der erste einen verwaisten Lock findet und
        // entfernt, greift der zweite Versuch danach.
        for _ in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    writeln!(f, "{}", std::process::id())?;
                    return Ok(SyncLock { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Self::is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    let pid = fs::read_to_string(&path).unwrap_or_default();
                    return Err(anyhow!(
                        "Ein anderer Sync-Prozess (PID {}) scheint bereits für diesen Ordner \
                         zu laufen (Lockdatei: {}).\n\
                         Falls das nicht stimmt (z. B. nach einem Absturz oder harten Kill), \
                         löschen Sie die Datei manuell und versuchen Sie es erneut.",
                        pid.trim(),
                        path.display()
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }

        Err(anyhow!(
            "Konnte den Sync-Lock für {} nicht erwerben.",
            path.display()
        ))
    }

    /// Prüft heuristisch, ob eine vorhandene Lockdatei von einem Prozess
    /// stammt, der nicht mehr existiert (verwaister Lock, z. B. nach einem
    /// Absturz oder Kill -9).
    fn is_stale(path: &Path) -> bool {
        if let Ok(pid_str) = fs::read_to_string(path) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                let proc_dir = Path::new("/proc");
                if proc_dir.is_dir() {
                    // Linux: eindeutig feststellbar, ob der Prozess noch lebt.
                    return !proc_dir.join(pid.to_string()).exists();
                }
            }
        }

        // Fallback für Plattformen ohne /proc oder unlesbare PID: nach einer
        // großzügigen Alters-Schwelle als verwaist betrachten. Ein normaler
        // Sync-Lauf dauert Sekunden bis Minuten, selbst ein Watch-Prozess
        // erneuert implizit nichts an dieser Datei – ein sehr alter Lock ist
        // daher fast immer verwaist.
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = modified.elapsed() {
                    return age > Duration::from_secs(6 * 60 * 60);
                }
            }
        }
        false
    }
}

impl Drop for SyncLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
