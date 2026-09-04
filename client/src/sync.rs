use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::crypto::{hash_file_streaming, sha256_hex, Crypto};
use crate::ignore::IgnoreList;
use crate::server::{RemoteMeta, ServerClient};

/// Marker-Dateiname für Ordner, deren mehrere Dateien als ein ZIP-Archiv
/// behandelt werden.
const ARCHIVE_MARKER: &str = "__archive__.zip";

/// Name des Scratch-Verzeichnisses im Sync-Ordner für temporäre
/// Streaming-Zwischendateien (Chiffretext vor dem Upload/nach dem Download,
/// im Speicher NICHT vollständig gehaltene ZIP-Archive für Mehrdatei-
/// Ordner). Wird von `IgnoreList` immer implizit von der Synchronisation
/// ausgeschlossen.
pub const TMP_DIR_NAME: &str = ".sync_tmp";

/// Anzahl paralleler Uploads/Downloads/Löschungen.
const PARALLELISM: usize = 8;

/// Merkt sich pro synchronisierter Einheit (Datei oder Archiv) den zuletzt
/// bekannten Zustand, um bei der nächsten Synchronisation lokale und
/// serverseitige Änderungen (inkl. Löschungen) unterscheiden zu können.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub plain_hash: String,
    pub mtime: i64,
}

pub type Cache = HashMap<String, CacheEntry>;

/// Eine "Synchronisationseinheit": entweder eine einzelne Datei oder,
/// falls ein Ordner mehrere Dateien direkt enthält, deren gemeinsames
/// ZIP-Archiv.
struct LocalUnit {
    relpath: String,
    is_archive: bool,
    files: Vec<PathBuf>,
    mtime: i64,
}

/// Ein bereits eingelesener/gebauter lokaler Stand: `plaintext_path` zeigt
/// entweder direkt auf die echte Nutzerdatei (Einzeldatei-Fall – dort wird
/// NIE eine Kopie angelegt) oder auf ein im `.sync_tmp`-Scratch-Verzeichnis
/// gebautes ZIP-Archiv (Mehrdatei-Ordner). In beiden Fällen wird der Inhalt
/// nie komplett in den Arbeitsspeicher geladen, sondern nur chunkweise
/// gelesen (Hashing, Verschlüsselung).
struct LocalEntry {
    unit: LocalUnit,
    plaintext_path: PathBuf,
    /// true, wenn `plaintext_path` eine von uns angelegte Temp-Datei ist,
    /// die nach der Nutzung wieder gelöscht werden muss.
    is_temp: bool,
    hash: String,
}

fn cache_path(root: &Path) -> PathBuf {
    root.join(".sync_cache.json")
}

fn load_cache(root: &Path) -> Cache {
    match fs::read_to_string(cache_path(root)) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => Cache::new(),
    }
}

fn save_cache(root: &Path, cache: &Cache) -> Result<()> {
    fs::write(cache_path(root), serde_json::to_string_pretty(cache)?)?;
    Ok(())
}

fn to_rel_slash(root: &Path, p: &Path) -> String {
    let rel = p.strip_prefix(root).unwrap_or(p);
    rel.to_string_lossy().replace('\\', "/")
}

fn file_mtime_secs(p: &Path) -> Result<i64> {
    let m = fs::metadata(p)?.modified()?;
    Ok(m.duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64)
}

/// Legt das Scratch-Verzeichnis für Streaming-Zwischendateien an und räumt
/// eventuell von einem abgestürzten/hart beendeten vorherigen Lauf übrig
/// gebliebene Dateien darin auf (best effort).
fn prepare_tmp_dir(root: &Path) -> Result<PathBuf> {
    let tmp_dir = root.join(TMP_DIR_NAME);
    fs::create_dir_all(&tmp_dir)?;
    if let Ok(entries) = fs::read_dir(&tmp_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.is_file() {
                let _ = fs::remove_file(p);
            }
        }
    }
    Ok(tmp_dir)
}

/// Eindeutiger, stabiler Temp-Dateiname für einen relativen Pfad und einen
/// Zweck (z. B. "zip", "enc", "dl.enc", "dl.plain").
fn tmp_file_for(tmp_dir: &Path, relpath: &str, suffix: &str) -> PathBuf {
    tmp_dir.join(format!("{}.{suffix}", sha256_hex(relpath.as_bytes())))
}

/// Durchsucht den lokalen Baum und bildet pro Ordner eine Synchronisations-
/// einheit: ein Ordner mit >1 Datei wird zu einem ZIP-Archiv, ein Ordner mit
/// genau 1 Datei bleibt eine einzelne Datei. Leere Ordner werden ignoriert.
/// Durch `.syncignore` ausgeschlossene Dateien/Ordner (inkl. des internen
/// `.sync_tmp`-Verzeichnisses) werden komplett übersprungen.
fn scan_local_units(root: &Path, ignore: &IgnoreList) -> Result<Vec<LocalUnit>> {
    let mut units = Vec::new();

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        if e.path() == root {
            return true;
        }
        let relpath = to_rel_slash(root, e.path());
        !ignore.is_ignored(&relpath)
    });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_dir() {
            continue;
        }
        let dir_path = entry.path();

        let mut direct_files: Vec<PathBuf> = fs::read_dir(dir_path)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter(|p| !ignore.is_ignored(&to_rel_slash(root, p)))
            .collect();
        direct_files.sort();

        if direct_files.is_empty() {
            continue;
        }

        let dir_rel = to_rel_slash(root, dir_path);

        let mut newest_mtime = 0i64;
        for f in &direct_files {
            newest_mtime = newest_mtime.max(file_mtime_secs(f)?);
        }

        if direct_files.len() > 1 {
            let relpath = if dir_rel.is_empty() {
                ARCHIVE_MARKER.to_string()
            } else {
                format!("{dir_rel}/{ARCHIVE_MARKER}")
            };
            units.push(LocalUnit {
                relpath,
                is_archive: true,
                files: direct_files,
                mtime: newest_mtime,
            });
        } else {
            let f = direct_files[0].clone();
            let relpath = to_rel_slash(root, &f);
            let mtime = file_mtime_secs(&f)?;
            units.push(LocalUnit {
                relpath,
                is_archive: false,
                files: vec![f],
                mtime,
            });
        }
    }

    Ok(units)
}

/// Ermittelt die Klartext-Quelle einer Einheit, ohne ihren Inhalt in den
/// Arbeitsspeicher zu laden:
/// - Einzeldatei: der Pfad der echten Datei selbst (keine Kopie nötig).
/// - Mehrdatei-Ordner: wird direkt auf die Festplatte (`.sync_tmp`) gezippt
///   – jede enthaltene Datei wird dabei per `io::copy` in Blöcken in das
///   ZIP geschrieben, nie komplett eingelesen.
fn build_plaintext_source(tmp_dir: &Path, unit: &LocalUnit) -> Result<(PathBuf, bool)> {
    if !unit.is_archive {
        return Ok((unit.files[0].clone(), false));
    }

    let tmp_path = tmp_file_for(tmp_dir, &unit.relpath, "zip");
    {
        let out_file = fs::File::create(&tmp_path)?;
        let mut zip = zip::ZipWriter::new(BufWriter::new(out_file));
        let options = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for f in &unit.files {
            let name = f
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            zip.start_file(name, options)?;
            let mut src = fs::File::open(f)?;
            std::io::copy(&mut src, &mut zip)?;
        }
        zip.finish()?;
    }
    Ok((tmp_path, true))
}

/// Entpackt ein (bereits entschlüsseltes) ZIP-Archiv von der Festplatte in
/// den Zielordner. Liest dabei jede enthaltene Datei blockweise
/// (`io::copy`), ohne den kompletten Archivinhalt im Speicher zu halten.
fn extract_zip_to_dir(zip_path: &Path, dir_path: &Path) -> Result<()> {
    fs::create_dir_all(dir_path)?;
    let file = fs::File::open(zip_path)?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let outpath = dir_path.join(entry.name());
        if let Some(parent) = outpath.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut outfile = fs::File::create(&outpath)?;
        std::io::copy(&mut entry, &mut outfile)?;
    }
    Ok(())
}

fn archive_dir_path(root: &Path, relpath: &str) -> PathBuf {
    let dir_rel = relpath
        .strip_suffix(ARCHIVE_MARKER)
        .unwrap_or(relpath)
        .trim_end_matches('/');
    if dir_rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(dir_rel)
    }
}

/// Verschiebt eine (temporäre) Datei an ihren endgültigen Zielort. Nutzt
/// `rename` (praktisch kostenlos, kein erneutes Kopieren des Inhalts),
/// fällt aber auf Kopieren+Löschen zurück, falls Quelle und Ziel auf
/// unterschiedlichen Dateisystemen liegen (rename schlägt dann fehl).
fn move_into_place(tmp_path: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::rename(tmp_path, dest).is_err() {
        fs::copy(tmp_path, dest)?;
        fs::remove_file(tmp_path)?;
    }
    Ok(())
}

/// Entfernt eine lokale Einheit wieder (Gegenstück zu einer vom Server
/// gemeldeten Löschung): bei einem Archiv werden die zugehörigen Dateien
/// gelöscht (nur die direkten Dateien des Ordners, keine Unterordner), bei
/// einer einzelnen Datei einfach die Datei selbst.
fn remove_local_unit(root: &Path, relpath: &str, is_archive: bool) -> Result<()> {
    if is_archive {
        let dir_path = archive_dir_path(root, relpath);
        if dir_path.is_dir() {
            for entry in fs::read_dir(&dir_path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_file() {
                    let _ = fs::remove_file(p);
                }
            }
            // Leeren Ordner ebenfalls aufräumen (falls nichts mehr drin ist).
            let _ = fs::remove_dir(&dir_path);
        }
    } else {
        let path = root.join(relpath);
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Was für eine gegebene Sync-Einheit als Nächstes zu tun ist. Wird zuerst
/// (schnell, sequentiell, ohne Netzwerk-I/O) für alle Einheiten geplant und
/// anschließend parallel ausgeführt.
enum PlannedAction {
    Upload,
    Download,
    /// Server hat die Datei gelöscht (Tombstone), lokal unverändert -> lokal
    /// ebenfalls löschen.
    AcceptRemoteDelete { is_archive: bool },
    /// Lokal existiert die Datei nicht mehr, war aber zuvor synchronisiert
    /// -> Löschung an den Server melden.
    PropagateLocalDelete,
    /// Nur einen veralteten Cache-Eintrag entfernen, ohne I/O.
    ClearCacheOnly,
}

struct PlannedItem {
    relpath: String,
    action: PlannedAction,
}

/// Kategorie einer ausgeführten Aktion, für die Abschluss-Zusammenfassung.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    Upload,
    Download,
    Delete,
    CacheCleanup,
}

/// Optionen für einen Sync-Lauf: Sicherheitsnetz gegen versehentliche
/// Massenlöschungen (z. B. durch ein falsches/leeres `--dir`) sowie ein
/// Vorschau-Modus, der nichts verändert.
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// Zeigt nur an, was passieren würde, führt aber keine Aktion aus und
    /// schreibt auch den lokalen Cache nicht.
    pub dry_run: bool,
    /// Erzwingt den Sync auch dann, wenn die Löschschwelle überschritten
    /// wird (siehe `delete_threshold`).
    pub force: bool,
    /// Anteil (0.0–1.0) der zuvor bekannten Einheiten, ab dem eine geplante
    /// Löschwelle als verdächtig gilt. Wird er überschritten, bricht
    /// `run_sync` ohne `force` mit einem Fehler ab, statt zu löschen.
    pub delete_threshold: f64,
}

impl Default for SyncOptions {
    fn default() -> Self {
        SyncOptions {
            dry_run: false,
            force: false,
            delete_threshold: 0.3,
        }
    }
}

/// Ergebnis der (parallelen) Ausführung einer geplanten Aktion.
struct ExecResult {
    relpath: String,
    /// `Some(entry)` aktualisiert den Cache, `None` entfernt den Eintrag.
    cache_update: Option<CacheEntry>,
    message: String,
    kind: ActionKind,
}

/// Räumt beim Verlassen der Funktion (auch bei frühzeitigem `return`/
/// `bail!`) alle temporären ZIP-Dateien auf, die für Mehrdatei-Ordner in
/// `local_map` gebaut wurden.
struct TempZipGuard<'a> {
    local_map: &'a HashMap<String, LocalEntry>,
}

impl Drop for TempZipGuard<'_> {
    fn drop(&mut self) {
        for entry in self.local_map.values() {
            if entry.is_temp {
                let _ = fs::remove_file(&entry.plaintext_path);
            }
        }
    }
}

/// Führt eine vollständige Zwei-Wege-Synchronisation zwischen dem lokalen
/// Ordner `root` und dem Server durch – inklusive Löschungen in beide
/// Richtungen.
///
/// Ablauf:
/// 1. Lokalen Baum scannen (unter Beachtung von `.syncignore`) und
///    Sync-Einheiten (Dateien/Archive) bilden. Mehrdatei-Ordner werden
///    dabei direkt auf die Festplatte gezippt (`.sync_tmp`), nie komplett
///    im Speicher gehalten; Hashes werden chunkweise von der Festplatte
///    berechnet.
/// 2. Server-Liste abrufen (Metadaten inkl. Tombstones für Löschungen).
/// 3. Für die Vereinigung aller bekannten Pfade (lokal ∪ Server ∪ Cache)
///    einen 3-Wege-Vergleich durchführen und die passende Aktion planen:
///    hochladen, herunterladen, lokal löschen, Löschung an den Server
///    melden, oder bei einem echten Konflikt anhand der neueren
///    Änderungszeit entscheiden.
/// 4. **Sicherheitsnetz**: Betreffen die geplanten Löschungen einen zu
///    großen Anteil der zuvor bekannten Einheiten (siehe
///    `SyncOptions::delete_threshold`), bricht der Sync ohne `force` ab,
///    statt blind zu löschen – typischerweise ein Zeichen für ein
///    falsches/leeres `--dir`.
/// 5. Alle geplanten Aktionen parallel ausführen (mehrere Uploads/Downloads
///    gleichzeitig statt strikt nacheinander). Jede Datei wird dabei
///    chunkweise ver-/entschlüsselt und gestreamt übertragen – der
///    Speicherbedarf bleibt unabhängig von der Dateigröße konstant klein.
///    Im Dry-Run-Modus wird stattdessen nur der Plan ausgegeben, ohne
///    etwas zu verändern.
pub fn run_sync(root: &Path, server: &ServerClient, crypto: &Crypto, options: &SyncOptions) -> Result<()> {
    let ignore = IgnoreList::load(root);
    let mut cache = load_cache(root);
    let remote = server.list()?;
    let tmp_dir = prepare_tmp_dir(root)?;
    let local_units = scan_local_units(root, &ignore)?;

    let mut local_map: HashMap<String, LocalEntry> = HashMap::new();
    for unit in local_units {
        let (plaintext_path, is_temp) = build_plaintext_source(&tmp_dir, &unit)?;
        let hash = hash_file_streaming(&plaintext_path)?;
        local_map.insert(
            unit.relpath.clone(),
            LocalEntry {
                unit,
                plaintext_path,
                is_temp,
                hash,
            },
        );
    }
    // Räumt die oben gebauten temporären ZIP-Dateien beim Verlassen dieser
    // Funktion automatisch auf – auch bei einem frühen return/bail! weiter
    // unten (Dry-Run, Löschschwelle).
    let _temp_zip_guard = TempZipGuard {
        local_map: &local_map,
    };

    // Vereinigung aller Pfade, die irgendwo (lokal, Server oder Cache)
    // bekannt sind, damit auch reine Löschungen erkannt werden.
    let mut all_relpaths: HashSet<String> = HashSet::new();
    all_relpaths.extend(local_map.keys().cloned());
    all_relpaths.extend(remote.keys().cloned());
    all_relpaths.extend(cache.keys().cloned());

    let mut planned: Vec<PlannedItem> = Vec::new();
    // Zählt Einheiten, bei denen weder lokal noch auf dem Server eine
    // Änderung seit dem letzten Sync festgestellt wurde – für die
    // Abschluss-Zusammenfassung.
    let mut unchanged_count: u32 = 0;

    for relpath in all_relpaths {
        let local = local_map.get(&relpath);
        let remote_meta = remote.get(&relpath);
        let cached = cache.get(&relpath);

        match (local, remote_meta) {
            // Fall A: lokale Datei, auf dem Server nie gesehen -> neu hochladen.
            (Some(_), None) => {
                planned.push(PlannedItem {
                    relpath,
                    action: PlannedAction::Upload,
                });
            }

            // Fall B: existiert lokal, Server-Eintrag ist (noch) kein Tombstone.
            (Some(entry), Some(rm)) if !rm.deleted => {
                let local_changed = cached
                    .map(|c| c.plain_hash != entry.hash)
                    .unwrap_or(true);
                let remote_changed = match cached {
                    Some(c) => c.plain_hash != rm.plain_hash,
                    None => true,
                };

                if !local_changed && !remote_changed {
                    unchanged_count += 1;
                } else if local_changed && !remote_changed {
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::Upload,
                    });
                } else if !local_changed && remote_changed {
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::Download,
                    });
                } else {
                    // Konflikt: neuere mtime gewinnt.
                    if entry.unit.mtime >= rm.mtime {
                        planned.push(PlannedItem {
                            relpath,
                            action: PlannedAction::Upload,
                        });
                    } else {
                        planned.push(PlannedItem {
                            relpath,
                            action: PlannedAction::Download,
                        });
                    }
                }
            }

            // Fall C: existiert lokal, wurde aber auf dem Server (von einem
            // anderen Client) gelöscht.
            (Some(entry), Some(rm)) if rm.deleted => {
                let changed_since_sync = cached
                    .map(|c| c.plain_hash != entry.hash)
                    .unwrap_or(true);
                if changed_since_sync {
                    // Lokal wurde die Datei nach der Löschung neu angelegt
                    // oder bearbeitet -> "wiederbeleben" statt zu löschen.
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::Upload,
                    });
                } else {
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::AcceptRemoteDelete {
                            is_archive: rm.is_archive,
                        },
                    });
                }
            }

            // Fall D: nicht (mehr) lokal vorhanden, Server hat einen aktiven Eintrag.
            (None, Some(rm)) if !rm.deleted => {
                if cached.is_some() {
                    // War synchronisiert, ist lokal jetzt weg -> lokale
                    // Löschung an den Server melden.
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::PropagateLocalDelete,
                    });
                } else {
                    // Komplett neu für uns -> herunterladen.
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::Download,
                    });
                }
            }

            // Fall E: nicht lokal vorhanden, Server-Eintrag ist ein Tombstone.
            (None, Some(_)) => {
                if cached.is_some() {
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::ClearCacheOnly,
                    });
                }
                // sonst: nie gekannt, nie lokal -> nichts zu tun
            }

            // Fall F: weder lokal noch auf dem Server, nur noch im Cache
            // (kann z. B. nach einem fehlgeschlagenen vorherigen Sync
            // vorkommen) -> Cache aufräumen.
            (None, None) => {
                if cached.is_some() {
                    planned.push(PlannedItem {
                        relpath,
                        action: PlannedAction::ClearCacheOnly,
                    });
                }
            }

            // Von den Guards oben (rm.deleted / !rm.deleted) logisch bereits
            // vollständig abgedeckt; dieser Zweig wird nie erreicht, ist aber
            // nötig, damit der Match für den Compiler exhaustiv ist.
            (Some(_), Some(_)) => unreachable!(
                "Sync-Logikfehler: (Some, Some) ohne passenden deleted-Guard für {relpath}"
            ),
        }
    }

    // Sicherheitsnetz: Ein großer Anteil an Löschungen auf einmal ist oft
    // ein Zeichen für ein falsches/leeres --dir (Tippfehler, nicht
    // gemountetes Netzlaufwerk, versehentlich verschobener Ordner) – ein
    // einziger Fehlaufruf könnte sonst den kompletten, zuvor bekannten
    // Datenbestand bei allen Clients löschen.
    let deletion_count = planned
        .iter()
        .filter(|p| {
            matches!(
                p.action,
                PlannedAction::AcceptRemoteDelete { .. } | PlannedAction::PropagateLocalDelete
            )
        })
        .count();
    let known_before = cache.len();
    let deletion_ratio = if known_before > 0 {
        deletion_count as f64 / known_before as f64
    } else {
        0.0
    };
    let threshold_exceeded =
        known_before > 0 && deletion_count > 0 && deletion_ratio > options.delete_threshold;

    if options.dry_run {
        print_dry_run_report(&planned, unchanged_count);
        if threshold_exceeded {
            println!(
                "\n⚠️  Löschschwelle würde greifen: {deletion_count} von {known_before} zuvor \
                 bekannten Einheiten ({:.0} %) würden gelöscht (Grenze: {:.0} %).\n\
                 Ohne --dry-run würde die Synchronisation deshalb abbrechen, außer mit --force.",
                deletion_ratio * 100.0,
                options.delete_threshold * 100.0
            );
        }
        return Ok(());
    }

    if threshold_exceeded && !options.force {
        anyhow::bail!(
            "Abgebrochen: {deletion_count} von {known_before} zuvor bekannten Einheiten \
             ({:.0} %) würden gelöscht – das überschreitet die Löschschwelle von {:.0} %.\n\
             Das ist oft ein Zeichen für ein falsches oder (noch) leeres --dir (z. B. Tippfehler \
             im Pfad oder ein nicht gemountetes Netzlaufwerk). Es wurde NICHTS verändert.\n\
             Prüfen Sie den geplanten Sync mit --dry-run, oder erzwingen Sie ihn bewusst mit --force.",
            deletion_ratio * 100.0,
            options.delete_threshold * 100.0
        );
    }

    if threshold_exceeded && options.force {
        println!(
            "⚠️  Löschschwelle überschritten ({deletion_count}/{known_before} = {:.0} %), \
             aber durch --force trotzdem fortgesetzt.",
            deletion_ratio * 100.0
        );
    }

    // Alle geplanten Aktionen parallel ausführen.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(PARALLELISM)
        .build()?;

    let results: Vec<Result<ExecResult>> = pool.install(|| {
        planned
            .par_iter()
            .map(|item| execute_action(root, &tmp_dir, server, crypto, &local_map, &remote, item))
            .collect()
    });

    // Ergebnisse sortiert anwenden/ausgeben, damit die Ausgabe stabil bleibt.
    let mut applied: Vec<ExecResult> = Vec::new();
    let mut had_error = false;
    for r in results {
        match r {
            Ok(res) => applied.push(res),
            Err(e) => {
                eprintln!("Fehler: {e}");
                had_error = true;
            }
        }
    }
    applied.sort_by(|a, b| a.relpath.cmp(&b.relpath));

    let mut uploaded = 0u32;
    let mut downloaded = 0u32;
    let mut deleted = 0u32;
    let mut cache_cleaned = 0u32;

    for res in applied {
        match res.kind {
            ActionKind::Upload => uploaded += 1,
            ActionKind::Download => downloaded += 1,
            ActionKind::Delete => deleted += 1,
            ActionKind::CacheCleanup => cache_cleaned += 1,
        }
        match res.cache_update {
            Some(entry) => {
                cache.insert(res.relpath.clone(), entry);
            }
            None => {
                cache.remove(&res.relpath);
            }
        }
        println!("{}", res.message);
    }

    save_cache(root, &cache)?;

    let mut summary = format!(
        "Zusammenfassung: {uploaded} hochgeladen, {downloaded} heruntergeladen, \
         {deleted} gelöscht, {unchanged_count} unverändert."
    );
    if cache_cleaned > 0 {
        summary.push_str(&format!(" ({cache_cleaned} veraltete Cache-Einträge bereinigt.)"));
    }
    println!("{summary}");

    if had_error {
        anyhow::bail!("Synchronisation mit Fehlern beendet (siehe oben)");
    }

    Ok(())
}

fn describe_action(item: &PlannedItem) -> String {
    match &item.action {
        PlannedAction::Upload => format!("Würde hochladen: {}", item.relpath),
        PlannedAction::Download => format!("Würde herunterladen: {}", item.relpath),
        PlannedAction::AcceptRemoteDelete { .. } => {
            format!("Würde lokal löschen (auf Server entfernt): {}", item.relpath)
        }
        PlannedAction::PropagateLocalDelete => {
            format!("Würde Löschung an Server melden: {}", item.relpath)
        }
        PlannedAction::ClearCacheOnly => format!(
            "Würde veralteten Cache-Eintrag bereinigen: {}",
            item.relpath
        ),
    }
}

fn print_dry_run_report(planned: &[PlannedItem], unchanged_count: u32) {
    if planned.is_empty() {
        println!(
            "[DRY-RUN] Keine Änderungen nötig, alles ist bereits synchron ({unchanged_count} unverändert)."
        );
        return;
    }

    let mut sorted: Vec<&PlannedItem> = planned.iter().collect();
    sorted.sort_by(|a, b| a.relpath.cmp(&b.relpath));
    for item in &sorted {
        println!("[DRY-RUN] {}", describe_action(item));
    }

    let uploads = planned
        .iter()
        .filter(|p| matches!(p.action, PlannedAction::Upload))
        .count();
    let downloads = planned
        .iter()
        .filter(|p| matches!(p.action, PlannedAction::Download))
        .count();
    let deletions = planned
        .iter()
        .filter(|p| {
            matches!(
                p.action,
                PlannedAction::AcceptRemoteDelete { .. } | PlannedAction::PropagateLocalDelete
            )
        })
        .count();
    println!(
        "[DRY-RUN] Zusammenfassung: {uploads} hochzuladen, {downloads} herunterzuladen, \
         {deletions} zu löschen, {unchanged_count} unverändert."
    );
}

fn execute_action(
    root: &Path,
    tmp_dir: &Path,
    server: &ServerClient,
    crypto: &Crypto,
    local_map: &HashMap<String, LocalEntry>,
    remote: &HashMap<String, RemoteMeta>,
    item: &PlannedItem,
) -> Result<ExecResult> {
    let relpath = item.relpath.clone();

    match &item.action {
        PlannedAction::Upload => {
            let entry = local_map
                .get(&relpath)
                .expect("Upload geplant, aber keine lokale Einheit vorhanden");

            // Chunkweise verschlüsseln in eine temporäre Datei, dann von
            // dort gestreamt hochladen – der Inhalt liegt zu keinem
            // Zeitpunkt komplett im Arbeitsspeicher.
            let ciphertext_tmp = tmp_file_for(tmp_dir, &relpath, "upload.enc");
            crypto.encrypt_file_streaming(&entry.plaintext_path, &ciphertext_tmp)?;
            let upload_result = server.upload_from_file(
                &relpath,
                entry.unit.mtime,
                entry.unit.is_archive,
                &entry.hash,
                &ciphertext_tmp,
            );
            let _ = fs::remove_file(&ciphertext_tmp);
            upload_result?;

            Ok(ExecResult {
                relpath: relpath.clone(),
                cache_update: Some(CacheEntry {
                    plain_hash: entry.hash.clone(),
                    mtime: entry.unit.mtime,
                }),
                message: format!("Hochgeladen: {relpath}"),
                kind: ActionKind::Upload,
            })
        }

        PlannedAction::Download => {
            let meta = remote
                .get(&relpath)
                .expect("Download geplant, aber kein Server-Eintrag vorhanden");

            // Gestreamt in eine temporäre Datei herunterladen, dann
            // chunkweise in eine zweite temporäre Datei entschlüsseln –
            // erst danach an den endgültigen Zielort verschieben/entpacken.
            let ciphertext_tmp = tmp_file_for(tmp_dir, &relpath, "download.enc");
            let download_result = server.download_to_file(&relpath, &ciphertext_tmp);
            if let Err(e) = download_result {
                let _ = fs::remove_file(&ciphertext_tmp);
                return Err(e);
            }

            let plaintext_tmp = tmp_file_for(tmp_dir, &relpath, "download.plain");
            let decrypt_result = crypto.decrypt_file_streaming(&ciphertext_tmp, &plaintext_tmp);
            let _ = fs::remove_file(&ciphertext_tmp);
            if let Err(e) = decrypt_result {
                let _ = fs::remove_file(&plaintext_tmp);
                return Err(e);
            }

            if meta.is_archive {
                let extract_result =
                    extract_zip_to_dir(&plaintext_tmp, &archive_dir_path(root, &relpath));
                let _ = fs::remove_file(&plaintext_tmp);
                extract_result?;
            } else {
                move_into_place(&plaintext_tmp, &root.join(&relpath))?;
            }

            Ok(ExecResult {
                relpath: relpath.clone(),
                cache_update: Some(CacheEntry {
                    plain_hash: meta.plain_hash.clone(),
                    mtime: meta.mtime,
                }),
                message: format!("Heruntergeladen: {relpath}"),
                kind: ActionKind::Download,
            })
        }

        PlannedAction::AcceptRemoteDelete { is_archive } => {
            remove_local_unit(root, &relpath, *is_archive)?;
            Ok(ExecResult {
                relpath: relpath.clone(),
                cache_update: None,
                message: format!("Lokal gelöscht (auf Server entfernt): {relpath}"),
                kind: ActionKind::Delete,
            })
        }

        PlannedAction::PropagateLocalDelete => {
            server.delete(&relpath)?;
            Ok(ExecResult {
                relpath: relpath.clone(),
                cache_update: None,
                message: format!("Löschung an Server gemeldet: {relpath}"),
                kind: ActionKind::Delete,
            })
        }

        PlannedAction::ClearCacheOnly => Ok(ExecResult {
            relpath: relpath.clone(),
            cache_update: None,
            message: format!("Cache bereinigt (bereits überall entfernt): {relpath}"),
            kind: ActionKind::CacheCleanup,
        }),
    }
}
