mod crypto;
mod ignore;
mod lock;
mod server;
mod sync;

use anyhow::{Context, Result};
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

use crypto::Crypto;
use lock::SyncLock;
use server::ServerClient;
use sync::SyncOptions;

/// Verschlüsselter Datei-Synchronisations-Client.
///
/// Vergleicht einen lokalen Ordner mit dem Stand auf dem Server und
/// synchronisiert Änderungen (inkl. Löschungen) in beide Richtungen. Alle
/// Inhalte werden ausschließlich lokal mit dem übergebenen Passwort
/// ver-/entschlüsselt; der Server erhält niemals den Klartext oder das
/// Passwort.
///
/// Dateien/Ordner, die auf `.syncignore` im Sync-Ordner matchen, werden
/// übersprungen (siehe `client/src/ignore.rs` für das Format).
///
/// SICHERHEITSNETZ: Betrifft eine geplante Synchronisation ungewöhnlich
/// viele Löschungen (Standard: mehr als 30 % der zuvor bekannten Dateien),
/// bricht der Client ohne `--force` ab, statt zu löschen – das schützt vor
/// Datenverlust bei allen Clients durch ein falsches/leeres `--dir` (z. B.
/// Tippfehler im Pfad oder ein nicht gemountetes Netzlaufwerk). Mit
/// `--dry-run` lässt sich jeder Sync vorab risikofrei prüfen.
///
/// ROBUSTHEIT: Transiente Netzwerkfehler (Verbindungsabbrüche, Timeouts,
/// 5xx-Serverfehler) werden automatisch mit Backoff wiederholt (siehe
/// `--retries`/`--retry-delay-ms`). Ein `.sync.lock` im Sync-Ordner
/// verhindert, dass zwei Sync-Prozesse (z. B. Watch-Modus + manueller
/// Aufruf) gleichzeitig denselben Ordner bearbeiten.
#[derive(Parser, Debug)]
#[command(name = "sync-client", about = "Verschlüsselter Datei-Sync-Client")]
struct Args {
    /// Basis-URL des PHP-Servers, z. B. http://localhost:8080
    #[arg(long)]
    server: String,

    /// API-Schlüssel für die Authentifizierung gegenüber dem Server
    #[arg(long)]
    api_key: String,

    /// Lokales Passwort zur Ver-/Entschlüsselung (bleibt NUR beim Client).
    /// ACHTUNG: Auf der Kommandozeile ist es für andere lokale Nutzer über
    /// die Prozessliste (`ps`) sichtbar und landet in der Shell-History.
    /// Wird diese Option weggelassen, fragt der Client stattdessen sicher
    /// (ohne Bildschirmausgabe) danach, oder liest es aus der
    /// Umgebungsvariable SYNC_PASSWORD.
    #[arg(long)]
    password: Option<String>,

    /// Lokaler Ordner, der synchronisiert werden soll
    #[arg(long)]
    dir: PathBuf,

    /// Dauerbetrieb: überwacht `--dir` auf Änderungen und synchronisiert
    /// automatisch, statt nur einmalig zu laufen. Zusätzlich wird auch
    /// periodisch (siehe `--interval`) synchronisiert, um Änderungen
    /// anderer Clients auf dem Server mitzubekommen.
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// Nur im Watch-Modus relevant: Intervall in Sekunden für den
    /// regelmäßigen "Sicherheits-Sync" (fängt Änderungen anderer Clients
    /// ab, die lokal ja kein Dateisystem-Ereignis auslösen).
    #[arg(long, default_value_t = 30)]
    interval: u64,

    /// Nur im Watch-Modus relevant: Wartezeit in Millisekunden nach dem
    /// letzten Dateisystem-Ereignis, bevor synchronisiert wird (Debounce),
    /// damit z. B. das Kopieren vieler Dateien nicht dutzende Syncs auslöst.
    #[arg(long, default_value_t = 1500)]
    debounce_ms: u64,

    /// Nur im Watch-Modus relevant: Obergrenze in Millisekunden, wie lange
    /// das Debounce-Fenster maximal durch fortlaufende Ereignisse
    /// hinausgezögert werden darf, bevor trotzdem synchronisiert wird.
    /// Verhindert, dass ein sehr lange laufender, kontinuierlicher
    /// Schreibvorgang (z. B. ein stundenlanges Backup in den Sync-Ordner)
    /// den Sync auf unbestimmte Zeit verschiebt.
    #[arg(long, default_value_t = 60_000)]
    max_debounce_wait_ms: u64,

    /// Zeigt nur an, was eine Synchronisation tun würde (Uploads, Downloads,
    /// Löschungen), verändert aber nichts – weder lokal noch auf dem Server,
    /// auch der lokale Cache bleibt unangetastet.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Erzwingt den Sync auch dann, wenn ungewöhnlich viele Löschungen
    /// geplant sind (siehe `--delete-threshold`). Ohne diese Option bricht
    /// der Client in so einem Fall sicherheitshalber ab.
    #[arg(long, default_value_t = false)]
    force: bool,

    /// Löschschwelle in Prozent (0–100) der zuvor bekannten Dateien/Ordner.
    /// Würden mehr Einheiten gelöscht als dieser Anteil, bricht der Sync
    /// ohne `--force` ab. Standard: 30.
    #[arg(long, default_value_t = 30.0)]
    delete_threshold: f64,

    /// Maximale Anzahl an Versuchen (inkl. dem ersten) pro Netzwerk-Anfrage
    /// bei transienten Fehlern (Verbindungsabbruch, Timeout, 5xx). Bei
    /// dauerhaften Fehlern (4xx, z. B. falscher API-Key) wird nie wiederholt.
    #[arg(long, default_value_t = 3)]
    retries: u32,

    /// Basis-Wartezeit in Millisekunden zwischen Wiederholungsversuchen
    /// (wächst exponentiell: 1., 2., 3. Versuch usw.).
    #[arg(long, default_value_t = 500)]
    retry_delay_ms: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.dir.is_dir() {
        std::fs::create_dir_all(&args.dir)?;
    }

    // Verhindert, dass ein zweiter Sync-Prozess (Watch-Modus, manueller
    // Aufruf, Cronjob, ...) gleichzeitig denselben Ordner bearbeitet und
    // sich dabei mit diesem Prozess den lokalen Cache gegenseitig
    // überschreibt. Wird beim Beenden automatisch wieder freigegeben.
    let _lock = SyncLock::acquire(&args.dir)?;

    let password = resolve_password(&args)?;

    let server = ServerClient::new(&args.server, &args.api_key, args.retries, args.retry_delay_ms);

    // Das Salt ist nicht geheim, muss aber für alle Clients gleich sein,
    // damit aus demselben Passwort überall derselbe Schlüssel entsteht.
    // Es wird deshalb vom Server bezogen (dort einmalig zufällig erzeugt).
    let salt = server.get_salt()?;
    let crypto = Crypto::new(&password, &salt)?;

    let options = SyncOptions {
        dry_run: args.dry_run,
        force: args.force,
        delete_threshold: (args.delete_threshold / 100.0).clamp(0.0, 1.0),
    };

    if args.watch {
        run_watch_mode(&args, &server, &crypto, &options)
    } else {
        sync::run_sync(&args.dir, &server, &crypto, &options)?;
        Ok(())
    }
}

/// Ermittelt das Passwort, ohne es unnötig im Klartext auf der Kommandozeile
/// zu verlangen: zuerst `--password` (mit Warnung), sonst die
/// Umgebungsvariable `SYNC_PASSWORD`, sonst eine sichere interaktive Abfrage
/// ohne Bildschirmausgabe.
fn resolve_password(args: &Args) -> Result<String> {
    if let Some(p) = &args.password {
        eprintln!(
            "Warnung: --password auf der Kommandozeile ist unsicher (sichtbar für andere \
             lokale Nutzer via Prozessliste, landet in der Shell-History). Besser: \
             Umgebungsvariable SYNC_PASSWORD setzen oder --password weglassen für eine \
             sichere interaktive Abfrage."
        );
        return Ok(p.clone());
    }

    if let Ok(p) = std::env::var("SYNC_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }

    let password = rpassword::prompt_password("Passwort für die Ver-/Entschlüsselung: ")
        .context(
            "Konnte das Passwort nicht interaktiv abfragen (kein Terminal verfügbar? \
             z. B. in einem Cronjob oder Skript). Bitte stattdessen die Umgebungsvariable \
             SYNC_PASSWORD setzen oder --password verwenden.",
        )?;
    if password.is_empty() {
        anyhow::bail!("Kein Passwort angegeben.");
    }
    Ok(password)
}

/// Dauerbetrieb: synchronisiert sofort, danach erneut bei jeder lokalen
/// Dateisystem-Änderung (entprellt) sowie zusätzlich in festen Abständen
/// (um auch Änderungen mitzubekommen, die andere Clients auf dem Server
/// vorgenommen haben und die lokal kein Dateisystem-Ereignis auslösen).
///
/// Gegen ein Livelock abgesichert: hält ein kontinuierlicher Schreibvorgang
/// das Debounce-Fenster dauerhaft am Leben (z. B. ein sehr langes Backup,
/// das laufend neue Dateien anlegt), wird spätestens nach
/// `--max-debounce-wait-ms` seit dem *ersten* noch nicht synchronisierten
/// Ereignis trotzdem synchronisiert.
fn run_watch_mode(
    args: &Args,
    server: &ServerClient,
    crypto: &Crypto,
    options: &SyncOptions,
) -> Result<()> {
    println!(
        "Watch-Modus aktiv für '{}': Sync bei Änderungen (Debounce {} ms, spätestens nach {} ms) \
         sowie mindestens alle {} s.",
        args.dir.display(),
        args.debounce_ms,
        args.max_debounce_wait_ms,
        args.interval
    );
    if options.dry_run {
        println!("Dry-Run aktiv: es wird nichts verändert, nur der jeweilige Plan angezeigt.");
    }

    if let Err(e) = sync::run_sync(&args.dir, server, crypto, options) {
        eprintln!("Fehler beim initialen Sync: {e}");
    }

    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        // Wir interessieren uns nicht für die Art des Events, nur dafür,
        // dass sich irgendetwas getan hat -> Signal senden.
        let _ = tx.send(res);
    })?;
    watcher.watch(&args.dir, RecursiveMode::Recursive)?;

    let debounce = Duration::from_millis(args.debounce_ms);
    let max_debounce_wait = Duration::from_millis(args.max_debounce_wait_ms.max(args.debounce_ms));
    let interval = Duration::from_secs(args.interval.max(1));

    let mut last_event: Option<Instant> = None;
    // Zeitpunkt des ersten noch nicht synchronisierten Ereignisses seit dem
    // letzten Sync – wird bei jedem Sync zurückgesetzt. Grundlage für die
    // Livelock-Obergrenze.
    let mut first_pending_event: Option<Instant> = None;
    let mut last_sync = Instant::now();

    loop {
        // Warten, bis entweder ein FS-Event kommt oder eine der Fristen
        // (Debounce, Livelock-Obergrenze, Poll-Intervall) abgelaufen ist.
        let mut wait = interval.saturating_sub(last_sync.elapsed());
        if let Some(t) = last_event {
            wait = wait.min(debounce.saturating_sub(t.elapsed()));
        }
        if let Some(t) = first_pending_event {
            wait = wait.min(max_debounce_wait.saturating_sub(t.elapsed()));
        }
        let wait = if wait.is_zero() {
            Duration::from_millis(50)
        } else {
            wait
        };

        match rx.recv_timeout(wait) {
            Ok(Ok(event)) => {
                // Unsere eigenen internen Dateien ignorieren, um keine
                // Endlosschleife durch unser eigenes Schreiben von
                // .sync_cache.json bzw. .sync.lock auszulösen.
                let relevant = event.paths.iter().any(|p| {
                    p.file_name()
                        .map(|n| n != ".sync_cache.json" && n != lock::LOCK_FILE_NAME)
                        .unwrap_or(true)
                });
                if relevant {
                    let now = Instant::now();
                    last_event = Some(now);
                    first_pending_event.get_or_insert(now);
                }
            }
            Ok(Err(e)) => {
                eprintln!("Watcher-Fehler: {e}");
            }
            Err(RecvTimeoutError::Timeout) => {
                // fällt unten durch zur Sync-Entscheidung
            }
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("Datei-Watcher wurde unerwartet beendet");
            }
        }

        let debounce_elapsed = last_event.map(|t| t.elapsed() >= debounce).unwrap_or(false);
        let livelock_guard_elapsed = first_pending_event
            .map(|t| t.elapsed() >= max_debounce_wait)
            .unwrap_or(false);
        let interval_elapsed = last_sync.elapsed() >= interval;

        if debounce_elapsed || livelock_guard_elapsed || interval_elapsed {
            if livelock_guard_elapsed && !debounce_elapsed {
                println!(
                    "Anhaltende Aktivität im Sync-Ordner erkannt – synchronisiere trotzdem \
                     (Obergrenze {} ms erreicht), statt weiter zu warten.",
                    args.max_debounce_wait_ms
                );
            }
            if debounce_elapsed || livelock_guard_elapsed {
                last_event = None;
                first_pending_event = None;
            }
            last_sync = Instant::now();
            if let Err(e) = sync::run_sync(&args.dir, server, crypto, options) {
                eprintln!("Fehler bei der Synchronisation: {e}");
            }
        }
    }
}
