# Verschlüsselter Datei-Sync (PHP-Server + Rust-Client)

Dieses Projekt besteht aus zwei Teilen:

- **`server/`** – ein PHP-Server, der verschlüsselte Dateien/Ordner von mehreren
  Clients entgegennimmt, verwaltet und wieder ausliefert (Metadaten in SQLite).
- **`client/`** – ein Rust-Kommandozeilen-Client, der einen lokalen Ordner mit
  dem Server abgleicht – inklusive Löschungen, `.syncignore`, Parallelisierung,
  optionalem Dauerbetrieb (Watch-Modus), Robustheit gegenüber
  Netzwerkfehlern (automatische Wiederholungen, Lockfile, Livelock-Schutz)
  und chunkweisem Streaming auch sehr großer Dateien (kein vollständiges
  Laden in den Arbeitsspeicher).

## Funktionsweise / Sicherheitskonzept

- Die **Verschlüsselung findet ausschließlich auf dem Client** statt (AES-256-GCM).
  Das Passwort wird niemals an den Server übertragen.
- Der Schlüssel wird aus dem Passwort mit **Argon2id** (echtes, speicher- und
  rechenhartes Passwort-KDF) unter Verwendung eines **Salts** abgeleitet.
- Das Salt ist kein Geheimnis, muss aber für alle Clients, die denselben
  Datenbestand synchronisieren, identisch sein. Es wird deshalb einmalig
  zufällig vom Server erzeugt, dauerhaft gespeichert und über `/api/salt.php`
  an die Clients ausgeliefert. Der Server erfährt dabei nie das Passwort selbst.
- Der Server speichert und liefert **nur verschlüsselte Blobs** aus. Er kennt
  weder den Klartext-Inhalt noch das Passwort.
- Enthält ein Ordner **mehrere Dateien direkt** (nicht in Unterordnern), werden
  diese vom Client zu einem **ZIP-Archiv gepackt**, anschließend verschlüsselt
  und als eine Einheit hochgeladen. Enthält ein Ordner nur **eine** Datei, wird
  diese einzeln übertragen.
- Jeder Client hat einen eigenen **API-Key** (Authentifizierung gegenüber dem
  Server – NICHT die Verschlüsselung). Mehrere Clients mit demselben
  Verschlüsselungs-Passwort können so denselben Datenbestand synchron halten.

```
Client A  --(AES-256-GCM verschlüsselt)-->  PHP-Server  --(verschlüsselt)-->  Client B
   |                                        speichert nur                        |
   |                                        Chiffretext + Metadaten (SQLite)     |
   +-------------------- gemeinsames Passwort (nie übertragen) ------------------+
```

## 1. Server einrichten

1. `server/config.php` öffnen und für jeden Client einen eigenen API-Key
   vergeben:

   ```php
   'api_keys' => [
       'client1' => 'ihr-eigener-geheimer-schluessel-1',
       'client2' => 'ihr-eigener-geheimer-schluessel-2',
   ],
   ```

2. PHP-Erweiterung `pdo_sqlite` muss aktiv sein (Metadaten liegen in SQLite,
   z. B. `apt install php-sqlite3`).

3. Server starten (z. B. lokal zum Testen mit dem eingebauten PHP-Server):

   ```bash
   cd server
   php -S 0.0.0.0:8080 -t .
   ```

   Für den Produktivbetrieb: Apache/Nginx + PHP-FPM verwenden, dahinter
   idealerweise per Reverse Proxy mit HTTPS (siehe "Bekannte Einschränkungen").
   Wichtig: `server/storage/` darf **nicht** direkt über HTTP erreichbar sein
   (die mitgelieferte `.htaccess` in `storage/` blockt dies für Apache;
   bei Nginx entsprechend `location /storage/ { deny all; }` ergänzen).

4. Der Server stellt folgende Endpunkte bereit (jeweils mit Header
   `X-API-Key: <key>`):

   | Endpoint            | Methode | Zweck                                        |
   |---------------------|---------|-----------------------------------------------|
   | `/api/list.php`     | GET     | Liste aller Einheiten (inkl. Tombstones)       |
   | `/api/upload.php`   | POST    | Verschlüsselten Blob hochladen                 |
   | `/api/download.php` | GET     | Verschlüsselten Blob herunterladen             |
   | `/api/delete.php`   | POST    | Eintrag löschen (legt einen Tombstone an)      |
   | `/api/salt.php`     | GET     | Öffentliches Argon2id-Salt abrufen/erzeugen    |

### Metadaten-Speicherung (SQLite)

Statt einer JSON-Datei pro Eintrag liegen die Metadaten in
`server/storage/meta.sqlite3` (eine Tabelle `files`). Das skaliert deutlich
besser als tausende Einzeldateien im Dateisystem. Die verschlüsselten
Chiffretext-Blobs selbst liegen weiterhin einzeln unter `server/storage/data/`.

### Löschungen (Tombstones)

Löscht ein Client eine Datei/einen Ordner lokal, meldet er das per
`/api/delete.php` an den Server. Der Server **entfernt dabei nur den
verschlüsselten Blob**, behält aber einen Metadaten-Eintrag mit `deleted=1`
("Tombstone"). So sehen alle anderen Clients beim nächsten Sync, dass die
Datei absichtlich gelöscht wurde, und entfernen sie ebenfalls lokal – statt
sie beim nächsten Abgleich versehentlich wiederherzustellen.

Wird eine gelöschte Datei später wieder mit demselben Pfad angelegt, "belebt"
ein erneuter Upload den Eintrag automatisch wieder (Tombstone wird aufgehoben).

Tombstones werden nicht automatisch endgültig entfernt. Für die Wartung gibt
es `Storage::purgeOldTombstones($maxAgeSeconds)`, das sich z. B. per
Cronjob-Skript aufrufen lässt, um alte Tombstones (z. B. älter als 90 Tage)
endgültig aus der Datenbank zu löschen.

## 2. Client bauen

Voraussetzung: Rust/Cargo (getestet mit Rust 1.75+).

```bash
cd client
cargo build --release
```

Die fertige Binary liegt danach unter `target/release/sync-client`.

## 3. Client benutzen

```bash
./target/release/sync-client \
  --server http://localhost:8080 \
  --api-key ihr-eigener-geheimer-schluessel-1 \
  --dir /pfad/zum/sync-ordner
```

Der Client fragt das Passwort dabei sicher (ohne Bildschirmausgabe) interaktiv ab.

- `--server`   Basis-URL des PHP-Servers
- `--api-key`  API-Key dieses Clients (siehe `config.php`)
- `--dir`      lokaler Ordner, der synchronisiert werden soll

Jeder Sync-Lauf schließt mit einer Zusammenfassungszeile ab, die auf einen
Blick zeigt, was passiert ist:

```
Hochgeladen: urlaub/__archive__.zip
Heruntergeladen: bericht.docx
Löschung an Server gemeldet: alter_entwurf.txt
Zusammenfassung: 1 hochgeladen, 1 heruntergeladen, 1 gelöscht, 42 unverändert.
```

Das gilt auch für `--dry-run` (dort mit "hochzuladen"/"herunterzuladen"/"zu
löschen" statt der abgeschlossenen Form) sowie für jeden einzelnen Durchlauf
im Watch-Modus.

#### Passwort sicher übergeben

Das Verschlüsselungspasswort **muss bei allen Clients, die denselben
Datenbestand teilen sollen, identisch sein**. Es gibt drei Wege, es zu
übergeben (in dieser Reihenfolge geprüft):

1. **`--password "..."`** – funktioniert, ist aber unsicher: andere lokale
   Nutzer sehen das Passwort über die Prozessliste (`ps aux`), und es landet
   in der Shell-History. Der Client gibt bei Verwendung eine Warnung aus.
2. **Umgebungsvariable `SYNC_PASSWORD`** – nicht in der Prozessliste
   sichtbar, geeignet für Skripte/Cronjobs/CI:
   ```bash
   export SYNC_PASSWORD="IhrGeheimesSyncPasswort"
   ./target/release/sync-client --server http://localhost:8080 --api-key ... --dir ...
   ```
3. **Interaktive Abfrage** (Standard, wenn weder 1. noch 2. angegeben ist) –
   sicherste Variante für die manuelle Nutzung am Terminal, das Passwort wird
   nicht angezeigt und landet nirgends im Klartext. Funktioniert nicht ohne
   Terminal (z. B. in einem Cronjob ohne TTY) – dort `SYNC_PASSWORD` verwenden.

Ein einmaliger Aufruf synchronisiert in beide Richtungen:

1. Lokale neue/geänderte Dateien werden verschlüsselt hochgeladen.
2. Auf dem Server neue/geänderte Einheiten werden heruntergeladen,
   entschlüsselt und (falls es sich um ein Archiv handelt) automatisch
   entpackt.
3. Lokal gelöschte Dateien werden dem Server gemeldet (Tombstone); vom Server
   gemeldete Löschungen werden lokal übernommen (siehe oben).
4. Bei echten Konflikten (Änderung auf beiden Seiten seit dem letzten Sync)
   gewinnt die Version mit der neueren Änderungszeit.
5. Alle anstehenden Uploads/Downloads/Löschungen laufen **parallel**
   (standardmäßig bis zu 8 gleichzeitig) statt strikt nacheinander.

### Watch-Modus (Dauerbetrieb)

```bash
export SYNC_PASSWORD="IhrGeheimesSyncPasswort"
./target/release/sync-client \
  --server http://localhost:8080 \
  --api-key ihr-eigener-geheimer-schluessel-1 \
  --dir /pfad/zum/sync-ordner \
  --watch
```

(Im Dauerbetrieb ist `SYNC_PASSWORD` praktisch die einzig sinnvolle Option –
eine interaktive Abfrage würde den Prozess sonst sofort beim Start blockieren.)

Im Watch-Modus läuft der Client dauerhaft:

- Er überwacht `--dir` auf Dateisystem-Änderungen und synchronisiert dann
  automatisch (entprellt über `--debounce-ms`, Standard 1500 ms, damit z. B.
  das Kopieren vieler Dateien nicht dutzende Syncs auslöst).
- Zusätzlich wird mindestens alle `--interval` Sekunden (Standard 30)
  synchronisiert, auch ohne lokales Ereignis – das fängt Änderungen ab, die
  **andere Clients** auf dem Server vorgenommen haben.

Für Server ohne Dauerbetrieb-Wunsch kann stattdessen weiterhin ein einmaliger
Aufruf per Cronjob/Taskplaner wiederholt werden.

### Robustheit bei Netzwerkfehlern & Nebenläufigkeit

**Automatische Wiederholungen bei transienten Fehlern.** Jede Anfrage an den
Server wird bei Verbindungsabbrüchen, Timeouts oder 5xx-Serverfehlern
automatisch mit exponentiellem Backoff wiederholt (`--retries`, Standard 3
Versuche; `--retry-delay-ms`, Standard 500 ms Basis-Wartezeit, verdoppelt sich
pro Versuch: 500 ms, 1000 ms, 2000 ms, …). Bei dauerhaften Fehlern (4xx, z. B.
falscher API-Key oder ungültiger Pfad) wird dagegen sofort ohne Wiederholung
abgebrochen, da ein erneuter Versuch daran nichts ändern würde:

```
Warnung: Upload von urlaub/__archive__.zip fehlgeschlagen (Versuch 1/3),
erneuter Versuch in 0.5s...
Warnung: Upload von urlaub/__archive__.zip fehlgeschlagen (Versuch 2/3),
erneuter Versuch in 1.0s...
Hochgeladen: urlaub/__archive__.zip
```

Das macht kurze Netzwerkaussetzer (WLAN-Hänger, kurzer Server-Neustart) für
den Dauerbetrieb (`--watch`) unkritisch, ohne dass gleich der ganze Sync-Lauf
fehlschlägt.

**Lockfile gegen parallele Sync-Läufe.** Beim Start legt der Client im
Sync-Ordner eine `.sync.lock`-Datei mit seiner Prozess-ID an und hält sie für
die gesamte Laufzeit. Versucht ein zweiter Prozess (z. B. ein manueller Aufruf
während der Watch-Modus bereits läuft, oder zwei parallel gestartete
Cronjobs), denselben Ordner zu synchronisieren, bricht er sofort mit einer
klaren Fehlermeldung ab, statt sich mit dem ersten Prozess den lokalen Cache
(`.sync_cache.json`) gegenseitig zu überschreiben:

```
Error: Ein anderer Sync-Prozess (PID 12345) scheint bereits für diesen
Ordner zu laufen (Lockdatei: /pfad/zum/sync-ordner/.sync.lock).
Falls das nicht stimmt (z. B. nach einem Absturz oder harten Kill), löschen
Sie die Datei manuell und versuchen Sie es erneut.
```

Stürzt ein Client ab oder wird hart beendet (`kill -9`), bevor er die
Lockdatei wieder aufräumen konnte, erkennt der nächste Client das automatisch:
Unter Linux wird geprüft, ob die in der Lockdatei vermerkte Prozess-ID noch
existiert (`/proc/<pid>`); ist das nicht der Fall, gilt der Lock als verwaist
und wird automatisch übernommen. Auf Plattformen ohne `/proc` greift ersatzweise
eine Alters-Schwelle (Lockdateien älter als 6 Stunden gelten als verwaist).

**Livelock-Schutz im Watch-Modus.** Ohne Gegenmaßnahme könnte ein sehr lange
laufender, kontinuierlicher Schreibvorgang im Sync-Ordner (z. B. ein
stundenlanges Backup-Tool, das laufend neue Dateien anlegt) das
Debounce-Fenster (`--debounce-ms`) immer wieder aufs Neue anstoßen und den
Sync so theoretisch auf unbestimmte Zeit verschieben. Der Client merkt sich
deshalb zusätzlich den Zeitpunkt des *ersten* noch nicht synchronisierten
Ereignisses und synchronisiert spätestens nach `--max-debounce-wait-ms`
(Standard 60 000 ms = 60 s) trotzdem, auch wenn weiterhin neue Ereignisse
eintreffen:

```
Anhaltende Aktivität im Sync-Ordner erkannt – synchronisiere trotzdem
(Obergrenze 60000 ms erreicht), statt weiter zu warten.
```

### Streaming großer Dateien

Weder Client noch Server laden eine Datei jemals komplett in den
Arbeitsspeicher. Das gilt für den gesamten Weg einer Datei:

- **Hashing** (Änderungserkennung): liest die Datei blockweise (64 KiB) von
  der Festplatte, statt sie einzulesen und dann zu hashen.
- **ZIP-Bau** bei Mehrdatei-Ordnern: jede enthaltene Datei wird direkt beim
  Packen auf die Festplatte gestreamt (`.sync_tmp/…`), nie im Speicher
  zusammengesetzt.
- **Verschlüsselung/Entschlüsselung**: AES-256-GCM im STREAM-Modus
  (`aes-gcm`-Crate, `EncryptorBE32`/`DecryptorBE32`) verarbeitet die Datei in
  1-MiB-Chunks, jeder Chunk einzeln authentifiziert (kein "alles oder
  nichts" wie beim naiven Verschlüsseln der gesamten Datei in einem Stück).
  Das Format einer verschlüsselten Datei ist:
  `7-Byte-Nonce-Präfix || Chunk_1 || Chunk_2 || … || letzter_Chunk`, wobei
  jeder Chunk aus bis zu 1 MiB Klartext plus einem 16-Byte-Auth-Tag besteht.
- **Übertragung**: der Upload liest die verschlüsselte Datei blockweise von
  der Festplatte in den HTTP-Body (`multipart::Part::file`, kein Laden in
  einen Byte-Puffer); der Download schreibt die Server-Antwort blockweise
  direkt in eine Datei (`Response::copy_to`).
- **Serverseitig** kopiert PHP die hochgeladene Datei per `copy()` direkt an
  ihren Zielort und hasht sie mit `hash_file()` (beides streamend), statt
  `file_get_contents()`/`hash()` auf dem kompletten Inhalt aufzurufen; der
  Download nutzt `readfile()` statt den Inhalt vorher als PHP-String zu
  materialisieren.

In Tests blieb der Speicherbedarf bei einer 500-MB-Testdatei sowohl beim
Client (Upload wie Download) als auch beim PHP-Server durchgehend im
niedrigen zweistelligen Megabyte-Bereich – unabhängig von der Dateigröße.

**Wichtig für den Betrieb:** PHPs eigene `upload_max_filesize`- und
`post_max_size`-ini-Einstellungen begrenzen unabhängig von diesem Projekt,
wie groß eine einzelne Anfrage sein darf (Standard in vielen Distributionen:
2 MB / 8 MB!). Für größere Dateien müssen diese Werte sowie
`config.php`s `max_upload_size` entsprechend angehoben werden, z. B.:

```bash
php -d upload_max_filesize=2G -d post_max_size=2G -S 0.0.0.0:8080 -t server
```

oder dauerhaft in der `php.ini` bzw. der Apache/Nginx-PHP-FPM-Konfiguration.

### Sicherheitsnetz gegen Massenlöschung (Löschschwelle) & `--dry-run`

Da Löschungen automatisch zwischen allen Clients propagiert werden (siehe
oben), könnte ein einziger Fehlaufruf mit falschem/leerem `--dir` (Tippfehler
im Pfad, nicht gemountetes Netzlaufwerk, versehentlich umbenannter Ordner)
sonst dazu führen, dass der komplette bisherige Datenbestand bei **allen**
Clients gelöscht wird – der Client "sieht" ja nur einen leeren Ordner und
schließt daraus, dass alles gelöscht wurde.

Deshalb gilt: Würden mehr als **30 % der zuvor bekannten Dateien/Ordner**
gelöscht, bricht der Sync standardmäßig ab, **ohne irgendetwas zu
verändern**:

```
$ ./target/release/sync-client --server ... --api-key ... --dir /pfad
Error: Abgebrochen: 214 von 214 zuvor bekannten Einheiten (100 %) würden
gelöscht – das überschreitet die Löschschwelle von 30 %.
Das ist oft ein Zeichen für ein falsches oder (noch) leeres --dir ...
Prüfen Sie den geplanten Sync mit --dry-run, oder erzwingen Sie ihn bewusst
mit --force.
```

Optionen dafür:

- **`--dry-run`** – zeigt an, was eine Synchronisation tun würde (jede
  einzelne geplante Aktion plus eine Zusammenfassung), ohne irgendetwas zu
  verändern: kein Upload, kein Download, keine Löschung, nicht einmal der
  lokale Cache wird geschrieben. Empfehlenswert vor dem ersten Sync in einem
  neuen/umgezogenen Ordner oder nach Änderungen an der `.syncignore`.
- **`--force`** – führt den Sync trotz überschrittener Löschschwelle bewusst
  aus (z. B. wenn tatsächlich gewollt viele Dateien aufgeräumt wurden). Der
  Client weist dabei weiterhin per Warnung darauf hin, wie viel gelöscht wird.
- **`--delete-threshold <Prozent>`** – passt die Schwelle an (Standard 30).
  `--delete-threshold 100` deaktiviert die Sicherung praktisch vollständig,
  `--delete-threshold 0` lässt schon eine einzige Löschung abbrechen.

Die Schwelle bezieht sich auf den Anteil an den Einheiten, die dem Client aus
seinem **eigenen letzten Sync** (dem lokalen `.sync_cache.json`) bekannt
waren – nicht auf die absolute Zahl. Bei einem brandneuen Sync-Ordner (leerer
Cache) greift sie nicht, da noch nichts "bekannt" ist, das verloren gehen
könnte.

### `.syncignore`

Im Sync-Ordner kann eine `.syncignore`-Datei (ähnlich `.gitignore`, bewusst
einfacher) angelegt werden, um Dateien/Ordner von der Synchronisation
auszuschließen:

```
# Kommentare beginnen mit #
*.tmp
*.log
node_modules/
.cache/
notes/geheim.txt
```

- Eine Zeile = ein Muster (Glob-Syntax, z. B. `*.tmp`).
- Ein abschließendes `/` markiert einen ganzen Ordner (inkl. Inhalt).
- Muster werden sowohl gegen den relativen Pfad als auch gegen den reinen
  Dateinamen geprüft.
- `.git`-Ordner und die interne `.sync_cache.json` sind immer implizit
  ausgeschlossen.

**Achtung:** Wird eine bereits synchronisierte Datei nachträglich per
`.syncignore` ausgeschlossen, behandelt der Client sie beim nächsten Sync wie
eine lokale Löschung und meldet sie dem Server (Tombstone) – sie verschwindet
dann auch bei allen anderen Clients. Das ist beabsichtigt ("nicht mehr
synchronisieren" wird als "hier entfernen" interpretiert), sollte aber bewusst
eingesetzt werden.

### Beispiel

```
sync-ordner/
├── .syncignore
├── bericht.docx          -> wird einzeln übertragen
└── urlaubsfotos/
    ├── bild1.jpg
    ├── bild2.jpg
    └── bild3.jpg         -> Ordner mit mehreren Dateien wird als
                              "urlaubsfotos/__archive__.zip" (verschlüsselt)
                              auf dem Server gespeichert
```

## Bekannte Einschränkungen (bewusst einfach gehalten)

- Wechselt ein Ordner zwischen "eine Datei" und "mehrere Dateien", entsteht
  auf dem Server ein neuer Eintrag; der alte Pfad wird dabei automatisch als
  gelöscht gemeldet (Tombstone) – das ist inzwischen automatisiert, erzeugt
  aber weiterhin zwei getrennte historische Einträge in der Datenbank.
- Es gibt weiterhin keine Versionierung für **inhaltliche** Konflikte: Ändern
  zwei Clients dieselbe Datei zwischen zwei Syncs unabhängig voneinander,
  gewinnt schlicht die Version mit der neueren mtime (abhängig von der
  Systemuhr der jeweiligen Clients) – die unterlegene Version geht verloren.
  Das Lockfile (siehe oben) schützt nur vor *gleichzeitigen Sync-Läufen*
  desselben Clients/Ordners, nicht vor solchen inhaltlichen Konflikten
  zwischen verschiedenen Clients.
- Transportverschlüsselung (HTTPS) ist nicht Teil dieses Projekts – für den
  Produktivbetrieb unbedingt einen TLS-terminierenden Reverse Proxy
  davorschalten.
- Metadaten (Dateinamen, Pfade, Größen, Zeitstempel) sind auf dem Server
  nicht verschlüsselt, nur die Dateiinhalte selbst.
- Große Dateien werden zwar chunkweise verschlüsselt und übertragen (siehe
  "Streaming großer Dateien" oben), aber bei jeder Änderung komplett neu
  übertragen; es gibt keine Fortsetzung abgebrochener Übertragungen auf
  Chunk-Ebene (die Retry-Logik wiederholt bei einem Abbruch den kompletten
  Transfer der Datei, nicht nur den fehlenden Rest) und keine binäre
  Differenzübertragung (Delta-Sync) bei kleinen Änderungen in großen Dateien.
