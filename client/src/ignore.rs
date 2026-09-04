use glob::Pattern;
use std::fs;
use std::path::Path;

/// Ein einzelnes Muster aus der `.syncignore`-Datei.
struct IgnoreRule {
    pattern: Pattern,
    /// true, wenn das Muster mit "/" endete -> nur Ordner (und deren Inhalt)
    dir_only: bool,
    raw: String,
}

/// Lädt und wendet die Muster aus einer optionalen `.syncignore`-Datei im
/// Wurzelverzeichnis an (ähnlich wie `.gitignore`, aber bewusst simpel
/// gehalten): eine Zeile pro Muster, `#` leitet Kommentare ein, leere
/// Zeilen werden übersprungen, ein abschließendes `/` markiert ein
/// Verzeichnis-Muster (ignoriert dann auch dessen kompletten Inhalt).
///
/// Beispiel `.syncignore`:
/// ```text
/// # Temporäre Dateien
/// *.tmp
/// *.bak
/// # ganze Ordner
/// node_modules/
/// .cache/
/// # einzelne Datei per relativem Pfad
/// notes/geheim.txt
/// ```
pub struct IgnoreList {
    rules: Vec<IgnoreRule>,
}

impl IgnoreList {
    pub fn load(root: &Path) -> Self {
        let path = root.join(".syncignore");
        let mut rules = Vec::new();

        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let dir_only = line.ends_with('/');
                let pattern_str = line.trim_end_matches('/');
                if let Ok(pattern) = Pattern::new(pattern_str) {
                    rules.push(IgnoreRule {
                        pattern,
                        dir_only,
                        raw: pattern_str.to_string(),
                    });
                } else {
                    eprintln!("Warnung: ungültiges .syncignore-Muster wird übersprungen: {line}");
                }
            }
        }

        // Interne Dateien sind immer implizit ignoriert.
        IgnoreList { rules }
    }

    /// Prüft, ob ein relativer Pfad (mit "/" als Trenner, ohne führenden
    /// Slash) durch eine Regel abgedeckt ist. Geprüft wird sowohl gegen den
    /// vollständigen relativen Pfad als auch gegen den reinen Dateinamen,
    /// zusätzlich greifen Verzeichnis-Muster auch für alle Pfade darunter.
    pub fn is_ignored(&self, relpath: &str) -> bool {
        if relpath == ".sync_cache.json"
            || relpath == ".syncignore"
            || relpath == crate::lock::LOCK_FILE_NAME
        {
            return true;
        }
        // Versteckte VCS-Verzeichnisse und das interne Scratch-Verzeichnis
        // für Streaming-Zwischendateien (siehe sync::TMP_DIR_NAME) immer
        // ausschließen.
        if relpath
            .split('/')
            .any(|part| part == ".git" || part == crate::sync::TMP_DIR_NAME)
        {
            return true;
        }

        let basename = relpath.rsplit('/').next().unwrap_or(relpath);

        for rule in &self.rules {
            if rule.pattern.matches(relpath) || rule.pattern.matches(basename) {
                return true;
            }
            if rule.dir_only {
                let prefix = format!("{}/", rule.raw);
                if relpath.starts_with(&prefix) || relpath == rule.raw {
                    return true;
                }
            }
        }
        false
    }
}
