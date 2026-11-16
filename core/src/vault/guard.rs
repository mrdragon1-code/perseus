//! Impedisce di cifrare cartelle pericolose (sistema, profilo, l'app stessa, i suoi dati).
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Rule {
    /// vietata la cartella, i suoi figli e i suoi antenati
    Subtree,
    /// vietata solo la cartella stessa e i suoi antenati (es. profilo utente)
    Exact,
}

#[derive(Clone, Debug, Default)]
pub struct Guard {
    rules: Vec<(PathBuf, Rule, String)>,
}

fn canon(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

impl Guard {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn protect(mut self, p: impl AsRef<Path>, rule: Rule, why: &str) -> Self {
        if let Some(c) = canon(p.as_ref()) {
            self.rules.push((c, rule, why.to_string()));
        }
        self
    }

    /// Regole di sistema + cartella dati + cartella dell'eseguibile.
    pub fn system(data_dir: &Path) -> Self {
        let mut g = Self::empty().protect(data_dir, Rule::Subtree, "cartella dati di PERSEUS");
        if let Some(exe_dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
            g = g.protect(exe_dir, Rule::Subtree, "cartella del programma PERSEUS");
        }
        for (var, rule) in [
            ("SystemRoot", Rule::Subtree),
            ("ProgramFiles", Rule::Subtree),
            ("ProgramFiles(x86)", Rule::Subtree),
            ("ProgramData", Rule::Subtree),
            ("LOCALAPPDATA", Rule::Subtree),
            ("APPDATA", Rule::Subtree),
            ("USERPROFILE", Rule::Exact),
        ] {
            if let Ok(v) = std::env::var(var) {
                g = g.protect(v, rule, &format!("cartella di sistema (%{var}%)"));
            }
        }
        g
    }

    /// Ok(percorso canonico) se la cartella si può cifrare, altrimenti il motivo del rifiuto.
    /// Nota: le cartelle protette devono esistere quando il Guard viene costruito.
    pub fn check(&self, path: &Path) -> Result<PathBuf, String> {
        let p = canon(path).ok_or_else(|| format!("cartella inesistente: {}", path.display()))?;
        if !p.is_dir() {
            return Err("non è una cartella".into());
        }
        if p.parent().is_none() {
            return Err("non si può cifrare la radice di un disco".into());
        }
        for (prot, rule, why) in &self.rules {
            let hit = prot.starts_with(&p) || (*rule == Rule::Subtree && p.starts_with(prot));
            if hit {
                return Err(format!("vietata: contiene o è dentro {why}"));
            }
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let prof = d.path().join("profile");
        let docs = prof.join("docs");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&docs).unwrap();
        let g = Guard::empty().protect(&data, Rule::Subtree, "dati").protect(&prof, Rule::Exact, "profilo");
        assert!(g.check(&docs).is_ok());
        assert!(g.check(&prof).is_err());
        assert!(g.check(&data).is_err());
        assert!(g.check(d.path()).is_err()); // antenato dei dati
        assert!(g.check(&d.path().join("nope")).is_err());
    }
}
