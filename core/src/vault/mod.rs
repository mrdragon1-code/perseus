//! Vault: keystore + lista cartelle + stato di sblocco + lockout dei tentativi.
pub mod file_crypto;
pub mod folders;
pub mod guard;
pub mod journal;
pub mod keys;

use crate::{error::msg, Error, Result};
use folders::{Counts, Report};
use guard::Guard;
use journal::Journal;
use keys::{KdfParams, Keystore, MasterKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MIN_PASSWORD_LEN: usize = 8;

pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp-write");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub folders: Vec<PathBuf>,
    /// sottostringhe (case-insensitive) dei nomi camera ammessi
    pub camera_allow: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self { folders: vec![], camera_allow: vec!["iVCam".into()] }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Lockout {
    fails: u32,
    until: u64,
}
impl Lockout {
    /// 3 tentativi liberi, poi 5 s, 10 s, 20 s, ... fino a 15 minuti.
    fn delay(fails: u32) -> u64 {
        if fails < 3 {
            0
        } else {
            (5u64 << (fails - 3).min(10)).min(900)
        }
    }
}

#[derive(Serialize)]
pub struct FolderStatus {
    pub path: String,
    #[serde(flatten)]
    pub counts: Counts,
}

#[derive(Serialize)]
pub struct Status {
    pub setup_done: bool,
    pub unlocked: bool,
    pub lockout_secs: u64,
    pub journal_pending: bool,
    pub folders: Vec<FolderStatus>,
    pub camera_allow: Vec<String>,
}

pub struct Vault {
    dir: PathBuf,
    keystore: Keystore,
    journal: Journal,
    guard: Guard,
    kdf: KdfParams,
    pub config: Config,
    master: Option<MasterKey>,
}

impl Vault {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let guard = Guard::system(&dir);
        Self::open_with(dir, guard, KdfParams::DEFAULT)
    }

    pub fn open_with(dir: PathBuf, guard: Guard, kdf: KdfParams) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let config = match std::fs::read(dir.join("config.json")) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            keystore: Keystore::new(dir.join("keystore.json")),
            journal: Journal::new(dir.join("journal.json")),
            dir,
            guard,
            kdf,
            config,
            master: None,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.dir
    }

    /// Rilegge la config: un altro processo (menu contestuale) può averla cambiata.
    fn reload(&mut self) -> Result<()> {
        match std::fs::read(self.dir.join("config.json")) {
            Ok(b) => self.config = serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Lock esclusivo tra processi (app + menu contestuale) per tutta l'operazione.
    fn op_lock(&self) -> Result<std::fs::File> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join("vault.lock"))?;
        f.lock()?;
        Ok(f)
    }

    fn save_config(&self) -> Result<()> {
        write_atomic(&self.dir.join("config.json"), &serde_json::to_vec_pretty(&self.config)?)
    }

    fn lockout_path(&self) -> PathBuf {
        self.dir.join("lockout.json")
    }
    fn load_lockout(&self) -> Lockout {
        std::fs::read(self.lockout_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    fn save_lockout(&self, l: &Lockout) -> Result<()> {
        write_atomic(&self.lockout_path(), &serde_json::to_vec(l)?)
    }

    pub fn lockout_secs(&self) -> u64 {
        self.load_lockout().until.saturating_sub(now())
    }

    /// Registra un tentativo fallito (password, faccia ostile, voce ostile).
    pub fn register_failure(&self) -> Result<u64> {
        let mut l = self.load_lockout();
        l.fails += 1;
        let d = Lockout::delay(l.fails);
        l.until = now() + d;
        self.save_lockout(&l)?;
        Ok(d)
    }

    fn register_success(&self) -> Result<()> {
        self.save_lockout(&Lockout::default())
    }

    pub fn is_setup(&self) -> bool {
        self.keystore.exists()
    }
    pub fn is_unlocked(&self) -> bool {
        self.master.is_some()
    }

    fn master(&self) -> Result<&[u8; 32]> {
        self.master.as_deref().ok_or(Error::Locked)
    }

    pub fn status(&mut self) -> Status {
        let _ = self.reload();
        Status {
            setup_done: self.is_setup(),
            unlocked: self.is_unlocked(),
            lockout_secs: self.lockout_secs(),
            journal_pending: self.journal.pending().ok().flatten().is_some(),
            folders: self
                .config
                .folders
                .iter()
                .map(|f| FolderStatus { path: f.display().to_string(), counts: folders::counts(f) })
                .collect(),
            camera_allow: self.config.camera_allow.clone(),
        }
    }

    pub fn setup(&mut self, password: &str) -> Result<()> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(msg(format!("la password deve avere almeno {MIN_PASSWORD_LEN} caratteri")));
        }
        self.master = Some(self.keystore.create(password, self.kdf)?);
        self.save_config()
    }

    /// Ok(true) = autorizzato, Ok(false) = password errata (tentativo registrato).
    pub fn unlock_password(&mut self, password: &str) -> Result<bool> {
        let wait = self.lockout_secs();
        if wait > 0 {
            return Err(Error::LockedOut(wait));
        }
        match self.keystore.unlock_password(password) {
            Ok(m) => {
                self.register_success()?;
                self.master = Some(m);
                let _l = self.op_lock()?;
                self.recover()?;
                Ok(true)
            }
            Err(Error::BadPassword) => {
                self.register_failure()?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Da chiamare SOLO dopo che faccia o voce sono state verificate come autorizzate.
    #[allow(dead_code)]
    pub(crate) fn unlock_biometric(&mut self) -> Result<()> {
        let wait = self.lockout_secs();
        if wait > 0 {
            return Err(Error::LockedOut(wait));
        }
        self.master = Some(self.keystore.unlock_dpapi()?);
        self.register_success()?;
        let _l = self.op_lock()?;
        self.recover()
    }

    /// Cancella la chiave dalla memoria senza ricifrare (uso: menu contestuale dopo "Decifra").
    pub fn forget_key(&mut self) {
        self.master = None;
    }

    fn recover(&self) -> Result<()> {
        folders::recover(self.master()?, &self.journal)
    }

    /// Ricifra tutte le cartelle e cancella la chiave dalla memoria.
    pub fn lock(&mut self) -> Result<Report> {
        let rep = self.encrypt_all()?;
        self.master = None;
        Ok(rep)
    }

    pub fn encrypt_all(&mut self) -> Result<Report> {
        self.reload()?;
        let _l = self.op_lock()?;
        let m = self.master()?;
        self.recover()?;
        let mut rep = Report::default();
        for f in &self.config.folders {
            rep.merge(folders::encrypt_dir(m, f, &self.journal));
        }
        Ok(rep)
    }

    pub fn decrypt_all(&mut self) -> Result<Report> {
        self.reload()?;
        let _l = self.op_lock()?;
        let m = self.master()?;
        self.recover()?;
        let mut rep = Report::default();
        for f in &self.config.folders {
            rep.merge(folders::decrypt_dir(m, f, &self.journal));
        }
        Ok(rep)
    }

    pub fn add_folder(&mut self, path: &Path) -> Result<()> {
        self.master()?;
        self.reload()?;
        let p = self.guard.check(path).map_err(msg)?;
        for f in &self.config.folders {
            if p.starts_with(f) || f.starts_with(&p) {
                return Err(msg(format!("si sovrappone a una cartella già protetta: {}", f.display())));
            }
        }
        self.config.folders.push(p);
        self.save_config()
    }

    /// Rimuove dalla lista (decifrando prima i suoi file).
    pub fn remove_folder(&mut self, path: &Path) -> Result<Report> {
        let m = *self.master()?;
        self.reload()?;
        let _l = self.op_lock()?;
        let idx = self
            .config
            .folders
            .iter()
            .position(|f| f == path || std::fs::canonicalize(path).ok().as_ref() == Some(f))
            .ok_or_else(|| msg("cartella non in lista"))?;
        let rep = folders::decrypt_dir(&m, &self.config.folders[idx], &self.journal);
        if rep.failed.is_empty() {
            self.config.folders.remove(idx);
            self.save_config()?;
        }
        Ok(rep)
    }

    /// Menu contestuale "Cifra": NON richiede autenticazione perché cifrare non espone dati.
    /// Usa la copia DPAPI della chiave solo per il tempo dell'operazione.
    /// Se la cartella non è coperta da una già protetta, viene aggiunta alla lista.
    pub fn encrypt_folder_quick(&mut self, path: &Path) -> Result<Report> {
        if !self.is_setup() {
            return Err(msg("PERSEUS non è ancora configurato: apri l'app e crea la password"));
        }
        self.reload()?;
        let p = self.guard.check(path).map_err(msg)?;
        let covered = self.config.folders.iter().any(|f| p.starts_with(f));
        if !covered {
            if let Some(f) = self.config.folders.iter().find(|f| f.starts_with(&p)) {
                return Err(msg(format!("contiene una cartella già protetta: {}", f.display())));
            }
            self.config.folders.push(p.clone());
            self.save_config()?;
        }
        let _l = self.op_lock()?;
        let m = match &self.master {
            Some(m) => m.clone(),
            None => self.keystore.unlock_dpapi()?,
        };
        folders::recover(&m, &self.journal)?;
        Ok(folders::encrypt_dir(&m, &p, &self.journal))
    }

    /// Menu contestuale "Decifra": richiede vault sbloccato (password/volto/voce).
    pub fn decrypt_folder(&mut self, path: &Path) -> Result<Report> {
        let m = *self.master()?;
        let p = std::fs::canonicalize(path)?;
        let _l = self.op_lock()?;
        folders::recover(&m, &self.journal)?;
        Ok(folders::decrypt_dir(&m, &p, &self.journal))
    }

    pub fn set_camera_allow(&mut self, allow: Vec<String>) -> Result<()> {
        self.master()?;
        self.reload()?;
        self.config.camera_allow = allow;
        self.save_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const FAST: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };

    #[test]
    fn full_flow() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let target = d.path().join("segreti");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(target.join("piano.txt"), b"top secret").unwrap();

        let guard = Guard::empty().protect(&data, guard::Rule::Subtree, "dati");
        let mut v = Vault::open_with(data.clone(), guard.clone(), FAST).unwrap();
        assert!(v.setup("corta").is_err());
        v.setup("password-lunga").unwrap();
        v.add_folder(&target).unwrap();
        assert!(v.add_folder(&data).is_err());
        let r = v.lock().unwrap();
        assert_eq!(r.processed, 1);
        assert!(!v.is_unlocked());
        assert!(v.decrypt_all().is_err());

        let mut v = Vault::open_with(data, guard, FAST).unwrap();
        assert!(!v.unlock_password("sbagliata-1").unwrap());
        assert!(!v.unlock_password("sbagliata-2").unwrap());
        assert!(!v.unlock_password("sbagliata-3").unwrap());
        assert!(matches!(v.unlock_password("password-lunga"), Err(Error::LockedOut(_))));
        // azzera il lockout per il test
        v.save_lockout(&Lockout::default()).unwrap();
        assert!(v.unlock_password("password-lunga").unwrap());
        v.decrypt_all().unwrap();
        assert_eq!(std::fs::read(target.join("piano.txt")).unwrap(), b"top secret");
        v.lock().unwrap();
        v.unlock_biometric().unwrap();
        assert_eq!(v.decrypt_all().unwrap().processed, 1);
    }

    #[test]
    fn context_menu_flow() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        let target = d.path().join("foto");
        std::fs::create_dir_all(target.join("sub")).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(target.join("sub/x.jpg"), b"jpeg").unwrap();
        let guard = Guard::empty().protect(&data, guard::Rule::Subtree, "dati");

        let mut v = Vault::open_with(data.clone(), guard.clone(), FAST).unwrap();
        assert!(v.encrypt_folder_quick(&target).is_err()); // non configurato
        v.setup("password-lunga").unwrap();
        v.forget_key();

        // "Cifra" da un altro processo, senza autenticazione
        let mut other = Vault::open_with(data.clone(), guard.clone(), FAST).unwrap();
        assert_eq!(other.encrypt_folder_quick(&target).unwrap().processed, 1);
        assert_eq!(other.config.folders.len(), 1);
        // sottocartella: già coperta, non duplicata
        other.encrypt_folder_quick(&target.join("sub")).unwrap();
        assert_eq!(other.config.folders.len(), 1);
        // il primo processo vede la nuova cartella
        assert_eq!(v.status().folders.len(), 1);

        // "Decifra" richiede autenticazione
        assert!(matches!(other.decrypt_folder(&target), Err(Error::Locked)));
        assert!(other.unlock_password("password-lunga").unwrap());
        assert_eq!(other.decrypt_folder(&target).unwrap().processed, 1);
        other.forget_key();
        assert_eq!(std::fs::read(target.join("sub/x.jpg")).unwrap(), b"jpeg");
    }

    #[test]
    fn lockout_curve() {
        assert_eq!(Lockout::delay(2), 0);
        assert_eq!(Lockout::delay(3), 5);
        assert_eq!(Lockout::delay(4), 10);
        assert_eq!(Lockout::delay(50), 900);
    }
}
