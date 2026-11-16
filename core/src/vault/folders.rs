//! Cifratura/decifratura in-place dei file di una cartella, con scrittura sicura e journal.
use super::file_crypto::{decrypt_stream, encrypt_stream};
use super::journal::{Journal, Op};
use crate::{error::msg, Result};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub const EXT: &str = "prs";
const TMP_ENC: &str = ".prs.tmp";
const TMP_DEC: &str = ".dec.tmp";

#[derive(Serialize, Default, Debug)]
pub struct Report {
    pub processed: u32,
    pub failed: Vec<Failure>,
}
#[derive(Serialize, Debug)]
pub struct Failure {
    pub path: String,
    pub error: String,
}
impl Report {
    fn fail(&mut self, p: &Path, e: impl std::fmt::Display) {
        self.failed.push(Failure { path: p.display().to_string(), error: e.to_string() });
    }
    pub fn merge(&mut self, o: Report) {
        self.processed += o.processed;
        self.failed.extend(o.failed);
    }
}

#[derive(Serialize, Default, Debug, Clone, Copy)]
pub struct Counts {
    pub encrypted: u32,
    pub plain: u32,
}

fn is_prs(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case(EXT))
}
fn is_tmp(p: &Path) -> bool {
    let n = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    n.ends_with(TMP_ENC) || n.ends_with(TMP_DEC)
}

/// Elenco ricorsivo dei file regolari (non segue symlink/junction).
pub fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(&e.path(), out)?;
        } else if ft.is_file() {
            out.push(e.path());
        }
    }
    Ok(())
}

pub fn counts(dir: &Path) -> Counts {
    let mut files = Vec::new();
    let _ = walk(dir, &mut files);
    let mut c = Counts::default();
    for f in files.iter().filter(|f| !is_tmp(f)) {
        if is_prs(f) {
            c.encrypted += 1
        } else {
            c.plain += 1
        }
    }
    c
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Sovrascrive con zeri e cancella. Sugli SSD non garantisce la distruzione fisica.
fn wipe(path: &Path) -> io::Result<()> {
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();
    if perms.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(path, perms)?;
    }
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; 1 << 20];
        let mut left = meta.len();
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)
}

fn sibling(p: &Path, name: &str) -> PathBuf {
    p.parent().unwrap_or(Path::new(".")).join(name)
}

/// Primo nome libero: "a.txt", "a (1).txt", ...
fn unique(dir: &Path, name: &str) -> PathBuf {
    let cand = dir.join(name);
    if !cand.exists() {
        return cand;
    }
    let p = Path::new(name);
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    (1..).map(|i| dir.join(format!("{stem} ({i}){ext}"))).find(|c| !c.exists()).unwrap()
}

fn verify_prs(master: &[u8; 32], path: &Path) -> Result<(String, [u8; 32])> {
    decrypt_stream(master, BufReader::new(File::open(path)?), &mut io::sink())
}

pub fn encrypt_file(master: &[u8; 32], src: &Path, journal: &Journal) -> Result<PathBuf> {
    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| msg("nome file non UTF-8: rinominalo"))?
        .to_owned();
    let id = random_id();
    let tmp = sibling(src, &format!("{id}{TMP_ENC}"));
    let dst = sibling(src, &format!("{id}.{EXT}"));
    journal.begin(&Op::Encrypt { src: src.into(), tmp: tmp.clone(), dst: dst.clone() })?;
    let res = (|| -> Result<()> {
        let hash = {
            let mut w = BufWriter::new(File::create_new(&tmp)?);
            let h = encrypt_stream(master, &name, BufReader::new(File::open(src)?), &mut w)?;
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            h
        };
        let (n2, h2) = verify_prs(master, &tmp)?;
        if n2 != name || h2 != hash {
            return Err(msg("verifica post-cifratura fallita"));
        }
        fs::rename(&tmp, &dst)?;
        wipe(src)?;
        Ok(())
    })();
    if res.is_err() && !dst.exists() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    journal.clear()?;
    Ok(dst)
}

pub fn decrypt_file(master: &[u8; 32], src: &Path, journal: &Journal) -> Result<PathBuf> {
    let dir = src.parent().unwrap_or(Path::new(".")).to_path_buf();
    let tmp = dir.join(format!("{}{TMP_DEC}", random_id()));
    // Il nome finale si conosce solo dopo la decifratura: prima una verifica completa.
    let (name, _) = verify_prs(master, src)?;
    let dst = unique(&dir, &name);
    journal.begin(&Op::Decrypt { src: src.into(), tmp: tmp.clone(), dst: dst.clone() })?;
    let res = (|| -> Result<()> {
        let mut w = BufWriter::new(File::create_new(&tmp)?);
        decrypt_stream(master, BufReader::new(File::open(src)?), &mut w)?;
        w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        fs::rename(&tmp, &dst)?;
        fs::remove_file(src)?;
        Ok(())
    })();
    if res.is_err() && !dst.exists() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    journal.clear()?;
    Ok(dst)
}

/// Completa o annulla l'operazione interrotta registrata nel journal.
pub fn recover(master: &[u8; 32], journal: &Journal) -> Result<()> {
    match journal.pending()? {
        None => return Ok(()),
        Some(Op::Encrypt { src, tmp, dst }) => {
            if dst.exists() {
                // rinomina avvenuta: se il cifrato è valido completa la cancellazione del chiaro
                verify_prs(master, &dst)?;
                if src.exists() {
                    wipe(&src)?;
                }
            }
            if tmp.exists() {
                fs::remove_file(&tmp)?;
            }
        }
        Some(Op::Decrypt { src, tmp, dst }) => {
            if dst.exists() && src.exists() {
                fs::remove_file(&src)?;
            }
            if tmp.exists() {
                fs::remove_file(&tmp)?;
            }
        }
    }
    journal.clear()
}

fn files_of(dir: &Path, rep: &mut Report) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Err(e) = walk(dir, &mut files) {
        rep.fail(dir, e);
    }
    files.retain(|f| !is_tmp(f));
    files
}

pub fn encrypt_dir(master: &[u8; 32], dir: &Path, journal: &Journal) -> Report {
    let mut rep = Report::default();
    for f in files_of(dir, &mut rep).into_iter().filter(|f| !is_prs(f)) {
        match encrypt_file(master, &f, journal) {
            Ok(_) => rep.processed += 1,
            Err(e) => rep.fail(&f, e),
        }
    }
    rep
}

pub fn decrypt_dir(master: &[u8; 32], dir: &Path, journal: &Journal) -> Report {
    let mut rep = Report::default();
    for f in files_of(dir, &mut rep).into_iter().filter(|f| is_prs(f)) {
        match decrypt_file(master, &f, journal) {
            Ok(_) => rep.processed += 1,
            Err(e) => rep.fail(&f, e),
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Journal) {
        let d = tempfile::tempdir().unwrap();
        let j = Journal::new(d.path().join("journal.json"));
        fs::create_dir_all(d.path().join("box/sub")).unwrap();
        fs::write(d.path().join("box/a.txt"), b"ciao").unwrap();
        fs::write(d.path().join("box/sub/b.bin"), vec![3u8; 3_000_000]).unwrap();
        fs::write(d.path().join("box/vuoto"), b"").unwrap();
        (d, j)
    }

    #[test]
    fn dir_roundtrip() {
        let (d, j) = setup();
        let m = [5u8; 32];
        let b = d.path().join("box");
        let r = encrypt_dir(&m, &b, &j);
        assert_eq!((r.processed, r.failed.len()), (3, 0));
        let c = counts(&b);
        assert_eq!((c.encrypted, c.plain), (3, 0));
        assert!(!b.join("a.txt").exists());

        let r = decrypt_dir(&[6u8; 32], &b, &j); // chiave sbagliata: nulla cambia
        assert_eq!((r.processed, r.failed.len()), (0, 3));
        assert_eq!(counts(&b).encrypted, 3);

        let r = decrypt_dir(&m, &b, &j);
        assert_eq!((r.processed, r.failed.len()), (3, 0));
        assert_eq!(fs::read(b.join("a.txt")).unwrap(), b"ciao");
        assert_eq!(fs::read(b.join("sub/b.bin")).unwrap(), vec![3u8; 3_000_000]);
        assert_eq!(fs::read(b.join("vuoto")).unwrap(), b"");
        assert!(j.pending().unwrap().is_none());
    }

    #[test]
    fn recover_encrypt_after_rename() {
        // crash simulato: .prs scritto e rinominato, ma il chiaro non ancora cancellato
        let (d, j) = setup();
        let m = [5u8; 32];
        let src = d.path().join("box/a.txt");
        let dst = d.path().join("box/x.prs");
        let tmp = d.path().join("box/x.prs.tmp");
        let mut w = File::create(&dst).unwrap();
        encrypt_stream(&m, "a.txt", File::open(&src).unwrap(), &mut w).unwrap();
        drop(w);
        j.begin(&Op::Encrypt { src: src.clone(), tmp, dst: dst.clone() }).unwrap();
        recover(&m, &j).unwrap();
        assert!(!src.exists() && dst.exists());
        assert!(j.pending().unwrap().is_none());
    }

    #[test]
    fn recover_encrypt_before_rename() {
        // crash simulato a metà scrittura del temporaneo: il chiaro resta intatto
        let (d, j) = setup();
        let src = d.path().join("box/a.txt");
        let tmp = d.path().join("box/x.prs.tmp");
        fs::write(&tmp, b"PRS1 mezzo file").unwrap();
        j.begin(&Op::Encrypt { src: src.clone(), tmp: tmp.clone(), dst: d.path().join("box/x.prs") }).unwrap();
        recover(&[5u8; 32], &j).unwrap();
        assert!(src.exists() && !tmp.exists());
        assert_eq!(fs::read(&src).unwrap(), b"ciao");
    }

    #[test]
    fn name_collision() {
        let (d, j) = setup();
        let m = [5u8; 32];
        let a = d.path().join("box/a.txt");
        let prs = encrypt_file(&m, &a, &j).unwrap();
        fs::write(&a, b"nuovo").unwrap();
        let out = decrypt_file(&m, &prs, &j).unwrap();
        assert_eq!(out.file_name().unwrap(), "a (1).txt");
        assert_eq!(fs::read(&a).unwrap(), b"nuovo");
    }
}
