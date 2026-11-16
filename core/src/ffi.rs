//! API C per l'interfaccia C#. Convenzioni:
//! - stringhe in ingresso: UTF-8 terminate da NUL
//! - stringhe in uscita: allocate da Rust, liberare con `prs_free_string`
//! - codici di ritorno: >=0 successo (1 = autorizzato), -1 errore (dettagli in `prs_last_error`)
//!   per l'autenticazione: 1 = AUTORIZZATO, 0 = NON AUTORIZZATO
use crate::camera::{self, CameraStream};
use crate::vault::Vault;
use crate::{error::msg, Result};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use zeroize::Zeroizing;

static VAULT: OnceLock<Mutex<Vault>> = OnceLock::new();
static CAMERA: Mutex<Option<CameraStream>> = Mutex::new(None);

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_error(e: impl std::fmt::Display) {
    LAST_ERROR.with(|l| *l.borrow_mut() = e.to_string());
}

fn wrap(f: impl FnOnce() -> Result<i32>) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_error(e);
            -1
        }
        Err(_) => {
            set_error("errore interno (panic)");
            -1
        }
    }
}

fn wrap_str(f: impl FnOnce() -> Result<String>) -> *mut c_char {
    let mut out = None;
    let rc = wrap(|| {
        out = Some(f()?);
        Ok(0)
    });
    match (rc, out) {
        (0, Some(s)) => to_c(s),
        _ => std::ptr::null_mut(),
    }
}

fn to_c(s: String) -> *mut c_char {
    CString::new(s.replace('\0', "")).unwrap_or_default().into_raw()
}

unsafe fn arg(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(msg("argomento nullo"));
    }
    Ok(CStr::from_ptr(p).to_str().map_err(|_| msg("argomento non UTF-8"))?.to_owned())
}

fn vault() -> Result<MutexGuard<'static, Vault>> {
    let v = VAULT.get().ok_or_else(|| msg("prs_init non chiamato"))?;
    Ok(v.lock().unwrap_or_else(|p| p.into_inner()))
}

fn camera() -> MutexGuard<'static, Option<CameraStream>> {
    CAMERA.lock().unwrap_or_else(|p| p.into_inner())
}

fn default_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("Perseus")
}

/// Inizializza il core. `data_dir` può essere NULL (= %LOCALAPPDATA%\Perseus).
#[no_mangle]
pub unsafe extern "C" fn prs_init(data_dir: *const c_char) -> i32 {
    wrap(|| {
        if VAULT.get().is_some() {
            return Ok(0);
        }
        let dir = if data_dir.is_null() { default_data_dir() } else { PathBuf::from(arg(data_dir)?) };
        let _ = VAULT.set(Mutex::new(Vault::open(dir)?));
        Ok(0)
    })
}

/// Ultimo errore del thread chiamante (da liberare con prs_free_string).
#[no_mangle]
pub extern "C" fn prs_last_error() -> *mut c_char {
    to_c(LAST_ERROR.with(|l| l.borrow().clone()))
}

#[no_mangle]
pub unsafe extern "C" fn prs_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Stato JSON: setup, sblocco, lockout, cartelle con conteggi.
#[no_mangle]
pub extern "C" fn prs_status_json() -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.status())?))
}

/// 1 se esiste già la chiave master (password creata).
#[no_mangle]
pub extern "C" fn prs_is_setup() -> i32 {
    wrap(|| Ok(vault()?.is_setup() as i32))
}

/// Primo avvio: crea la chiave master protetta dalla password.
#[no_mangle]
pub unsafe extern "C" fn prs_setup(password: *const c_char) -> i32 {
    wrap(|| {
        let pw = Zeroizing::new(arg(password)?);
        vault()?.setup(&pw)?;
        Ok(1)
    })
}

/// 1 = AUTORIZZATO, 0 = NON AUTORIZZATO, -1 = errore/lockout.
#[no_mangle]
pub unsafe extern "C" fn prs_unlock_password(password: *const c_char) -> i32 {
    wrap(|| {
        let pw = Zeroizing::new(arg(password)?);
        Ok(vault()?.unlock_password(&pw)? as i32)
    })
}

/// Ricifra tutte le cartelle e cancella la chiave. Ritorna il report JSON.
#[no_mangle]
pub extern "C" fn prs_lock() -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.lock()?)?))
}

#[no_mangle]
pub extern "C" fn prs_encrypt_all() -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.encrypt_all()?)?))
}

#[no_mangle]
pub extern "C" fn prs_decrypt_all() -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.decrypt_all()?)?))
}

#[no_mangle]
pub unsafe extern "C" fn prs_folder_add(path: *const c_char) -> i32 {
    wrap(|| {
        vault()?.add_folder(Path::new(&arg(path)?))?;
        Ok(0)
    })
}

/// Decifra la cartella e la toglie dalla lista. Ritorna il report JSON.
#[no_mangle]
pub unsafe extern "C" fn prs_folder_remove(path: *const c_char) -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.remove_folder(Path::new(&arg(path)?))?)?))
}

/// Menu contestuale "Cifra": nessuna autenticazione richiesta. Ritorna il report JSON.
#[no_mangle]
pub unsafe extern "C" fn prs_encrypt_folder_quick(path: *const c_char) -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.encrypt_folder_quick(Path::new(&arg(path)?))?)?))
}

/// Menu contestuale "Decifra": richiede il vault sbloccato. Ritorna il report JSON.
#[no_mangle]
pub unsafe extern "C" fn prs_decrypt_folder(path: *const c_char) -> *mut c_char {
    wrap_str(|| Ok(serde_json::to_string(&vault()?.decrypt_folder(Path::new(&arg(path)?))?)?))
}

/// Cancella la chiave dalla memoria senza ricifrare.
#[no_mangle]
pub extern "C" fn prs_forget_key() -> i32 {
    wrap(|| {
        vault()?.forget_key();
        Ok(0)
    })
}

/// Allowlist camere come JSON array di stringhe (richiede vault sbloccato).
#[no_mangle]
pub unsafe extern "C" fn prs_set_camera_allow(json: *const c_char) -> i32 {
    wrap(|| {
        let list: Vec<String> = serde_json::from_str(&arg(json)?)?;
        vault()?.set_camera_allow(list)?;
        Ok(0)
    })
}

/// Elenco camere JSON con verdetto (Trusted / Blocked / Untrusted).
#[no_mangle]
pub extern "C" fn prs_camera_list_json() -> *mut c_char {
    wrap_str(|| {
        let allow = vault()?.config.camera_allow.clone();
        Ok(serde_json::to_string(&camera::list(&allow)?)?)
    })
}

/// Apre la camera (rifiuta OBS e camere fuori allowlist).
#[no_mangle]
pub extern "C" fn prs_camera_open(index: u32) -> i32 {
    wrap(|| {
        let allow = vault()?.config.camera_allow.clone();
        let mut cam = camera();
        *cam = None; // chiude l'eventuale camera precedente
        *cam = Some(CameraStream::open(index, &allow)?);
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn prs_camera_close() -> i32 {
    wrap(|| {
        *camera() = None;
        Ok(0)
    })
}

/// Copia l'ultimo frame BGRA in `buf` se più nuovo di `*seq`.
/// Ritorna 1 = nuovo frame, 0 = nessun frame nuovo, -2 = buffer piccolo (w/h impostati), -1 = errore.
#[no_mangle]
pub unsafe extern "C" fn prs_camera_frame(buf: *mut u8, cap: usize, w: *mut u32, h: *mut u32, seq: *mut u64) -> i32 {
    wrap(|| {
        if w.is_null() || h.is_null() || seq.is_null() {
            return Err(msg("puntatori nulli"));
        }
        let cam = camera();
        let cam = cam.as_ref().ok_or_else(|| msg("nessuna camera aperta"))?;
        let r = cam.latest(*seq, |f| {
            *w = f.width;
            *h = f.height;
            if buf.is_null() || cap < f.bgra.len() {
                return -2;
            }
            std::ptr::copy_nonoverlapping(f.bgra.as_ptr(), buf, f.bgra.len());
            *seq = f.seq;
            1
        })?;
        Ok(r.unwrap_or(0))
    })
}
