//! Keystore: chiave master (32 byte) salvata in due copie avvolte:
//!  - password: Argon2id -> KEK -> XChaCha20-Poly1305  (unico recupero)
//!  - biometrica: DPAPI utente, rilasciata solo dopo faccia/voce autorizzate
use super::write_atomic;
use crate::{dpapi, error::msg, Error, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub type MasterKey = Zeroizing<[u8; 32]>;
const AAD: &[u8] = b"perseus/keystore/v1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}
impl KdfParams {
    pub const DEFAULT: Self = Self { m_kib: 256 * 1024, t: 3, p: 4 };
}

#[derive(Serialize, Deserialize)]
struct KeystoreFile {
    version: u32,
    kdf: KdfParams,
    salt: String,
    pw_nonce: String,
    pw_wrapped: String,
    dpapi_wrapped: String,
}

fn kek(pw: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|e| msg(format!("argon2: {e}")))?;
    let mut k = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pw.as_bytes(), salt, &mut *k)
        .map_err(|e| msg(format!("argon2: {e}")))?;
    Ok(k)
}

fn to_master(v: &[u8]) -> Result<MasterKey> {
    let arr: [u8; 32] = v.try_into().map_err(|_| Error::Crypto)?;
    Ok(Zeroizing::new(arr))
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| msg("keystore corrotto"))
}

pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn create(&self, password: &str, kdf: KdfParams) -> Result<MasterKey> {
        if self.exists() {
            return Err(msg("keystore già esistente"));
        }
        let mut master = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *master);
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let k = kek(password, &salt, kdf)?;
        let wrapped = XChaCha20Poly1305::new(k.as_ref().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &master[..], aad: AAD })
            .map_err(|_| Error::Crypto)?;
        let file = KeystoreFile {
            version: 1,
            kdf,
            salt: hex::encode(salt),
            pw_nonce: hex::encode(nonce),
            pw_wrapped: hex::encode(wrapped),
            dpapi_wrapped: hex::encode(dpapi::protect(&master[..])?),
        };
        write_atomic(&self.path, &serde_json::to_vec_pretty(&file)?)?;
        Ok(master)
    }

    fn load(&self) -> Result<KeystoreFile> {
        Ok(serde_json::from_slice(&std::fs::read(&self.path)?)?)
    }

    pub fn unlock_password(&self, password: &str) -> Result<MasterKey> {
        let f = self.load()?;
        let k = kek(password, &unhex(&f.salt)?, f.kdf)?;
        let nonce = unhex(&f.pw_nonce)?;
        if nonce.len() != 24 {
            return Err(msg("keystore corrotto"));
        }
        let pt = XChaCha20Poly1305::new(k.as_ref().into())
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &unhex(&f.pw_wrapped)?, aad: AAD })
            .map_err(|_| Error::BadPassword)?;
        to_master(&Zeroizing::new(pt))
    }

    /// Solo per uso interno, dopo un'autenticazione biometrica riuscita.
    #[allow(dead_code)]
    pub(crate) fn unlock_dpapi(&self) -> Result<MasterKey> {
        let f = self.load()?;
        to_master(&dpapi::unprotect(&unhex(&f.dpapi_wrapped)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const FAST: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };

    #[test]
    fn create_and_unlock() {
        let d = tempfile::tempdir().unwrap();
        let ks = Keystore::new(d.path().join("keystore.json"));
        let m = ks.create("password-lunga", FAST).unwrap();
        assert_eq!(*ks.unlock_password("password-lunga").unwrap(), *m);
        assert!(matches!(ks.unlock_password("sbagliata"), Err(Error::BadPassword)));
        assert_eq!(*ks.unlock_dpapi().unwrap(), *m);
        assert!(ks.create("x", FAST).is_err());
    }
}
