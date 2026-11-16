//! Formato file `.prs`:
//! header = "PRS1" | versione(1) | salt(32) | nonce STREAM(19)   (56 byte, usato come AAD)
//! corpo  = STREAM XChaCha20-Poly1305 (BE32) su blocchi da 1 MiB di:
//!          len_nome(u16 LE) | nome UTF-8 | contenuto del file
//! Chiave per file = HKDF-SHA256(master, salt).
use crate::{error::msg, Error, Result};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{self, Cursor, Read, Write};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"PRS1";
pub const VERSION: u8 = 1;
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const SALT: usize = 32;
const NONCE: usize = 19;
pub const HEADER_LEN: usize = 4 + 1 + SALT + NONCE;

fn file_key(master: &[u8; 32], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(b"perseus/file/v1", &mut *k).expect("hkdf len");
    k
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Valida il nome originale salvato nel file (anti path-traversal).
pub fn validate_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.chars().any(|c| matches!(c, '/' | '\\' | ':' | '\0'));
    if bad {
        return Err(msg(format!("nome file non valido nel file cifrato: {name:?}")));
    }
    Ok(())
}

/// Cifra `input` in `out`. Ritorna lo SHA-256 del contenuto in chiaro.
pub fn encrypt_stream<R: Read, W: Write>(
    master: &[u8; 32],
    name: &str,
    input: R,
    out: &mut W,
) -> Result<[u8; 32]> {
    validate_name(name)?;
    let name_b = name.as_bytes();
    if name_b.len() > u16::MAX as usize {
        return Err(msg("nome file troppo lungo"));
    }
    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    OsRng.fill_bytes(&mut header[5..]);
    let (salt, nonce) = header[5..].split_at(SALT);
    let key = file_key(master, salt);
    let mut enc = EncryptorBE32::from_aead(XChaCha20Poly1305::new(key.as_ref().into()), nonce.into());
    out.write_all(&header)?;

    let mut prefix = Vec::with_capacity(2 + name_b.len());
    prefix.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    prefix.extend_from_slice(name_b);
    let mut hr = HashingReader { inner: input, hasher: Sha256::new() };
    {
        let mut src = Cursor::new(prefix).chain(&mut hr);
        let mut a = Zeroizing::new(vec![0u8; CHUNK]);
        let mut b = Zeroizing::new(vec![0u8; CHUNK]);
        let mut na = read_full(&mut src, &mut a)?;
        loop {
            let nb = if na == CHUNK { read_full(&mut src, &mut b)? } else { 0 };
            let p = Payload { msg: &a[..na], aad: &header };
            if nb == 0 {
                out.write_all(&enc.encrypt_last(p).map_err(|_| Error::Crypto)?)?;
                break;
            }
            out.write_all(&enc.encrypt_next(p).map_err(|_| Error::Crypto)?)?;
            std::mem::swap(&mut a, &mut b);
            na = nb;
        }
    }
    Ok(hr.hasher.finalize().into())
}

/// Decifra e autentica. Ritorna (nome originale, SHA-256 del contenuto).
/// Attenzione: `out` riceve dati prima che l'intero file sia autenticato:
/// scrivere sempre su un file temporaneo e rinominarlo solo se l'esito è Ok.
pub fn decrypt_stream<R: Read, W: Write>(
    master: &[u8; 32],
    mut input: R,
    out: &mut W,
) -> Result<(String, [u8; 32])> {
    let mut header = [0u8; HEADER_LEN];
    if read_full(&mut input, &mut header)? != HEADER_LEN || &header[..4] != MAGIC {
        return Err(msg("non è un file PERSEUS"));
    }
    if header[4] != VERSION {
        return Err(msg(format!("versione file non supportata: {}", header[4])));
    }
    let (salt, nonce) = header[5..].split_at(SALT);
    let key = file_key(master, salt);
    let mut dec = DecryptorBE32::from_aead(XChaCha20Poly1305::new(key.as_ref().into()), nonce.into());

    let ct = CHUNK + TAG;
    let mut a = vec![0u8; ct];
    let mut b = vec![0u8; ct];
    let mut na = read_full(&mut input, &mut a)?;
    let mut name: Option<String> = None;
    let mut hasher = Sha256::new();
    loop {
        if na < TAG {
            return Err(Error::Crypto);
        }
        let nb = if na == ct { read_full(&mut input, &mut b)? } else { 0 };
        let p = Payload { msg: &a[..na], aad: &header };
        let last = nb == 0;
        let pt = if last {
            // `decrypt_last` consuma il decryptor: lo sostituiamo con uno fittizio
            let d = std::mem::replace(
                &mut dec,
                DecryptorBE32::from_aead(XChaCha20Poly1305::new(&[0u8; 32].into()), &[0u8; NONCE].into()),
            );
            Zeroizing::new(d.decrypt_last(p).map_err(|_| Error::Crypto)?)
        } else {
            Zeroizing::new(dec.decrypt_next(p).map_err(|_| Error::Crypto)?)
        };
        let body: &[u8] = if name.is_none() {
            if pt.len() < 2 {
                return Err(Error::Crypto);
            }
            let l = u16::from_le_bytes([pt[0], pt[1]]) as usize;
            if pt.len() < 2 + l {
                return Err(Error::Crypto);
            }
            let n = std::str::from_utf8(&pt[2..2 + l]).map_err(|_| Error::Crypto)?.to_owned();
            validate_name(&n)?;
            name = Some(n);
            &pt[2 + l..]
        } else {
            &pt[..]
        };
        hasher.update(body);
        out.write_all(body)?;
        if last {
            break;
        }
        std::mem::swap(&mut a, &mut b);
        na = nb;
    }
    Ok((name.ok_or(Error::Crypto)?, hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let master = [7u8; 32];
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let mut ct = Vec::new();
        let h1 = encrypt_stream(&master, "relazione è.pdf", &data[..], &mut ct).unwrap();
        let mut pt = Vec::new();
        let (name, h2) = decrypt_stream(&master, &ct[..], &mut pt).unwrap();
        assert_eq!(name, "relazione è.pdf");
        assert_eq!(pt, data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn roundtrip_sizes() {
        for len in [0, 1, CHUNK - 3, CHUNK - 2, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 5] {
            roundtrip(len);
        }
    }

    #[test]
    fn tamper_detected() {
        let master = [1u8; 32];
        let data = vec![9u8; CHUNK + 100];
        let mut ct = Vec::new();
        encrypt_stream(&master, "a.txt", &data[..], &mut ct).unwrap();
        for pos in [10, HEADER_LEN + 5, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[pos] ^= 1;
            assert!(decrypt_stream(&master, &bad[..], &mut io::sink()).is_err(), "pos {pos}");
        }
        // troncamento esattamente al confine di un blocco
        let cut = &ct[..HEADER_LEN + CHUNK + TAG];
        assert!(decrypt_stream(&master, cut, &mut io::sink()).is_err());
        // chiave sbagliata
        assert!(decrypt_stream(&[2u8; 32], &ct[..], &mut io::sink()).is_err());
    }

    #[test]
    fn rejects_bad_names() {
        for n in ["..", "a/b", "a\\b", "C:x", ""] {
            assert!(encrypt_stream(&[0u8; 32], n, &b""[..], &mut Vec::new()).is_err());
        }
    }
}
